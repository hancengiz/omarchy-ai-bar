//! Deterministic in-memory provider state with watch-based publication.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use oab_domain::{
    AccountScope, ClassifiedError, CostUsageSnapshot, Freshness, ProviderSnapshot, RefreshPhase,
    RetryEligibility, SnapshotEnvelopeV1, SnapshotError, Timestamp, UsageSample,
};
use thiserror::Error;
use tokio::sync::watch;

/// One immutable, monotonically sequenced runtime publication.
#[derive(Clone, PartialEq)]
pub struct PublishedSnapshot {
    sequence: u64,
    envelope: SnapshotEnvelopeV1,
}

impl Debug for PublishedSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSnapshot")
            .field("sequence", &self.sequence)
            .field("generated_at", &self.envelope.generated_at())
            .field("snapshot_count", &self.envelope.snapshots().len())
            .finish()
    }
}

impl PublishedSnapshot {
    /// Monotonic publication sequence, beginning at one.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Deterministically ordered domain snapshot envelope.
    #[must_use]
    pub const fn envelope(&self) -> &SnapshotEnvelopeV1 {
        &self.envelope
    }
}

/// A rejected state-store construction or transition.
#[derive(Debug, Error)]
pub enum SnapshotStoreError {
    /// Initial configuration repeated an exact provider-instance-account scope.
    #[error("snapshot store contains a duplicate account scope")]
    DuplicateScope,

    /// A transition addressed a scope not owned by this store.
    #[error("snapshot transition addressed an unknown account scope")]
    UnknownScope,

    /// A provider returned data for a different exact routing scope.
    #[error("provider result scope does not match the requested account scope")]
    ScopeMismatch,

    /// The publication sequence reached its integer limit.
    #[error("snapshot publication sequence is exhausted")]
    SequenceExhausted,

    /// A domain snapshot invariant rejected the transition.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
}

/// Actor-owned state store. Mutation remains single-owner while readers
/// receive immutable [`Arc`] publications through a Tokio watch channel.
pub(crate) struct SnapshotStore {
    snapshots: BTreeMap<AccountScope, ProviderSnapshot>,
    sequence: u64,
    publisher: watch::Sender<Arc<PublishedSnapshot>>,
}

impl Debug for SnapshotStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotStore")
            .field("scope_count", &self.snapshots.len())
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl SnapshotStore {
    /// Creates a sequence-one loading envelope in deterministic scope order.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate scopes or when the initial domain
    /// envelope exceeds its validated bounds.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        scopes: impl IntoIterator<Item = AccountScope>,
        generated_at: Timestamp,
    ) -> Result<Self, SnapshotStoreError> {
        Self::new_with_retained(scopes, std::iter::empty(), generated_at)
    }

    pub(crate) fn new_with_retained(
        scopes: impl IntoIterator<Item = AccountScope>,
        retained: impl IntoIterator<Item = ProviderSnapshot>,
        generated_at: Timestamp,
    ) -> Result<Self, SnapshotStoreError> {
        let mut snapshots = BTreeMap::new();
        for scope in scopes {
            if snapshots
                .insert(scope.clone(), ProviderSnapshot::loading(scope))
                .is_some()
            {
                return Err(SnapshotStoreError::DuplicateScope);
            }
        }
        for snapshot in retained {
            let scope = snapshot.scope();
            let Some(sample) = snapshot.last_known_good() else {
                continue;
            };
            if !snapshots.contains_key(scope) {
                continue;
            }
            let stale_since = generated_at.max(sample.fetched_at());
            let restored = ProviderSnapshot::ready(
                sample.clone(),
                Freshness::Stale { since: stale_since },
                RefreshPhase::Idle,
                None,
            )?;
            snapshots.insert(scope.clone(), restored);
        }
        let envelope = build_envelope(&snapshots, generated_at)?;
        let initial = Arc::new(PublishedSnapshot {
            sequence: 1,
            envelope,
        });
        let (publisher, _receiver) = watch::channel(initial);
        Ok(Self {
            snapshots,
            sequence: 1,
            publisher,
        })
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<PublishedSnapshot>> {
        self.publisher.subscribe()
    }

    // This direct actor-side lookup is part of the store contract even though
    // the first actor implementation consumes only immutable publications.
    #[allow(dead_code)]
    pub(crate) fn snapshot(&self, scope: &AccountScope) -> Option<&ProviderSnapshot> {
        self.snapshots.get(scope)
    }

    pub(crate) fn mark_scheduled(
        &mut self,
        scope: &AccountScope,
        at: Timestamp,
        generated_at: Timestamp,
    ) -> Result<bool, SnapshotStoreError> {
        self.set_ready_refresh_phase(scope, RefreshPhase::Scheduled { at }, generated_at)
    }

    pub(crate) fn mark_refreshing(
        &mut self,
        scope: &AccountScope,
        started_at: Timestamp,
        generated_at: Timestamp,
    ) -> Result<bool, SnapshotStoreError> {
        self.set_ready_refresh_phase(scope, RefreshPhase::Refreshing { started_at }, generated_at)
    }

    pub(crate) fn apply_success(
        &mut self,
        scope: &AccountScope,
        sample: UsageSample,
        generated_at: Timestamp,
    ) -> Result<bool, SnapshotStoreError> {
        self.require_scope(scope)?;
        if sample.scope() != scope {
            return Err(SnapshotStoreError::ScopeMismatch);
        }

        let sample = match self
            .snapshots
            .get(scope)
            .and_then(ProviderSnapshot::last_known_good)
        {
            Some(cached) => sample.backfilling_reset_times(cached, generated_at)?,
            None => sample,
        };
        let next = ProviderSnapshot::ready(sample, Freshness::Fresh, RefreshPhase::Idle, None)?;
        self.publish_change(scope, next, generated_at)
    }

    pub(crate) fn apply_failure(
        &mut self,
        scope: &AccountScope,
        error: ClassifiedError,
        generated_at: Timestamp,
    ) -> Result<bool, SnapshotStoreError> {
        let current = self.require_scope(scope)?;
        let next = if error.retry() == RetryEligibility::Automatic {
            if let Some(last_known_good) = current.last_known_good() {
                let stale_since = generated_at.max(last_known_good.fetched_at());
                current.with_error_overlay(scope, error, stale_since)?
            } else {
                ProviderSnapshot::unavailable(scope.clone(), error)
            }
        } else {
            // Authentication, permission, missing-credential, and parse
            // failures are not transient. Retiring old usage prevents a
            // previous account's data from surviving a logout or credential
            // change under the same ambient scope.
            ProviderSnapshot::unavailable(scope.clone(), error)
        };
        self.publish_change(scope, next, generated_at)
    }

    pub(crate) fn apply_cost_usage(
        &mut self,
        scope: &AccountScope,
        base_fetched_at: Timestamp,
        cost_usage: CostUsageSnapshot,
        generated_at: Timestamp,
    ) -> Result<bool, SnapshotStoreError> {
        let current = self.require_scope(scope)?;
        let Some(sample) = current.last_known_good() else {
            return Ok(false);
        };
        if sample.fetched_at() != base_fetched_at {
            return Ok(false);
        }

        let Some((freshness, refresh)) = current.freshness().zip(current.refresh_phase()) else {
            return Ok(false);
        };
        let next = ProviderSnapshot::ready(
            sample.clone().with_cost_usage(cost_usage),
            freshness,
            refresh,
            current.error().cloned(),
        )?;
        self.publish_change(scope, next, generated_at)
    }

    fn set_ready_refresh_phase(
        &mut self,
        scope: &AccountScope,
        phase: RefreshPhase,
        generated_at: Timestamp,
    ) -> Result<bool, SnapshotStoreError> {
        let current = self.require_scope(scope)?;
        let Some(sample) = current.last_known_good() else {
            return Ok(false);
        };
        let Some(freshness) = current.freshness() else {
            return Ok(false);
        };
        let next =
            ProviderSnapshot::ready(sample.clone(), freshness, phase, current.error().cloned())?;
        self.publish_change(scope, next, generated_at)
    }

    fn require_scope(&self, scope: &AccountScope) -> Result<&ProviderSnapshot, SnapshotStoreError> {
        self.snapshots
            .get(scope)
            .ok_or(SnapshotStoreError::UnknownScope)
    }

    fn publish_change(
        &mut self,
        scope: &AccountScope,
        next: ProviderSnapshot,
        generated_at: Timestamp,
    ) -> Result<bool, SnapshotStoreError> {
        let current = self.require_scope(scope)?;
        if current == &next {
            return Ok(false);
        }

        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(SnapshotStoreError::SequenceExhausted)?;
        let mut next_snapshots = self.snapshots.clone();
        next_snapshots.insert(scope.clone(), next);
        let envelope = build_envelope(&next_snapshots, generated_at)?;
        let publication = Arc::new(PublishedSnapshot {
            sequence: next_sequence,
            envelope,
        });

        self.snapshots = next_snapshots;
        self.sequence = next_sequence;
        self.publisher.send_replace(publication);
        Ok(true)
    }
}

fn build_envelope(
    snapshots: &BTreeMap<AccountScope, ProviderSnapshot>,
    generated_at: Timestamp,
) -> Result<SnapshotEnvelopeV1, SnapshotError> {
    SnapshotEnvelopeV1::new(generated_at, snapshots.values().cloned().collect())
}

#[cfg(test)]
mod tests {
    use oab_domain::{
        AccountKey, CostProvenance, CostUnit, CostUsageCoverage, CostUsageMetrics,
        CostUsageSnapshot, CostUsageTokenMix, DataConfidence, ErrorKind, IdentitySnapshot,
        ProviderHealth, ProviderId, ProviderInstanceId, ProviderStatus, RateWindow, UsagePercent,
        WindowDuration, WindowUsage,
    };

    use super::*;

    fn timestamp(seconds: i64) -> Timestamp {
        Timestamp::from_unix_timestamp(seconds).expect("test timestamp")
    }

    fn scope(account: &str) -> AccountScope {
        AccountScope::new(
            ProviderId::Codex,
            ProviderInstanceId::new("default").expect("instance"),
            AccountKey::new(account).expect("account"),
        )
    }

    fn sample(
        scope: &AccountScope,
        fetched_at: Timestamp,
        primary: Option<RateWindow>,
    ) -> UsageSample {
        UsageSample::new(
            scope.clone(),
            IdentitySnapshot::new(scope.clone(), None, None, None, None, None, None),
            fetched_at,
            primary,
            None,
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DataConfidence::Exact,
            ProviderStatus::new(
                ProviderHealth::Operational,
                None,
                Some(fetched_at),
                Vec::new(),
            )
            .expect("provider status"),
        )
        .expect("usage sample")
    }

    fn cost_usage(updated_at: Timestamp) -> CostUsageSnapshot {
        let metrics = CostUsageMetrics::new(
            CostUsageTokenMix::default(),
            None,
            None,
            None,
            CostUsageCoverage::default(),
        )
        .expect("cost metrics");
        CostUsageSnapshot::new(
            CostUnit::provider("tokens").expect("provider unit"),
            metrics.clone(),
            metrics,
            None,
            1,
            false,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            updated_at,
            CostProvenance::Unknown,
        )
        .expect("cost usage")
    }

    #[test]
    fn initial_loading_publication_is_sequence_one_and_sorted() {
        let later = scope("z-account");
        let earlier = scope("a-account");
        let store = SnapshotStore::new([later.clone(), earlier.clone()], timestamp(1_000))
            .expect("snapshot store");
        let receiver = store.subscribe();
        let publication = receiver.borrow();

        assert_eq!(publication.sequence(), 1);
        assert_eq!(publication.envelope().generated_at(), timestamp(1_000));
        assert_eq!(
            publication
                .envelope()
                .snapshots()
                .iter()
                .map(ProviderSnapshot::scope)
                .collect::<Vec<_>>(),
            vec![&earlier, &later]
        );
        assert!(matches!(
            store.snapshot(&earlier),
            Some(ProviderSnapshot::Loading(_))
        ));
    }

    #[test]
    fn debug_views_expose_only_publication_metadata() {
        let sensitive_scope = scope("debug-secret-marker");
        let store =
            SnapshotStore::new([sensitive_scope], timestamp(1_000)).expect("snapshot store");
        let publication = store.subscribe().borrow().clone();

        assert!(!format!("{publication:?}").contains("debug-secret-marker"));
        assert!(!format!("{store:?}").contains("debug-secret-marker"));
    }

    #[test]
    fn duplicate_and_unknown_scopes_fail_without_publication() {
        let known = scope("known");
        assert!(matches!(
            SnapshotStore::new([known.clone(), known.clone()], timestamp(1)),
            Err(SnapshotStoreError::DuplicateScope)
        ));

        let mut store = SnapshotStore::new([known], timestamp(1)).expect("store");
        let receiver = store.subscribe();
        assert!(matches!(
            store.apply_failure(
                &scope("unknown"),
                ClassifiedError::new(ErrorKind::Network),
                timestamp(2)
            ),
            Err(SnapshotStoreError::UnknownScope)
        ));
        assert_eq!(receiver.borrow().sequence(), 1);
    }

    #[test]
    fn success_refresh_failure_and_noops_publish_only_real_mutations() {
        let account = scope("account-one");
        let fetched = timestamp(100);
        let mut store = SnapshotStore::new([account.clone()], timestamp(90)).expect("store");
        let mut receiver = store.subscribe();
        receiver.borrow_and_update();

        assert!(
            !store
                .mark_scheduled(&account, timestamp(95), timestamp(95))
                .expect("loading schedule noop")
        );
        assert!(!receiver.has_changed().expect("watch open"));

        assert!(
            store
                .apply_success(&account, sample(&account, fetched, None), timestamp(101))
                .expect("success")
        );
        assert_eq!(receiver.borrow_and_update().sequence(), 2);
        let ready = store.snapshot(&account).expect("ready snapshot");
        assert_eq!(ready.freshness(), Some(Freshness::Fresh));
        assert_eq!(ready.refresh_phase(), Some(RefreshPhase::Idle));
        assert!(ready.error().is_none());
        let preserved = ready
            .last_known_good()
            .expect("last-known-good sample")
            .clone();
        assert!(
            !store
                .apply_success(&account, preserved.clone(), timestamp(999))
                .expect("identical success noop")
        );
        assert_eq!(receiver.borrow_and_update().sequence(), 2);

        assert!(
            store
                .mark_scheduled(&account, timestamp(110), timestamp(102))
                .expect("scheduled")
        );
        assert!(
            store
                .mark_refreshing(&account, timestamp(103), timestamp(103))
                .expect("refreshing")
        );
        assert!(
            !store
                .mark_refreshing(&account, timestamp(103), timestamp(999))
                .expect("identical refreshing noop")
        );
        assert_eq!(receiver.borrow_and_update().sequence(), 4);

        let failure = ClassifiedError::new(ErrorKind::Network);
        assert!(
            store
                .apply_failure(&account, failure.clone(), timestamp(50))
                .expect("failure overlay")
        );
        let failed = store.snapshot(&account).expect("failed snapshot");
        assert_eq!(
            failed.last_known_good().map(UsageSample::fetched_at),
            Some(fetched)
        );
        assert_eq!(
            failed.freshness(),
            Some(Freshness::Stale { since: fetched })
        );
        assert_eq!(failed.refresh_phase(), Some(RefreshPhase::Idle));
        assert_eq!(failed.error(), Some(&failure));
        assert_eq!(failed.last_known_good(), Some(&preserved));
        assert!(
            !store
                .apply_failure(&account, failure.clone(), timestamp(50))
                .expect("identical failure noop")
        );
        assert_eq!(receiver.borrow_and_update().sequence(), 5);
        assert!(
            store
                .apply_failure(&account, failure, timestamp(150))
                .expect("later stale overlay")
        );
        let later_failure = store.snapshot(&account).expect("later failed snapshot");
        assert_eq!(later_failure.last_known_good(), Some(&preserved));
        assert_eq!(
            later_failure.freshness(),
            Some(Freshness::Stale {
                since: timestamp(150)
            })
        );
        assert_eq!(receiver.borrow_and_update().sequence(), 6);
    }

    #[test]
    fn returned_scope_must_match_requested_scope() {
        let requested = scope("requested");
        let returned = scope("returned");
        let mut store = SnapshotStore::new([requested.clone()], timestamp(1)).expect("store");
        assert!(matches!(
            store.apply_success(
                &requested,
                sample(&returned, timestamp(2), None),
                timestamp(3)
            ),
            Err(SnapshotStoreError::ScopeMismatch)
        ));
        assert!(matches!(
            store.snapshot(&requested),
            Some(ProviderSnapshot::Loading(_))
        ));
    }

    #[test]
    fn failure_without_last_good_becomes_unavailable() {
        let account = scope("account");
        let failure = ClassifiedError::new(ErrorKind::AuthenticationExpired);
        let mut store = SnapshotStore::new([account.clone()], timestamp(1)).expect("store");
        assert!(
            store
                .apply_failure(&account, failure.clone(), timestamp(2))
                .expect("failure")
        );
        let snapshot = store.snapshot(&account).expect("snapshot");
        assert!(matches!(snapshot, ProviderSnapshot::Unavailable(_)));
        assert_eq!(snapshot.error(), Some(&failure));
        assert!(
            !store
                .mark_refreshing(&account, timestamp(3), timestamp(3))
                .expect("unavailable refresh noop")
        );
    }

    #[test]
    fn non_retryable_failure_retires_last_good_account_data() {
        let account = scope("account");
        let fetched = timestamp(100);
        let failure = ClassifiedError::new(ErrorKind::AuthenticationExpired);
        let mut store = SnapshotStore::new([account.clone()], timestamp(1)).expect("store");
        store
            .apply_success(&account, sample(&account, fetched, None), fetched)
            .expect("initial success");

        store
            .apply_failure(&account, failure.clone(), timestamp(110))
            .expect("terminal failure");
        let snapshot = store.snapshot(&account).expect("snapshot");
        assert!(matches!(snapshot, ProviderSnapshot::Unavailable(_)));
        assert!(snapshot.last_known_good().is_none());
        assert_eq!(snapshot.error(), Some(&failure));
    }

    #[test]
    fn success_backfills_only_same_scope_future_reset_metadata() {
        let account = scope("backfill");
        let cached_reset = timestamp(500);
        let cached_window = RateWindow::new(
            WindowUsage::known(UsagePercent::new(20.0).expect("percent")),
            Some(WindowDuration::from_seconds(300).expect("duration")),
            Some(cached_reset),
            None,
            None,
            false,
        )
        .expect("cached window");
        let fresh_window = RateWindow::new(
            WindowUsage::known(UsagePercent::new(25.0).expect("percent")),
            None,
            None,
            None,
            None,
            false,
        )
        .expect("fresh window");
        let mut store = SnapshotStore::new([account.clone()], timestamp(90)).expect("store");
        store
            .apply_success(
                &account,
                sample(&account, timestamp(100), Some(cached_window)),
                timestamp(100),
            )
            .expect("cached success");
        store
            .apply_success(
                &account,
                sample(&account, timestamp(200), Some(fresh_window)),
                timestamp(250),
            )
            .expect("fresh success");

        let primary = store
            .snapshot(&account)
            .and_then(ProviderSnapshot::last_known_good)
            .and_then(UsageSample::primary)
            .expect("primary window");
        assert_eq!(primary.resets_at(), Some(cached_reset));
        assert_eq!(primary.used_percent().map(UsagePercent::get), Some(25.0));
    }

    #[test]
    fn cost_usage_requires_the_exact_base_and_preserves_ready_state() {
        let account = scope("cost");
        let fetched = timestamp(100);
        let mut store = SnapshotStore::new([account.clone()], timestamp(90)).expect("store");
        store
            .apply_success(&account, sample(&account, fetched, None), timestamp(101))
            .expect("success");
        store
            .mark_refreshing(&account, timestamp(102), timestamp(102))
            .expect("refreshing");

        assert!(
            !store
                .apply_cost_usage(
                    &account,
                    timestamp(99),
                    cost_usage(timestamp(103)),
                    timestamp(103)
                )
                .expect("stale cost ignored")
        );
        assert!(
            store
                .apply_cost_usage(
                    &account,
                    fetched,
                    cost_usage(timestamp(103)),
                    timestamp(103)
                )
                .expect("cost applied")
        );
        let snapshot = store.snapshot(&account).expect("snapshot");
        assert_eq!(
            snapshot.refresh_phase(),
            Some(RefreshPhase::Refreshing {
                started_at: timestamp(102)
            })
        );
        assert!(
            snapshot
                .last_known_good()
                .and_then(UsageSample::cost_usage)
                .is_some()
        );
        assert!(
            !store
                .apply_cost_usage(
                    &account,
                    fetched,
                    cost_usage(timestamp(103)),
                    timestamp(999)
                )
                .expect("identical cost noop")
        );
    }
}
