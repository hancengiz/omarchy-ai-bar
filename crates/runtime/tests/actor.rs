use std::sync::Arc;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ClassifiedError, DataConfidence, ErrorKind, Freshness,
    IdentitySnapshot, ProviderHealth, ProviderId, ProviderInstanceId, ProviderSnapshot,
    ProviderStatus, Timestamp, UsageSample,
};
use oab_runtime::actor::{
    RefreshFuture, RefreshRegistration, RefreshSource, RuntimeActor, RuntimeConfig, RuntimeLimits,
    TryCommandError,
};
use oab_runtime::command::{RefreshAdmission, RefreshTrigger};
use oab_runtime::scheduler::{Clock, SchedulePolicy};
use oab_runtime::snapshot_store::PublishedSnapshot;
use oab_test_support::clock::FakeClock;
use oab_test_support::fake_provider::{
    CancellationBehavior, FakeGate, ScriptedProvider, ScriptedStep,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
struct TestClock(FakeClock);

impl TestClock {
    fn new(now: Timestamp) -> Self {
        Self(FakeClock::new(now))
    }
}

impl Clock for TestClock {
    fn wall_now(&self) -> Timestamp {
        self.0.wall_now()
    }

    fn monotonic_now(&self) -> tokio::time::Instant {
        self.0.monotonic_now()
    }
}

#[derive(Debug, Clone)]
struct FakeSource(Arc<ScriptedProvider>);

impl RefreshSource for FakeSource {
    fn fetch_required(
        &self,
        scope: AccountScope,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<UsageSample, ClassifiedError>> {
        let provider = Arc::clone(&self.0);
        Box::pin(async move { provider.run_required(scope, cancellation).await })
    }

    fn fetch_optional(
        &self,
        required: UsageSample,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<Option<oab_domain::CostUsageSnapshot>, ClassifiedError>> {
        let provider = Arc::clone(&self.0);
        Box::pin(async move { provider.run_optional(required, cancellation).await })
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("primary").expect("fixture provider instance"),
        AccountKey::new(account).expect("fixture account"),
    )
}

fn sample(scope: &AccountScope, fetched_at: Timestamp) -> UsageSample {
    UsageSample::new(
        scope.clone(),
        IdentitySnapshot::new(scope.clone(), None, None, None, None, None, None),
        fetched_at,
        None,
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
        .expect("fixture provider status"),
    )
    .expect("fixture usage sample")
}

fn config(command_capacity: usize, max_in_flight: usize, grace: Duration) -> RuntimeConfig {
    let schedule = SchedulePolicy::new(Duration::from_hours(24), Duration::from_hours(1))
        .expect("fixture schedule policy");
    let limits = RuntimeLimits::new(command_capacity, 16, 32, max_in_flight)
        .expect("fixture runtime limits");
    RuntimeConfig::new(schedule, limits, grace).expect("fixture runtime config")
}

fn build(
    runtime_config: RuntimeConfig,
    account_scope: AccountScope,
    provider: Arc<ScriptedProvider>,
) -> (RuntimeActor, oab_runtime::actor::RuntimeHandle) {
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(timestamp(1_700_000_000)));
    let source: Arc<dyn RefreshSource> = Arc::new(FakeSource(provider));
    RuntimeActor::new(
        runtime_config,
        clock,
        [RefreshRegistration::new(account_scope, source)],
    )
    .expect("fixture runtime actor")
}

async fn wait_for_publication(
    receiver: &mut watch::Receiver<Arc<PublishedSnapshot>>,
    predicate: impl Fn(&ProviderSnapshot) -> bool,
) -> Arc<PublishedSnapshot> {
    loop {
        let publication = receiver.borrow().clone();
        let snapshot = publication
            .envelope()
            .snapshots()
            .first()
            .expect("fixture has one scope");
        if predicate(snapshot) {
            return publication;
        }
        receiver.changed().await.expect("runtime remains active");
    }
}

#[tokio::test(start_paused = true)]
async fn publications_use_strictly_increasing_sequences() {
    let account_scope = scope("account-a");
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_required(ScriptedStep::success(sample(
        &account_scope,
        timestamp(1_700_000_001),
    )));
    provider.push_required(ScriptedStep::success(sample(
        &account_scope,
        timestamp(1_700_000_002),
    )));
    let (actor, handle) = build(
        config(8, 1, Duration::from_secs(2)),
        account_scope.clone(),
        provider,
    );
    let mut snapshots = handle.subscribe();
    assert_eq!(snapshots.borrow().sequence(), 1);
    let task = actor.spawn();

    assert_eq!(
        handle
            .refresh(account_scope.clone(), RefreshTrigger::Manual)
            .await
            .expect("first refresh admitted"),
        RefreshAdmission::Started
    );
    let first = wait_for_publication(&mut snapshots, |snapshot| {
        snapshot
            .last_known_good()
            .is_some_and(|sample| sample.fetched_at() == timestamp(1_700_000_001))
    })
    .await;

    assert_eq!(
        handle
            .refresh(account_scope, RefreshTrigger::Manual)
            .await
            .expect("second refresh admitted"),
        RefreshAdmission::Started
    );
    let second = wait_for_publication(&mut snapshots, |snapshot| {
        snapshot
            .last_known_good()
            .is_some_and(|sample| sample.fetched_at() == timestamp(1_700_000_002))
    })
    .await;

    assert!(first.sequence() > 1);
    assert!(second.sequence() > first.sequence());
    let exit = task.shutdown().await.expect("clean runtime shutdown");
    assert!(exit.fault().is_none());
}

#[tokio::test(start_paused = true)]
async fn bounded_commands_backpressure_and_overlapping_refreshes_coalesce() {
    let account_scope = scope("account-a");
    let gate = FakeGate::closed();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_required(
        ScriptedStep::success(sample(&account_scope, timestamp(1_700_000_001)))
            .behind(gate.clone()),
    );
    let (actor, handle) = build(
        config(1, 1, Duration::from_secs(2)),
        account_scope.clone(),
        Arc::clone(&provider),
    );

    let first = handle
        .try_refresh(account_scope.clone(), RefreshTrigger::Manual)
        .expect("first command fits");
    assert!(matches!(
        handle.try_refresh(account_scope.clone(), RefreshTrigger::Manual),
        Err(TryCommandError::Full)
    ));

    let mut snapshots = handle.subscribe();
    let task = actor.spawn();
    assert_eq!(
        first.admission().await.expect("first receipt"),
        RefreshAdmission::Started
    );
    assert_eq!(
        handle
            .refresh(account_scope, RefreshTrigger::Manual)
            .await
            .expect("overlap receipt"),
        RefreshAdmission::Coalesced
    );
    assert_eq!(provider.required_calls(), 1);

    gate.release();
    wait_for_publication(&mut snapshots, |snapshot| {
        snapshot.last_known_good().is_some()
    })
    .await;
    assert_eq!(provider.required_calls(), 1);
    task.shutdown().await.expect("clean runtime shutdown");
}

#[tokio::test(start_paused = true)]
async fn optional_failure_does_not_mutate_required_display_state() {
    let account_scope = scope("account-a");
    let optional_gate = FakeGate::closed();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_required(ScriptedStep::success(sample(
        &account_scope,
        timestamp(1_700_000_001),
    )));
    provider.push_optional(
        ScriptedStep::failure(ClassifiedError::new(ErrorKind::Api)).behind(optional_gate.clone()),
    );
    let (actor, handle) = build(
        config(8, 1, Duration::from_secs(2)),
        account_scope.clone(),
        Arc::clone(&provider),
    );
    let mut snapshots = handle.subscribe();
    let mut events = handle.subscribe_events();
    let task = actor.spawn();

    handle
        .refresh(account_scope.clone(), RefreshTrigger::Manual)
        .await
        .expect("refresh admitted");
    let required = wait_for_publication(&mut snapshots, |snapshot| {
        snapshot.last_known_good().is_some()
    })
    .await;
    let required_sequence = required.sequence();
    let required_snapshot = &required.envelope().snapshots()[0];
    assert_eq!(required_snapshot.freshness(), Some(Freshness::Fresh));
    assert!(required_snapshot.error().is_none());
    assert_eq!(provider.optional_calls(), 1);

    optional_gate.release();
    loop {
        let event = events.recv().await.expect("runtime event");
        if let oab_runtime::actor::RuntimeEvent::OptionalEnrichmentFailed { scope, error, .. } =
            event
        {
            assert_eq!(scope, account_scope);
            assert_eq!(error.kind(), ErrorKind::Api);
            break;
        }
    }

    let after_optional = snapshots.borrow().clone();
    assert_eq!(after_optional.sequence(), required_sequence);
    let snapshot = &after_optional.envelope().snapshots()[0];
    assert_eq!(snapshot.freshness(), Some(Freshness::Fresh));
    assert!(snapshot.error().is_none());
    task.shutdown().await.expect("clean runtime shutdown");
}

#[tokio::test(start_paused = true)]
async fn required_failure_preserves_last_good_and_overlays_classified_error() {
    let account_scope = scope("account-a");
    let fetched_at = timestamp(1_700_000_001);
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_required(ScriptedStep::success(sample(&account_scope, fetched_at)));
    provider.push_required(ScriptedStep::failure(ClassifiedError::new(
        ErrorKind::Network,
    )));
    let (actor, handle) = build(
        config(8, 1, Duration::from_secs(2)),
        account_scope.clone(),
        provider,
    );
    let mut snapshots = handle.subscribe();
    let task = actor.spawn();

    handle
        .refresh(account_scope.clone(), RefreshTrigger::Manual)
        .await
        .expect("first refresh admitted");
    wait_for_publication(&mut snapshots, |snapshot| {
        snapshot.last_known_good().is_some()
    })
    .await;
    handle
        .refresh(account_scope, RefreshTrigger::Manual)
        .await
        .expect("failed refresh admitted");
    let failed = wait_for_publication(&mut snapshots, |snapshot| {
        snapshot
            .error()
            .is_some_and(|error| error.kind() == ErrorKind::Network)
    })
    .await;

    let snapshot = &failed.envelope().snapshots()[0];
    assert_eq!(
        snapshot.last_known_good().map(UsageSample::fetched_at),
        Some(fetched_at)
    );
    assert!(matches!(
        snapshot.freshness(),
        Some(Freshness::Stale { .. })
    ));
    assert_eq!(
        snapshot.error().map(ClassifiedError::kind),
        Some(ErrorKind::Network)
    );
    task.shutdown().await.expect("clean runtime shutdown");
}

#[tokio::test(start_paused = true)]
async fn newer_required_generation_aborts_the_previous_optional_task() {
    let account_scope = scope("account-a");
    let stale_optional = FakeGate::closed();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_required(ScriptedStep::success(sample(
        &account_scope,
        timestamp(1_700_000_001),
    )));
    provider.push_optional(
        ScriptedStep::success(None)
            .behind(stale_optional)
            .cancellation(CancellationBehavior::Ignore),
    );
    provider.push_required(ScriptedStep::success(sample(
        &account_scope,
        timestamp(1_700_000_002),
    )));
    provider.push_optional(ScriptedStep::success(None));
    let (actor, handle) = build(
        config(8, 1, Duration::from_secs(2)),
        account_scope.clone(),
        Arc::clone(&provider),
    );
    let mut snapshots = handle.subscribe();
    let task = actor.spawn();

    handle
        .refresh(account_scope.clone(), RefreshTrigger::Manual)
        .await
        .expect("first refresh admitted");
    wait_for_publication(&mut snapshots, |snapshot| {
        snapshot
            .last_known_good()
            .is_some_and(|sample| sample.fetched_at() == timestamp(1_700_000_001))
    })
    .await;
    handle
        .refresh(account_scope, RefreshTrigger::Manual)
        .await
        .expect("new generation admitted");
    wait_for_publication(&mut snapshots, |snapshot| {
        snapshot
            .last_known_good()
            .is_some_and(|sample| sample.fetched_at() == timestamp(1_700_000_002))
    })
    .await;
    tokio::task::yield_now().await;

    assert_eq!(provider.required_calls(), 2);
    assert_eq!(provider.optional_calls(), 2);
    task.shutdown().await.expect("clean runtime shutdown");
}

#[tokio::test(start_paused = true)]
async fn actor_shutdown_aborts_cancellation_ignoring_work_at_the_grace_deadline() {
    let account_scope = scope("account-a");
    let never = FakeGate::closed();
    let provider = Arc::new(ScriptedProvider::new());
    provider.push_required(
        ScriptedStep::success(sample(&account_scope, timestamp(1_700_000_001)))
            .behind(never)
            .cancellation(CancellationBehavior::Ignore),
    );
    let grace = Duration::from_secs(7);
    let (actor, handle) = build(config(8, 1, grace), account_scope.clone(), provider);
    let task = actor.spawn();
    assert_eq!(
        handle
            .refresh(account_scope, RefreshTrigger::Manual)
            .await
            .expect("refresh admitted"),
        RefreshAdmission::Started
    );
    let before = tokio::time::Instant::now();

    let exit = task.shutdown().await.expect("bounded runtime shutdown");

    assert_eq!(tokio::time::Instant::now().duration_since(before), grace);
    assert!(exit.fault().is_none());
    assert!(exit.shutdown_report().timed_out());
    assert_eq!(exit.shutdown_report().cancelled(), 1);
}
