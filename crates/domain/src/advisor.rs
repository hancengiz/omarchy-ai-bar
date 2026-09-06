//! Read-only reset-redemption advice for providers with banked resets.
//!
//! The advisor ranks capped Codex accounts against their natural limit resets
//! and banked reset inventories. It never redeems anything; it only names the
//! account and credit a redemption would spend, the natural reset it would
//! advance, and credits at risk of expiring unused.
//!
//! Only the main model lanes (`primary` and `secondary`) participate. Extra
//! windows such as Codex Spark or gpt-reserve are deliberately excluded: they
//! meter separate model families, not the limits a full reset clears.

use serde::Serialize;

use crate::snapshot::SnapshotError;
use crate::text::BoundedText;
use crate::{ResetCredit, Timestamp, UsageSample};

/// A main-model lane at or above this raw percentage is treated as exhausted.
pub const CAPPED_USED_PERCENT: f64 = 99.5;

/// Longest account label accepted by the advisor. Identity text already fits.
pub const MAX_ADVISOR_LABEL_LENGTH: usize = 256;

/// Maximum accounts considered by one decision.
pub const MAX_ADVISED_ACCOUNTS: usize = 8;

/// Maximum credits tracked per advised account.
pub const MAX_ADVISED_CREDITS: usize = 64;

/// Maximum expiry notes attached to one decision.
pub const MAX_EXPIRY_NOTES: usize = 8;

/// A credit expiring within this horizon is flagged while its account is capped.
pub const EXPIRY_NOTE_HORIZON_SECONDS: i64 = 14 * 24 * 60 * 60;

/// One advised account: main-lane exhaustion, natural reset, and credits.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvisorAccount {
    label: BoundedText<MAX_ADVISOR_LABEL_LENGTH>,
    capped: bool,
    remaining_percent: Option<f64>,
    natural_reset: Option<Timestamp>,
    credit_expiries: Vec<Option<Timestamp>>,
}

impl AdvisorAccount {
    /// Creates one advised account.
    ///
    /// # Errors
    ///
    /// Returns an error when the label is empty, contains control characters,
    /// or exceeds [`MAX_ADVISOR_LABEL_LENGTH`], or when more than
    /// [`MAX_ADVISED_CREDITS`] credits are supplied.
    pub fn new(
        label: impl Into<String>,
        capped: bool,
        remaining_percent: Option<f64>,
        natural_reset: Option<Timestamp>,
        credit_expiries: Vec<Option<Timestamp>>,
    ) -> Result<Self, SnapshotError> {
        check_limit(
            "advised credits",
            credit_expiries.len(),
            MAX_ADVISED_CREDITS,
        )?;
        Ok(Self {
            label: BoundedText::new(label.into())?,
            capped,
            remaining_percent: remaining_percent.filter(|percent| percent.is_finite()),
            natural_reset,
            credit_expiries,
        })
    }

    /// Projects a usage sample into an advised account.
    ///
    /// The label prefers the identity email, then the account label, then the
    /// opaque account key. Returns `None` when neither main lane reports a
    /// known percentage, leaving nothing to advise on.
    #[must_use]
    pub fn from_sample(sample: &UsageSample, now: Timestamp) -> Option<Self> {
        let mut capped = false;
        let mut known = false;
        let mut remaining_percent: Option<f64> = None;
        let mut natural_reset = None;
        for lane in [sample.primary(), sample.secondary()].into_iter().flatten() {
            let Some(used_percent) = lane.used_percent() else {
                continue;
            };
            known = true;
            let used = used_percent.get();
            remaining_percent = Some(match remaining_percent {
                Some(current) => current.min(100.0 - used),
                None => 100.0 - used,
            });
            if used >= CAPPED_USED_PERCENT {
                capped = true;
                if let Some(resets_at) = lane
                    .resets_at()
                    .filter(|resets_at| *resets_at > now)
                {
                    natural_reset = Some(natural_reset.map_or(resets_at, |current: Timestamp| {
                        current.min(resets_at)
                    }));
                }
            }
        }
        if !known {
            return None;
        }
        let identity = sample.identity();
        let label = identity
            .email()
            .or(identity.account_label())
            .map_or_else(
                || sample.scope().account().as_str().to_owned(),
                |text| text.as_str().to_owned(),
            );
        let credit_expiries = sample
            .available_reset_credits(now)
            .into_iter()
            .map(ResetCredit::expires_at)
            .collect();
        // Labels drawn from bounded identity text cannot exceed the bound, so
        // construction cannot fail here.
        Self::new(label, capped, remaining_percent, natural_reset, credit_expiries).ok()
    }

    #[must_use]
    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    #[must_use]
    pub const fn is_capped(&self) -> bool {
        self.capped
    }

    #[must_use]
    pub const fn remaining_percent(&self) -> Option<f64> {
        self.remaining_percent
    }

    #[must_use]
    pub const fn natural_reset(&self) -> Option<Timestamp> {
        self.natural_reset
    }

    #[must_use]
    pub fn credit_expiries(&self) -> &[Option<Timestamp>] {
        &self.credit_expiries
    }

    /// The expiry of the credit a redemption should spend: the most
    /// perishable available credit, with non-expiring credits last.
    #[must_use]
    pub fn next_credit_expiry(&self) -> Option<Timestamp> {
        self.credit_expiries.iter().flatten().copied().min()
    }
}

/// One decision: a primary action, alternatives, and expiry warnings.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResetAdvice {
    primary: AdviceAction,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    alternatives: Vec<AdviceAction>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    expiring: Vec<ExpiringCredit>,
}

impl ResetAdvice {
    /// Evaluates every advised account and returns one deterministic decision.
    ///
    /// `active` selects the primary action once every account is capped and a
    /// redemption candidate exists: an active user is told to redeem, with the
    /// natural-reset wait as the alternative; an idle user is told to wait,
    /// with the redemption as the alternative.
    ///
    /// # Errors
    ///
    /// Returns an error when more than [`MAX_ADVISED_ACCOUNTS`] accounts are
    /// supplied.
    pub fn evaluate(
        accounts: &[AdvisorAccount],
        now: Timestamp,
        active: bool,
    ) -> Result<Self, SnapshotError> {
        check_limit("advised accounts", accounts.len(), MAX_ADVISED_ACCOUNTS)?;
        let capped: Vec<&AdvisorAccount> = accounts.iter().filter(|a| a.is_capped()).collect();
        if capped.is_empty() {
            return Ok(Self::not_applicable());
        }

        let expiring = expiring_notes(&capped, now);
        let headroom: Vec<&AdvisorAccount> = accounts.iter().filter(|a| !a.is_capped()).collect();
        if let Some(best) = headroom
            .iter()
            .max_by(|left, right| switch_order(left, right))
            .copied()
        {
            return Ok(Self {
                primary: AdviceAction::Switch {
                    account: best.label().to_owned(),
                },
                alternatives: Vec::new(),
                expiring,
            });
        }

        let wait = soonest_reset(&capped, now);
        let Some(candidate) = redeem_candidate(&capped) else {
            return Ok(Self {
                primary: AdviceAction::Blocked {},
                alternatives: wait_alternatives(wait, now),
                expiring,
            });
        };
        let redeem = AdviceAction::Redeem {
            account: candidate.label().to_owned(),
            credit_expires_at: candidate.next_credit_expiry(),
            advances_availability_by_seconds: seconds_between(now, candidate.natural_reset()),
        };
        let wait_actions = wait_alternatives(wait, now);
        let (primary, alternatives) = match (!active, wait_actions.split_first()) {
            (true, Some((wait_action, _))) => (wait_action.clone(), vec![redeem]),
            _ => (redeem, wait_actions),
        };
        Ok(Self {
            primary,
            alternatives,
            expiring,
        })
    }

    fn not_applicable() -> Self {
        Self {
            primary: AdviceAction::NotApplicable {},
            alternatives: Vec::new(),
            expiring: Vec::new(),
        }
    }

    #[must_use]
    pub const fn primary(&self) -> &AdviceAction {
        &self.primary
    }

    #[must_use]
    pub fn alternatives(&self) -> &[AdviceAction] {
        &self.alternatives
    }

    #[must_use]
    pub fn expiring(&self) -> &[ExpiringCredit] {
        &self.expiring
    }
}

/// A single recommended move.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdviceAction {
    /// No capped account needs a decision.
    NotApplicable {},
    /// Another account still has main-lane headroom.
    Switch {
        account: String,
    },
    /// Spend a banked reset on this account now.
    Redeem {
        account: String,
        credit_expires_at: Option<Timestamp>,
        /// Seconds earlier than its natural reset the account becomes usable.
        advances_availability_by_seconds: Option<i64>,
    },
    /// Keep the credits and let a natural reset arrive.
    Wait {
        account: String,
        resets_at: Timestamp,
        resets_in_seconds: i64,
    },
    /// Every account is capped and no credits are available.
    Blocked {},
}

/// A banked credit that may expire while its account is still capped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpiringCredit {
    account: String,
    expires_at: Timestamp,
    expires_in_seconds: i64,
}

impl ExpiringCredit {
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    #[must_use]
    pub const fn expires_in_seconds(&self) -> i64 {
        self.expires_in_seconds
    }
}

impl AdviceAction {
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        match self {
            Self::NotApplicable {} | Self::Blocked {} => None,
            Self::Switch { account }
            | Self::Redeem { account, .. }
            | Self::Wait { account, .. } => Some(account),
        }
    }
}

fn check_limit(field: &'static str, actual: usize, maximum: usize) -> Result<(), SnapshotError> {
    if actual > maximum {
        Err(SnapshotError::LimitExceeded { field, maximum })
    } else {
        Ok(())
    }
}

/// Orders headroom accounts by most remaining main-lane capacity, then label.
fn switch_order(left: &AdvisorAccount, right: &AdvisorAccount) -> std::cmp::Ordering {
    left.remaining_percent()
        .partial_cmp(&right.remaining_percent())
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| left.label().cmp(right.label()))
}

fn soonest_reset<'a>(
    capped: &[&'a AdvisorAccount],
    now: Timestamp,
) -> Option<(&'a AdvisorAccount, Timestamp)> {
    capped
        .iter()
        .filter_map(|account| {
            account
                .natural_reset()
                .filter(|resets_at| *resets_at > now)
                .map(|reset| (*account, reset))
        })
        .min_by_key(|(account, reset)| (*reset, account.label()))
}

fn redeem_candidate<'a>(capped: &[&'a AdvisorAccount]) -> Option<&'a AdvisorAccount> {
    capped
        .iter()
        .copied()
        .filter(|account| !account.credit_expiries().is_empty())
        .min_by(|left, right| redeem_order(left, right))
}

/// Prefers an account whose redemption preserves a credit reserve elsewhere,
/// then the most perishable credit, then the soonest natural reset, then label.
fn redeem_order(left: &AdvisorAccount, right: &AdvisorAccount) -> std::cmp::Ordering {
    let reserve = usize::from(left.credit_expiries().len() < 2)
        .cmp(&usize::from(right.credit_expiries().len() < 2));
    let perishability = left
        .next_credit_expiry()
        .map_or(i64::MAX, Timestamp::unix_timestamp)
        .cmp(&right.next_credit_expiry().map_or(i64::MAX, Timestamp::unix_timestamp));
    let natural = left
        .natural_reset()
        .map_or(i64::MAX, Timestamp::unix_timestamp)
        .cmp(&right.natural_reset().map_or(i64::MAX, Timestamp::unix_timestamp));
    reserve
        .then(perishability)
        .then(natural)
        .then_with(|| left.label().cmp(right.label()))
}

fn wait_alternatives(
    wait: Option<(&AdvisorAccount, Timestamp)>,
    now: Timestamp,
) -> Vec<AdviceAction> {
    let Some((account, resets_at)) = wait else {
        return Vec::new();
    };
    vec![AdviceAction::Wait {
        account: account.label().to_owned(),
        resets_at,
        resets_in_seconds: resets_at.unix_timestamp() - now.unix_timestamp(),
    }]
}

fn seconds_between(now: Timestamp, until: Option<Timestamp>) -> Option<i64> {
    until.map(|until| until.unix_timestamp() - now.unix_timestamp())
}

fn expiring_notes(capped: &[&AdvisorAccount], now: Timestamp) -> Vec<ExpiringCredit> {
    let mut notes: Vec<ExpiringCredit> = capped
        .iter()
        .flat_map(|account| {
            let label = account.label().to_owned();
            account
                .credit_expiries()
                .iter()
                .flatten()
                .map(|expires_at| ExpiringCredit {
                    account: label.clone(),
                    expires_at: *expires_at,
                    expires_in_seconds: expires_at.unix_timestamp() - now.unix_timestamp(),
                })
                .collect::<Vec<_>>()
        })
        .filter(|note| {
            note.expires_in_seconds > 0 && note.expires_in_seconds <= EXPIRY_NOTE_HORIZON_SECONDS
        })
        .collect();
    notes.sort_by(|left, right| {
        (left.expires_at, &left.account).cmp(&(right.expires_at, &right.account))
    });
    notes.truncate(MAX_EXPIRY_NOTES);
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ts(value: &str) -> Timestamp {
        Timestamp::parse(value).expect("test timestamp")
    }

    fn now() -> Timestamp {
        ts("2026-09-06T12:46:36Z")
    }

    fn account(
        label: &str,
        used_percent: f64,
        resets_at: Option<&str>,
        credit_expiries: &[Option<&str>],
    ) -> AdvisorAccount {
        AdvisorAccount::new(
            label,
            used_percent >= CAPPED_USED_PERCENT,
            Some(100.0 - used_percent),
            resets_at.map(ts),
            credit_expiries.iter().map(|expiry| expiry.map(ts)).collect(),
        )
        .expect("advised account")
    }

    fn live_scenario() -> Vec<AdvisorAccount> {
        vec![
            account(
                "cengiz@cengizhan.com",
                100.0,
                Some("2026-09-07T06:38:49Z"),
                &[
                    Some("2026-09-20T23:55:02Z"),
                    Some("2026-10-04T01:50:29Z"),
                    Some("2026-10-05T04:18:19Z"),
                ],
            ),
            account(
                "cengiz@fabriqa.ai",
                100.0,
                Some("2026-09-12T21:22:55Z"),
                &[Some("2026-10-05T04:19:02Z")],
            ),
        ]
    }

    #[test]
    fn active_scenario_redeems_the_perishable_credit_on_the_stocked_account() {
        let advice = ResetAdvice::evaluate(&live_scenario(), now(), true).expect("advice");
        let AdviceAction::Redeem {
            account,
            credit_expires_at,
            advances_availability_by_seconds,
        } = advice.primary()
        else {
            panic!("expected redeem, got {:?}", advice.primary());
        };
        assert_eq!(account, "cengiz@cengizhan.com");
        assert_eq!(credit_expires_at, &Some(ts("2026-09-20T23:55:02Z")));
        assert_eq!(advances_availability_by_seconds, &Some(64_333));
        assert_eq!(
            advice.alternatives(),
            [AdviceAction::Wait {
                account: "cengiz@cengizhan.com".to_owned(),
                resets_at: ts("2026-09-07T06:38:49Z"),
                resets_in_seconds: 64_333,
            }]
        );
        assert!(advice.expiring().is_empty());
    }

    #[test]
    fn idle_scenario_waits_for_the_soonest_natural_reset() {
        let advice = ResetAdvice::evaluate(&live_scenario(), now(), false).expect("advice");
        assert_eq!(
            advice.primary(),
            &AdviceAction::Wait {
                account: "cengiz@cengizhan.com".to_owned(),
                resets_at: ts("2026-09-07T06:38:49Z"),
                resets_in_seconds: 64_333,
            }
        );
        let [AdviceAction::Redeem { account, .. }] = advice.alternatives() else {
            panic!(
                "expected redeem alternative, got {:?}",
                advice.alternatives()
            );
        };
        assert_eq!(*account, "cengiz@cengizhan.com");
    }

    #[test]
    fn headroom_account_switches_instead_of_redeeming() {
        let mut accounts = live_scenario();
        accounts[1] = account("cengiz@fabriqa.ai", 40.0, Some("2026-09-12T21:22:55Z"), &[]);
        let advice = ResetAdvice::evaluate(&accounts, now(), true).expect("advice");
        assert_eq!(
            advice.primary(),
            &AdviceAction::Switch {
                account: "cengiz@fabriqa.ai".to_owned()
            }
        );
        assert!(advice.alternatives().is_empty());
    }

    #[test]
    fn blocked_when_no_account_holds_credits() {
        let accounts: Vec<AdvisorAccount> = live_scenario()
            .into_iter()
            .map(|account| {
                AdvisorAccount::new(
                    account.label(),
                    true,
                    None,
                    account.natural_reset(),
                    Vec::new(),
                )
                .expect("advised account")
            })
            .collect();
        let advice = ResetAdvice::evaluate(&accounts, now(), true).expect("advice");
        assert_eq!(advice.primary(), &AdviceAction::Blocked {});
        assert_eq!(
            advice.alternatives(),
            [AdviceAction::Wait {
                account: "cengiz@cengizhan.com".to_owned(),
                resets_at: ts("2026-09-07T06:38:49Z"),
                resets_in_seconds: 64_333,
            }]
        );
    }

    #[test]
    fn reserve_rule_beats_perishability_when_one_account_is_down_to_one_credit() {
        let accounts = vec![
            account(
                "a@example.com",
                100.0,
                Some("2026-09-13T00:00:00Z"),
                &[Some("2026-09-08T00:00:00Z")],
            ),
            account(
                "b@example.com",
                100.0,
                Some("2026-09-13T00:00:00Z"),
                &[Some("2026-09-15T00:00:00Z"), Some("2026-09-16T00:00:00Z")],
            ),
        ];
        let advice = ResetAdvice::evaluate(&accounts, now(), true).expect("advice");
        assert_eq!(advice.primary().account(), Some("b@example.com"));
    }

    #[test]
    fn single_capped_account_with_a_credit_still_advises() {
        let accounts = vec![account(
            "solo@example.com",
            100.0,
            Some("2026-09-10T00:00:00Z"),
            &[None],
        )];
        let advice = ResetAdvice::evaluate(&accounts, now(), true).expect("advice");
        let AdviceAction::Redeem {
            credit_expires_at, ..
        } = advice.primary()
        else {
            panic!("expected redeem");
        };
        assert_eq!(*credit_expires_at, None);
    }

    #[test]
    fn past_natural_reset_is_ignored_so_waiting_disappears() {
        let accounts = vec![account(
            "stale@example.com",
            100.0,
            Some("2026-09-05T00:00:00Z"),
            &[Some("2026-09-20T00:00:00Z")],
        )];
        let advice = ResetAdvice::evaluate(&accounts, now(), true).expect("advice");
        assert!(matches!(advice.primary(), AdviceAction::Redeem { .. }));
        assert!(advice.alternatives().is_empty());
    }

    #[test]
    fn credit_expiring_within_the_horizon_is_flagged() {
        let accounts = vec![account(
            "expiry@example.com",
            100.0,
            Some("2026-09-20T00:00:00Z"),
            &[Some("2026-09-09T00:00:00Z")],
        )];
        let advice = ResetAdvice::evaluate(&accounts, now(), false).expect("advice");
        assert_eq!(advice.expiring().len(), 1);
        assert_eq!(advice.expiring()[0].account(), "expiry@example.com");
        assert_eq!(
            advice.expiring()[0].expires_at(),
            ts("2026-09-09T00:00:00Z")
        );
    }

    fn sample_value(secondary_used: f64) -> serde_json::Value {
        json!({
            "scope": {"provider": "codex", "instance": "default", "account": "acct-a0c9"},
            "identity": {
                "scope": {"provider": "codex", "instance": "default", "account": "acct-a0c9"},
                "provider_account_id": null,
                "email": "user@example.com",
                "organization": null,
                "account_label": null,
                "plan": null,
                "login_method": null
            },
            "fetched_at": "2026-09-06T12:46:36Z",
            "primary": null,
            "secondary": {
                "usage": {"state": "known", "used_percent": secondary_used},
                "duration_seconds": 604_800,
                "resets_at": "2026-09-07T06:38:49Z",
                "reset_description": null,
                "next_regen_percent": null,
                "synthetic_placeholder": false
            },
            "tertiary": null,
            "extra_windows": [{
                "id": "codex-spark",
                "title": "Codex Spark 5-hour",
                "window": {
                    "usage": {"state": "known", "used_percent": 0.0},
                    "duration_seconds": 18000,
                    "resets_at": "2026-09-06T17:46:36Z",
                    "reset_description": null,
                    "next_regen_percent": null,
                    "synthetic_placeholder": false
                }
            }],
            "credits": null,
            "balance": null,
            "cost": null,
            "subscription_renews_at": null,
            "subscription_expires_at": null,
            "reset_credits": {
                "scope": {"provider": "codex", "instance": "default", "account": "acct-a0c9"},
                "credits": [{
                    "scope": {"provider": "codex", "instance": "default", "account": "acct-a0c9"},
                    "id": "6aeb031dd534bf84c7992e27d5ed70fb",
                    "reset_type": "codex_rate_limits",
                    "status": "available",
                    "granted_at": "2026-08-21T23:55:02.481069Z",
                    "expires_at": "2026-09-20T23:55:02.481069Z",
                    "redeem_started_at": null,
                    "redeemed_at": null,
                    "title": "Full reset",
                    "description": null
                }],
                "reported_available_count": 1,
                "updated_at": "2026-09-06T12:46:36Z"
            },
            "detail_sections": [],
            "extensions": [],
            "chart_points": [],
            "provenance": [{"source": "Codex HTTP", "strategy": "oauth"}],
            "confidence": "exact",
            "status": {
                "health": "unknown",
                "description": null,
                "checked_at": null,
                "incidents": [],
                "components": []
            }
        })
    }

    #[test]
    fn extra_window_usage_does_not_make_an_account_uncapped() {
        // Mirrors the live Codex shape: secondary weekly at 100%, Spark 5-hour
        // at 0% in extra_windows. Only main lanes may judge exhaustion.
        let sample: UsageSample =
            serde_json::from_value(sample_value(100.0)).expect("sample decodes");
        let account = AdvisorAccount::from_sample(&sample, now()).expect("sample is advisable");
        assert!(account.is_capped());
        assert_eq!(account.natural_reset(), Some(ts("2026-09-07T06:38:49Z")));
        assert_eq!(
            account.next_credit_expiry(),
            Some(ts("2026-09-20T23:55:02.481069Z"))
        );
        assert_eq!(account.label(), "user@example.com");
    }

    #[test]
    fn sample_without_main_lanes_is_skipped() {
        let sample: UsageSample =
            serde_json::from_value(sample_value(12.0)).expect("sample decodes");
        assert!(!AdvisorAccount::from_sample(&sample, now())
            .expect("sample is advisable")
            .is_capped());

        let mut no_lanes = sample_value(12.0);
        no_lanes["secondary"] = serde_json::Value::Null;
        let sample: UsageSample = serde_json::from_value(no_lanes).expect("sample decodes");
        assert!(AdvisorAccount::from_sample(&sample, now()).is_none());
    }

    #[test]
    fn too_many_accounts_is_rejected() {
        let accounts: Vec<AdvisorAccount> = (0..9)
            .map(|index| account(&format!("acct{index}@example.com"), 100.0, None, &[None]))
            .collect();
        assert!(ResetAdvice::evaluate(&accounts, now(), true).is_err());
    }

    #[test]
    fn uncapped_accounts_need_no_advice() {
        let accounts = vec![account("ok@example.com", 12.0, None, &[])];
        let advice = ResetAdvice::evaluate(&accounts, now(), true).expect("advice");
        assert_eq!(advice.primary(), &AdviceAction::NotApplicable {});
    }

    #[test]
    fn advice_serializes_without_credentials() {
        let advice = ResetAdvice::evaluate(&live_scenario(), now(), true).expect("advice");
        let rendered = serde_json::to_value(&advice).expect("advice serializes");
        assert_eq!(
            rendered.pointer("/primary/kind").and_then(serde_json::Value::as_str),
            Some("redeem")
        );
        assert_eq!(
            rendered
                .pointer("/primary/credit_expires_at")
                .and_then(serde_json::Value::as_str),
            Some("2026-09-20T23:55:02Z")
        );
        assert_eq!(
            rendered
                .pointer("/alternatives/0/resets_in_seconds")
                .and_then(serde_json::Value::as_i64),
            Some(64_333)
        );
    }
}
