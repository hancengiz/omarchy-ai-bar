use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ProviderId, ProviderInstanceId, Timestamp};
use oab_runtime::scheduler::{
    Clock, SchedulePolicy, SchedulePolicyError, ScheduledRefresh, Scheduler,
};
use oab_test_support::clock::FakeClock;

#[derive(Debug, Clone)]
struct TestClock(FakeClock);

impl TestClock {
    fn new(wall_now: Timestamp) -> Self {
        Self(FakeClock::new(wall_now))
    }

    fn rewind_wall(&self, amount: Duration) {
        self.0.rewind_wall(amount);
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

fn policy() -> SchedulePolicy {
    SchedulePolicy::new(Duration::from_secs(60), Duration::from_secs(10))
        .expect("fixture scheduling policy")
}

#[test]
fn policy_rejects_zero_and_nonaccelerating_cadences() {
    assert!(matches!(
        SchedulePolicy::new(Duration::ZERO, Duration::from_secs(1)),
        Err(SchedulePolicyError::ZeroCadence { .. })
    ));
    assert!(matches!(
        SchedulePolicy::new(Duration::from_secs(60), Duration::from_secs(60)),
        Err(SchedulePolicyError::PopupNotShorter { .. })
    ));
    assert!(matches!(
        SchedulePolicy::new(Duration::from_secs(60), Duration::ZERO),
        Err(SchedulePolicyError::ZeroCadence { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn popup_cadence_accelerates_then_returns_to_normal_anchor() {
    let clock = TestClock::new(timestamp(1_700_000_000));
    let start = clock.monotonic_now();
    let mut scheduler = Scheduler::new(policy(), &clock);
    assert_eq!(
        scheduler.next_deadline(),
        Some(start + Duration::from_secs(60))
    );

    tokio::time::advance(Duration::from_secs(20)).await;
    scheduler.set_popup_open(true, &clock);
    assert_eq!(
        scheduler.next_deadline(),
        Some(start + Duration::from_secs(30))
    );

    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(scheduler.take_due(&clock), vec![ScheduledRefresh::Periodic]);
    assert_eq!(
        scheduler.next_deadline(),
        Some(start + Duration::from_secs(40))
    );

    scheduler.set_popup_open(false, &clock);
    assert_eq!(
        scheduler.next_deadline(),
        Some(start + Duration::from_secs(60))
    );
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(scheduler.take_due(&clock).is_empty());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(scheduler.take_due(&clock), vec![ScheduledRefresh::Periodic]);
}

#[tokio::test(start_paused = true)]
async fn missed_periods_coalesce_without_a_catch_up_burst() {
    let clock = TestClock::new(timestamp(1_700_000_000));
    let mut scheduler = Scheduler::new(policy(), &clock);
    tokio::time::advance(Duration::from_mins(5)).await;

    assert_eq!(scheduler.take_due(&clock), vec![ScheduledRefresh::Periodic]);
    assert!(scheduler.take_due(&clock).is_empty());
    assert_eq!(
        scheduler.next_deadline(),
        Some(clock.monotonic_now() + Duration::from_secs(60))
    );
}

#[tokio::test(start_paused = true)]
async fn a_reset_boundary_fires_exactly_once() {
    let clock = TestClock::new(timestamp(1_700_000_000));
    let mut scheduler = Scheduler::new(policy(), &clock);
    let account_scope = scope("account-a");
    let boundary = timestamp(1_700_000_030);

    assert!(
        scheduler
            .schedule_reset(account_scope.clone(), boundary, &clock)
            .expect("schedule reset")
    );
    assert!(
        !scheduler
            .schedule_reset(account_scope.clone(), boundary, &clock)
            .expect("idempotent reset")
    );

    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(
        scheduler.take_due(&clock),
        vec![ScheduledRefresh::ResetBoundary {
            scope: account_scope.clone(),
            boundary,
        }]
    );
    assert!(scheduler.take_due(&clock).is_empty());
    assert!(
        !scheduler
            .schedule_reset(account_scope, boundary, &clock)
            .expect("fired reset remains idempotent")
    );
}

#[tokio::test(start_paused = true)]
async fn projected_reset_ignores_later_wall_clock_rollback() {
    let clock = TestClock::new(timestamp(1_700_000_000));
    let mut scheduler = Scheduler::new(policy(), &clock);
    let account_scope = scope("account-a");
    let boundary = timestamp(1_700_000_050);
    scheduler
        .schedule_reset(account_scope.clone(), boundary, &clock)
        .expect("schedule reset");

    tokio::time::advance(Duration::from_secs(25)).await;
    clock.rewind_wall(Duration::from_secs(3_600));
    tokio::time::advance(Duration::from_secs(25)).await;

    assert_eq!(
        scheduler.take_due(&clock),
        vec![ScheduledRefresh::ResetBoundary {
            scope: account_scope,
            boundary,
        }]
    );
}

#[tokio::test(start_paused = true)]
async fn coincident_periodic_and_reset_boundaries_are_both_reported() {
    let clock = TestClock::new(timestamp(1_700_000_000));
    let mut scheduler = Scheduler::new(policy(), &clock);
    let account_scope = scope("account-a");
    let boundary = timestamp(1_700_000_060);
    scheduler
        .schedule_reset(account_scope.clone(), boundary, &clock)
        .expect("schedule reset");

    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(
        scheduler.take_due(&clock),
        vec![
            ScheduledRefresh::Periodic,
            ScheduledRefresh::ResetBoundary {
                scope: account_scope,
                boundary,
            },
        ]
    );
}
