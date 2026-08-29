use std::future;
use std::time::Duration;

use oab_runtime::shutdown::{MAX_SHUTDOWN_GRACE, cancel_and_drain};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[tokio::test(start_paused = true)]
async fn cooperative_jobs_finish_without_consuming_the_grace_period() {
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();
    for value in 0..4 {
        let task_cancellation = cancellation.clone();
        tasks.spawn(async move {
            task_cancellation.cancelled().await;
            value
        });
    }

    let before = Instant::now();
    let report = cancel_and_drain(&cancellation, &mut tasks, Duration::from_secs(30)).await;

    assert_eq!(report.completed(), 4);
    assert_eq!(report.cancelled(), 0);
    assert_eq!(report.panicked(), 0);
    assert_eq!(report.total(), 4);
    assert!(!report.timed_out());
    assert_eq!(Instant::now(), before);
    assert!(tasks.is_empty());
    assert!(cancellation.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn ignorant_async_jobs_are_aborted_at_the_exact_deadline_and_fully_drained() {
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let aware_cancellation = cancellation.clone();
    tasks.spawn(async move {
        aware_cancellation.cancelled().await;
    });
    tasks.spawn(future::pending::<()>());
    tasks.spawn(future::pending::<()>());

    let before = Instant::now();
    let grace = Duration::from_secs(7);
    let report = cancel_and_drain(&cancellation, &mut tasks, grace).await;

    assert_eq!(Instant::now().duration_since(before), grace);
    assert_eq!(report.completed(), 1);
    assert_eq!(report.cancelled(), 2);
    assert_eq!(report.panicked(), 0);
    assert_eq!(report.total(), 3);
    assert!(report.timed_out());
    assert!(tasks.is_empty());
}

#[tokio::test(start_paused = true)]
async fn panics_are_counted_and_do_not_prevent_other_tasks_from_draining() {
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::<()>::new();
    tasks.spawn(async { panic!("test panic") });
    let aware_cancellation = cancellation.clone();
    tasks.spawn(async move {
        aware_cancellation.cancelled().await;
    });

    let report = cancel_and_drain(&cancellation, &mut tasks, Duration::from_secs(1)).await;

    assert_eq!(report.completed(), 1);
    assert_eq!(report.cancelled(), 0);
    assert_eq!(report.panicked(), 1);
    assert_eq!(report.total(), 2);
    assert!(!report.timed_out());
    assert!(tasks.is_empty());
}

#[tokio::test(start_paused = true)]
async fn empty_shutdown_still_cancels_the_shared_token() {
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::<()>::new();

    let report = cancel_and_drain(&cancellation, &mut tasks, Duration::ZERO).await;

    assert_eq!(report.total(), 0);
    assert!(!report.timed_out());
    assert!(cancellation.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn unrepresentable_public_grace_is_safely_clamped() {
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();
    tasks.spawn(future::pending::<()>());
    let before = Instant::now();

    let report = cancel_and_drain(&cancellation, &mut tasks, Duration::MAX).await;

    assert_eq!(Instant::now().duration_since(before), MAX_SHUTDOWN_GRACE);
    assert!(report.timed_out());
    assert_eq!(report.cancelled(), 1);
    assert!(tasks.is_empty());
}
