//! Cooperative cancellation followed by bounded asynchronous task draining.

use std::time::Duration;

use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

/// Defensive upper bound for a single graceful asynchronous drain.
pub const MAX_SHUTDOWN_GRACE: Duration = Duration::from_hours(1);

/// Outcome counts for one bounded shutdown pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    completed: usize,
    cancelled: usize,
    panicked: usize,
    timed_out: bool,
}

impl ShutdownReport {
    /// Tasks that returned normally, including cancellation-aware tasks.
    #[must_use]
    pub const fn completed(&self) -> usize {
        self.completed
    }

    /// Tasks cancelled by aborting the remaining join set after the grace
    /// deadline.
    #[must_use]
    pub const fn cancelled(&self) -> usize {
        self.cancelled
    }

    /// Tasks whose futures panicked before shutdown finished.
    #[must_use]
    pub const fn panicked(&self) -> usize {
        self.panicked
    }

    /// Whether at least one task remained when the grace deadline elapsed.
    #[must_use]
    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }

    /// Total number of fully drained join results.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.completed
            .saturating_add(self.cancelled)
            .saturating_add(self.panicked)
    }

    fn record<T>(&mut self, result: Result<T, JoinError>) {
        match result {
            Ok(_) => self.completed = self.completed.saturating_add(1),
            Err(error) if error.is_cancelled() => {
                self.cancelled = self.cancelled.saturating_add(1);
            }
            Err(_) => self.panicked = self.panicked.saturating_add(1),
        }
    }
}

/// Cancels cooperative work, drains it until `grace` elapses, then aborts and
/// fully joins every remaining asynchronous task.
///
/// The grace bound applies to ordinary asynchronous tasks that yield to the
/// Tokio executor. Rust cannot preempt a future that never yields, and Tokio
/// cannot abort an already-running `spawn_blocking` closure. Such work must be
/// bounded separately and must not be placed in this join set when a hard
/// shutdown deadline is required.
///
/// Grace values above [`MAX_SHUTDOWN_GRACE`] are clamped, preventing arbitrary
/// public `Duration` values from overflowing Tokio's deadline representation.
pub async fn cancel_and_drain<T>(
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<T>,
    grace: Duration,
) -> ShutdownReport
where
    T: 'static,
{
    cancellation.cancel();
    let grace = grace.min(MAX_SHUTDOWN_GRACE);
    let started_at = Instant::now();
    let deadline = started_at.checked_add(grace).unwrap_or(started_at);
    let mut report = ShutdownReport::default();

    while !tasks.is_empty() {
        match timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(result)) => report.record(result),
            Ok(None) => return report,
            Err(_) => {
                report.timed_out = true;
                break;
            }
        }
    }

    if report.timed_out {
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            report.record(result);
        }
    }
    report
}
