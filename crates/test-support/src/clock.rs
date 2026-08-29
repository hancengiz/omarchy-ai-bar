//! Deterministic clock support for paused-Tokio-time tests.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oab_domain::Timestamp;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
struct ClockState {
    wall_anchor: Timestamp,
    monotonic_anchor: Instant,
}

/// Trait-neutral clock whose wall time follows Tokio's monotonic test clock.
///
/// Construct this inside a `#[tokio::test(start_paused = true)]`. Advancing
/// Tokio time advances both observations by the same amount. [`Self::set_wall_now`]
/// can independently simulate an NTP correction or civil-clock rollback.
#[derive(Debug, Clone)]
pub struct FakeClock {
    state: Arc<Mutex<ClockState>>,
}

impl FakeClock {
    /// Anchors a fake wall clock at the current Tokio monotonic instant.
    #[must_use]
    pub fn new(wall_now: Timestamp) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClockState {
                wall_anchor: wall_now,
                monotonic_anchor: Instant::now(),
            })),
        }
    }

    /// Returns wall time advanced by elapsed Tokio monotonic time.
    ///
    /// # Panics
    ///
    /// Panics if a test advances beyond the domain timestamp range.
    #[must_use]
    pub fn wall_now(&self) -> Timestamp {
        let state = self.lock_state();
        let elapsed = Instant::now().saturating_duration_since(state.monotonic_anchor);
        let wall = state.wall_anchor.as_offset_date_time() + elapsed;
        Timestamp::new(wall).expect("test wall clock remains RFC 3339 representable")
    }

    /// Returns Tokio's current monotonic test instant.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    /// Reanchors wall time without changing the monotonic observation.
    pub fn set_wall_now(&self, wall_now: Timestamp) {
        *self.lock_state() = ClockState {
            wall_anchor: wall_now,
            monotonic_anchor: Instant::now(),
        };
    }

    /// Advances only the wall-clock observation.
    ///
    /// This is useful for simulating a forward NTP or manual adjustment. Tokio
    /// monotonic time is not changed.
    ///
    /// # Panics
    ///
    /// Panics if the adjustment exceeds the domain timestamp range.
    pub fn advance_wall(&self, amount: Duration) {
        let now = self.wall_now();
        let advanced = now.as_offset_date_time() + amount;
        self.set_wall_now(
            Timestamp::new(advanced).expect("test wall clock remains RFC 3339 representable"),
        );
    }

    /// Rewinds only the wall-clock observation.
    ///
    /// This is useful for proving already-projected deadlines are immune to
    /// civil-clock rollback. Tokio monotonic time is not changed.
    ///
    /// # Panics
    ///
    /// Panics if the adjustment exceeds the domain timestamp range.
    pub fn rewind_wall(&self, amount: Duration) {
        let now = self.wall_now();
        let rewound = now.as_offset_date_time() - amount;
        self.set_wall_now(
            Timestamp::new(rewound).expect("test wall clock remains RFC 3339 representable"),
        );
    }

    fn lock_state(&self) -> MutexGuard<'_, ClockState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
