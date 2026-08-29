//! Monotonic refresh scheduling independent of desktop event acquisition.

use std::cmp;
use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{AccountScope, Timestamp};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::time::Instant;

const DEFAULT_NORMAL_CADENCE: Duration = Duration::from_mins(5);
const DEFAULT_POPUP_CADENCE: Duration = Duration::from_secs(30);

/// Supplies paired wall-clock and monotonic observations to the scheduler.
///
/// Implementations should sample both clocks from one coherent time source.
/// Wall time is used only to project provider reset boundaries. Once projected,
/// all deadlines are driven by monotonic time.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current civil time.
    fn wall_now(&self) -> Timestamp;

    /// Returns the current monotonic time.
    fn monotonic_now(&self) -> Instant;
}

/// Production clock backed by UTC wall time and Tokio's monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn wall_now(&self) -> Timestamp {
        Timestamp::new(OffsetDateTime::now_utc())
            .expect("the current UTC time is RFC 3339 representable")
    }

    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }
}

/// Validated refresh cadences for normal and popup-open operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulePolicy {
    normal_cadence: Duration,
    popup_cadence: Duration,
}

impl SchedulePolicy {
    /// Builds a scheduling policy.
    ///
    /// # Errors
    ///
    /// Returns an error when either cadence is zero or when the popup cadence
    /// is not strictly shorter than normal cadence.
    pub fn new(
        normal_cadence: Duration,
        popup_cadence: Duration,
    ) -> Result<Self, SchedulePolicyError> {
        validate_cadence(normal_cadence, CadenceKind::Normal)?;
        validate_cadence(popup_cadence, CadenceKind::Popup)?;
        if popup_cadence >= normal_cadence {
            return Err(SchedulePolicyError::PopupNotShorter {
                normal: normal_cadence,
                popup: popup_cadence,
            });
        }
        Ok(Self {
            normal_cadence,
            popup_cadence,
        })
    }

    /// Returns the background refresh cadence.
    #[must_use]
    pub const fn normal_cadence(self) -> Duration {
        self.normal_cadence
    }

    /// Returns the accelerated popup-open refresh cadence.
    #[must_use]
    pub const fn popup_cadence(self) -> Duration {
        self.popup_cadence
    }
}

impl Default for SchedulePolicy {
    fn default() -> Self {
        Self {
            normal_cadence: DEFAULT_NORMAL_CADENCE,
            popup_cadence: DEFAULT_POPUP_CADENCE,
        }
    }
}

/// Why a policy could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SchedulePolicyError {
    /// A cadence must advance time.
    #[error("{kind} refresh cadence must be nonzero")]
    ZeroCadence {
        /// The invalid cadence.
        kind: CadenceKind,
    },
    /// Opening the popup must accelerate refreshes.
    #[error("popup cadence {popup:?} must be shorter than normal cadence {normal:?}")]
    PopupNotShorter {
        /// The configured normal cadence.
        normal: Duration,
        /// The configured popup cadence.
        popup: Duration,
    },
}

/// Identifies one cadence in validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CadenceKind {
    /// Background cadence.
    Normal,
    /// Popup-open cadence.
    Popup,
}

impl std::fmt::Display for CadenceKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Normal => "normal",
            Self::Popup => "popup",
        })
    }
}

/// A refresh trigger that became due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledRefresh {
    /// A normal or popup-open cadence elapsed.
    Periodic,
    /// A provider-reported usage reset boundary was reached.
    ResetBoundary {
        /// Exact account whose boundary elapsed.
        scope: AccountScope,
        /// Provider-reported civil-time boundary.
        boundary: Timestamp,
    },
}

/// Failure to project a provider reset boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScheduleError {
    /// The positive wall-time difference cannot be represented as a duration.
    #[error("reset boundary is outside the supported wall-time range")]
    WallDeltaOutOfRange,
}

#[derive(Debug, Clone, Copy)]
struct ResetDeadline {
    boundary: Timestamp,
    due: Instant,
}

/// Deterministic refresh scheduling state machine.
///
/// Desktop integrations translate their signals into [`Self::set_popup_open`]
/// calls; this type has no Hyprland, D-Bus, or process I/O dependency.
#[derive(Debug)]
pub struct Scheduler {
    policy: SchedulePolicy,
    normal_due: Instant,
    popup_due: Option<Instant>,
    pending_resets: BTreeMap<AccountScope, ResetDeadline>,
    last_fired_resets: BTreeMap<AccountScope, Timestamp>,
}

impl Scheduler {
    /// Starts a scheduler with the normal cadence anchored at the current
    /// monotonic time.
    #[must_use]
    pub fn new(policy: SchedulePolicy, clock: &dyn Clock) -> Self {
        let now = clock.monotonic_now();
        Self {
            policy,
            normal_due: saturating_instant_add(now, policy.normal_cadence()),
            popup_due: None,
            pending_resets: BTreeMap::new(),
            last_fired_resets: BTreeMap::new(),
        }
    }

    /// Enables or disables the accelerated popup-open cadence.
    ///
    /// Opening starts a separate accelerated cadence. Closing removes it and
    /// leaves the original normal-cadence anchor intact.
    pub fn set_popup_open(&mut self, open: bool, clock: &dyn Clock) {
        match (open, self.popup_due.is_some()) {
            (true, false) => {
                self.popup_due = Some(saturating_instant_add(
                    clock.monotonic_now(),
                    self.policy.popup_cadence(),
                ));
            }
            (false, true) => self.popup_due = None,
            _ => {}
        }
    }

    /// Arms the current reset boundary for an account.
    ///
    /// A different boundary replaces that account's pending boundary. The
    /// same account/boundary pair is idempotent even after it has fired.
    ///
    /// # Errors
    ///
    /// Returns an error if a positive wall-time difference cannot be converted
    /// into a standard duration.
    pub fn schedule_reset(
        &mut self,
        scope: AccountScope,
        boundary: Timestamp,
        clock: &dyn Clock,
    ) -> Result<bool, ScheduleError> {
        if self
            .last_fired_resets
            .get(&scope)
            .is_some_and(|last_fired| boundary <= *last_fired)
            || self
                .pending_resets
                .get(&scope)
                .is_some_and(|pending| pending.boundary == boundary)
        {
            return Ok(false);
        }

        let wall_now = clock.wall_now();
        let monotonic_now = clock.monotonic_now();
        let due = project_wall_deadline(boundary, wall_now, monotonic_now)?;
        self.pending_resets
            .insert(scope, ResetDeadline { boundary, due });
        Ok(true)
    }

    /// Returns the earliest pending monotonic deadline.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let periodic = self
            .popup_due
            .map_or(self.normal_due, |popup| cmp::min(self.normal_due, popup));
        std::iter::once(periodic)
            .chain(self.pending_resets.values().map(|reset| reset.due))
            .min()
    }

    /// Takes every trigger due at the current monotonic instant.
    ///
    /// Missed cadence intervals collapse to one periodic trigger and reanchor
    /// at `now`, preventing catch-up bursts.
    #[must_use]
    pub fn take_due(&mut self, clock: &dyn Clock) -> Vec<ScheduledRefresh> {
        let now = clock.monotonic_now();
        let normal_due = self.normal_due <= now;
        let popup_due = self.popup_due.is_some_and(|due| due <= now);
        let mut refreshes = Vec::new();

        if normal_due || popup_due {
            refreshes.push(ScheduledRefresh::Periodic);
        }
        if normal_due {
            self.normal_due = saturating_instant_add(now, self.policy.normal_cadence());
        }
        if popup_due {
            self.popup_due = Some(saturating_instant_add(now, self.policy.popup_cadence()));
        }

        let due_scopes: Vec<_> = self
            .pending_resets
            .iter()
            .filter(|(_, reset)| reset.due <= now)
            .map(|(scope, _)| scope.clone())
            .collect();
        for scope in due_scopes {
            if let Some(reset) = self.pending_resets.remove(&scope) {
                self.last_fired_resets.insert(scope.clone(), reset.boundary);
                refreshes.push(ScheduledRefresh::ResetBoundary {
                    scope,
                    boundary: reset.boundary,
                });
            }
        }

        refreshes
    }
}

fn validate_cadence(cadence: Duration, kind: CadenceKind) -> Result<(), SchedulePolicyError> {
    if cadence.is_zero() {
        return Err(SchedulePolicyError::ZeroCadence { kind });
    }
    Ok(())
}

fn project_wall_deadline(
    boundary: Timestamp,
    wall_now: Timestamp,
    monotonic_now: Instant,
) -> Result<Instant, ScheduleError> {
    if boundary <= wall_now {
        return Ok(monotonic_now);
    }
    let wall_delta = boundary.as_offset_date_time() - wall_now.as_offset_date_time();
    let duration =
        Duration::try_from(wall_delta).map_err(|_| ScheduleError::WallDeltaOutOfRange)?;
    Ok(saturating_instant_add(monotonic_now, duration))
}

fn saturating_instant_add(base: Instant, duration: Duration) -> Instant {
    if let Some(deadline) = base.checked_add(duration) {
        return deadline;
    }

    let mut lower = 0_u128;
    let mut upper = duration.as_nanos();
    let mut best = base;
    while lower <= upper {
        let middle = lower + ((upper - lower) / 2);
        let candidate_duration = duration_from_nanos(middle);
        if let Some(candidate) = base.checked_add(candidate_duration) {
            best = candidate;
            lower = middle.saturating_add(1);
        } else if middle == 0 {
            break;
        } else {
            upper = middle - 1;
        }
    }
    best
}

fn duration_from_nanos(nanoseconds: u128) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let seconds = nanoseconds / NANOS_PER_SECOND;
    let subsecond = nanoseconds % NANOS_PER_SECOND;
    Duration::new(
        u64::try_from(seconds).expect("source duration seconds fit in u64"),
        u32::try_from(subsecond).expect("subsecond nanoseconds fit in u32"),
    )
}
