//! Policy for showing the `StatusNotifier` fallback when no frontend is present.
//!
//! Callers provide [`Duration`] values measured from one monotonic origin. The
//! policy rejects timestamps older than the last one it observed, making the
//! transition logic deterministic without owning a clock or a timer.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroU64;
use std::time::Duration;

use crate::protocol::{Capability, ServerHello};

/// The `StatusNotifier` status desired by the frontend-presence policy.
///
/// This type deliberately does not expose the `ksni` dependency to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniStatus {
    /// Show the `StatusNotifier` fallback.
    Active,
    /// Keep the `StatusNotifier` registered without presenting it as active.
    Passive,
}

/// Whether one connected transport completed a compatible frontend handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendCompatibility {
    /// The transport is a compatible frontend and suppresses the fallback.
    Compatible,
    /// The transport is incompatible and must not suppress the fallback.
    Incompatible,
}

impl FrontendCompatibility {
    /// Classifies the result of a successful protocol negotiation.
    ///
    /// A frontend suppresses the fallback only when the negotiated capability
    /// intersection contains display snapshots. Pre-handshake and rejected
    /// transports have no [`ServerHello`] and therefore cannot be classified
    /// as compatible through this boundary.
    #[must_use]
    pub fn from_server_hello(hello: &ServerHello) -> Self {
        if hello.capabilities().contains(Capability::DisplaySnapshots) {
            Self::Compatible
        } else {
            Self::Incompatible
        }
    }
}

/// An opaque identity allocated for one transport connection.
///
/// It is intentionally distinct from a stable frontend session identifier.
/// Two overlapping transports from the same frontend receive different IDs,
/// so a late disconnect from the old transport cannot remove the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrontendConnectionId(NonZeroU64);

/// A deterministic frontend-presence policy for the `StatusNotifier` fallback.
#[derive(Debug)]
pub struct FrontendPresence {
    grace_period: Duration,
    observed_at: Duration,
    next_connection_id: Option<NonZeroU64>,
    compatible_connections: BTreeSet<FrontendConnectionId>,
    fallback: FallbackState,
}

impl FrontendPresence {
    /// Creates a policy with no compatible frontend connected.
    ///
    /// The fallback remains passive for `grace_period`, beginning at
    /// `started_at`. A zero grace period makes it active immediately.
    #[must_use]
    pub fn new(grace_period: Duration, started_at: Duration) -> Self {
        Self {
            grace_period,
            observed_at: started_at,
            next_connection_id: NonZeroU64::new(1),
            compatible_connections: BTreeSet::new(),
            fallback: FallbackState::after_grace(grace_period, started_at),
        }
    }

    /// Records a new transport connection at `now` and returns its unique ID.
    ///
    /// A compatible connection makes the desired status passive before this
    /// method returns. An incompatible connection does not affect the status or
    /// a pending grace deadline.
    ///
    /// # Errors
    ///
    /// Returns [`FrontendPresenceError::NonMonotonicTime`] if `now` predates the
    /// last observed timestamp, or
    /// [`FrontendPresenceError::ConnectionIdSpaceExhausted`] if every transport
    /// ID has been allocated.
    pub fn connect_at(
        &mut self,
        now: Duration,
        compatibility: FrontendCompatibility,
    ) -> Result<FrontendConnectionId, FrontendPresenceError> {
        let connection_id = self
            .next_connection_id
            .ok_or(FrontendPresenceError::ConnectionIdSpaceExhausted)?;
        self.observe(now)?;

        self.next_connection_id = connection_id.get().checked_add(1).and_then(NonZeroU64::new);
        let connection_id = FrontendConnectionId(connection_id);
        if compatibility == FrontendCompatibility::Compatible {
            self.compatible_connections.insert(connection_id);
            self.fallback = FallbackState::Suppressed;
        }
        Ok(connection_id)
    }

    /// Records a transport disconnection at `now`.
    ///
    /// Unknown and duplicate IDs are ignored. Removing the last compatible
    /// connection starts a fresh grace period; removing any other connection
    /// does not change the pending deadline or desired status.
    ///
    /// # Errors
    ///
    /// Returns [`FrontendPresenceError::NonMonotonicTime`] if `now` predates the
    /// last observed timestamp.
    pub fn disconnect_at(
        &mut self,
        now: Duration,
        connection_id: FrontendConnectionId,
    ) -> Result<(), FrontendPresenceError> {
        self.observe(now)?;
        let removed = self.compatible_connections.remove(&connection_id);
        if removed && self.compatible_connections.is_empty() {
            self.fallback = FallbackState::after_grace(self.grace_period, now);
        }
        Ok(())
    }

    /// Advances the logical clock and returns the resulting desired status.
    ///
    /// The runtime can call this when [`Self::next_deadline`] expires.
    ///
    /// # Errors
    ///
    /// Returns [`FrontendPresenceError::NonMonotonicTime`] if `now` predates the
    /// last observed timestamp.
    pub fn advance_to(&mut self, now: Duration) -> Result<SniStatus, FrontendPresenceError> {
        self.observe(now)?;
        Ok(self.status())
    }

    /// Returns the desired `StatusNotifier` status at the last observed time.
    #[must_use]
    pub const fn status(&self) -> SniStatus {
        match self.fallback {
            FallbackState::Active => SniStatus::Active,
            FallbackState::Suppressed | FallbackState::Waiting(_) => SniStatus::Passive,
        }
    }

    /// Returns the next logical time at which the fallback should activate.
    ///
    /// `None` means no representable activation deadline is pending. This is
    /// expected while a compatible frontend suppresses the fallback and after
    /// the fallback has already activated.
    #[must_use]
    pub const fn next_deadline(&self) -> Option<Duration> {
        match self.fallback {
            FallbackState::Waiting(GraceDeadline::At(deadline)) => Some(deadline),
            FallbackState::Active
            | FallbackState::Suppressed
            | FallbackState::Waiting(GraceDeadline::BeyondRange) => None,
        }
    }

    fn observe(&mut self, now: Duration) -> Result<(), FrontendPresenceError> {
        if now < self.observed_at {
            return Err(FrontendPresenceError::NonMonotonicTime {
                last_observed: self.observed_at,
                attempted: now,
            });
        }
        self.observed_at = now;
        if matches!(
            self.fallback,
            FallbackState::Waiting(GraceDeadline::At(deadline)) if now >= deadline
        ) {
            self.fallback = FallbackState::Active;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackState {
    Active,
    Suppressed,
    Waiting(GraceDeadline),
}

impl FallbackState {
    fn after_grace(grace_period: Duration, now: Duration) -> Self {
        if grace_period.is_zero() {
            return Self::Active;
        }
        match now.checked_add(grace_period) {
            Some(deadline) => Self::Waiting(GraceDeadline::At(deadline)),
            None => Self::Waiting(GraceDeadline::BeyondRange),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraceDeadline {
    At(Duration),
    BeyondRange,
}

/// An invalid logical-time or connection-ID transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendPresenceError {
    /// A transition supplied a timestamp older than the last observed one.
    NonMonotonicTime {
        /// The latest timestamp accepted by the policy.
        last_observed: Duration,
        /// The rejected timestamp.
        attempted: Duration,
    },
    /// The policy has allocated every non-zero 64-bit connection ID.
    ConnectionIdSpaceExhausted,
}

impl Display for FrontendPresenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMonotonicTime {
                last_observed,
                attempted,
            } => write!(
                formatter,
                "logical time moved backwards from {last_observed:?} to {attempted:?}"
            ),
            Self::ConnectionIdSpaceExhausted => {
                formatter.write_str("frontend connection ID space exhausted")
            }
        }
    }
}

impl Error for FrontendPresenceError {}
