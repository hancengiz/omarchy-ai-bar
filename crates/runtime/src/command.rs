//! Commands accepted by the bounded runtime actor.

use oab_domain::{AccountScope, Timestamp};
use thiserror::Error;
use tokio::sync::oneshot;

use crate::scheduler::ScheduleError;

/// Why a provider/account refresh entered the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTrigger {
    /// An explicit user, CLI, or local-API request.
    Manual,
    /// A normal or popup-accelerated scheduler tick.
    Periodic,
    /// A refresh aligned to a provider reset boundary.
    ResetBoundary { boundary: Timestamp },
}

/// The actor's bounded-work admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshAdmission {
    /// The scope began refreshing immediately.
    Started,
    /// The scope is waiting behind the configured concurrency limit.
    Queued,
    /// Work for the same scope was already active or queued.
    Coalesced,
    /// No refresh source is registered for the requested scope.
    UnknownScope,
}

/// Result of arming a provider reset-boundary refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetScheduleAdmission {
    /// A new boundary was armed or replaced a previous boundary.
    Armed,
    /// The same boundary was already armed.
    Unchanged,
    /// No refresh source is registered for the requested scope.
    UnknownScope,
}

/// Error returned when a receipt cannot be delivered because the actor ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the runtime actor stopped before acknowledging the command")]
pub struct ReceiptError;

/// Acknowledgement for a refresh command accepted by the command channel.
#[derive(Debug)]
pub struct RefreshReceipt {
    receiver: oneshot::Receiver<RefreshAdmission>,
}

impl RefreshReceipt {
    pub(crate) const fn new(receiver: oneshot::Receiver<RefreshAdmission>) -> Self {
        Self { receiver }
    }

    /// Waits for the actor's work-admission decision.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError`] if the actor exits before handling the command.
    pub async fn admission(self) -> Result<RefreshAdmission, ReceiptError> {
        self.receiver.await.map_err(|_| ReceiptError)
    }
}

/// Acknowledgement for a popup-state command.
#[derive(Debug)]
pub struct CommandReceipt {
    receiver: oneshot::Receiver<()>,
}

impl CommandReceipt {
    pub(crate) const fn new(receiver: oneshot::Receiver<()>) -> Self {
        Self { receiver }
    }

    /// Waits until the actor applies the command.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError`] if the actor exits before handling the command.
    pub async fn applied(self) -> Result<(), ReceiptError> {
        self.receiver.await.map_err(|_| ReceiptError)
    }
}

/// Acknowledgement for a reset-boundary scheduling command.
#[derive(Debug)]
pub struct ResetScheduleReceipt {
    receiver: oneshot::Receiver<Result<ResetScheduleAdmission, ScheduleError>>,
}

impl ResetScheduleReceipt {
    pub(crate) const fn new(
        receiver: oneshot::Receiver<Result<ResetScheduleAdmission, ScheduleError>>,
    ) -> Self {
        Self { receiver }
    }

    /// Waits until the actor applies the reset-boundary command.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError`] if the actor exits before handling the command,
    /// or [`ScheduleError`] if the wall-clock boundary cannot be represented by
    /// the monotonic scheduler.
    pub async fn admission(self) -> Result<ResetScheduleAdmission, ResetScheduleReceiptError> {
        self.receiver
            .await
            .map_err(|_| ResetScheduleReceiptError::ActorStopped(ReceiptError))?
            .map_err(ResetScheduleReceiptError::Schedule)
    }
}

/// Failure while acknowledging a reset-boundary command.
#[derive(Debug, Error)]
pub enum ResetScheduleReceiptError {
    /// The runtime stopped before it handled the command.
    #[error(transparent)]
    ActorStopped(#[from] ReceiptError),
    /// The boundary could not be mapped to the scheduler's monotonic clock.
    #[error(transparent)]
    Schedule(#[from] ScheduleError),
}

pub(crate) enum RuntimeCommand {
    Refresh {
        scope: AccountScope,
        trigger: RefreshTrigger,
        response: oneshot::Sender<RefreshAdmission>,
    },
    PopupOpen {
        open: bool,
        response: oneshot::Sender<()>,
    },
    ScheduleReset {
        scope: AccountScope,
        boundary: Timestamp,
        response: oneshot::Sender<Result<ResetScheduleAdmission, ScheduleError>>,
    },
}
