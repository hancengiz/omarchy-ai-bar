//! Privacy-projected desktop notification contracts.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use oab_domain::PrivacyPolicy;
use thiserror::Error;

/// Maximum provider or account label size accepted for a notification.
pub const MAX_IDENTITY_LABEL_BYTES: usize = 128;
/// Maximum projected notification summary size.
pub const MAX_NOTIFICATION_SUMMARY_BYTES: usize = 128;
/// Maximum projected notification body size.
pub const MAX_NOTIFICATION_BODY_BYTES: usize = 512;

/// Personal account context that may be projected only under an explicit policy.
#[derive(Clone, PartialEq, Eq)]
pub struct NotificationIdentity {
    provider: String,
    account: String,
}

impl NotificationIdentity {
    /// Creates bounded, single-line personal context.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationValidationError`] when either label is empty,
    /// oversized, or contains control characters.
    pub fn new(
        provider: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, NotificationValidationError> {
        Ok(Self {
            provider: checked_label(provider.into())?,
            account: checked_label(account.into())?,
        })
    }
}

impl fmt::Debug for NotificationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NotificationIdentity(<personal-info>)")
    }
}

/// Typed events that can cross the desktop notification boundary.
pub enum NotificationEvent {
    /// A provider refresh could not complete.
    RefreshFailed(NotificationIdentity),
    /// A usage threshold between zero and one hundred percent was reached.
    UsageThreshold {
        /// Whole percentage used.
        percent: u8,
        /// Account context subject to privacy projection.
        identity: NotificationIdentity,
    },
    /// A newer packaged version is available.
    UpdateAvailable,
}

impl NotificationEvent {
    /// Creates a bounded usage-threshold event.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationValidationError::InvalidPercentage`] above 100.
    pub fn usage_threshold(
        percent: u8,
        identity: NotificationIdentity,
    ) -> Result<Self, NotificationValidationError> {
        if percent > 100 {
            return Err(NotificationValidationError::InvalidPercentage);
        }
        Ok(Self::UsageThreshold { percent, identity })
    }

    fn project(self, policy: PrivacyPolicy) -> NotificationPayload {
        let (summary, mut body, identity) = match self {
            Self::RefreshFailed(identity) => (
                "AI usage refresh failed".to_owned(),
                "An AI usage account could not be refreshed.".to_owned(),
                Some(identity),
            ),
            Self::UsageThreshold { percent, identity } => (
                "AI usage limit".to_owned(),
                format!("An AI usage account has reached {percent}% of its limit."),
                Some(identity),
            ),
            Self::UpdateAvailable => (
                "omarchy-ai-bar update available".to_owned(),
                "A newer packaged version is available.".to_owned(),
                None,
            ),
        };

        if policy == PrivacyPolicy::ShowPersonalInfo
            && let Some(identity) = identity
        {
            body.push_str(" (");
            body.push_str(&identity.provider);
            body.push_str(": ");
            body.push_str(&identity.account);
            body.push(')');
        }
        debug_assert!(summary.len() <= MAX_NOTIFICATION_SUMMARY_BYTES);
        debug_assert!(body.len() <= MAX_NOTIFICATION_BODY_BYTES);
        NotificationPayload {
            summary,
            body,
            icon: "omarchy-ai-bar",
        }
    }
}

impl fmt::Debug for NotificationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RefreshFailed(_) => formatter.write_str("RefreshFailed(<personal-info>)"),
            Self::UsageThreshold { percent, .. } => formatter
                .debug_struct("UsageThreshold")
                .field("percent", percent)
                .field("identity", &"<personal-info>")
                .finish(),
            Self::UpdateAvailable => formatter.write_str("UpdateAvailable"),
        }
    }
}

/// Fully projected, bounded data accepted by notification sinks.
#[derive(Clone, PartialEq, Eq)]
pub struct NotificationPayload {
    summary: String,
    body: String,
    icon: &'static str,
}

impl NotificationPayload {
    /// Projected single-line summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Projected body, which contains personal context only when policy allowed it.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Freedesktop icon theme name.
    #[must_use]
    pub const fn icon(&self) -> &'static str {
        self.icon
    }
}

impl fmt::Debug for NotificationPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotificationPayload")
            .field("summary", &self.summary)
            .field("body", &"<projected>")
            .field("icon", &self.icon)
            .finish()
    }
}

/// A boxed asynchronous notification operation.
pub type NotificationFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe destination for already projected notification data.
pub trait NotificationSink: Send + Sync {
    /// Delivers one notification payload.
    fn send(
        &self,
        payload: NotificationPayload,
    ) -> NotificationFuture<'_, Result<(), NotificationSinkError>>;
}

/// Applies privacy policy before invoking a notification sink.
#[derive(Debug)]
pub struct NotificationService<S> {
    sink: S,
    policy: PrivacyPolicy,
}

impl<S> NotificationService<S>
where
    S: NotificationSink,
{
    /// Creates a notification boundary with a fixed privacy policy.
    #[must_use]
    pub const fn new(sink: S, policy: PrivacyPolicy) -> Self {
        Self { sink, policy }
    }

    /// Projects and delivers one typed event.
    ///
    /// # Errors
    ///
    /// Returns a stable sink failure without exposing backend diagnostics.
    pub async fn notify(&self, event: NotificationEvent) -> Result<(), NotificationSinkError> {
        self.sink.send(event.project(self.policy)).await
    }

    /// Returns the underlying sink, primarily for shutdown and contract tests.
    #[must_use]
    pub const fn sink(&self) -> &S {
        &self.sink
    }
}

/// Freedesktop.org desktop notification adapter using Tokio-backed zbus.
#[derive(Debug, Default, Clone, Copy)]
pub struct FreedesktopNotificationSink;

impl NotificationSink for FreedesktopNotificationSink {
    fn send(
        &self,
        payload: NotificationPayload,
    ) -> NotificationFuture<'_, Result<(), NotificationSinkError>> {
        Box::pin(async move {
            notify_rust::Notification::new()
                .appname("omarchy-ai-bar")
                .summary(payload.summary())
                .body(payload.body())
                .icon(payload.icon())
                .show_async()
                .await
                .map(|_| ())
                .map_err(|_| NotificationSinkError::Unavailable)
        })
    }
}

/// Notification validation failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NotificationValidationError {
    /// An identity label was empty.
    #[error("notification identity labels must not be empty")]
    EmptyLabel,
    /// An identity label exceeded its fixed bound.
    #[error("notification identity label exceeds its size limit")]
    LabelTooLarge,
    /// An identity label contained a control character.
    #[error("notification identity labels must not contain control characters")]
    ControlCharacter,
    /// A usage threshold exceeded one hundred percent.
    #[error("notification usage percentage must be between zero and one hundred")]
    InvalidPercentage,
}

/// Stable notification delivery failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NotificationSinkError {
    /// No freedesktop notification service was available.
    #[error("desktop notifications are unavailable")]
    Unavailable,
    /// A sink rejected an otherwise valid payload.
    #[error("desktop notification delivery failed")]
    Delivery,
}

fn checked_label(value: String) -> Result<String, NotificationValidationError> {
    if value.is_empty() {
        return Err(NotificationValidationError::EmptyLabel);
    }
    if value.len() > MAX_IDENTITY_LABEL_BYTES {
        return Err(NotificationValidationError::LabelTooLarge);
    }
    if value.chars().any(char::is_control) {
        return Err(NotificationValidationError::ControlCharacter);
    }
    Ok(value)
}
