use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{BoundedText, WindowDuration};

pub const MAX_ERROR_CODE_BYTES: usize = 128;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 512;

/// A provider failure class. This is intentionally smaller than provider error
/// vocabularies: callers receive an actionable category without a raw response
/// or credential-adjacent detail string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    MissingCredential,
    AuthenticationExpired,
    PermissionDenied,
    RateLimited,
    ProviderUnavailable,
    Network,
    Parse,
    Api,
}

/// Whether the runtime may retry without user intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryEligibility {
    Automatic,
    Manual,
    Never,
}

/// The authentication-specific action implied by an error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthImplication {
    None,
    ConfigureCredential,
    Reauthenticate,
    PermissionDenied,
}

/// A bounded, public-safe error suitable for domain snapshots.
///
/// `retry` and `auth_implication` are serialized for consumers, but are
/// derived from `kind` and validated on decode so a wire payload cannot claim
/// contradictory recovery semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifiedError {
    kind: ErrorKind,
    code: BoundedText<MAX_ERROR_CODE_BYTES>,
    message: BoundedText<MAX_ERROR_MESSAGE_BYTES>,
    retry: RetryEligibility,
    auth_implication: AuthImplication,
    retry_after: Option<WindowDuration>,
}

impl ClassifiedError {
    /// Creates a classified error whose serialized code and message are
    /// selected only from the normalized error kind.
    ///
    /// Raw provider diagnostics deliberately have no input path into this
    /// serializable domain value.
    ///
    /// # Panics
    ///
    /// Panics only if a fixed string in this module violates its own bounded
    /// text contract.
    #[must_use]
    pub fn new(kind: ErrorKind) -> Self {
        Self::from_kind(kind, None)
    }

    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &BoundedText<MAX_ERROR_CODE_BYTES> {
        &self.code
    }

    #[must_use]
    pub const fn message(&self) -> &BoundedText<MAX_ERROR_MESSAGE_BYTES> {
        &self.message
    }

    #[must_use]
    pub const fn retry(&self) -> RetryEligibility {
        self.retry
    }

    #[must_use]
    pub const fn auth_implication(&self) -> AuthImplication {
        self.auth_implication
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<WindowDuration> {
        self.retry_after
    }

    /// Returns the public projection of this error.
    ///
    /// Error kind, fixed code/message, derived recovery semantics, and an
    /// optional retry delay are retained.
    #[must_use]
    pub fn without_personal_information(&self) -> Self {
        self.clone()
    }

    /// Alias for callers that name the privacy boundary by its target rather
    /// than the transformation.
    #[must_use]
    pub fn public_projection(&self) -> Self {
        self.without_personal_information()
    }

    /// Adds a provider-requested retry delay to an automatically retryable
    /// error.
    ///
    /// # Errors
    ///
    /// Returns an error when this error class requires manual intervention or
    /// must never be retried automatically.
    pub fn with_retry_after(
        mut self,
        retry_after: WindowDuration,
    ) -> Result<Self, ClassifiedErrorValidationError> {
        if self.retry != RetryEligibility::Automatic {
            return Err(ClassifiedErrorValidationError::RetryAfterNotAutomatic { kind: self.kind });
        }
        self.retry_after = Some(retry_after);
        Ok(self)
    }

    fn from_kind(kind: ErrorKind, retry_after: Option<WindowDuration>) -> Self {
        let (retry, auth_implication) = Self::semantics(kind);
        let code = BoundedText::new(Self::public_code(kind))
            .expect("fixed public error codes must satisfy their own bounded-text contract");
        let message = BoundedText::new(Self::public_message(kind))
            .expect("fixed public error messages must satisfy their own bounded-text contract");
        Self {
            kind,
            code,
            message,
            retry,
            auth_implication,
            retry_after,
        }
    }

    const fn semantics(kind: ErrorKind) -> (RetryEligibility, AuthImplication) {
        match kind {
            ErrorKind::MissingCredential => (
                RetryEligibility::Manual,
                AuthImplication::ConfigureCredential,
            ),
            ErrorKind::AuthenticationExpired => {
                (RetryEligibility::Manual, AuthImplication::Reauthenticate)
            }
            ErrorKind::PermissionDenied => {
                (RetryEligibility::Manual, AuthImplication::PermissionDenied)
            }
            ErrorKind::RateLimited
            | ErrorKind::ProviderUnavailable
            | ErrorKind::Network
            | ErrorKind::Api => (RetryEligibility::Automatic, AuthImplication::None),
            ErrorKind::Parse => (RetryEligibility::Never, AuthImplication::None),
        }
    }

    const fn public_message(kind: ErrorKind) -> &'static str {
        match kind {
            ErrorKind::MissingCredential => "Configure credentials for this provider.",
            ErrorKind::AuthenticationExpired => "Sign in again to continue.",
            ErrorKind::PermissionDenied => {
                "This account does not have permission for this provider."
            }
            ErrorKind::RateLimited => "The provider asked us to slow down.",
            ErrorKind::ProviderUnavailable => "The provider is currently unavailable.",
            ErrorKind::Network => "The provider could not be reached.",
            ErrorKind::Parse => "The provider returned an unsupported response.",
            ErrorKind::Api => "The provider returned an unexpected response.",
        }
    }

    const fn public_code(kind: ErrorKind) -> &'static str {
        match kind {
            ErrorKind::MissingCredential => "auth.missing",
            ErrorKind::AuthenticationExpired => "auth.expired",
            ErrorKind::PermissionDenied => "auth.permission_denied",
            ErrorKind::RateLimited => "provider.rate_limited",
            ErrorKind::ProviderUnavailable => "provider.unavailable",
            ErrorKind::Network => "provider.network",
            ErrorKind::Parse => "provider.parse",
            ErrorKind::Api => "provider.api",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifiedErrorWire {
    kind: ErrorKind,
    code: BoundedText<MAX_ERROR_CODE_BYTES>,
    message: BoundedText<MAX_ERROR_MESSAGE_BYTES>,
    retry: RetryEligibility,
    auth_implication: AuthImplication,
    retry_after: Option<WindowDuration>,
}

impl<'de> Deserialize<'de> for ClassifiedError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ClassifiedErrorWire::deserialize(deserializer)?;
        let decoded = Self::from_kind(wire.kind, wire.retry_after);
        if decoded.code != wire.code
            || decoded.message != wire.message
            || decoded.retry != wire.retry
            || decoded.auth_implication != wire.auth_implication
        {
            return Err(serde::de::Error::custom(
                "code, message, retry, and auth_implication must match the error kind",
            ));
        }
        if decoded.retry_after.is_some() && decoded.retry != RetryEligibility::Automatic {
            return Err(serde::de::Error::custom(
                "retry_after is valid only for automatic error-kind semantics",
            ));
        }
        Ok(decoded)
    }
}

#[derive(Debug, Error)]
pub enum ClassifiedErrorValidationError {
    #[error("retry-after is invalid for non-automatic {kind:?} errors")]
    RetryAfterNotAutomatic { kind: ErrorKind },
}

impl Display for ClassifiedError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}",
            self.code.as_str(),
            self.message.as_str()
        )
    }
}
