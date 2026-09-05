//! Account-scoped orchestration for the closed Codex source plan.
//!
//! This module owns only source selection and fallback policy. Credential
//! discovery, HTTP requests, and app-server execution are supplied by a
//! [`CodexAttemptRunner`], keeping those side effects behind one auditable
//! boundary.

use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, PrivacyKey, ProviderId, Timestamp, UsageSample,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::codex::{
    CodexAttemptFailure, CodexCredentialError, CodexPatHomeScope, CodexSourceAttempt,
    CodexSourceMode, CodexSourcePlan, should_continue_codex_plan,
};
use super::codex_app_server::CodexAppServerError;
use super::codex_http::CodexHttpError;

const MAX_MANAGED_WORKSPACE_ID_BYTES: usize = 1024;
const MAX_CLI_VERSION_BYTES: usize = 128;

/// A validated managed-workspace identifier used only for Codex request routing.
///
/// It is deliberately separate from [`AccountScope`]: the domain account key
/// identifies local state, while this value is a provider-owned HTTP header.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodexManagedWorkspaceId(String);

impl CodexManagedWorkspaceId {
    /// Trims and validates one provider-owned managed-workspace identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CodexCoordinatorError::Configuration`] for an empty,
    /// oversized, or header-unsafe value.
    pub fn new(value: impl Into<String>) -> Result<Self, CodexCoordinatorError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_MANAGED_WORKSPACE_ID_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(CodexCoordinatorError::Configuration);
        }
        Ok(Self(value.to_owned()))
    }

    /// Validated provider-owned identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for CodexManagedWorkspaceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodexManagedWorkspaceId(<redacted>)")
    }
}

/// Account authority selected before any Codex credential or process access.
#[derive(Clone, PartialEq, Eq)]
pub enum CodexAccountSelection {
    /// Ambient `$HOME/.codex` authority.
    Ambient,
    /// An already-resolved profile `CODEX_HOME` authority.
    Profile,
    /// An app-managed OAuth workspace with an explicit provider account ID.
    Managed(CodexManagedWorkspaceId),
    /// A managed selection whose backing store could not be read safely.
    FailClosedManaged,
}

impl CodexAccountSelection {
    /// PAT root-selection class for this account authority.
    #[must_use]
    pub const fn pat_scope(&self) -> CodexPatHomeScope {
        match self {
            Self::Ambient => CodexPatHomeScope::Ambient,
            Self::Profile => CodexPatHomeScope::Profile,
            Self::Managed(_) => CodexPatHomeScope::Managed,
            Self::FailClosedManaged => CodexPatHomeScope::FailClosed,
        }
    }

    /// Explicit provider account ID for the managed HTTP header, when valid.
    #[must_use]
    pub fn managed_account_id(&self) -> Option<&str> {
        match self {
            Self::Managed(id) => Some(id.as_str()),
            Self::Ambient | Self::Profile | Self::FailClosedManaged => None,
        }
    }

    /// Whether account routing selected either live or fail-closed managed state.
    #[must_use]
    pub const fn managed_selected(&self) -> bool {
        matches!(self, Self::Managed(_) | Self::FailClosedManaged)
    }

    /// Whether automatic planning may use the ambient Codex app-server.
    #[must_use]
    pub const fn allows_cli(&self) -> bool {
        !self.managed_selected()
    }
}

impl Debug for CodexAccountSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ambient => formatter.write_str("Ambient"),
            Self::Profile => formatter.write_str("Profile"),
            Self::Managed(_) => formatter.write_str("Managed(<redacted>)"),
            Self::FailClosedManaged => formatter.write_str("FailClosedManaged"),
        }
    }
}

/// Immutable inputs for one Codex coordinator fetch.
#[derive(Clone, PartialEq, Eq)]
pub struct CodexCoordinatorSettings {
    mode: CodexSourceMode,
    account: CodexAccountSelection,
    allow_external_oauth: bool,
    resolved_cli_version: Option<String>,
    reset_credit_key: Option<PrivacyKey>,
}

impl CodexCoordinatorSettings {
    /// Builds validated settings after all filesystem and executable discovery.
    ///
    /// A blank CLI version is normalized to absence. Version text is retained
    /// only for the attempt runner and never appears in this type's debug view.
    ///
    /// # Errors
    ///
    /// Returns [`CodexCoordinatorError::Configuration`] for oversized or
    /// control-character-bearing version text.
    pub fn new(
        mode: CodexSourceMode,
        account: CodexAccountSelection,
        allow_external_oauth: bool,
        resolved_cli_version: Option<String>,
    ) -> Result<Self, CodexCoordinatorError> {
        let resolved_cli_version = resolved_cli_version
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if resolved_cli_version.as_ref().is_some_and(|value| {
            value.len() > MAX_CLI_VERSION_BYTES || value.chars().any(char::is_control)
        }) {
            return Err(CodexCoordinatorError::Configuration);
        }
        Ok(Self {
            mode,
            account,
            allow_external_oauth,
            resolved_cli_version,
            reset_credit_key: None,
        })
    }

    /// Enables optional banked-reset inventory with installation-local private IDs.
    #[must_use]
    pub fn with_reset_credit_key(mut self, key: PrivacyKey) -> Self {
        self.reset_credit_key = Some(key);
        self
    }

    pub(crate) fn reset_credit_key(&self) -> Option<&PrivacyKey> {
        self.reset_credit_key.as_ref()
    }

    /// User-selected source mode.
    #[must_use]
    pub const fn mode(&self) -> CodexSourceMode {
        self.mode
    }

    /// Account authority selected for the fetch.
    #[must_use]
    pub const fn account(&self) -> &CodexAccountSelection {
        &self.account
    }

    /// Whether explicitly consented legacy/OpenCode OAuth discovery is allowed.
    #[must_use]
    pub const fn allow_external_oauth(&self) -> bool {
        self.allow_external_oauth
    }

    /// Already-resolved CLI version, if a compatible executable was found.
    #[must_use]
    pub fn resolved_cli_version(&self) -> Option<&str> {
        self.resolved_cli_version.as_deref()
    }
}

impl Debug for CodexCoordinatorSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexCoordinatorSettings")
            .field("mode", &self.mode)
            .field("account", &self.account)
            .field("allow_external_oauth", &self.allow_external_oauth)
            .field("has_cli_version", &self.resolved_cli_version.is_some())
            .field("reset_credit_key", &self.reset_credit_key)
            .finish()
    }
}

/// Stable, redacted failure from Codex source coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodexCoordinatorError {
    /// Cooperative cancellation stopped the plan.
    #[error("Codex usage fetch was cancelled")]
    Cancelled,
    /// No planned source was available.
    #[error("Codex credentials or executable are missing")]
    MissingCredential,
    /// Account or coordinator settings were invalid.
    #[error("Codex coordinator configuration is invalid")]
    Configuration,
    /// Credential discovery or freshness validation failed.
    #[error(transparent)]
    Credential(#[from] CodexCredentialError),
    /// A Codex HTTP attempt failed.
    #[error(transparent)]
    Http(#[from] CodexHttpError),
    /// A Codex app-server attempt failed.
    #[error(transparent)]
    Cli(#[from] CodexAppServerError),
}

impl CodexCoordinatorError {
    /// Failure class consumed by the closed source-plan fallback matrix.
    #[must_use]
    pub const fn attempt_failure(self) -> CodexAttemptFailure {
        match self {
            Self::Cancelled | Self::Configuration => CodexAttemptFailure::Other,
            Self::MissingCredential => CodexAttemptFailure::Unavailable,
            Self::Credential(error) => CodexAttemptFailure::Credential(error),
            Self::Http(error) => error.attempt_failure(),
            Self::Cli(error) => error.attempt_failure(),
        }
    }

    /// Whether the error represents cancellation rather than a fallback-safe failure.
    #[must_use]
    pub const fn is_cancelled(self) -> bool {
        matches!(
            self,
            Self::Cancelled
                | Self::Http(CodexHttpError::Cancelled)
                | Self::Cli(CodexAppServerError::Cancelled)
        )
    }

    /// Public-safe domain projection.
    #[must_use]
    pub fn classified(self) -> ClassifiedError {
        let kind = match self {
            Self::Cancelled => ErrorKind::Network,
            Self::MissingCredential => ErrorKind::MissingCredential,
            Self::Configuration => ErrorKind::Api,
            Self::Credential(error) => match error {
                CodexCredentialError::NotFound
                | CodexCredentialError::Unreadable
                | CodexCredentialError::MissingTokens => ErrorKind::MissingCredential,
                CodexCredentialError::Invalid => ErrorKind::Parse,
                CodexCredentialError::NativeRefreshRequired
                | CodexCredentialError::ReadOnlySource => ErrorKind::AuthenticationExpired,
            },
            Self::Http(error) => return error.classified(),
            Self::Cli(error) => return error.classified(),
        };
        ClassifiedError::new(kind)
    }
}

/// One side-effecting source attempt outcome.
// The successful sample is immediately returned by the coordinator. Keeping
// exact ownership here avoids a heap allocation at every successful refresh.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum CodexAttemptOutcome {
    /// The source had no usable credential, executable, or selected resource.
    Unavailable,
    /// The source returned one authoritative account-scoped sample.
    Success(UsageSample),
    /// The source was available but failed with a stable classification.
    Failed(CodexCoordinatorError),
}

/// Boxed future returned by a [`CodexAttemptRunner`].
pub type CodexAttemptFuture<'a> = Pin<Box<dyn Future<Output = CodexAttemptOutcome> + Send + 'a>>;

/// Side-effect boundary for one already-planned Codex source attempt.
pub trait CodexAttemptRunner: Send + Sync {
    /// Prepares and executes exactly one attempt.
    ///
    /// Availability checks must be side-effect free. In particular, an
    /// unavailable `CliOwnerRecovery` attempt must not spawn a child process.
    fn run<'a>(
        &'a self,
        attempt: CodexSourceAttempt,
        settings: &'a CodexCoordinatorSettings,
        scope: &'a AccountScope,
        fetched_at: Timestamp,
        cancellation: &'a CancellationToken,
    ) -> CodexAttemptFuture<'a>;
}

/// Closed Codex plan executor for one exact account scope.
pub struct CodexCoordinator {
    scope: AccountScope,
    settings: CodexCoordinatorSettings,
    runner: Arc<dyn CodexAttemptRunner>,
}

impl CodexCoordinator {
    /// Creates a coordinator around a production or deterministic attempt runner.
    #[must_use]
    pub fn new(
        scope: AccountScope,
        settings: CodexCoordinatorSettings,
        runner: Arc<dyn CodexAttemptRunner>,
    ) -> Self {
        Self {
            scope,
            settings,
            runner,
        }
    }

    /// Exact provider/account domain scope.
    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    /// Immutable source/account settings.
    #[must_use]
    pub const fn settings(&self) -> &CodexCoordinatorSettings {
        &self.settings
    }

    /// Executes the bounded source plan at one caller-supplied timestamp.
    ///
    /// Unavailable attempts do not erase an earlier available-source error.
    /// Cancellation is checked on both sides of every runner call and can
    /// never fall through to another source.
    ///
    /// # Errors
    ///
    /// Returns the last available-source failure, a stable missing-source
    /// error when every attempt was unavailable, or cancellation immediately.
    pub async fn fetch_at(
        &self,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> Result<UsageSample, CodexCoordinatorError> {
        if self.scope.provider() != ProviderId::Codex {
            return Err(CodexCoordinatorError::Configuration);
        }

        let plan = CodexSourcePlan::new(self.settings.mode(), self.settings.account().allows_cli());
        let mut last_error = None;
        for &attempt in plan.attempts() {
            if cancellation.is_cancelled() {
                return Err(CodexCoordinatorError::Cancelled);
            }

            let outcome = self
                .runner
                .run(
                    attempt,
                    &self.settings,
                    &self.scope,
                    fetched_at,
                    cancellation,
                )
                .await;

            if cancellation.is_cancelled() {
                return Err(CodexCoordinatorError::Cancelled);
            }

            match outcome {
                CodexAttemptOutcome::Success(sample) => {
                    if sample.scope() != &self.scope {
                        return Err(CodexCoordinatorError::Configuration);
                    }
                    return Ok(sample);
                }
                CodexAttemptOutcome::Unavailable => {
                    if !should_continue_codex_plan(
                        self.settings.mode(),
                        attempt,
                        CodexAttemptFailure::Unavailable,
                    ) {
                        break;
                    }
                }
                CodexAttemptOutcome::Failed(error) => {
                    if error.is_cancelled() {
                        return Err(error);
                    }
                    let continue_plan = should_continue_codex_plan(
                        self.settings.mode(),
                        attempt,
                        error.attempt_failure(),
                    );
                    last_error = Some(error);
                    if !continue_plan {
                        break;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(CodexCoordinatorError::MissingCredential))
    }
}

impl Debug for CodexCoordinator {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexCoordinator")
            .field("scope", &self.scope)
            .field("settings", &self.settings)
            .field("runner", &"<opaque>")
            .finish()
    }
}
