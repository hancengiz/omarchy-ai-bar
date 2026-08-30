//! Production side-effect boundary for the Codex source coordinator.
//!
//! Executable discovery and CLI version probing happen before construction.
//! Each attempt performs only its selected credential read and, after another
//! cancellation check, the corresponding HTTP or app-server operation.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use oab_domain::{AccountScope, ProviderId, Timestamp};
use tokio_util::sync::CancellationToken;

use super::codex::{
    CodexCredentialError, CodexSourceAttempt, CodexSourceMode, may_attempt_codex_cli_owner_recovery,
};
use super::codex_app_server::{CodexAppServerClient, CodexAppServerError};
use super::codex_files::{
    CodexCredentialLoadError, CodexCredentialPaths, load_bearer_selection_for_usage,
    load_pat_bundle_for_scope,
};
use super::codex_http::{CodexHttpClient, CodexHttpError, CodexHttpRoutes};
use super::codex_normalize::{normalize_codex_oauth_usage, normalize_codex_pat_usage};
use super::codex_provider::{
    CodexAccountSelection, CodexAttemptFuture, CodexAttemptOutcome, CodexAttemptRunner,
    CodexCoordinator, CodexCoordinatorError, CodexCoordinatorSettings,
};
use crate::executable::ExecutablePath;
use crate::transport::TransportConfig;

/// Production credential, HTTP, and app-server attempt runner.
pub struct CodexProductionRunner {
    credential_paths: CodexCredentialPaths,
    cli: Option<CodexAppServerClient>,
    http: CodexHttpMode,
}

impl CodexCoordinator {
    /// Creates the production Codex coordinator from already-resolved host inputs.
    ///
    /// Executable lookup and version probing remain caller-owned and therefore
    /// cannot occur during [`CodexCoordinator::fetch_at`]. Construction does
    /// not read credentials, access the network, or spawn the CLI.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error when the selected child
    /// environment cannot satisfy the bounded app-server contract.
    pub fn production(
        scope: AccountScope,
        settings: CodexCoordinatorSettings,
        credential_paths: CodexCredentialPaths,
        cli_executable: Option<ExecutablePath>,
        child_environment: &BTreeMap<String, String>,
    ) -> Result<Self, CodexCoordinatorError> {
        let runner =
            CodexProductionRunner::new(credential_paths, cli_executable, child_environment)?;
        Ok(Self::new(scope, settings, Arc::new(runner)))
    }
}

impl CodexProductionRunner {
    /// Creates a production runner from already-resolved local inputs.
    ///
    /// No credential file is read, network request is made, or process is
    /// spawned during construction. The child environment is reduced to the
    /// app-server adapter's closed Linux allowlist.
    ///
    /// # Errors
    ///
    /// Returns a stable CLI configuration error when an allowlisted child
    /// environment value violates the transport bounds.
    pub fn new(
        credential_paths: CodexCredentialPaths,
        cli_executable: Option<ExecutablePath>,
        child_environment: &BTreeMap<String, String>,
    ) -> Result<Self, CodexCoordinatorError> {
        Self::with_http_mode(
            credential_paths,
            cli_executable,
            child_environment,
            CodexHttpMode::Production,
        )
    }

    /// Creates a production runner with deterministic loopback HTTP routes.
    ///
    /// This seam retains production credential loading, config validation,
    /// normalization, cancellation, and app-server behavior. Only the final
    /// HTTP destinations and deadlines are replaced for integration tests.
    ///
    /// # Errors
    ///
    /// Returns a stable CLI configuration error when child construction fails.
    #[doc(hidden)]
    pub fn with_test_http_routes(
        credential_paths: CodexCredentialPaths,
        cli_executable: Option<ExecutablePath>,
        child_environment: &BTreeMap<String, String>,
        routes: CodexHttpRoutes,
        transport: TransportConfig,
    ) -> Result<Self, CodexCoordinatorError> {
        if !routes.is_loopback_only() {
            return Err(CodexCoordinatorError::Configuration);
        }
        Self::with_http_mode(
            credential_paths,
            cli_executable,
            child_environment,
            CodexHttpMode::Fixed {
                routes: Box::new(routes),
                transport,
            },
        )
    }

    fn with_http_mode(
        credential_paths: CodexCredentialPaths,
        cli_executable: Option<ExecutablePath>,
        child_environment: &BTreeMap<String, String>,
        http: CodexHttpMode,
    ) -> Result<Self, CodexCoordinatorError> {
        let cli = if let Some(executable) = cli_executable {
            let (home, codex_home) = credential_paths
                .cli_environment_roots()
                .ok_or(CodexCoordinatorError::Configuration)?;
            Some(
                CodexAppServerClient::from_environment_for_authority(
                    executable,
                    child_environment,
                    home,
                    codex_home,
                )
                .map_err(CodexCoordinatorError::Cli)?,
            )
        } else {
            None
        };
        Ok(Self {
            credential_paths,
            cli,
            http,
        })
    }

    async fn run_pat(
        &self,
        settings: &CodexCoordinatorSettings,
        scope: &AccountScope,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> CodexAttemptOutcome {
        let bundle = match load_pat_bundle_for_scope(
            &self.credential_paths,
            settings.account().pat_scope(),
            cancellation,
        ) {
            Ok(bundle) => bundle,
            Err(error) => return credential_load_outcome(error),
        };
        let client = match self.http.client(bundle.config_toml()) {
            Ok(client) => client,
            Err(error) => return http_failure(error),
        };
        if cancellation.is_cancelled() {
            return cancelled();
        }
        let fetched = match client
            .fetch_pat_usage(
                bundle.credentials(),
                settings.resolved_cli_version(),
                cancellation,
            )
            .await
        {
            Ok(fetched) => fetched,
            Err(error) => return http_failure(error),
        };
        if cancellation.is_cancelled() {
            return cancelled();
        }
        match normalize_codex_pat_usage(&fetched, scope.clone(), fetched_at) {
            Ok(sample) => CodexAttemptOutcome::Success(sample),
            Err(error) => http_failure(error),
        }
    }

    async fn run_oauth(
        &self,
        settings: &CodexCoordinatorSettings,
        scope: &AccountScope,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> CodexAttemptOutcome {
        if matches!(settings.account(), CodexAccountSelection::FailClosedManaged) {
            return CodexAttemptOutcome::Unavailable;
        }
        let selection = match load_bearer_selection_for_usage(
            &self.credential_paths,
            settings.allow_external_oauth(),
            cancellation,
        ) {
            Ok(selection) => selection,
            Err(error) => return credential_load_outcome(error),
        };
        if selection.credentials().needs_refresh_at(fetched_at) {
            let error = if selection.credentials().source().is_native() {
                CodexCredentialError::NativeRefreshRequired
            } else {
                CodexCredentialError::ReadOnlySource
            };
            return credential_failure(error);
        }
        let bundle = match selection.bind_config(cancellation) {
            Ok(bundle) => bundle,
            Err(error) => return credential_load_outcome(error),
        };
        let credentials = bundle.credentials();
        let client = match self.http.client(bundle.config_toml()) {
            Ok(client) => client,
            Err(error) => return http_failure(error),
        };
        if cancellation.is_cancelled() {
            return cancelled();
        }
        let response = match client
            .fetch_oauth_usage(
                credentials,
                settings.account().managed_account_id(),
                cancellation,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => return http_failure(error),
        };
        if cancellation.is_cancelled() {
            return cancelled();
        }
        match normalize_codex_oauth_usage(
            &response,
            credentials,
            settings.account().managed_account_id(),
            scope.clone(),
            fetched_at,
        ) {
            Ok(sample) => CodexAttemptOutcome::Success(sample),
            Err(error) => http_failure(error),
        }
    }

    async fn run_cli(
        &self,
        scope: &AccountScope,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> CodexAttemptOutcome {
        let Some(cli) = &self.cli else {
            return CodexAttemptOutcome::Unavailable;
        };
        if cancellation.is_cancelled() {
            return cancelled();
        }
        match cli.fetch(scope.clone(), fetched_at, cancellation).await {
            Ok(snapshot) => match snapshot.into_usage_sample() {
                Ok(sample) => CodexAttemptOutcome::Success(sample),
                Err(error) => cli_failure(error),
            },
            Err(error) => cli_failure(error),
        }
    }

    async fn run_cli_owner_recovery(
        &self,
        settings: &CodexCoordinatorSettings,
        scope: &AccountScope,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> CodexAttemptOutcome {
        if settings.mode() != CodexSourceMode::OAuth
            || settings.account().managed_selected()
            || self.cli.is_none()
        {
            return CodexAttemptOutcome::Unavailable;
        }
        let may_spawn = match load_bearer_selection_for_usage(
            &self.credential_paths,
            settings.allow_external_oauth(),
            cancellation,
        ) {
            Ok(selection) => may_attempt_codex_cli_owner_recovery(
                settings.mode(),
                false,
                true,
                Some(selection.credentials().source()),
                selection.credentials().needs_refresh_at(fetched_at),
            ),
            Err(CodexCredentialLoadError::Cancelled) => return cancelled(),
            Err(CodexCredentialLoadError::Credential(_)) => false,
        };
        if !may_spawn {
            return CodexAttemptOutcome::Unavailable;
        }
        if cancellation.is_cancelled() {
            return cancelled();
        }
        self.run_cli(scope, fetched_at, cancellation).await
    }
}

impl CodexAttemptRunner for CodexProductionRunner {
    fn run<'a>(
        &'a self,
        attempt: CodexSourceAttempt,
        settings: &'a CodexCoordinatorSettings,
        scope: &'a AccountScope,
        fetched_at: Timestamp,
        cancellation: &'a CancellationToken,
    ) -> CodexAttemptFuture<'a> {
        Box::pin(async move {
            if scope.provider() != ProviderId::Codex {
                return CodexAttemptOutcome::Failed(CodexCoordinatorError::Configuration);
            }
            if cancellation.is_cancelled() {
                return cancelled();
            }
            match attempt {
                CodexSourceAttempt::Pat => {
                    self.run_pat(settings, scope, fetched_at, cancellation)
                        .await
                }
                CodexSourceAttempt::OAuth => {
                    self.run_oauth(settings, scope, fetched_at, cancellation)
                        .await
                }
                CodexSourceAttempt::Cli => self.run_cli(scope, fetched_at, cancellation).await,
                CodexSourceAttempt::CliOwnerRecovery => {
                    self.run_cli_owner_recovery(settings, scope, fetched_at, cancellation)
                        .await
                }
            }
        })
    }
}

impl Debug for CodexProductionRunner {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexProductionRunner")
            .field("credential_paths", &self.credential_paths)
            .field("has_cli", &self.cli.is_some())
            .field("http", &self.http)
            .finish()
    }
}

enum CodexHttpMode {
    Production,
    Fixed {
        routes: Box<CodexHttpRoutes>,
        transport: TransportConfig,
    },
}

impl CodexHttpMode {
    fn client(&self, config_toml: Option<&str>) -> Result<CodexHttpClient, CodexHttpError> {
        match self {
            Self::Production => CodexHttpClient::from_config_text(config_toml),
            Self::Fixed { routes, transport } => {
                // Even deterministic tests retain production config validation.
                CodexHttpRoutes::from_config_text(config_toml)?;
                CodexHttpClient::with_transport_config(routes.as_ref().clone(), *transport)
            }
        }
    }
}

impl Debug for CodexHttpMode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Production => "Production",
            Self::Fixed { .. } => "Fixed(<redacted>)",
        })
    }
}

fn credential_load_outcome(error: CodexCredentialLoadError) -> CodexAttemptOutcome {
    match error {
        CodexCredentialLoadError::Cancelled => cancelled(),
        CodexCredentialLoadError::Credential(
            CodexCredentialError::NotFound | CodexCredentialError::MissingTokens,
        ) => CodexAttemptOutcome::Unavailable,
        CodexCredentialLoadError::Credential(error) => credential_failure(error),
    }
}

fn credential_failure(error: CodexCredentialError) -> CodexAttemptOutcome {
    CodexAttemptOutcome::Failed(CodexCoordinatorError::Credential(error))
}

fn http_failure(error: CodexHttpError) -> CodexAttemptOutcome {
    if error == CodexHttpError::Cancelled {
        cancelled()
    } else {
        CodexAttemptOutcome::Failed(CodexCoordinatorError::Http(error))
    }
}

fn cli_failure(error: CodexAppServerError) -> CodexAttemptOutcome {
    if error == CodexAppServerError::Cancelled {
        cancelled()
    } else {
        CodexAttemptOutcome::Failed(CodexCoordinatorError::Cli(error))
    }
}

const fn cancelled() -> CodexAttemptOutcome {
    CodexAttemptOutcome::Failed(CodexCoordinatorError::Cancelled)
}
