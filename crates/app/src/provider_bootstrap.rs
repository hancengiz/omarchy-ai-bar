//! Production discovery for the first end-to-end provider set.

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use oab_domain::{AccountKey, AccountScope, ProviderId, ProviderInstanceId};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::executable::resolve_executable;
use oab_providers::providers::claude::{ClaudeProvider, ClaudeSettings};
use oab_providers::providers::codex::CodexSourceMode;
use oab_providers::providers::codex_files::CodexCredentialPaths;
use oab_providers::providers::codex_provider::{
    CodexAccountSelection, CodexCoordinator, CodexCoordinatorSettings,
};
use oab_providers::providers::grok::{GrokProvider, GrokSettings};
use oab_providers::providers::zai::{ZaiProvider, ZaiSettings};
use oab_runtime::actor::RefreshRegistration;
use oab_runtime::actor::{RefreshFuture, RefreshSource};
use thiserror::Error;

use crate::provider_refresh::{
    CodexRefreshSource, ConfiguredProvider, ProviderRefreshBuildError, ProviderRefreshSource,
};

/// A provider registration and the exact scope used for runtime actions.
pub(crate) struct ProductionProviders {
    pub(crate) registrations: Vec<RefreshRegistration>,
    pub(crate) scopes: Vec<AccountScope>,
}

/// Stable, path-free production discovery failure.
#[derive(Debug, Error)]
pub(crate) enum ProviderBootstrapError {
    #[error("Codex environment is unavailable")]
    MissingHome,
    #[error("Codex credential paths are invalid")]
    CredentialPaths,
    #[error("Codex executable configuration is invalid")]
    Executable,
    #[error("Codex coordinator configuration is invalid")]
    Coordinator,
    #[error("Codex runtime binding is invalid")]
    RuntimeBinding(#[from] ProviderRefreshBuildError),
    #[error("Codex runtime identity is invalid")]
    Identity,
    #[error("Claude provider configuration is invalid")]
    Claude,
    #[error("Grok executable configuration is invalid")]
    GrokExecutable,
    #[error("Grok provider configuration is invalid")]
    Grok,
}

/// Discovers the initial production providers without reading credentials,
/// accessing the network, or starting provider child processes.
pub(crate) fn discover() -> Result<ProductionProviders, ProviderBootstrapError> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ProviderBootstrapError::MissingHome)?;
    let paths = CodexCredentialPaths::resolve(
        &home,
        env::var_os("CODEX_HOME").as_deref(),
        env::var_os("XDG_DATA_HOME").as_deref(),
    )
    .map_err(|_| ProviderBootstrapError::CredentialPaths)?;
    let executable_override = env::var("OMARCHY_AI_BAR_CODEX_EXECUTABLE").ok();
    let executable = resolve_executable(
        "codex",
        executable_override.as_deref(),
        env::var_os("PATH").as_deref(),
        &[],
    )
    .map_err(|_| ProviderBootstrapError::Executable)?;

    let scope = AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let settings = CodexCoordinatorSettings::new(
        CodexSourceMode::Auto,
        CodexAccountSelection::Ambient,
        false,
        None,
    )
    .map_err(|_| ProviderBootstrapError::Coordinator)?;
    let child_environment = unicode_environment();
    let coordinator = CodexCoordinator::production(
        scope.clone(),
        settings,
        paths,
        executable,
        &child_environment,
    )
    .map_err(|_| ProviderBootstrapError::Coordinator)?;
    let source = Arc::new(CodexRefreshSource::new(coordinator)?);

    let mut registrations = vec![RefreshRegistration::new(scope.clone(), source)];
    let mut scopes = vec![scope];
    let (scope, source) = discover_claude(&child_environment, &home)?;
    registrations.push(RefreshRegistration::new(scope.clone(), source));
    scopes.push(scope);
    let (scope, source) = discover_grok(&child_environment)?;
    registrations.push(RefreshRegistration::new(scope.clone(), source));
    scopes.push(scope);
    let (scope, source) = discover_zai(&child_environment)?;
    registrations.push(RefreshRegistration::new(scope.clone(), source));
    scopes.push(scope);

    Ok(ProductionProviders {
        registrations,
        scopes,
    })
}

fn discover_claude(
    environment: &BTreeMap<String, String>,
    home: &std::path::Path,
) -> Result<(AccountScope, Arc<dyn oab_runtime::actor::RefreshSource>), ProviderBootstrapError> {
    let scope = AccountScope::new(
        ProviderId::Claude,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let settings =
        ClaudeSettings::resolve(environment, home).map_err(|_| ProviderBootstrapError::Claude)?;
    let adapter =
        ClaudeProvider::new(scope.clone(), settings).map_err(|_| ProviderBootstrapError::Claude)?;
    let adapter = Arc::new(ConfiguredProvider::new(
        adapter,
        scope.clone(),
        ProviderSource::OAuth,
    ));
    let source = Arc::new(ProviderRefreshSource::new(adapter)?);
    Ok((scope, source))
}

fn discover_grok(
    environment: &BTreeMap<String, String>,
) -> Result<(AccountScope, Arc<dyn RefreshSource>), ProviderBootstrapError> {
    let executable_override = environment
        .get("OMARCHY_AI_BAR_GROK_EXECUTABLE")
        .map(String::as_str);
    let executable = resolve_executable(
        "grok",
        executable_override,
        env::var_os("PATH").as_deref(),
        &[],
    )
    .map_err(|_| ProviderBootstrapError::GrokExecutable)?;
    let scope = AccountScope::new(
        ProviderId::Grok,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let settings = GrokSettings::new(executable, environment.clone());
    let adapter =
        GrokProvider::new(scope.clone(), settings).map_err(|_| ProviderBootstrapError::Grok)?;
    let adapter = Arc::new(ConfiguredProvider::new(
        adapter,
        scope.clone(),
        ProviderSource::Cli,
    ));
    let source = Arc::new(ProviderRefreshSource::new(adapter)?);
    Ok((scope, source))
}

fn discover_zai(
    environment: &BTreeMap<String, String>,
) -> Result<(AccountScope, Arc<dyn RefreshSource>), ProviderBootstrapError> {
    let scope = AccountScope::new(
        ProviderId::Zai,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let source = Arc::new(LazyZaiSource {
        scope: scope.clone(),
        environment: environment.clone(),
        source: ProviderSource::ApiKey,
    });
    Ok((scope, source))
}

struct LazyZaiSource {
    scope: AccountScope,
    environment: BTreeMap<String, String>,
    source: ProviderSource,
}

impl RefreshSource for LazyZaiSource {
    fn fetch_required(
        &self,
        scope: AccountScope,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> RefreshFuture<Result<oab_domain::UsageSample, oab_domain::ClassifiedError>> {
        let expected = self.scope.clone();
        let environment = self.environment.clone();
        let source = self.source;
        Box::pin(async move {
            if scope != expected {
                return Err(oab_domain::ClassifiedError::new(oab_domain::ErrorKind::Api));
            }
            let settings = ZaiSettings::resolve(&environment)?;
            let adapter = ZaiProvider::new(scope.clone(), settings)?;
            let context = ProviderContext::new(scope, source, cancellation);
            adapter.fetch(&context).await
        })
    }
}

fn unicode_environment() -> BTreeMap<String, String> {
    env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}
