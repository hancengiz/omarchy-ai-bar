//! Generic bridge from one configured provider adapter to runtime refresh work.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use oab_auth::browser_safe_storage::{
    BrowserKeyringAccess, BrowserSafeStorageProduct, BrowserSafeStorageReader,
};
use oab_domain::{
    AccountScope, ClassifiedError, CostUsageSnapshot, ErrorKind, ProviderId, Timestamp, UsageSample,
};
use oab_providers::browser_cookie::ChromiumCookieDecryptor;
use oab_providers::browser_profile::{
    BrowserKind, BrowserProfileDiscovery, FlatpakProfileDiscovery,
};
use oab_providers::chromium_crypto::LinuxChromiumCookieCrypto;
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::normalize::system_timestamp;
use oab_providers::providers::antigravity_cost::{
    AntigravityHistoryRoots, scan_antigravity_token_history,
};
use oab_providers::providers::claude_cost::{scan_claude_cost_history, scan_vertexai_cost_history};
use oab_providers::providers::codex_cost::scan_codex_cost_history;
use oab_providers::providers::codex_provider::{CodexCoordinator, CodexCoordinatorError};
use oab_providers::providers::copilot_cost::scan_copilot_token_history;
use oab_providers::providers::cursor_cost::scan_cursor_cost_history;
use oab_providers::providers::grok_cost::scan_grok_token_history;
use oab_providers::providers::opencodego_cost::scan_opencodego_local_usage;
use oab_providers::registry::descriptor_for;
use oab_runtime::actor::{RefreshFuture, RefreshSource};
use oab_runtime::command::RefreshTrigger;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const BROWSER_KEYRING_TIMEOUT: Duration = Duration::from_secs(3);

/// A provider adapter that exposes the exact identity selected at construction.
///
/// The runtime bridge derives all routing state from this contract so callers
/// cannot independently bind an adapter to another account or source.
pub trait BoundProviderAdapter: ProviderAdapter {
    /// Exact provider-instance/account scope owned by this adapter.
    fn bound_scope(&self) -> &AccountScope;

    /// Exact provider source owned by this adapter.
    fn bound_source(&self) -> ProviderSource;
}

/// Gives an already configured native adapter its exact runtime binding.
///
/// The wrapper is intentionally small: provider construction still owns all
/// credential, endpoint, and account validation, while this type prevents the
/// runtime scope/source from drifting afterward.
pub struct ConfiguredProvider<A> {
    adapter: A,
    scope: AccountScope,
    source: ProviderSource,
}

impl<A> ConfiguredProvider<A> {
    #[must_use]
    pub const fn new(adapter: A, scope: AccountScope, source: ProviderSource) -> Self {
        Self {
            adapter,
            scope,
            source,
        }
    }
}

impl<A: ProviderAdapter> ProviderAdapter for ConfiguredProvider<A> {
    fn descriptor(&self) -> &'static oab_providers::descriptor::ProviderDescriptor {
        self.adapter.descriptor()
    }

    fn fetch<'a>(
        &'a self,
        context: &'a ProviderContext,
    ) -> oab_providers::context::ProviderFuture<'a> {
        self.adapter.fetch(context)
    }
}

impl<A: ProviderAdapter> BoundProviderAdapter for ConfiguredProvider<A> {
    fn bound_scope(&self) -> &AccountScope {
        &self.scope
    }

    fn bound_source(&self) -> ProviderSource {
        self.source
    }
}

/// Stable failure while binding one provider adapter to an exact runtime scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderRefreshBuildError {
    /// The adapter's bound scope names a different provider than its descriptor.
    #[error("provider refresh scope does not match its adapter")]
    ProviderMismatch,
    /// The adapter's bound source is not declared by its descriptor.
    #[error("provider refresh source is unsupported")]
    UnsupportedSource,
}

/// One exact account scope, selected source, and native provider adapter.
pub struct ProviderRefreshSource {
    scope: AccountScope,
    source: ProviderSource,
    adapter: Arc<dyn BoundProviderAdapter>,
    claude_history_root: Option<PathBuf>,
    grok_history_root: Option<PathBuf>,
    history_cache: Arc<Mutex<Option<(Instant, CostUsageSnapshot)>>>,
}

pub(crate) type LazyAdapterBuilder = fn(
    AccountScope,
    &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError>;

/// Constructs a provider adapter from the shared, read-only browser boundary.
///
/// Provider modules retain ownership of domain allowlists, cookie/local-storage
/// parsing, and profile isolation. The application supplies only the validated
/// discovery roots, Chromium decryptor, and refresh timestamp.
pub(crate) type BrowserAdapterBuilder = fn(
    AccountScope,
    &BTreeMap<String, String>,
    &BrowserProfileDiscovery,
    &dyn ChromiumCookieDecryptor,
    Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError>;

/// Constructs one native adapter only when its account is refreshed.
///
/// Keeping construction lazy lets the daemon advertise setup rows for
/// providers whose credentials are not configured yet. Discovery remains
/// side-effect free: no secret parsing, network access, or child process is
/// attempted until the runtime explicitly refreshes the account.
pub(crate) struct LazyProviderRefreshSource {
    scope: AccountScope,
    source: ProviderSource,
    environment: Arc<BTreeMap<String, String>>,
    builder: LazyAdapterBuilder,
    browser_fallback: Option<BrowserAdapterBuilder>,
    browser_keyring_access: BrowserKeyringAccess,
    grok_history_root: Option<PathBuf>,
    copilot_history_root: Option<PathBuf>,
    opencodego_history_root: Option<PathBuf>,
    vertex_history_root: Option<PathBuf>,
    cursor_history_root: Option<PathBuf>,
    antigravity_history_roots: Option<AntigravityHistoryRoots>,
    history_cache: Arc<Mutex<Option<(Instant, CostUsageSnapshot)>>>,
}

impl LazyProviderRefreshSource {
    pub(crate) fn new(
        scope: AccountScope,
        source: ProviderSource,
        environment: Arc<BTreeMap<String, String>>,
        builder: LazyAdapterBuilder,
    ) -> Result<Self, ProviderRefreshBuildError> {
        if !descriptor_for(scope.provider()).sources().contains(source) {
            return Err(ProviderRefreshBuildError::UnsupportedSource);
        }
        Ok(Self {
            scope,
            source,
            environment,
            builder,
            browser_fallback: None,
            // This path is reached only for an enabled provider after its
            // explicit/CLI source reports missing or expired authentication.
            // Access remains read-only and exact-product scoped in oab-auth.
            browser_keyring_access: BrowserKeyringAccess::Enabled,
            grok_history_root: None,
            copilot_history_root: None,
            opencodego_history_root: None,
            vertex_history_root: None,
            cursor_history_root: None,
            antigravity_history_roots: None,
            history_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Adds a browser-session fallback after the primary source.
    ///
    /// The fallback is attempted only for missing or expired authentication;
    /// rate limits, permissions, provider failures, and cancellation never
    /// trigger browser/keyring access.
    pub(crate) fn with_browser_fallback(
        mut self,
        builder: BrowserAdapterBuilder,
    ) -> Result<Self, ProviderRefreshBuildError> {
        if !descriptor_for(self.scope.provider())
            .sources()
            .contains(ProviderSource::BrowserSession)
        {
            return Err(ProviderRefreshBuildError::UnsupportedSource);
        }
        self.browser_fallback = Some(builder);
        Ok(self)
    }

    #[cfg(test)]
    #[must_use]
    fn with_browser_keyring_access(mut self, access: BrowserKeyringAccess) -> Self {
        self.browser_keyring_access = access;
        self
    }

    #[must_use]
    pub(crate) fn with_copilot_history_root(mut self, history_root: PathBuf) -> Self {
        self.copilot_history_root = Some(history_root);
        self
    }

    #[must_use]
    pub(crate) fn with_grok_history_root(mut self, history_root: PathBuf) -> Self {
        self.grok_history_root = Some(history_root);
        self
    }

    #[must_use]
    pub(crate) fn with_opencodego_history_root(mut self, history_root: PathBuf) -> Self {
        self.opencodego_history_root = Some(history_root);
        self
    }

    #[must_use]
    pub(crate) fn with_vertex_history_root(mut self, history_root: PathBuf) -> Self {
        self.vertex_history_root = Some(history_root);
        self
    }

    #[must_use]
    pub(crate) fn with_cursor_history_root(mut self, history_root: PathBuf) -> Self {
        self.cursor_history_root = Some(history_root);
        self
    }

    #[must_use]
    pub(crate) fn with_antigravity_history_roots(
        mut self,
        history_roots: AntigravityHistoryRoots,
    ) -> Self {
        self.antigravity_history_roots = Some(history_roots);
        self
    }
}

struct BrowserRuntime {
    discovery: BrowserProfileDiscovery,
    decryptor: LinuxChromiumCookieCrypto,
}

impl BrowserRuntime {
    async fn prepare(
        environment: &BTreeMap<String, String>,
        keyring_access: BrowserKeyringAccess,
        cancellation: &CancellationToken,
    ) -> Result<Self, ClassifiedError> {
        let discovery = BrowserProfileDiscovery::enabled_from_environment(
            environment,
            FlatpakProfileDiscovery::Enabled,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let mut decryptor = LinuxChromiumCookieCrypto::new();

        if keyring_access == BrowserKeyringAccess::Enabled {
            let keyring_load = async {
                if let Ok(reader) = BrowserSafeStorageReader::connect(keyring_access).await {
                    install_browser_secret(
                        &reader,
                        BrowserSafeStorageProduct::GoogleChrome,
                        &[BrowserKind::GoogleChrome],
                        &mut decryptor,
                    )
                    .await;
                    install_browser_secret(
                        &reader,
                        BrowserSafeStorageProduct::Chromium,
                        &[BrowserKind::Chromium],
                        &mut decryptor,
                    )
                    .await;
                    // Brave and Brave Origin deliberately share the same exact Secret
                    // Service identity, but retain isolated derived-key slots.
                    install_browser_secret(
                        &reader,
                        BrowserSafeStorageProduct::Brave,
                        &[BrowserKind::Brave, BrowserKind::BraveOrigin],
                        &mut decryptor,
                    )
                    .await;
                    install_browser_secret(
                        &reader,
                        BrowserSafeStorageProduct::MicrosoftEdge,
                        &[BrowserKind::MicrosoftEdge],
                        &mut decryptor,
                    )
                    .await;
                }
            };
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    return Err(ClassifiedError::new(ErrorKind::Network));
                }
                _ = tokio::time::timeout(BROWSER_KEYRING_TIMEOUT, keyring_load) => {}
            }
        }

        Ok(Self {
            discovery,
            decryptor,
        })
    }
}

async fn install_browser_secret(
    reader: &BrowserSafeStorageReader,
    product: BrowserSafeStorageProduct,
    browsers: &[BrowserKind],
    decryptor: &mut LinuxChromiumCookieCrypto,
) {
    let Ok(Some(secret)) = reader.read(product).await else {
        return;
    };
    for browser in browsers {
        // Each owned copy is zeroized by set_v11_secret on every return path.
        let _ = decryptor.set_v11_secret(*browser, Zeroizing::new(secret.expose_secret().to_vec()));
    }
}

async fn fetch_lazy_adapter(
    adapter: Result<Box<dyn ProviderAdapter>, ClassifiedError>,
    scope: AccountScope,
    source: ProviderSource,
    cancellation: CancellationToken,
) -> Result<UsageSample, ClassifiedError> {
    let adapter = adapter?;
    if adapter.descriptor().id != scope.provider()
        || !adapter.descriptor().sources().contains(source)
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    if cancellation.is_cancelled() {
        return Err(ClassifiedError::new(ErrorKind::Network));
    }
    let context = ProviderContext::new(scope, source, cancellation);
    adapter.fetch(&context).await
}

const fn should_try_browser_fallback(error: &ClassifiedError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::MissingCredential | ErrorKind::AuthenticationExpired
    )
}

fn resolve_fallback_error(
    primary_error: ClassifiedError,
    fallback_error: ClassifiedError,
) -> ClassifiedError {
    if primary_error.kind() == ErrorKind::MissingCredential {
        fallback_error
    } else {
        primary_error
    }
}

impl RefreshSource for LazyProviderRefreshSource {
    fn fetch_required(
        &self,
        scope: AccountScope,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<UsageSample, ClassifiedError>> {
        if scope != self.scope {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Api)) });
        }
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Network)) });
        }

        let environment = Arc::clone(&self.environment);
        let source = self.source;
        let builder = self.builder;
        let browser_fallback = self.browser_fallback;
        let browser_keyring_access = self.browser_keyring_access;
        Box::pin(async move {
            let primary = fetch_lazy_adapter(
                builder(scope.clone(), environment.as_ref()),
                scope.clone(),
                source,
                cancellation.clone(),
            )
            .await;
            let primary_error = match primary {
                Ok(sample) => return Ok(sample),
                Err(error) => error,
            };

            let Some(browser_fallback) = browser_fallback else {
                return Err(primary_error);
            };
            if cancellation.is_cancelled() {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            if !should_try_browser_fallback(&primary_error) {
                return Err(primary_error);
            }

            let runtime = match BrowserRuntime::prepare(
                environment.as_ref(),
                browser_keyring_access,
                &cancellation,
            )
            .await
            {
                Ok(runtime) => runtime,
                Err(fallback_error) => {
                    return Err(resolve_fallback_error(primary_error, fallback_error));
                }
            };
            if cancellation.is_cancelled() {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            let now = match system_timestamp() {
                Ok(now) => now,
                Err(fallback_error) => {
                    return Err(resolve_fallback_error(primary_error, fallback_error));
                }
            };
            let fallback_cancellation = cancellation.clone();
            let fallback = fetch_lazy_adapter(
                browser_fallback(
                    scope.clone(),
                    environment.as_ref(),
                    &runtime.discovery,
                    &runtime.decryptor,
                    now,
                ),
                scope,
                ProviderSource::BrowserSession,
                cancellation,
            )
            .await;
            if fallback_cancellation.is_cancelled() {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            fallback.map_err(|fallback_error| resolve_fallback_error(primary_error, fallback_error))
        })
    }

    fn fetch_optional(
        &self,
        required: UsageSample,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<Option<CostUsageSnapshot>, ClassifiedError>> {
        enum LazyHistory {
            Path(PathBuf, ProviderId),
            Antigravity(AntigravityHistoryRoots),
        }
        let history = self
            .grok_history_root
            .clone()
            .map(|root| LazyHistory::Path(root, ProviderId::Grok))
            .or_else(|| {
                self.copilot_history_root
                    .clone()
                    .map(|root| LazyHistory::Path(root, ProviderId::Copilot))
            })
            .or_else(|| {
                self.opencodego_history_root
                    .clone()
                    .map(|root| LazyHistory::Path(root, ProviderId::OpenCodeGo))
            })
            .or_else(|| {
                self.vertex_history_root
                    .clone()
                    .map(|root| LazyHistory::Path(root, ProviderId::VertexAi))
            })
            .or_else(|| {
                self.cursor_history_root
                    .clone()
                    .map(|root| LazyHistory::Path(root, ProviderId::Cursor))
            })
            .or_else(|| {
                self.antigravity_history_roots
                    .clone()
                    .map(LazyHistory::Antigravity)
            });
        let Some(history) = history else {
            return Box::pin(async { Ok(None) });
        };
        let scope = self.scope.clone();
        let worker_cancellation = cancellation.clone();
        let cache = Arc::clone(&self.history_cache);
        Box::pin(async move {
            if let Ok(guard) = cache.lock()
                && let Some((cached_at, snapshot)) = guard.as_ref()
                && cached_at.elapsed() < Duration::from_mins(15)
            {
                return Ok(Some(snapshot.clone()));
            }
            let updated_at = required.fetched_at();
            let result = tokio::task::spawn_blocking(move || match history {
                LazyHistory::Path(history_root, provider) => match provider {
                    ProviderId::Grok => {
                        scan_grok_token_history(&history_root, updated_at, &worker_cancellation)
                    }
                    ProviderId::Copilot => scan_copilot_token_history(&history_root, updated_at),
                    ProviderId::OpenCodeGo => {
                        scan_opencodego_local_usage(&history_root, scope, updated_at)
                            .map(|usage| usage.map(|usage| usage.cost))
                    }
                    ProviderId::VertexAi => {
                        scan_vertexai_cost_history(&history_root, updated_at, &worker_cancellation)
                    }
                    ProviderId::Cursor => {
                        scan_cursor_cost_history(&history_root, updated_at, &worker_cancellation)
                    }
                    _ => Err(ClassifiedError::new(ErrorKind::Api)),
                },
                LazyHistory::Antigravity(roots) => {
                    scan_antigravity_token_history(&roots, updated_at, &worker_cancellation)
                }
            })
            .await
            .map_err(|_| ClassifiedError::new(ErrorKind::ProviderUnavailable))??;
            if let Some(snapshot) = result.as_ref()
                && let Ok(mut guard) = cache.lock()
            {
                *guard = Some((Instant::now(), snapshot.clone()));
            }
            Ok(result)
        })
    }
}

impl Debug for LazyProviderRefreshSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LazyProviderRefreshSource")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("environment", &"<redacted>")
            .field("builder", &"<function>")
            .field(
                "browser_fallback",
                &self.browser_fallback.map(|_| "<function>"),
            )
            .finish_non_exhaustive()
    }
}

impl ProviderRefreshSource {
    /// Binds an adapter to its validated provider/account scope and source.
    ///
    /// Construction performs no adapter fetch, credential read, network
    /// request, or child-process launch.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderRefreshBuildError::ProviderMismatch`] when the bound
    /// scope and descriptor identify different providers, or
    /// [`ProviderRefreshBuildError::UnsupportedSource`] when the descriptor
    /// does not declare the bound source.
    pub fn new(adapter: Arc<dyn BoundProviderAdapter>) -> Result<Self, ProviderRefreshBuildError> {
        let scope = adapter.bound_scope().clone();
        let source = adapter.bound_source();
        let descriptor = adapter.descriptor();
        if scope.provider() != descriptor.id {
            return Err(ProviderRefreshBuildError::ProviderMismatch);
        }
        if !descriptor.sources().contains(source) {
            return Err(ProviderRefreshBuildError::UnsupportedSource);
        }
        Ok(Self {
            scope,
            source,
            adapter,
            claude_history_root: None,
            grok_history_root: None,
            history_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Enables bounded local Claude Code history enrichment.
    #[must_use]
    pub fn with_claude_history_root(mut self, history_root: PathBuf) -> Self {
        self.claude_history_root = Some(history_root);
        self
    }

    /// Enables bounded local Grok CLI session history enrichment.
    #[must_use]
    pub fn with_grok_history_root(mut self, history_root: PathBuf) -> Self {
        self.grok_history_root = Some(history_root);
        self
    }
}

impl RefreshSource for ProviderRefreshSource {
    fn fetch_required(
        &self,
        scope: AccountScope,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<UsageSample, ClassifiedError>> {
        if scope != self.scope {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Api)) });
        }
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Network)) });
        }

        let adapter = Arc::clone(&self.adapter);
        let source = self.source;
        Box::pin(async move {
            let context = ProviderContext::new(scope, source, cancellation);
            adapter.fetch(&context).await
        })
    }

    fn fetch_required_with_trigger(
        &self,
        scope: AccountScope,
        cancellation: CancellationToken,
        trigger: RefreshTrigger,
    ) -> RefreshFuture<Result<UsageSample, ClassifiedError>> {
        if scope != self.scope {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Api)) });
        }
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Network)) });
        }

        let adapter = Arc::clone(&self.adapter);
        let source = self.source;
        Box::pin(async move {
            let mut context = ProviderContext::new(scope, source, cancellation);
            if matches!(trigger, RefreshTrigger::Manual) {
                context = context.with_provider_cache_bypass();
            }
            adapter.fetch(&context).await
        })
    }

    fn fetch_optional(
        &self,
        required: UsageSample,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<Option<CostUsageSnapshot>, ClassifiedError>> {
        let history = self
            .claude_history_root
            .clone()
            .map(|root| (root, ProviderId::Claude))
            .or_else(|| {
                self.grok_history_root
                    .clone()
                    .map(|root| (root, ProviderId::Grok))
            });
        let Some((history_root, provider)) = history else {
            return Box::pin(async { Ok(None) });
        };
        let cache = Arc::clone(&self.history_cache);
        Box::pin(async move {
            if let Ok(guard) = cache.lock()
                && let Some((cached_at, snapshot)) = guard.as_ref()
                && cached_at.elapsed() < Duration::from_mins(15)
            {
                return Ok(Some(snapshot.clone()));
            }
            let updated_at = required.fetched_at();
            let worker_cancellation = cancellation.clone();
            let result = tokio::task::spawn_blocking(move || match provider {
                ProviderId::Claude => {
                    scan_claude_cost_history(&history_root, updated_at, &worker_cancellation)
                }
                ProviderId::Grok => {
                    scan_grok_token_history(&history_root, updated_at, &worker_cancellation)
                }
                _ => Err(ClassifiedError::new(ErrorKind::Api)),
            })
            .await
            .map_err(|_| ClassifiedError::new(ErrorKind::ProviderUnavailable))??;
            if let Some(snapshot) = result.as_ref()
                && let Ok(mut guard) = cache.lock()
            {
                *guard = Some((Instant::now(), snapshot.clone()));
            }
            Ok(result)
        })
    }
}

impl Debug for ProviderRefreshSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRefreshSource")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("adapter", &"<opaque>")
            .finish_non_exhaustive()
    }
}

/// Runtime source for Codex's ordered multi-mechanism coordinator.
///
/// Codex automatic and OAuth owner-recovery plans may cross PAT, OAuth/API-key,
/// configurable-endpoint, and CLI boundaries. This bridge therefore preserves
/// the coordinator as one composite plan instead of assigning a false exact
/// [`ProviderSource`].
pub struct CodexRefreshSource {
    scope: AccountScope,
    coordinator: Arc<CodexCoordinator>,
    history_root: Option<PathBuf>,
    history_cache: Arc<Mutex<Option<(Instant, CostUsageSnapshot)>>>,
}

impl CodexRefreshSource {
    /// Binds one validated Codex coordinator to its exact runtime account scope.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderRefreshBuildError::ProviderMismatch`] when the
    /// coordinator was constructed for another provider.
    pub fn new(coordinator: CodexCoordinator) -> Result<Self, ProviderRefreshBuildError> {
        let scope = coordinator.scope().clone();
        if scope.provider() != ProviderId::Codex {
            return Err(ProviderRefreshBuildError::ProviderMismatch);
        }
        Ok(Self {
            scope,
            coordinator: Arc::new(coordinator),
            history_root: None,
            history_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Enables bounded local Codex rollout history enrichment.
    #[must_use]
    pub fn with_history_root(mut self, history_root: PathBuf) -> Self {
        self.history_root = Some(history_root);
        self
    }
}

impl RefreshSource for CodexRefreshSource {
    fn fetch_required(
        &self,
        scope: AccountScope,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<UsageSample, ClassifiedError>> {
        if scope != self.scope {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Api)) });
        }
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(ClassifiedError::new(ErrorKind::Network)) });
        }

        let coordinator = Arc::clone(&self.coordinator);
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            coordinator
                .fetch_at(fetched_at, &cancellation)
                .await
                .map_err(CodexCoordinatorError::classified)
        })
    }

    fn fetch_optional(
        &self,
        required: UsageSample,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<Option<CostUsageSnapshot>, ClassifiedError>> {
        let Some(history_root) = self.history_root.clone() else {
            return Box::pin(async { Ok(None) });
        };
        let cache = Arc::clone(&self.history_cache);
        Box::pin(async move {
            if let Ok(guard) = cache.lock()
                && let Some((cached_at, snapshot)) = guard.as_ref()
                && cached_at.elapsed() < Duration::from_mins(15)
            {
                return Ok(Some(snapshot.clone()));
            }
            let updated_at = required.fetched_at();
            let worker_cancellation = cancellation.clone();
            let result = tokio::task::spawn_blocking(move || {
                scan_codex_cost_history(&history_root, updated_at, &worker_cancellation)
            })
            .await
            .map_err(|_| ClassifiedError::new(ErrorKind::ProviderUnavailable))??;
            if let Some(snapshot) = result.as_ref()
                && let Ok(mut guard) = cache.lock()
            {
                *guard = Some((Instant::now(), snapshot.clone()));
            }
            Ok(result)
        })
    }
}

impl Debug for CodexRefreshSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexRefreshSource")
            .field("scope", &"<redacted>")
            .field("coordinator", &"<opaque>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, PoisonError};
    use std::time::Duration;

    use oab_domain::{AccountKey, ProviderId, ProviderInstanceId, Timestamp};
    use oab_providers::context::ProviderFuture;
    use oab_providers::descriptor::ProviderDescriptor;
    use oab_providers::normalize::UsageSampleBuilder;
    use oab_providers::providers::codex::{CodexSourceAttempt, CodexSourceMode};
    use oab_providers::providers::codex_provider::{
        CodexAccountSelection, CodexAttemptFuture, CodexAttemptOutcome, CodexAttemptRunner,
        CodexCoordinator, CodexCoordinatorSettings,
    };
    use oab_providers::registry::descriptor_for;
    use tokio::sync::Notify;

    use super::*;

    static LAZY_BUILDS: AtomicUsize = AtomicUsize::new(0);
    static BROWSER_AFTER_MISSING_BUILDS: AtomicUsize = AtomicUsize::new(0);
    static BROWSER_AFTER_SUCCESS_BUILDS: AtomicUsize = AtomicUsize::new(0);
    static BROWSER_AFTER_RATE_LIMIT_BUILDS: AtomicUsize = AtomicUsize::new(0);
    static BROWSER_AFTER_EXPIRED_BUILDS: AtomicUsize = AtomicUsize::new(0);
    static BROWSER_AFTER_CANCELLATION_BUILDS: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedContext {
        scope: AccountScope,
        source: ProviderSource,
        cancelled_on_entry: bool,
        provider_cache_bypass: bool,
    }

    enum FakeBehavior {
        Success(Box<UsageSample>),
        Failure(ErrorKind),
        CancelThenFail(ErrorKind),
        WaitForCancellation,
    }

    struct FakeAdapter {
        descriptor_provider: ProviderId,
        bound_scope: AccountScope,
        bound_source: ProviderSource,
        behavior: FakeBehavior,
        calls: AtomicUsize,
        observations: Mutex<Vec<ObservedContext>>,
        entered: Notify,
        _secret_canary: &'static str,
    }

    impl FakeAdapter {
        fn success(
            bound_scope: AccountScope,
            bound_source: ProviderSource,
            sample: UsageSample,
        ) -> Self {
            let descriptor_provider = bound_scope.provider();
            Self::success_with_descriptor(descriptor_provider, bound_scope, bound_source, sample)
        }

        fn success_with_descriptor(
            descriptor_provider: ProviderId,
            bound_scope: AccountScope,
            bound_source: ProviderSource,
            sample: UsageSample,
        ) -> Self {
            Self {
                descriptor_provider,
                bound_scope,
                bound_source,
                behavior: FakeBehavior::Success(Box::new(sample)),
                calls: AtomicUsize::new(0),
                observations: Mutex::new(Vec::new()),
                entered: Notify::new(),
                _secret_canary: "adapter-secret-canary",
            }
        }

        fn cancellation(bound_scope: AccountScope, bound_source: ProviderSource) -> Self {
            let descriptor_provider = bound_scope.provider();
            Self {
                descriptor_provider,
                bound_scope,
                bound_source,
                behavior: FakeBehavior::WaitForCancellation,
                calls: AtomicUsize::new(0),
                observations: Mutex::new(Vec::new()),
                entered: Notify::new(),
                _secret_canary: "adapter-secret-canary",
            }
        }

        fn failure(
            bound_scope: AccountScope,
            bound_source: ProviderSource,
            kind: ErrorKind,
        ) -> Self {
            let descriptor_provider = bound_scope.provider();
            Self {
                descriptor_provider,
                bound_scope,
                bound_source,
                behavior: FakeBehavior::Failure(kind),
                calls: AtomicUsize::new(0),
                observations: Mutex::new(Vec::new()),
                entered: Notify::new(),
                _secret_canary: "adapter-secret-canary",
            }
        }

        fn cancel_then_fail(
            bound_scope: AccountScope,
            bound_source: ProviderSource,
            kind: ErrorKind,
        ) -> Self {
            let descriptor_provider = bound_scope.provider();
            Self {
                descriptor_provider,
                bound_scope,
                bound_source,
                behavior: FakeBehavior::CancelThenFail(kind),
                calls: AtomicUsize::new(0),
                observations: Mutex::new(Vec::new()),
                entered: Notify::new(),
                _secret_canary: "adapter-secret-canary",
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn observations(&self) -> Vec<ObservedContext> {
            self.observations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        async fn wait_until_called(&self) {
            while self.call_count() == 0 {
                self.entered.notified().await;
            }
        }
    }

    impl ProviderAdapter for FakeAdapter {
        fn descriptor(&self) -> &'static ProviderDescriptor {
            descriptor_for(self.descriptor_provider)
        }

        fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(ObservedContext {
                    scope: context.scope().clone(),
                    source: context.source(),
                    cancelled_on_entry: context.cancellation().is_cancelled(),
                    provider_cache_bypass: context.provider_cache_bypass(),
                });
            self.entered.notify_one();

            match &self.behavior {
                FakeBehavior::Success(sample) => {
                    let sample = sample.as_ref().clone();
                    Box::pin(async move { Ok(sample) })
                }
                FakeBehavior::Failure(kind) => {
                    let error = ClassifiedError::new(*kind);
                    Box::pin(async move { Err(error) })
                }
                FakeBehavior::CancelThenFail(kind) => {
                    context.cancellation().cancel();
                    let error = ClassifiedError::new(*kind);
                    Box::pin(async move { Err(error) })
                }
                FakeBehavior::WaitForCancellation => Box::pin(async move {
                    context.cancellation().cancelled().await;
                    Err(ClassifiedError::new(ErrorKind::Network))
                }),
            }
        }
    }

    impl BoundProviderAdapter for FakeAdapter {
        fn bound_scope(&self) -> &AccountScope {
            &self.bound_scope
        }

        fn bound_source(&self) -> ProviderSource {
            self.bound_source
        }
    }

    struct SuccessfulCodexRunner {
        sample: UsageSample,
        calls: AtomicUsize,
    }

    impl CodexAttemptRunner for SuccessfulCodexRunner {
        fn run<'a>(
            &'a self,
            _attempt: CodexSourceAttempt,
            _settings: &'a CodexCoordinatorSettings,
            _scope: &'a AccountScope,
            _fetched_at: Timestamp,
            _cancellation: &'a CancellationToken,
        ) -> CodexAttemptFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let sample = self.sample.clone();
            Box::pin(async move { CodexAttemptOutcome::Success(sample) })
        }
    }

    fn scope(provider: ProviderId, instance: &str, account: &str) -> AccountScope {
        AccountScope::new(
            provider,
            ProviderInstanceId::new(instance).expect("provider instance"),
            AccountKey::new(account).expect("account key"),
        )
    }

    fn sample(scope: AccountScope) -> UsageSample {
        UsageSampleBuilder::new(
            scope,
            Timestamp::from_unix_timestamp(1_800_000_000).expect("fixture timestamp"),
        )
        .provenance("fixture", "adapter")
        .and_then(UsageSampleBuilder::build)
        .expect("fixture sample")
    }

    fn erase(adapter: &Arc<FakeAdapter>) -> Arc<dyn BoundProviderAdapter> {
        Arc::clone(adapter) as Arc<dyn BoundProviderAdapter>
    }

    fn build_lazy_fake(
        exact_scope: AccountScope,
        environment: &BTreeMap<String, String>,
    ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
        if environment.is_empty() {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        LAZY_BUILDS.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(FakeAdapter::success(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            sample(exact_scope),
        )))
    }

    fn build_amp_primary_missing(
        _scope: AccountScope,
        _environment: &BTreeMap<String, String>,
    ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
        Err(ClassifiedError::new(ErrorKind::MissingCredential))
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "test builder must match the production function-pointer contract"
    )]
    fn build_amp_primary_success(
        exact_scope: AccountScope,
        _environment: &BTreeMap<String, String>,
    ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
        Ok(Box::new(FakeAdapter::success(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            sample(exact_scope),
        )))
    }

    fn build_amp_primary_rate_limited(
        _scope: AccountScope,
        _environment: &BTreeMap<String, String>,
    ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
        Err(ClassifiedError::new(ErrorKind::RateLimited))
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "test builder must match the production function-pointer contract"
    )]
    fn build_amp_primary_expired(
        exact_scope: AccountScope,
        _environment: &BTreeMap<String, String>,
    ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
        Ok(Box::new(FakeAdapter::failure(
            exact_scope,
            ProviderSource::ApiKey,
            ErrorKind::AuthenticationExpired,
        )))
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "test builder must match the production function-pointer contract"
    )]
    fn build_amp_primary_cancels(
        exact_scope: AccountScope,
        _environment: &BTreeMap<String, String>,
    ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
        Ok(Box::new(FakeAdapter::cancel_then_fail(
            exact_scope,
            ProviderSource::ApiKey,
            ErrorKind::AuthenticationExpired,
        )))
    }

    fn build_browser_sample(
        exact_scope: AccountScope,
        counter: &AtomicUsize,
    ) -> Box<dyn ProviderAdapter> {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::new(FakeAdapter::success(
            exact_scope.clone(),
            ProviderSource::BrowserSession,
            sample(exact_scope),
        ))
    }

    macro_rules! browser_test_builder {
        ($name:ident, $counter:ident) => {
            fn $name(
                exact_scope: AccountScope,
                _environment: &BTreeMap<String, String>,
                _discovery: &BrowserProfileDiscovery,
                _decryptor: &dyn ChromiumCookieDecryptor,
                _now: Timestamp,
            ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
                Ok(build_browser_sample(exact_scope, &$counter))
            }
        };
    }

    browser_test_builder!(build_browser_after_missing, BROWSER_AFTER_MISSING_BUILDS);
    browser_test_builder!(build_browser_after_success, BROWSER_AFTER_SUCCESS_BUILDS);
    browser_test_builder!(
        build_browser_after_rate_limit,
        BROWSER_AFTER_RATE_LIMIT_BUILDS
    );
    browser_test_builder!(
        build_browser_after_cancellation,
        BROWSER_AFTER_CANCELLATION_BUILDS
    );

    fn build_browser_missing_after_expired(
        _exact_scope: AccountScope,
        _environment: &BTreeMap<String, String>,
        _discovery: &BrowserProfileDiscovery,
        _decryptor: &dyn ChromiumCookieDecryptor,
        _now: Timestamp,
    ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
        BROWSER_AFTER_EXPIRED_BUILDS.fetch_add(1, Ordering::SeqCst);
        Err(ClassifiedError::new(ErrorKind::MissingCredential))
    }

    #[tokio::test]
    async fn lazy_source_defers_adapter_construction_and_redacts_environment() {
        LAZY_BUILDS.store(0, Ordering::SeqCst);
        let exact_scope = scope(ProviderId::OpenAi, "openai-primary", "lazy-account");
        let environment = Arc::new(BTreeMap::from([(
            "OPENAI_API_KEY".to_owned(),
            "environment-secret-canary".to_owned(),
        )]));
        let bridge = LazyProviderRefreshSource::new(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            environment,
            build_lazy_fake,
        )
        .expect("valid lazy source");

        assert_eq!(LAZY_BUILDS.load(Ordering::SeqCst), 0);
        let debug = format!("{bridge:?}");
        assert!(!debug.contains("environment-secret-canary"));
        assert!(!debug.contains("lazy-account"));

        let wrong_scope = bridge
            .fetch_required(
                scope(ProviderId::OpenAi, "openai-primary", "wrong-account"),
                CancellationToken::new(),
            )
            .await
            .expect_err("wrong account must fail closed");
        assert_eq!(wrong_scope.kind(), ErrorKind::Api);
        assert_eq!(LAZY_BUILDS.load(Ordering::SeqCst), 0);

        let fetched = bridge
            .fetch_required(exact_scope.clone(), CancellationToken::new())
            .await
            .expect("lazy adapter fetch");
        assert_eq!(fetched, sample(exact_scope));
        assert_eq!(LAZY_BUILDS.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lazy_source_falls_back_to_browser_after_missing_primary_credentials() {
        BROWSER_AFTER_MISSING_BUILDS.store(0, Ordering::SeqCst);
        let exact_scope = scope(ProviderId::Amp, "amp-primary", "browser-account");
        let bridge = LazyProviderRefreshSource::new(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            Arc::new(BTreeMap::from([("HOME".to_owned(), "/tmp".to_owned())])),
            build_amp_primary_missing,
        )
        .expect("valid primary source")
        .with_browser_fallback(build_browser_after_missing)
        .expect("supported browser fallback")
        .with_browser_keyring_access(BrowserKeyringAccess::Disabled);

        let fetched = bridge
            .fetch_required(exact_scope.clone(), CancellationToken::new())
            .await
            .expect("browser fallback sample");

        assert_eq!(fetched, sample(exact_scope));
        assert_eq!(BROWSER_AFTER_MISSING_BUILDS.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lazy_source_never_touches_browser_after_primary_success() {
        BROWSER_AFTER_SUCCESS_BUILDS.store(0, Ordering::SeqCst);
        let exact_scope = scope(ProviderId::Amp, "amp-primary", "explicit-account");
        let bridge = LazyProviderRefreshSource::new(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            Arc::new(BTreeMap::new()),
            build_amp_primary_success,
        )
        .expect("valid primary source")
        .with_browser_fallback(build_browser_after_success)
        .expect("supported browser fallback");

        let fetched = bridge
            .fetch_required(exact_scope.clone(), CancellationToken::new())
            .await
            .expect("primary sample");

        assert_eq!(fetched, sample(exact_scope));
        assert_eq!(BROWSER_AFTER_SUCCESS_BUILDS.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lazy_source_does_not_fallback_on_rate_limit() {
        BROWSER_AFTER_RATE_LIMIT_BUILDS.store(0, Ordering::SeqCst);
        let exact_scope = scope(ProviderId::Amp, "amp-primary", "rate-limited-account");
        let bridge = LazyProviderRefreshSource::new(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            Arc::new(BTreeMap::new()),
            build_amp_primary_rate_limited,
        )
        .expect("valid primary source")
        .with_browser_fallback(build_browser_after_rate_limit)
        .expect("supported browser fallback");

        let error = bridge
            .fetch_required(exact_scope, CancellationToken::new())
            .await
            .expect_err("rate limit must not switch accounts");

        assert_eq!(error.kind(), ErrorKind::RateLimited);
        assert_eq!(BROWSER_AFTER_RATE_LIMIT_BUILDS.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_between_sources_stops_before_browser_access() {
        BROWSER_AFTER_CANCELLATION_BUILDS.store(0, Ordering::SeqCst);
        let exact_scope = scope(ProviderId::Amp, "amp-primary", "cancelled-fallback");
        let bridge = LazyProviderRefreshSource::new(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            Arc::new(BTreeMap::new()),
            build_amp_primary_cancels,
        )
        .expect("valid primary source")
        .with_browser_fallback(build_browser_after_cancellation)
        .expect("supported browser fallback");

        let error = bridge
            .fetch_required(exact_scope, CancellationToken::new())
            .await
            .expect_err("cancelled refresh must stop");

        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(BROWSER_AFTER_CANCELLATION_BUILDS.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn expired_explicit_credential_remains_actionable_when_browser_is_missing() {
        BROWSER_AFTER_EXPIRED_BUILDS.store(0, Ordering::SeqCst);
        let exact_scope = scope(ProviderId::Amp, "amp-primary", "expired-account");
        let bridge = LazyProviderRefreshSource::new(
            exact_scope.clone(),
            ProviderSource::ApiKey,
            Arc::new(BTreeMap::from([("HOME".to_owned(), "/tmp".to_owned())])),
            build_amp_primary_expired,
        )
        .expect("valid primary source")
        .with_browser_fallback(build_browser_missing_after_expired)
        .expect("supported browser fallback")
        .with_browser_keyring_access(BrowserKeyringAccess::Disabled);

        let error = bridge
            .fetch_required(exact_scope, CancellationToken::new())
            .await
            .expect_err("both authentication sources fail");

        assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
        assert_eq!(BROWSER_AFTER_EXPIRED_BUILDS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn browser_fallback_policy_is_auth_only() {
        assert!(should_try_browser_fallback(&ClassifiedError::new(
            ErrorKind::MissingCredential
        )));
        assert!(should_try_browser_fallback(&ClassifiedError::new(
            ErrorKind::AuthenticationExpired
        )));
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::RateLimited,
            ErrorKind::ProviderUnavailable,
            ErrorKind::Network,
            ErrorKind::Parse,
            ErrorKind::Api,
        ] {
            assert!(!should_try_browser_fallback(&ClassifiedError::new(kind)));
        }
    }

    #[tokio::test]
    async fn successful_fetch_returns_the_adapter_sample_unchanged() {
        let exact_scope = scope(ProviderId::Codex, "codex-primary", "account-one");
        let expected = sample(exact_scope.clone());
        let adapter = Arc::new(FakeAdapter::success(
            exact_scope.clone(),
            ProviderSource::OAuth,
            expected.clone(),
        ));
        let bridge = ProviderRefreshSource::new(erase(&adapter)).expect("valid bridge");

        let actual = bridge
            .fetch_required(exact_scope, CancellationToken::new())
            .await
            .expect("successful fetch");

        assert_eq!(actual, expected);
        assert_eq!(adapter.call_count(), 1);
    }

    #[tokio::test]
    async fn exact_bound_scope_and_source_reach_the_context() {
        let exact_scope = scope(ProviderId::Codex, "codex-primary", "account-two");
        let adapter = Arc::new(FakeAdapter::success(
            exact_scope.clone(),
            ProviderSource::Cli,
            sample(exact_scope.clone()),
        ));
        let bridge = ProviderRefreshSource::new(erase(&adapter)).expect("valid bridge");

        bridge
            .fetch_required(exact_scope.clone(), CancellationToken::new())
            .await
            .expect("successful fetch");

        assert_eq!(
            adapter.observations(),
            [ObservedContext {
                scope: exact_scope,
                source: ProviderSource::Cli,
                cancelled_on_entry: false,
                provider_cache_bypass: false,
            }]
        );
    }

    #[tokio::test]
    async fn only_manual_runtime_refresh_bypasses_provider_local_success_caches() {
        let exact_scope = scope(ProviderId::Claude, "claude-primary", "ambient");
        let adapter = Arc::new(FakeAdapter::success(
            exact_scope.clone(),
            ProviderSource::OAuth,
            sample(exact_scope.clone()),
        ));
        let bridge = ProviderRefreshSource::new(erase(&adapter)).expect("valid bridge");

        bridge
            .fetch_required_with_trigger(
                exact_scope.clone(),
                CancellationToken::new(),
                RefreshTrigger::Periodic,
            )
            .await
            .expect("periodic fetch");
        bridge
            .fetch_required_with_trigger(
                exact_scope,
                CancellationToken::new(),
                RefreshTrigger::Manual,
            )
            .await
            .expect("manual fetch");

        let observations = adapter.observations();
        assert_eq!(observations.len(), 2);
        assert!(!observations[0].provider_cache_bypass);
        assert!(observations[1].provider_cache_bypass);
    }

    #[tokio::test]
    async fn already_cancelled_token_is_rejected_before_adapter_io() {
        let exact_scope = scope(ProviderId::Codex, "codex-primary", "pre-cancelled");
        let adapter = Arc::new(FakeAdapter::success(
            exact_scope.clone(),
            ProviderSource::OAuth,
            sample(exact_scope.clone()),
        ));
        let bridge = ProviderRefreshSource::new(erase(&adapter)).expect("valid bridge");
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = bridge
            .fetch_required(exact_scope, cancellation)
            .await
            .expect_err("pre-cancelled work must fail closed");

        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(adapter.call_count(), 0);
        assert!(adapter.observations().is_empty());
    }

    #[test]
    fn constructor_rejects_provider_and_source_mismatches() {
        let codex_scope = scope(ProviderId::Codex, "codex-primary", "account-three");
        let openai_adapter = Arc::new(FakeAdapter::success_with_descriptor(
            ProviderId::OpenAi,
            codex_scope.clone(),
            ProviderSource::ApiKey,
            sample(codex_scope.clone()),
        ));
        assert_eq!(
            ProviderRefreshSource::new(erase(&openai_adapter)).expect_err("provider mismatch"),
            ProviderRefreshBuildError::ProviderMismatch
        );

        let codex_adapter = Arc::new(FakeAdapter::success(
            codex_scope.clone(),
            ProviderSource::ConfigurableEndpoint,
            sample(codex_scope.clone()),
        ));
        assert_eq!(
            ProviderRefreshSource::new(erase(&codex_adapter)).expect_err("unsupported source"),
            ProviderRefreshBuildError::UnsupportedSource
        );
        assert_eq!(openai_adapter.call_count(), 0);
        assert_eq!(codex_adapter.call_count(), 0);
    }

    #[tokio::test]
    async fn runtime_scope_mismatch_is_rejected_before_adapter_io() {
        let registered_scope = scope(ProviderId::Codex, "codex-primary", "registered-account");
        let adapter = Arc::new(FakeAdapter::success(
            registered_scope.clone(),
            ProviderSource::OAuth,
            sample(registered_scope.clone()),
        ));
        let bridge = ProviderRefreshSource::new(erase(&adapter)).expect("valid bridge");
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = bridge
            .fetch_required(
                scope(ProviderId::Codex, "codex-primary", "other-account"),
                cancellation,
            )
            .await
            .expect_err("scope mismatch");

        assert_eq!(error.kind(), ErrorKind::Api);
        assert_eq!(adapter.call_count(), 0);
        assert!(adapter.observations().is_empty());
    }

    #[tokio::test]
    async fn runtime_cancellation_reaches_an_in_flight_adapter_fetch() {
        let exact_scope = scope(ProviderId::Codex, "codex-primary", "cancelled-account");
        let adapter = Arc::new(FakeAdapter::cancellation(
            exact_scope.clone(),
            ProviderSource::OAuth,
        ));
        let bridge = ProviderRefreshSource::new(erase(&adapter)).expect("valid bridge");
        let cancellation = CancellationToken::new();
        let fetch = tokio::spawn(bridge.fetch_required(exact_scope, cancellation.clone()));
        adapter.wait_until_called().await;

        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), fetch)
            .await
            .expect("cancelled adapter completed")
            .expect("fetch task")
            .expect_err("fake adapter reports cancellation");

        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(adapter.call_count(), 1);
    }

    #[tokio::test]
    async fn composite_codex_source_runs_auto_without_claiming_one_exact_source() {
        let exact_scope = scope(ProviderId::Codex, "codex-primary", "real-adapter");
        let expected = sample(exact_scope.clone());
        let settings = CodexCoordinatorSettings::new(
            CodexSourceMode::Auto,
            CodexAccountSelection::Ambient,
            false,
            None,
        )
        .expect("valid coordinator settings");
        let runner = Arc::new(SuccessfulCodexRunner {
            sample: expected.clone(),
            calls: AtomicUsize::new(0),
        });
        let coordinator = CodexCoordinator::new(exact_scope.clone(), settings, runner.clone());
        let bridge = CodexRefreshSource::new(coordinator).expect("composite Codex source");
        let actual = bridge
            .fetch_required(exact_scope, CancellationToken::new())
            .await
            .expect("automatic Codex fetch");

        assert_eq!(actual, expected);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn composite_codex_source_rejects_scope_and_pre_cancel_before_runner_io() {
        let exact_scope = scope(ProviderId::Codex, "codex-primary", "composite-guard");
        let runner = Arc::new(SuccessfulCodexRunner {
            sample: sample(exact_scope.clone()),
            calls: AtomicUsize::new(0),
        });
        let coordinator = CodexCoordinator::new(
            exact_scope.clone(),
            CodexCoordinatorSettings::new(
                CodexSourceMode::Auto,
                CodexAccountSelection::Ambient,
                false,
                None,
            )
            .expect("valid coordinator settings"),
            runner.clone(),
        );
        let bridge = CodexRefreshSource::new(coordinator).expect("composite Codex source");
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let wrong_scope = bridge
            .fetch_required(
                scope(ProviderId::Codex, "codex-primary", "other-account"),
                cancellation.clone(),
            )
            .await
            .expect_err("scope mismatch wins before cancellation");
        let cancelled = bridge
            .fetch_required(exact_scope, cancellation)
            .await
            .expect_err("exact pre-cancelled work stops before the runner");

        assert_eq!(wrong_scope.kind(), ErrorKind::Api);
        assert_eq!(cancelled.kind(), ErrorKind::Network);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn composite_codex_source_rejects_foreign_coordinator_and_redacts_debug() {
        let foreign_scope = scope(ProviderId::OpenAi, "openai-primary", "foreign-secret");
        let foreign = CodexCoordinator::new(
            foreign_scope.clone(),
            CodexCoordinatorSettings::new(
                CodexSourceMode::Auto,
                CodexAccountSelection::Ambient,
                false,
                None,
            )
            .expect("valid settings"),
            Arc::new(SuccessfulCodexRunner {
                sample: sample(foreign_scope),
                calls: AtomicUsize::new(0),
            }),
        );
        assert_eq!(
            CodexRefreshSource::new(foreign).expect_err("foreign coordinator"),
            ProviderRefreshBuildError::ProviderMismatch
        );

        let secret_scope = scope(ProviderId::Codex, "route-secret", "account-secret");
        let coordinator = CodexCoordinator::new(
            secret_scope.clone(),
            CodexCoordinatorSettings::new(
                CodexSourceMode::Auto,
                CodexAccountSelection::Ambient,
                false,
                None,
            )
            .expect("valid settings"),
            Arc::new(SuccessfulCodexRunner {
                sample: sample(secret_scope),
                calls: AtomicUsize::new(0),
            }),
        );
        let debug = format!(
            "{:?}",
            CodexRefreshSource::new(coordinator).expect("Codex source")
        );
        assert!(!debug.contains("route-secret"));
        assert!(!debug.contains("account-secret"));
    }

    #[test]
    fn debug_redacts_scope_and_adapter_details() {
        let secret_scope = scope(
            ProviderId::Codex,
            "route-secret-canary",
            "account-secret-canary",
        );
        let adapter = Arc::new(FakeAdapter::success(
            secret_scope.clone(),
            ProviderSource::OAuth,
            sample(secret_scope.clone()),
        ));
        let bridge = ProviderRefreshSource::new(erase(&adapter)).expect("valid bridge");

        let diagnostics = format!("{bridge:?}");
        assert!(diagnostics.contains("ProviderRefreshSource"));
        assert!(diagnostics.contains("OAuth"));
        for secret in [
            "route-secret-canary",
            "account-secret-canary",
            "adapter-secret-canary",
            "FakeAdapter",
        ] {
            assert!(!diagnostics.contains(secret));
        }
    }
}
