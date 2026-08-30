//! Generic bridge from one configured provider adapter to runtime refresh work.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use oab_domain::{AccountScope, ClassifiedError, ErrorKind, ProviderId, UsageSample};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::normalize::system_timestamp;
use oab_providers::providers::codex_provider::{CodexCoordinator, CodexCoordinatorError};
use oab_runtime::actor::{RefreshFuture, RefreshSource};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

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
        })
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
}

impl Debug for ProviderRefreshSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRefreshSource")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("adapter", &"<opaque>")
            .finish()
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
        })
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedContext {
        scope: AccountScope,
        source: ProviderSource,
        cancelled_on_entry: bool,
    }

    enum FakeBehavior {
        Success(Box<UsageSample>),
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
                });
            self.entered.notify_one();

            match &self.behavior {
                FakeBehavior::Success(sample) => {
                    let sample = sample.as_ref().clone();
                    Box::pin(async move { Ok(sample) })
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
            }]
        );
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
