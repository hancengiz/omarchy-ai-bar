//! Side-effect-free production discovery for daemon-backed providers.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oab_domain::{
    AccountKey, AccountScope, ClassifiedError, PrivacyKey, ProviderId, ProviderInstanceId,
    Timestamp,
};
use oab_providers::browser_cookie::ChromiumCookieDecryptor;
use oab_providers::browser_profile::BrowserProfileDiscovery;
use oab_providers::context::ProviderAdapter;
use oab_providers::descriptor::ProviderSource;
use oab_providers::executable::resolve_executable;
use oab_providers::fixed_api::ApiKeyCredential;
use oab_providers::providers::abacus::AbacusProvider;
use oab_providers::providers::aiand::AiAndProvider;
use oab_providers::providers::alibaba::{AlibabaProvider, AlibabaRegion};
use oab_providers::providers::alibabatokenplan::{
    AlibabaTokenPlanCliSettings, AlibabaTokenPlanProvider, AlibabaTokenPlanRegion,
};
use oab_providers::providers::amp::AmpProvider;
use oab_providers::providers::antigravity::{AntigravityProvider, AntigravitySettings};
use oab_providers::providers::antigravity_cost::AntigravityHistoryRoots;
use oab_providers::providers::augment::{AugmentCliSettings, AugmentProvider};
use oab_providers::providers::azureopenai::{AzureOpenAiProvider, AzureOpenAiSettings};
use oab_providers::providers::bedrock::{BedrockProvider, BedrockSettings};
use oab_providers::providers::chutes::{ChutesProvider, ChutesSettings};
use oab_providers::providers::claude::{ClaudeProvider, ClaudeSettings, ClaudeSourceMode};
use oab_providers::providers::clawrouter::{ClawRouterProvider, ClawRouterSettings};
use oab_providers::providers::clinepass::ClinePassProvider;
use oab_providers::providers::codebuff::{CodebuffProvider, CodebuffSettings};
use oab_providers::providers::codex::CodexSourceMode;
use oab_providers::providers::codex_files::CodexCredentialPaths;
use oab_providers::providers::codex_provider::{
    CodexAccountSelection, CodexCoordinator, CodexCoordinatorSettings,
};
use oab_providers::providers::commandcode::CommandCodeProvider;
use oab_providers::providers::copilot::{
    CopilotBudgetEnrichment, CopilotCredentialOwner, CopilotProvider,
};
use oab_providers::providers::crof::CrofProvider;
use oab_providers::providers::cursor::CursorProvider;
use oab_providers::providers::deepgram::{DeepgramProvider, DeepgramSettings};
use oab_providers::providers::deepinfra::DeepInfraProvider;
use oab_providers::providers::deepseek::DeepSeekProvider;
use oab_providers::providers::devin::DevinProvider;
use oab_providers::providers::doubao::DoubaoProvider;
use oab_providers::providers::elevenlabs::ElevenLabsProvider;
use oab_providers::providers::factory::FactoryProvider;
use oab_providers::providers::fireworks::{FireworksCredential, FireworksProvider};
use oab_providers::providers::gemini::{GeminiProvider, GeminiSettings};
use oab_providers::providers::grok::{
    GrokBrowserProvider, GrokCookieSource, GrokProvider, GrokSettings, GrokSourceMode,
};
use oab_providers::providers::groq::{GroqProvider, GroqSettings};
use oab_providers::providers::ibmbob::{IBMBobProvider, IBMBobSettings};
use oab_providers::providers::jetbrains::{JetBrainsProvider, JetBrainsSettings};
use oab_providers::providers::kilo::{KiloProvider, KiloUsageScope};
use oab_providers::providers::kimi::KimiProvider;
use oab_providers::providers::kiro::{KiroCliSettings, KiroProvider};
use oab_providers::providers::litellm::{LiteLlmProvider, LiteLlmSettings};
use oab_providers::providers::llmproxy::{LlmProxyProvider, LlmProxySettings};
use oab_providers::providers::longcat::LongCatProvider;
use oab_providers::providers::manus::ManusProvider;
use oab_providers::providers::mimo::{MiMoLocalProvider, MiMoProvider};
use oab_providers::providers::minimax::{MiniMaxProvider, MiniMaxRegion};
use oab_providers::providers::mistral::MistralProvider;
use oab_providers::providers::moonshot::{MoonshotProvider, MoonshotSettings};
use oab_providers::providers::neuralwatt::{NeuralWattProvider, NeuralWattSettings};
use oab_providers::providers::notion::NotionProvider;
use oab_providers::providers::ollama::{OllamaProvider, OllamaSettings};
use oab_providers::providers::openai::{OpenAiCredential, OpenAiProvider};
use oab_providers::providers::opencode::OpenCodeProvider;
use oab_providers::providers::opencodego::{OpenCodeGoLocalProvider, OpenCodeGoProvider};
use oab_providers::providers::opencodego_cost::has_opencodego_local_usage;
use oab_providers::providers::openrouter::{OpenRouterProvider, OpenRouterSettings};
use oab_providers::providers::perplexity::PerplexityProvider;
use oab_providers::providers::poe::PoeProvider;
use oab_providers::providers::qoder::QoderProvider;
use oab_providers::providers::qwencloud::QwenCloudProvider;
use oab_providers::providers::sakana::SakanaProvider;
use oab_providers::providers::stepfun::StepFunProvider;
use oab_providers::providers::sub2api::{Sub2ApiProvider, Sub2ApiSettings};
use oab_providers::providers::synthetic::SyntheticProvider;
use oab_providers::providers::t3chat::T3ChatProvider;
use oab_providers::providers::venice::VeniceProvider;
use oab_providers::providers::vertexai::{VertexAiProvider, VertexSettings};
use oab_providers::providers::warp::WarpProvider;
use oab_providers::providers::wayfinder::{WayfinderProvider, WayfinderSettings};
use oab_providers::providers::windsurf::{WindsurfProvider, WindsurfSettings};
use oab_providers::providers::xai::{XaiCredential, XaiProvider};
use oab_providers::providers::zai::{ZaiProvider, ZaiSettings};
use oab_providers::providers::zed::{ZedProvider, ZedSettings};
use oab_providers::providers::zenmux::ZenMuxProvider;
use oab_providers::providers::zoommate::ZoomMateProvider;
use oab_runtime::actor::RefreshRegistration;
use oab_runtime::actor::RefreshSource;
use oab_storage::config::{AppConfig, ProviderSourceMode};
use thiserror::Error;

use crate::provider_refresh::{
    BrowserAdapterBuilder, CodexRefreshSource, ConfiguredProvider, LazyAdapterBuilder,
    LazyProviderRefreshSource, ProviderRefreshBuildError, ProviderRefreshSource,
};

#[derive(Clone, Copy)]
struct LazyRegistrationSpec {
    provider: ProviderId,
    source: ProviderSource,
    builder: LazyAdapterBuilder,
    browser_fallback: Option<BrowserAdapterBuilder>,
}

const LAZY_PROVIDER_SPECS: [LazyRegistrationSpec; 57] = [
    lazy_spec(ProviderId::Zai, ProviderSource::ApiKey, build_zai),
    lazy_spec(ProviderId::OpenAi, ProviderSource::ApiKey, build_openai),
    lazy_spec(
        ProviderId::AzureOpenAi,
        ProviderSource::ConfigurableEndpoint,
        build_azure_openai,
    ),
    lazy_spec(
        ProviderId::Fireworks,
        ProviderSource::ApiKey,
        build_fireworks,
    ),
    lazy_spec(ProviderId::Moonshot, ProviderSource::ApiKey, build_moonshot),
    lazy_spec(
        ProviderId::OpenRouter,
        ProviderSource::ApiKey,
        build_openrouter,
    ),
    lazy_spec(ProviderId::Deepgram, ProviderSource::ApiKey, build_deepgram),
    lazy_spec(ProviderId::Chutes, ProviderSource::ApiKey, build_chutes),
    lazy_spec(
        ProviderId::Neuralwatt,
        ProviderSource::ApiKey,
        build_neuralwatt,
    ),
    lazy_spec(ProviderId::IbmBob, ProviderSource::ApiKey, build_ibm_bob),
    lazy_spec(ProviderId::Xai, ProviderSource::ApiKey, build_xai),
    lazy_spec(
        ProviderId::LiteLlm,
        ProviderSource::ConfigurableEndpoint,
        build_litellm,
    ),
    lazy_spec(
        ProviderId::LlmProxy,
        ProviderSource::ConfigurableEndpoint,
        build_llm_proxy,
    ),
    lazy_spec(
        ProviderId::Sub2Api,
        ProviderSource::ConfigurableEndpoint,
        build_sub2api,
    ),
    lazy_spec(
        ProviderId::Synthetic,
        ProviderSource::ApiKey,
        build_synthetic,
    ),
    lazy_spec(
        ProviderId::DeepInfra,
        ProviderSource::ApiKey,
        build_deepinfra,
    ),
    lazy_spec(ProviderId::Venice, ProviderSource::ApiKey, build_venice),
    lazy_spec(ProviderId::Poe, ProviderSource::ApiKey, build_poe),
    lazy_spec(ProviderId::ZenMux, ProviderSource::ApiKey, build_zenmux),
    lazy_spec(ProviderId::AiAnd, ProviderSource::ApiKey, build_aiand),
    lazy_spec(ProviderId::Warp, ProviderSource::ApiKey, build_warp),
    lazy_spec(
        ProviderId::ClinePass,
        ProviderSource::ApiKey,
        build_clinepass,
    ),
    lazy_spec(
        ProviderId::ElevenLabs,
        ProviderSource::ApiKey,
        build_elevenlabs,
    ),
    lazy_spec(
        ProviderId::Bedrock,
        ProviderSource::CloudCredentials,
        build_bedrock,
    ),
    lazy_spec(
        ProviderId::VertexAi,
        ProviderSource::CloudCredentials,
        build_vertexai,
    ),
    lazy_spec(
        ProviderId::JetBrains,
        ProviderSource::LocalData,
        build_jetbrains,
    ),
    lazy_spec(
        ProviderId::Wayfinder,
        ProviderSource::ConfigurableEndpoint,
        build_wayfinder,
    ),
    lazy_spec(
        ProviderId::ClawRouter,
        ProviderSource::ConfigurableEndpoint,
        build_clawrouter,
    ),
    lazy_spec(ProviderId::Crof, ProviderSource::ApiKey, build_crof),
    lazy_spec(ProviderId::Kiro, ProviderSource::Cli, build_kiro),
    lazy_spec(
        ProviderId::AlibabaTokenPlan,
        ProviderSource::Cli,
        build_alibaba_token_plan,
    ),
    browser_lazy_spec(
        ProviderId::Abacus,
        ProviderSource::ManualCookie,
        build_abacus,
        build_abacus_browser,
    ),
    browser_lazy_spec(
        ProviderId::CommandCode,
        ProviderSource::ManualCookie,
        build_command_code,
        build_command_code_browser,
    ),
    browser_lazy_spec(
        ProviderId::Devin,
        ProviderSource::ManualCookie,
        build_devin,
        build_devin_browser,
    ),
    lazy_spec(
        ProviderId::LongCat,
        ProviderSource::ManualCookie,
        build_longcat,
    ),
    lazy_spec(ProviderId::Manus, ProviderSource::ManualCookie, build_manus),
    browser_lazy_spec(
        ProviderId::Mistral,
        ProviderSource::ManualCookie,
        build_mistral,
        build_mistral_browser,
    ),
    browser_lazy_spec(
        ProviderId::Notion,
        ProviderSource::ManualCookie,
        build_notion,
        build_notion_browser,
    ),
    browser_lazy_spec(
        ProviderId::OpenCode,
        ProviderSource::ManualCookie,
        build_opencode,
        build_opencode_browser,
    ),
    browser_lazy_spec(
        ProviderId::Perplexity,
        ProviderSource::ManualCookie,
        build_perplexity,
        build_perplexity_browser,
    ),
    lazy_spec(ProviderId::Qoder, ProviderSource::ManualCookie, build_qoder),
    browser_lazy_spec(
        ProviderId::QwenCloud,
        ProviderSource::ManualCookie,
        build_qwencloud,
        build_qwencloud_browser,
    ),
    lazy_spec(
        ProviderId::Sakana,
        ProviderSource::ManualCookie,
        build_sakana,
    ),
    lazy_spec(
        ProviderId::StepFun,
        ProviderSource::ManualCookie,
        build_stepfun,
    ),
    browser_lazy_spec(
        ProviderId::T3Chat,
        ProviderSource::ManualCookie,
        build_t3chat,
        build_t3chat_browser,
    ),
    lazy_spec(
        ProviderId::ZoomMate,
        ProviderSource::ManualCookie,
        build_zoommate,
    ),
    lazy_spec(ProviderId::Copilot, ProviderSource::OAuth, build_copilot),
    lazy_spec(ProviderId::DeepSeek, ProviderSource::ApiKey, build_deepseek),
    lazy_spec(ProviderId::Groq, ProviderSource::ApiKey, build_groq),
    lazy_spec(
        ProviderId::OpenCodeGo,
        ProviderSource::ApiKey,
        build_opencodego,
    ),
    lazy_spec(ProviderId::Zed, ProviderSource::ApiKey, build_zed),
    lazy_spec(ProviderId::Augment, ProviderSource::Cli, build_augment),
    lazy_spec(ProviderId::Gemini, ProviderSource::OAuth, build_gemini),
    lazy_spec(ProviderId::Factory, ProviderSource::ApiKey, build_factory),
    lazy_spec(
        ProviderId::Cursor,
        ProviderSource::ManualCookie,
        build_cursor,
    ),
    lazy_spec(
        ProviderId::Antigravity,
        ProviderSource::OAuth,
        build_antigravity,
    ),
    lazy_spec(
        ProviderId::Windsurf,
        ProviderSource::LocalData,
        build_windsurf,
    ),
];

const fn lazy_spec(
    provider: ProviderId,
    source: ProviderSource,
    builder: LazyAdapterBuilder,
) -> LazyRegistrationSpec {
    LazyRegistrationSpec {
        provider,
        source,
        builder,
        browser_fallback: None,
    }
}

const fn browser_lazy_spec(
    provider: ProviderId,
    source: ProviderSource,
    builder: LazyAdapterBuilder,
    browser_fallback: BrowserAdapterBuilder,
) -> LazyRegistrationSpec {
    LazyRegistrationSpec {
        provider,
        source,
        builder,
        browser_fallback: Some(browser_fallback),
    }
}

fn selected_lazy_specs(environment: &BTreeMap<String, String>) -> [LazyRegistrationSpec; 9] {
    [
        lazy_spec(
            ProviderId::Codebuff,
            choose_source(
                environment_has_value(environment, "CODEBUFF_API_KEY"),
                ProviderSource::ApiKey,
                ProviderSource::LocalData,
            ),
            build_codebuff,
        ),
        browser_lazy_spec(
            ProviderId::Amp,
            choose_source(
                environment_has_value(environment, "AMP_API_KEY"),
                ProviderSource::ApiKey,
                ProviderSource::Cli,
            ),
            build_amp,
            build_amp_browser,
        ),
        lazy_spec(ProviderId::Doubao, doubao_source(environment), build_doubao),
        lazy_spec(
            ProviderId::Kilo,
            choose_source(
                environment_has_value(environment, "KILO_API_KEY"),
                ProviderSource::ApiKey,
                ProviderSource::Cli,
            ),
            build_kilo,
        ),
        lazy_spec(
            ProviderId::Alibaba,
            choose_source(
                environment_has_any_value(environment, ALIBABA_API_KEYS),
                ProviderSource::ApiKey,
                ProviderSource::ManualCookie,
            ),
            build_alibaba,
        ),
        browser_lazy_spec(
            ProviderId::MiniMax,
            choose_source(
                environment_has_any_value(environment, MINIMAX_API_KEYS),
                ProviderSource::ApiKey,
                ProviderSource::ManualCookie,
            ),
            build_minimax,
            build_minimax_browser,
        ),
        browser_lazy_spec(
            ProviderId::Kimi,
            kimi_source(environment),
            build_kimi,
            build_kimi_browser,
        ),
        lazy_spec(
            ProviderId::Mimo,
            choose_source(
                environment_has_value(environment, "OMARCHY_AI_BAR_MIMO_COOKIE"),
                ProviderSource::ManualCookie,
                ProviderSource::LocalData,
            ),
            build_mimo,
        ),
        lazy_spec(
            ProviderId::Ollama,
            choose_source(
                environment_has_value(environment, "OLLAMA_API_URL"),
                ProviderSource::ConfigurableEndpoint,
                ProviderSource::ApiKey,
            ),
            build_ollama,
        ),
    ]
}

const ALIBABA_API_KEYS: &[&str] = &[
    "ALIBABA_CODING_PLAN_API_KEY",
    "ALIBABA_QWEN_API_KEY",
    "DASHSCOPE_API_KEY",
];
const MINIMAX_API_KEYS: &[&str] = &["MINIMAX_CODING_API_KEY", "MINIMAX_API_KEY"];

const fn choose_source(
    condition: bool,
    when_true: ProviderSource,
    when_false: ProviderSource,
) -> ProviderSource {
    if condition { when_true } else { when_false }
}

fn kimi_source(environment: &BTreeMap<String, String>) -> ProviderSource {
    if environment_has_value(environment, "KIMI_CODE_API_KEY") {
        choose_source(
            environment_has_value(environment, "KIMI_CODE_BASE_URL"),
            ProviderSource::ConfigurableEndpoint,
            ProviderSource::ApiKey,
        )
    } else if environment_has_any_value(environment, &["KIMI_MANUAL_COOKIE", "KIMI_AUTH_TOKEN"]) {
        ProviderSource::ManualCookie
    } else {
        ProviderSource::Cli
    }
}

fn doubao_source(environment: &BTreeMap<String, String>) -> ProviderSource {
    let access_key = environment_has_any_value(
        environment,
        &[
            "VOLCENGINE_ACCESS_KEY_ID",
            "VOLCENGINE_ACCESS_KEY",
            "VOLC_ACCESSKEY",
            "DOUBAO_ACCESS_KEY_ID",
        ],
    );
    let secret_key = environment_has_any_value(
        environment,
        &[
            "VOLCENGINE_SECRET_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
            "VOLCENGINE_ACCESS_KEY_SECRET",
            "VOLC_SECRETKEY",
            "DOUBAO_SECRET_ACCESS_KEY",
        ],
    );
    if access_key && secret_key {
        ProviderSource::CloudCredentials
    } else if environment_has_any_value(
        environment,
        &["ARK_API_KEY", "VOLCENGINE_API_KEY", "DOUBAO_API_KEY"],
    ) {
        ProviderSource::ApiKey
    } else {
        ProviderSource::Cli
    }
}

/// A provider registration and the exact scope used for runtime actions.
pub(crate) struct ProductionProviders {
    pub(crate) registrations: Vec<RefreshRegistration>,
    pub(crate) scopes: Vec<AccountScope>,
}

fn select_enabled_providers(
    config: Option<&AppConfig>,
    detected_providers: &BTreeSet<ProviderId>,
    registrations: Vec<RefreshRegistration>,
    scopes: Vec<AccountScope>,
) -> ProductionProviders {
    let (registrations, scopes) = registrations
        .into_iter()
        .zip(scopes)
        .filter(|(_registration, scope)| {
            provider_enabled(
                config,
                scope.provider(),
                detected_providers.contains(&scope.provider()),
            )
        })
        .unzip();
    ProductionProviders {
        registrations,
        scopes,
    }
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
    #[error("provider runtime binding is invalid")]
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

fn discover_codex(
    config: Option<&AppConfig>,
    app_data_dir: &Path,
    privacy_key: &PrivacyKey,
    home: &Path,
    child_environment: &BTreeMap<String, String>,
) -> Result<(Vec<RefreshRegistration>, Vec<AccountScope>, bool), ProviderBootstrapError> {
    let paths = CodexCredentialPaths::resolve(
        home,
        env::var_os("CODEX_HOME").as_deref(),
        env::var_os("XDG_DATA_HOME").as_deref(),
    )
    .map_err(|_| ProviderBootstrapError::CredentialPaths)?;
    let codex_history_root = paths.native_root().to_path_buf();
    let executable_override = env::var("OMARCHY_AI_BAR_CODEX_EXECUTABLE").ok();
    let executable = resolve_executable(
        "codex",
        executable_override.as_deref(),
        env::var_os("PATH").as_deref(),
        &[],
    )
    .map_err(|_| ProviderBootstrapError::Executable)?;
    let managed_accounts = crate::codex_accounts::configured_managed_accounts(config);
    let detected = executable.is_some() || !managed_accounts.is_empty();
    let default_instance =
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?;
    let ambient_scope = AccountScope::new(
        ProviderId::Codex,
        default_instance.clone(),
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let codex_source = resolve_codex_source(crate::provider_config::provider_source(
        config,
        ProviderId::Codex,
    ))?;
    let allow_external_oauth = crate::provider_config::provider_toggle(
        config,
        ProviderId::Codex,
        "external_oauth_sources",
    )
    .unwrap_or(false);
    let settings = CodexCoordinatorSettings::new(
        codex_source,
        CodexAccountSelection::Ambient,
        allow_external_oauth,
        None,
    )
    .map_err(|_| ProviderBootstrapError::Coordinator)?
    .with_reset_credit_key(privacy_key.clone());
    let coordinator = CodexCoordinator::production(
        ambient_scope.clone(),
        settings,
        paths,
        executable.clone(),
        child_environment,
    )
    .map_err(|_| ProviderBootstrapError::Coordinator)?;
    let source =
        Arc::new(CodexRefreshSource::new(coordinator)?.with_history_root(codex_history_root));
    let mut registrations = vec![RefreshRegistration::new(ambient_scope.clone(), source)];
    let mut scopes = vec![ambient_scope];

    for account in managed_accounts
        .into_iter()
        .filter(|account| account.enabled)
    {
        let managed_home = app_data_dir
            .join("codex/managed-accounts")
            .join(account.id.as_str());
        let managed_paths = CodexCredentialPaths::resolve(
            home,
            Some(managed_home.as_os_str()),
            env::var_os("XDG_DATA_HOME").as_deref(),
        )
        .map_err(|_| ProviderBootstrapError::CredentialPaths)?;
        let managed_scope =
            AccountScope::new(ProviderId::Codex, default_instance.clone(), account.id);
        let settings = CodexCoordinatorSettings::new(
            codex_source,
            CodexAccountSelection::Profile,
            false,
            None,
        )
        .map_err(|_| ProviderBootstrapError::Coordinator)?
        .with_reset_credit_key(privacy_key.clone());
        let coordinator = CodexCoordinator::production(
            managed_scope.clone(),
            settings,
            managed_paths,
            executable.clone(),
            child_environment,
        )
        .map_err(|_| ProviderBootstrapError::Coordinator)?;
        let source =
            Arc::new(CodexRefreshSource::new(coordinator)?.with_history_root(managed_home));
        registrations.push(RefreshRegistration::new(managed_scope.clone(), source));
        scopes.push(managed_scope);
    }
    Ok((registrations, scopes, detected))
}

/// Discovers production providers without accessing provider networks or
/// starting provider child processes. Explicit environment credentials win;
/// missing manual-session values may be hydrated from desktop Secret Service.
pub(crate) fn discover(
    config: Option<&AppConfig>,
    app_data_dir: &std::path::Path,
    privacy_key: &PrivacyKey,
) -> Result<ProductionProviders, ProviderBootstrapError> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ProviderBootstrapError::MissingHome)?;
    let mut child_environment = unicode_environment();
    crate::credentials::hydrate_environment(&mut child_environment);
    crate::provider_config::apply_provider_route_environment(config, &mut child_environment);
    let (mut registrations, mut scopes, codex_detected) =
        discover_codex(config, app_data_dir, privacy_key, &home, &child_environment)?;

    let mut detected_providers = BTreeSet::new();
    if codex_detected {
        detected_providers.insert(ProviderId::Codex);
    }
    let claude_source = resolve_claude_source(crate::provider_config::provider_source(
        config,
        ProviderId::Claude,
    ))?;
    let (scope, source, detected) = discover_claude(&child_environment, &home, claude_source)?;
    if detected {
        detected_providers.insert(ProviderId::Claude);
    }
    registrations.push(RefreshRegistration::new(scope.clone(), source));
    scopes.push(scope);
    validate_grok_source(crate::provider_config::provider_source(
        config,
        ProviderId::Grok,
    ))?;
    let (scope, source, detected) = discover_grok(&child_environment, &home)?;
    if detected {
        detected_providers.insert(ProviderId::Grok);
    }
    registrations.push(RefreshRegistration::new(scope.clone(), source));
    scopes.push(scope);
    let lazy_environment = Arc::new(child_environment);
    for spec in LAZY_PROVIDER_SPECS
        .into_iter()
        .chain(selected_lazy_specs(&lazy_environment))
    {
        let spec = resolve_lazy_source(spec, &lazy_environment);
        let (scope, source, detected) = discover_lazy(spec, Arc::clone(&lazy_environment))?;
        if detected {
            detected_providers.insert(scope.provider());
        }
        registrations.push(RefreshRegistration::new(scope.clone(), source));
        scopes.push(scope);
    }

    Ok(select_enabled_providers(
        config,
        &detected_providers,
        registrations,
        scopes,
    ))
}

fn resolve_codex_source(
    source: Option<ProviderSourceMode>,
) -> Result<CodexSourceMode, ProviderBootstrapError> {
    match source.unwrap_or(ProviderSourceMode::Auto) {
        ProviderSourceMode::Auto => Ok(CodexSourceMode::Auto),
        ProviderSourceMode::Pat => Ok(CodexSourceMode::Pat),
        ProviderSourceMode::Oauth | ProviderSourceMode::Api | ProviderSourceMode::ApiKey => {
            Ok(CodexSourceMode::OAuth)
        }
        ProviderSourceMode::Cli => Ok(CodexSourceMode::Cli),
        ProviderSourceMode::Web
        | ProviderSourceMode::ConfigurableEndpoint
        | ProviderSourceMode::ManualCookie
        | ProviderSourceMode::BrowserSession
        | ProviderSourceMode::Local
        | ProviderSourceMode::CloudCredentials => Err(ProviderBootstrapError::Coordinator),
    }
}

fn resolve_claude_source(
    source: Option<ProviderSourceMode>,
) -> Result<ClaudeSourceMode, ProviderBootstrapError> {
    match source.unwrap_or(ProviderSourceMode::Auto) {
        ProviderSourceMode::Auto => Ok(ClaudeSourceMode::Auto),
        ProviderSourceMode::Oauth => Ok(ClaudeSourceMode::OAuth),
        ProviderSourceMode::Cli => Ok(ClaudeSourceMode::Cli),
        _ => Err(ProviderBootstrapError::Claude),
    }
}

fn validate_grok_source(source: Option<ProviderSourceMode>) -> Result<(), ProviderBootstrapError> {
    match source {
        None
        | Some(
            ProviderSourceMode::Auto
            | ProviderSourceMode::Cli
            | ProviderSourceMode::Oauth
            | ProviderSourceMode::Web,
        ) => Ok(()),
        _ => Err(ProviderBootstrapError::Grok),
    }
}

fn grok_source_mode(environment: &BTreeMap<String, String>) -> GrokSourceMode {
    match environment
        .get("OMARCHY_AI_BAR_GROK_USAGE_SOURCE")
        .map(String::as_str)
    {
        Some("cli") => GrokSourceMode::Cli,
        Some("oauth") => GrokSourceMode::OAuth,
        Some("web") => GrokSourceMode::Web,
        _ => GrokSourceMode::Auto,
    }
}

fn grok_cookie_source(environment: &BTreeMap<String, String>) -> GrokCookieSource {
    match environment
        .get("OMARCHY_AI_BAR_GROK_COOKIE_SOURCE")
        .map(String::as_str)
    {
        Some("manual") => GrokCookieSource::Manual,
        Some("off") => GrokCookieSource::Off,
        _ => GrokCookieSource::Auto,
    }
}

fn provider_enabled(config: Option<&AppConfig>, provider: ProviderId, detected: bool) -> bool {
    config
        .and_then(|config| {
            config
                .providers
                .iter()
                .find(|route| route.id == provider && route.instance_id.as_str() == "default")
        })
        .map_or(detected, |route| route.enabled)
}

fn discover_claude(
    environment: &BTreeMap<String, String>,
    home: &std::path::Path,
    source_mode: ClaudeSourceMode,
) -> Result<
    (
        AccountScope,
        Arc<dyn oab_runtime::actor::RefreshSource>,
        bool,
    ),
    ProviderBootstrapError,
> {
    let explicit_credential = environment_has_any_value(
        environment,
        &[
            "OMARCHY_AI_BAR_CLAUDE_OAUTH_TOKEN",
            "CLAUDE_OAUTH_TOKEN",
            "ANTHROPIC_OAUTH_TOKEN",
        ],
    );
    let config_root = environment
        .get("CLAUDE_SECURESTORAGE_CONFIG_DIR")
        .or_else(|| environment.get("CLAUDE_CONFIG_DIR"))
        .filter(|value| !value.is_empty())
        .map_or_else(|| home.join(".claude"), PathBuf::from);
    let config_root = if config_root.is_absolute() {
        config_root
    } else {
        home.join(config_root)
    };
    let credential_file = config_root.join(".credentials.json");
    let executable = resolve_executable(
        "claude",
        environment
            .get("OMARCHY_AI_BAR_CLAUDE_EXECUTABLE")
            .map(String::as_str),
        environment.get("PATH").map(std::ffi::OsStr::new),
        &[],
    )
    .map_err(|_| ProviderBootstrapError::Claude)?;
    let cli_detected = executable.is_some();
    let detected = explicit_credential || credential_file.is_file() || cli_detected;
    let scope = AccountScope::new(
        ProviderId::Claude,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let settings = ClaudeSettings::resolve(environment, home)
        .map_err(|_| ProviderBootstrapError::Claude)?
        .with_source(source_mode, executable);
    let adapter =
        ClaudeProvider::new(scope.clone(), settings).map_err(|_| ProviderBootstrapError::Claude)?;
    let bound_source = match source_mode {
        ClaudeSourceMode::Cli => ProviderSource::Cli,
        ClaudeSourceMode::Auto | ClaudeSourceMode::OAuth => ProviderSource::OAuth,
    };
    let adapter = Arc::new(ConfiguredProvider::new(
        adapter,
        scope.clone(),
        bound_source,
    ));
    let source =
        Arc::new(ProviderRefreshSource::new(adapter)?.with_claude_history_root(config_root));
    Ok((scope, source, detected))
}

fn discover_grok(
    environment: &BTreeMap<String, String>,
    home: &std::path::Path,
) -> Result<(AccountScope, Arc<dyn RefreshSource>, bool), ProviderBootstrapError> {
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
    let grok_root = environment
        .get("GROK_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .map_or_else(
            || home.join(".grok"),
            |root| {
                if root.is_absolute() {
                    root
                } else if let Ok(relative) = root.strip_prefix("~") {
                    home.join(relative)
                } else {
                    home.join(root)
                }
            },
        );
    let detected = executable.is_some()
        || environment_has_any_value(
            environment,
            &["OMARCHY_AI_BAR_GROK_OAUTH_TOKEN", "GROK_OAUTH_TOKEN"],
        )
        || grok_root.join("auth.json").is_file()
        || environment_has_value(environment, "OMARCHY_AI_BAR_GROK_COOKIE");
    let scope = AccountScope::new(
        ProviderId::Grok,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let source_mode = grok_source_mode(environment);
    let cookie_source = grok_cookie_source(environment);
    let bound_source = match (source_mode, cookie_source) {
        (GrokSourceMode::OAuth, _) => ProviderSource::OAuth,
        (GrokSourceMode::Web, GrokCookieSource::Manual) => ProviderSource::ManualCookie,
        (GrokSourceMode::Web, GrokCookieSource::Auto | GrokCookieSource::Off) => {
            ProviderSource::BrowserSession
        }
        (GrokSourceMode::Auto | GrokSourceMode::Cli, _) => ProviderSource::Cli,
    };
    let mut source = LazyProviderRefreshSource::new(
        scope.clone(),
        bound_source,
        Arc::new(environment.clone()),
        build_grok,
    )?
    .with_grok_history_root(grok_root);
    if cookie_source == GrokCookieSource::Auto
        && matches!(source_mode, GrokSourceMode::Auto | GrokSourceMode::Web)
    {
        source = source.with_browser_fallback(build_grok_browser)?;
    }
    let source = Arc::new(source);
    Ok((scope, source, detected))
}

fn discover_lazy(
    spec: LazyRegistrationSpec,
    environment: Arc<BTreeMap<String, String>>,
) -> Result<(AccountScope, Arc<dyn RefreshSource>, bool), ProviderBootstrapError> {
    let scope = AccountScope::new(
        spec.provider,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let detected = lazy_provider_detected(spec, &scope, &environment);
    let copilot_history_root = (spec.provider == ProviderId::Copilot)
        .then(|| {
            environment
                .get("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".copilot"))
        })
        .flatten();
    let opencodego_history_root = (spec.provider == ProviderId::OpenCodeGo)
        .then(|| opencode_data_root(&environment))
        .flatten();
    let vertex_history_root = (spec.provider == ProviderId::VertexAi)
        .then(|| claude_data_root(&environment))
        .flatten();
    let cursor_history_root = (spec.provider == ProviderId::Cursor)
        .then(|| cursor_cache_root(&environment))
        .flatten();
    let antigravity_history_roots = (spec.provider == ProviderId::Antigravity)
        .then(|| antigravity_history_roots(&environment))
        .flatten();
    let mut source =
        LazyProviderRefreshSource::new(scope.clone(), spec.source, environment, spec.builder)?;
    if let Some(browser_fallback) = spec.browser_fallback {
        source = source.with_browser_fallback(browser_fallback)?;
    }
    if let Some(history_root) = copilot_history_root {
        source = source.with_copilot_history_root(history_root);
    }
    if let Some(history_root) = opencodego_history_root {
        source = source.with_opencodego_history_root(history_root);
    }
    if let Some(history_root) = vertex_history_root {
        source = source.with_vertex_history_root(history_root);
    }
    if let Some(history_root) = cursor_history_root {
        source = source.with_cursor_history_root(history_root);
    }
    if let Some(history_roots) = antigravity_history_roots {
        source = source.with_antigravity_history_roots(history_roots);
    }
    let source = Arc::new(source);
    Ok((scope, source, detected))
}

fn lazy_provider_detected(
    spec: LazyRegistrationSpec,
    scope: &AccountScope,
    environment: &BTreeMap<String, String>,
) -> bool {
    if (spec.builder)(scope.clone(), environment).is_err() {
        return false;
    }
    match spec.provider {
        ProviderId::OpenCodeGo => {
            environment_has_value(environment, "OPENCODE_API_KEY")
                || opencode_data_root(environment)
                    .as_deref()
                    .is_some_and(has_opencodego_local_usage)
        }
        ProviderId::Wayfinder => environment_has_value(environment, "WAYFINDER_GATEWAY_URL"),
        ProviderId::Mimo => {
            if environment_has_value(environment, "OMARCHY_AI_BAR_MIMO_COOKIE") {
                return true;
            }
            local_data_path(
                environment,
                "MIMO_LOCAL_USAGE_PATH",
                "mimo-local-usage.json",
            )
            .is_some_and(|path| path.is_file())
        }
        ProviderId::Windsurf => {
            windsurf_database_path(environment).is_some_and(|path| path.is_file())
        }
        ProviderId::JetBrains => jetbrains_configuration_detected(environment),
        _ => true,
    }
}

fn resolve_lazy_source(
    mut spec: LazyRegistrationSpec,
    environment: &BTreeMap<String, String>,
) -> LazyRegistrationSpec {
    if spec.provider == ProviderId::OpenCodeGo
        && !environment_has_value(environment, "OPENCODE_API_KEY")
        && opencode_data_root(environment)
            .as_deref()
            .is_some_and(has_opencodego_local_usage)
    {
        spec.source = ProviderSource::LocalData;
    }
    spec
}

fn opencode_data_root(environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    environment
        .get("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            environment
                .get("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .map(|root| root.join("opencode"))
}

fn claude_data_root(environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    let home = environment
        .get("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    let root = environment
        .get("CLAUDE_SECURESTORAGE_CONFIG_DIR")
        .or_else(|| environment.get("CLAUDE_CONFIG_DIR"))
        .filter(|value| !value.is_empty())
        .map_or_else(|| home.join(".claude"), PathBuf::from);
    Some(if root.is_absolute() {
        root
    } else {
        home.join(root)
    })
}

fn cursor_cache_root(environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    if let Some(root) = environment
        .get("TOKSCALE_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return Some(root.join("cursor-cache"));
    }
    environment
        .get("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".config/tokscale/cursor-cache"))
}

fn antigravity_history_roots(
    environment: &BTreeMap<String, String>,
) -> Option<AntigravityHistoryRoots> {
    let home = environment
        .get("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    let gemini_home = environment
        .get("GEMINI_CLI_HOME")
        .filter(|value| !value.is_empty())
        .map_or_else(|| home.join(".gemini"), PathBuf::from);
    let app = gemini_home.join("antigravity");
    let config = environment
        .get("TOKSCALE_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map_or_else(|| home.join(".config/tokscale"), PathBuf::from);
    Some(AntigravityHistoryRoots {
        database_roots: vec![
            gemini_home.join("antigravity-cli/conversations"),
            app.clone(),
            app.join("conversations"),
        ],
        cache_root: config.join("antigravity-cache/sessions"),
    })
}

fn local_data_path(
    environment: &BTreeMap<String, String>,
    override_name: &str,
    file_name: &str,
) -> Option<PathBuf> {
    if let Some(path) = environment
        .get(override_name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(PathBuf::from(path));
    }
    environment
        .get("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            environment
                .get("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .map(|root| root.join("omarchy-ai-bar").join(file_name))
}

fn windsurf_database_path(environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    environment
        .get("WINDSURF_DATA_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            environment
                .get("XDG_CONFIG_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .or_else(|| {
                    environment
                        .get("HOME")
                        .filter(|value| !value.is_empty())
                        .map(|home| PathBuf::from(home).join(".config"))
                })
                .map(|root| root.join("Windsurf/User/globalStorage"))
        })
        .map(|root| root.join("state.vscdb"))
}

fn jetbrains_configuration_detected(environment: &BTreeMap<String, String>) -> bool {
    if let Some(path) = environment
        .get("OMARCHY_AI_BAR_JETBRAINS_IDE_PATH")
        .filter(|value| !value.is_empty())
    {
        return PathBuf::from(path).is_dir();
    }
    let Some(home) = environment.get("HOME").filter(|value| !value.is_empty()) else {
        return false;
    };
    let config = environment
        .get("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map_or_else(|| PathBuf::from(home).join(".config"), PathBuf::from);
    let data = environment
        .get("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map_or_else(|| PathBuf::from(home).join(".local/share"), PathBuf::from);
    [
        config.join("JetBrains"),
        config.join("Google"),
        data.join("JetBrains"),
    ]
    .into_iter()
    .any(|path| path.is_dir())
}

fn build_zai(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(ZaiProvider::new(
        scope,
        ZaiSettings::resolve(environment)?,
    )?))
}

fn build_openai(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(OpenAiProvider::new(
        scope,
        OpenAiCredential::resolve(environment)?,
        30,
    )?))
}

fn build_azure_openai(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(AzureOpenAiProvider::new(
        scope,
        AzureOpenAiSettings::resolve(environment)?,
    )?))
}

fn build_fireworks(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(FireworksProvider::new(
        scope,
        FireworksCredential::resolve(environment)?,
    )?))
}

fn build_moonshot(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(MoonshotProvider::new(
        scope,
        MoonshotSettings::resolve(environment)?,
    )?))
}

fn build_openrouter(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(OpenRouterProvider::new(
        scope,
        OpenRouterSettings::resolve(environment)?,
    )?))
}

fn build_deepgram(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(DeepgramProvider::new(
        scope,
        DeepgramSettings::resolve(environment)?,
    )?))
}

fn build_chutes(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(ChutesProvider::new(
        scope,
        ChutesSettings::resolve(environment)?,
    )?))
}

fn build_neuralwatt(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(NeuralWattProvider::new(
        scope,
        NeuralWattSettings::resolve(environment)?,
    )?))
}

fn build_ibm_bob(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(IBMBobProvider::new(
        scope,
        IBMBobSettings::resolve(environment)?,
    )?))
}

fn build_xai(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(XaiProvider::new(
        scope,
        XaiCredential::resolve(environment)?,
    )?))
}

fn build_litellm(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(LiteLlmProvider::new(
        scope,
        LiteLlmSettings::resolve(environment)?,
    )?))
}

fn build_llm_proxy(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(LlmProxyProvider::new(
        scope,
        LlmProxySettings::resolve(environment)?,
    )?))
}

fn build_sub2api(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(Sub2ApiProvider::new(
        scope,
        Sub2ApiSettings::resolve(environment)?,
    )?))
}

fn build_synthetic(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(SyntheticProvider::new(
        scope,
        SyntheticProvider::resolve_credential(environment)?,
    )?))
}

fn build_deepinfra(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(DeepInfraProvider::new(
        scope,
        DeepInfraProvider::resolve_credential(environment)?,
    )?))
}

fn build_deepseek(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(DeepSeekProvider::new(
        scope,
        DeepSeekProvider::resolve_credential(environment)?,
    )?))
}

fn build_groq(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(GroqProvider::new(
        scope,
        GroqSettings::resolve(environment)?,
    )?))
}

fn build_opencodego(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    if environment_has_value(environment, "OPENCODE_API_KEY") {
        return Ok(Box::new(OpenCodeGoProvider::new(
            scope,
            OpenCodeGoProvider::resolve_credential(environment)?,
        )?));
    }
    let root = opencode_data_root(environment)
        .ok_or_else(|| ClassifiedError::new(oab_domain::ErrorKind::MissingCredential))?;
    Ok(Box::new(OpenCodeGoLocalProvider::new(scope, root)?))
}

fn build_zed(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(ZedProvider::new(
        scope,
        ZedSettings::resolve(environment)?,
    )?))
}

fn build_augment(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(AugmentProvider::new(
        scope,
        AugmentCliSettings::resolve(environment)?,
    )))
}

fn build_gemini(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(GeminiProvider::new(
        scope,
        GeminiSettings::resolve(environment)?,
    )?))
}

fn build_factory(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(FactoryProvider::new(
        scope,
        FactoryProvider::resolve_credential(environment)?,
    )?))
}

fn build_cursor(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(CursorProvider::new_manual(
        scope,
        required_environment_value(environment, "OMARCHY_AI_BAR_CURSOR_COOKIE")?,
    )?))
}

fn build_antigravity(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(AntigravityProvider::new(
        scope,
        AntigravitySettings::resolve(environment)?,
    )?))
}

fn build_windsurf(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(WindsurfProvider::new(
        scope,
        WindsurfSettings::resolve(environment)?,
    )))
}

fn build_venice(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(VeniceProvider::new(
        scope,
        VeniceProvider::resolve_credential(environment)?,
    )?))
}

fn build_poe(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(PoeProvider::new(
        scope,
        PoeProvider::resolve_credential(environment)?,
    )?))
}

fn build_zenmux(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(ZenMuxProvider::new(
        scope,
        ZenMuxProvider::resolve_credential(environment)?,
    )?))
}

fn build_aiand(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(AiAndProvider::new(
        scope,
        AiAndProvider::resolve_credential(environment)?,
    )?))
}

fn build_warp(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(WarpProvider::new(
        scope,
        WarpProvider::resolve_credential(environment)?,
    )?))
}

fn build_clinepass(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(ClinePassProvider::new(
        scope,
        ClinePassProvider::resolve_credential(environment)?,
    )?))
}

fn build_elevenlabs(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(ElevenLabsProvider::new(
        scope,
        ApiKeyCredential::resolve(environment, &["ELEVENLABS_API_KEY"])?,
    )?))
}

fn build_bedrock(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(BedrockProvider::new(
        scope,
        BedrockSettings::resolve(environment)?,
    )?))
}

fn build_vertexai(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(VertexAiProvider::new(
        scope,
        VertexSettings::resolve(environment)?,
    )?))
}

fn build_jetbrains(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(JetBrainsProvider::new(
        scope,
        JetBrainsSettings::resolve(environment)?,
    )?))
}

fn build_wayfinder(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(WayfinderProvider::new(
        scope,
        WayfinderSettings::resolve(environment)?,
    )?))
}

fn build_clawrouter(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(ClawRouterProvider::new(
        scope,
        ClawRouterSettings::resolve(environment)?,
    )?))
}

fn build_crof(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(CrofProvider::new(
        scope,
        CrofProvider::resolve_credential(environment)?,
    )?))
}

fn build_codebuff(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(CodebuffProvider::new(
        scope,
        CodebuffSettings::resolve(environment)?,
    )?))
}

fn build_kiro(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(KiroProvider::new(
        scope,
        KiroCliSettings::resolve(environment)?,
    )?))
}

fn build_alibaba_token_plan(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(AlibabaTokenPlanProvider::new_cli(
        scope,
        AlibabaTokenPlanRegion::InternationalTeam,
        AlibabaTokenPlanCliSettings::resolve(environment)?,
    )?))
}

fn build_amp(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let source = if environment_has_value(environment, "AMP_API_KEY") {
        ProviderSource::ApiKey
    } else {
        ProviderSource::Cli
    };
    Ok(Box::new(AmpProvider::resolve(scope, source, environment)?))
}

fn build_grok(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let executable = resolve_executable(
        "grok",
        environment
            .get("OMARCHY_AI_BAR_GROK_EXECUTABLE")
            .map(String::as_str),
        environment.get("PATH").map(std::ffi::OsStr::new),
        &[],
    )
    .map_err(|_| ClassifiedError::new(oab_domain::ErrorKind::Api))?;
    let settings = GrokSettings::new(executable, environment.clone())
        .with_source_mode(grok_source_mode(environment))
        .with_cookie_source(grok_cookie_source(environment));
    Ok(Box::new(GrokProvider::new(scope, settings)?))
}

fn build_grok_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(GrokBrowserProvider::new(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_amp_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(AmpProvider::new_browser(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_doubao(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let source = if environment_has_any_value(
        environment,
        &[
            "VOLCENGINE_ACCESS_KEY_ID",
            "VOLCENGINE_ACCESS_KEY",
            "VOLC_ACCESSKEY",
            "DOUBAO_ACCESS_KEY_ID",
        ],
    ) && environment_has_any_value(
        environment,
        &[
            "VOLCENGINE_SECRET_ACCESS_KEY",
            "VOLCENGINE_SECRET_KEY",
            "VOLCENGINE_ACCESS_KEY_SECRET",
            "VOLC_SECRETKEY",
            "DOUBAO_SECRET_ACCESS_KEY",
        ],
    ) {
        ProviderSource::CloudCredentials
    } else if environment_has_any_value(
        environment,
        &["ARK_API_KEY", "VOLCENGINE_API_KEY", "DOUBAO_API_KEY"],
    ) {
        ProviderSource::ApiKey
    } else {
        ProviderSource::Cli
    };
    Ok(Box::new(DoubaoProvider::resolve(
        scope,
        source,
        environment,
    )?))
}

fn build_kilo(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let source = if environment_has_value(environment, "KILO_API_KEY") {
        ProviderSource::ApiKey
    } else {
        ProviderSource::Cli
    };
    Ok(Box::new(KiloProvider::resolve(
        scope,
        source,
        environment,
        KiloUsageScope::Personal,
    )?))
}

macro_rules! manual_provider_builder {
    ($builder:ident, $provider:ty, $environment_key:literal) => {
        fn $builder(
            scope: AccountScope,
            environment: &BTreeMap<String, String>,
        ) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
            Ok(Box::new(<$provider>::new_manual(
                scope,
                required_environment_value(environment, $environment_key)?,
            )?))
        }
    };
}

manual_provider_builder!(build_abacus, AbacusProvider, "OMARCHY_AI_BAR_ABACUS_COOKIE");
manual_provider_builder!(
    build_command_code,
    CommandCodeProvider,
    "OMARCHY_AI_BAR_COMMANDCODE_COOKIE"
);
manual_provider_builder!(
    build_longcat,
    LongCatProvider,
    "OMARCHY_AI_BAR_LONGCAT_COOKIE"
);
manual_provider_builder!(build_manus, ManusProvider, "OMARCHY_AI_BAR_MANUS_COOKIE");
manual_provider_builder!(
    build_mistral,
    MistralProvider,
    "OMARCHY_AI_BAR_MISTRAL_COOKIE"
);
manual_provider_builder!(build_notion, NotionProvider, "OMARCHY_AI_BAR_NOTION_COOKIE");
manual_provider_builder!(
    build_perplexity,
    PerplexityProvider,
    "OMARCHY_AI_BAR_PERPLEXITY_COOKIE"
);
manual_provider_builder!(build_qoder, QoderProvider, "OMARCHY_AI_BAR_QODER_COOKIE");
manual_provider_builder!(
    build_qwencloud,
    QwenCloudProvider,
    "OMARCHY_AI_BAR_QWENCLOUD_COOKIE"
);
manual_provider_builder!(build_sakana, SakanaProvider, "OMARCHY_AI_BAR_SAKANA_COOKIE");
manual_provider_builder!(
    build_stepfun,
    StepFunProvider,
    "OMARCHY_AI_BAR_STEPFUN_COOKIE"
);
manual_provider_builder!(build_t3chat, T3ChatProvider, "OMARCHY_AI_BAR_T3CHAT_COOKIE");
manual_provider_builder!(
    build_zoommate,
    ZoomMateProvider,
    "OMARCHY_AI_BAR_ZOOMMATE_COOKIE"
);

fn build_abacus_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(AbacusProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_command_code_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(CommandCodeProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_notion_browser(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(NotionProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
        environment
            .get("OMARCHY_AI_BAR_NOTION_WORKSPACE")
            .map(String::as_str),
    )?))
}

fn build_t3chat_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(T3ChatProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_mistral_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(MistralProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_perplexity_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(PerplexityProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_qwencloud_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(QwenCloudProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_devin(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(DevinProvider::new_manual(
        scope,
        required_environment_value(environment, "OMARCHY_AI_BAR_DEVIN_TOKEN")?,
        environment
            .get("OMARCHY_AI_BAR_DEVIN_ORGANIZATION")
            .map(String::as_str),
    )?))
}

fn build_devin_browser(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    _decryptor: &dyn ChromiumCookieDecryptor,
    _now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(DevinProvider::new_browser(
        scope,
        discovery,
        environment
            .get("OMARCHY_AI_BAR_DEVIN_ORGANIZATION")
            .map(String::as_str),
    )?))
}

fn build_opencode(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(OpenCodeProvider::new_manual(
        scope,
        required_environment_value(environment, "OMARCHY_AI_BAR_OPENCODE_COOKIE")?,
        environment
            .get("OMARCHY_AI_BAR_OPENCODE_WORKSPACE")
            .map(String::as_str),
    )?))
}

fn build_opencode_browser(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(OpenCodeProvider::new_browser_from_discovery(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
        environment
            .get("OMARCHY_AI_BAR_OPENCODE_WORKSPACE")
            .map(String::as_str),
    )?))
}

fn build_alibaba(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let provider = if environment_has_any_value(
        environment,
        &[
            "ALIBABA_CODING_PLAN_API_KEY",
            "ALIBABA_QWEN_API_KEY",
            "DASHSCOPE_API_KEY",
        ],
    ) {
        AlibabaProvider::new_api_key(
            scope,
            AlibabaRegion::International,
            required_first_environment_value(
                environment,
                &[
                    "ALIBABA_CODING_PLAN_API_KEY",
                    "ALIBABA_QWEN_API_KEY",
                    "DASHSCOPE_API_KEY",
                ],
            )?,
        )?
    } else {
        AlibabaProvider::new_manual(
            scope,
            AlibabaRegion::International,
            required_environment_value(environment, "OMARCHY_AI_BAR_ALIBABA_COOKIE")?,
        )?
    };
    Ok(Box::new(provider))
}

fn build_minimax(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let provider =
        if environment_has_any_value(environment, &["MINIMAX_CODING_API_KEY", "MINIMAX_API_KEY"]) {
            MiniMaxProvider::new_api_key(
                scope,
                MiniMaxRegion::Global,
                required_first_environment_value(
                    environment,
                    &["MINIMAX_CODING_API_KEY", "MINIMAX_API_KEY"],
                )?,
            )?
        } else {
            MiniMaxProvider::from_manual_environment(scope, MiniMaxRegion::Global, environment)?
        };
    Ok(Box::new(provider))
}

fn build_minimax_browser(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(
        MiniMaxProvider::new_browser_with_environment_and_decryptor(
            scope,
            MiniMaxRegion::Global,
            environment,
            discovery,
            now.as_offset_date_time(),
            decryptor,
        )?,
    ))
}

fn build_copilot(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let credential_owner = match environment
        .get(crate::credentials::COPILOT_CREDENTIAL_OWNER_ENVIRONMENT)
        .map(String::as_str)
    {
        Some(crate::credentials::COPILOT_CREDENTIAL_OWNER_APPLICATION) => {
            CopilotCredentialOwner::Application
        }
        Some(crate::credentials::COPILOT_CREDENTIAL_OWNER_EXPLICIT_ENVIRONMENT) => {
            CopilotCredentialOwner::Environment
        }
        _ => CopilotCredentialOwner::Unspecified,
    };
    let mut provider = CopilotProvider::new_with_credential_owner(
        scope,
        CopilotProvider::resolve_credential(environment)?,
        environment
            .get("OMARCHY_AI_BAR_COPILOT_ENTERPRISE_HOST")
            .map(String::as_str),
        credential_owner,
    )?;
    if copilot_budget_extras_enabled(environment)
        && environment
            .get("OMARCHY_AI_BAR_COPILOT_BUDGET_COOKIE_SOURCE")
            .is_some_and(|source| source == "manual")
        && let Some(cookie) = environment
            .get("OMARCHY_AI_BAR_COPILOT_BUDGET_COOKIE")
            .map(String::as_str)
            .map(str::trim)
            .filter(|cookie| !cookie.is_empty())
        && let Ok(enrichment) = CopilotBudgetEnrichment::manual(cookie)
    {
        provider = provider.with_budget_enrichment(enrichment);
    }
    Ok(Box::new(provider))
}

fn copilot_budget_extras_enabled(environment: &BTreeMap<String, String>) -> bool {
    environment
        .get("OMARCHY_AI_BAR_COPILOT_BUDGET_EXTRAS")
        .map(String::as_str)
        .is_some_and(|value| matches!(value, "1" | "true" | "yes" | "on"))
}

fn build_kimi(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    let provider = if environment_has_value(environment, "KIMI_CODE_API_KEY") {
        KimiProvider::new_api(scope, environment)?
    } else if environment_has_any_value(environment, &["KIMI_MANUAL_COOKIE", "KIMI_AUTH_TOKEN"]) {
        KimiProvider::new_manual_from_environment(scope, environment)?
    } else {
        KimiProvider::new_cli(
            scope,
            environment,
            oab_providers::normalize::system_timestamp()?,
        )?
    };
    Ok(Box::new(provider))
}

fn build_kimi_browser(
    scope: AccountScope,
    _environment: &BTreeMap<String, String>,
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: Timestamp,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(KimiProvider::new_browser(
        scope,
        discovery,
        decryptor,
        now.as_offset_date_time(),
    )?))
}

fn build_mimo(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    if environment_has_value(environment, "OMARCHY_AI_BAR_MIMO_COOKIE") {
        return Ok(Box::new(MiMoProvider::new_manual(
            scope,
            required_environment_value(environment, "OMARCHY_AI_BAR_MIMO_COOKIE")?,
        )?));
    }
    Ok(Box::new(MiMoLocalProvider::resolve(scope, environment)?))
}

fn build_ollama(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(OllamaProvider::new(
        scope,
        OllamaSettings::resolve(environment)?,
    )?))
}

fn environment_has_value(environment: &BTreeMap<String, String>, name: &str) -> bool {
    environment
        .get(name)
        .is_some_and(|value| !value.trim().trim_matches(['\'', '"']).is_empty())
}

fn environment_has_any_value(environment: &BTreeMap<String, String>, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| environment_has_value(environment, name))
}

fn required_environment_value<'a>(
    environment: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, ClassifiedError> {
    environment
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| oab_domain::ClassifiedError::new(oab_domain::ErrorKind::MissingCredential))
}

fn required_first_environment_value<'a>(
    environment: &'a BTreeMap<String, String>,
    names: &[&str],
) -> Result<&'a str, ClassifiedError> {
    names
        .iter()
        .find_map(|name| required_environment_value(environment, name).ok())
        .ok_or_else(|| oab_domain::ClassifiedError::new(oab_domain::ErrorKind::MissingCredential))
}

fn unicode_environment() -> BTreeMap<String, String> {
    env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_source_configuration_maps_only_supported_runtime_modes() {
        for (configured, expected) in [
            (None, CodexSourceMode::Auto),
            (Some(ProviderSourceMode::Auto), CodexSourceMode::Auto),
            (Some(ProviderSourceMode::Pat), CodexSourceMode::Pat),
            (Some(ProviderSourceMode::Oauth), CodexSourceMode::OAuth),
            (Some(ProviderSourceMode::Api), CodexSourceMode::OAuth),
            (Some(ProviderSourceMode::ApiKey), CodexSourceMode::OAuth),
            (Some(ProviderSourceMode::Cli), CodexSourceMode::Cli),
        ] {
            assert_eq!(
                resolve_codex_source(configured).expect("supported Codex source"),
                expected
            );
        }
        for unsupported in [
            ProviderSourceMode::Web,
            ProviderSourceMode::ConfigurableEndpoint,
            ProviderSourceMode::ManualCookie,
            ProviderSourceMode::BrowserSession,
            ProviderSourceMode::Local,
            ProviderSourceMode::CloudCredentials,
        ] {
            assert!(resolve_codex_source(Some(unsupported)).is_err());
        }
    }

    #[test]
    fn flagship_sources_reject_settings_the_runtime_would_ignore() {
        for (configured, expected) in [
            (None, ClaudeSourceMode::Auto),
            (Some(ProviderSourceMode::Auto), ClaudeSourceMode::Auto),
            (Some(ProviderSourceMode::Oauth), ClaudeSourceMode::OAuth),
            (Some(ProviderSourceMode::Cli), ClaudeSourceMode::Cli),
        ] {
            assert_eq!(
                resolve_claude_source(configured).expect("supported Claude source"),
                expected
            );
        }
        for unsupported in [
            ProviderSourceMode::Api,
            ProviderSourceMode::ApiKey,
            ProviderSourceMode::Pat,
            ProviderSourceMode::Web,
            ProviderSourceMode::ConfigurableEndpoint,
            ProviderSourceMode::ManualCookie,
            ProviderSourceMode::BrowserSession,
            ProviderSourceMode::Local,
            ProviderSourceMode::CloudCredentials,
        ] {
            assert!(resolve_claude_source(Some(unsupported)).is_err());
        }

        assert!(validate_grok_source(None).is_ok());
        assert!(validate_grok_source(Some(ProviderSourceMode::Auto)).is_ok());
        assert!(validate_grok_source(Some(ProviderSourceMode::Cli)).is_ok());
        assert!(validate_grok_source(Some(ProviderSourceMode::Oauth)).is_ok());
        assert!(validate_grok_source(Some(ProviderSourceMode::Web)).is_ok());
        assert!(validate_grok_source(Some(ProviderSourceMode::Api)).is_err());
    }

    #[test]
    fn grok_source_and_cookie_routes_are_closed_and_default_to_auto() {
        assert_eq!(grok_source_mode(&BTreeMap::new()), GrokSourceMode::Auto);
        assert_eq!(
            grok_source_mode(&BTreeMap::from([(
                "OMARCHY_AI_BAR_GROK_USAGE_SOURCE".to_owned(),
                "oauth".to_owned(),
            )])),
            GrokSourceMode::OAuth
        );
        assert_eq!(
            grok_cookie_source(&BTreeMap::from([(
                "OMARCHY_AI_BAR_GROK_COOKIE_SOURCE".to_owned(),
                "manual".to_owned(),
            )])),
            GrokCookieSource::Manual
        );
    }

    #[test]
    fn copilot_budget_enrichment_requires_an_explicit_true_flag() {
        for value in ["1", "true", "yes", "on"] {
            assert!(copilot_budget_extras_enabled(&BTreeMap::from([(
                "OMARCHY_AI_BAR_COPILOT_BUDGET_EXTRAS".to_owned(),
                value.to_owned(),
            )])));
        }
        for value in ["", "0", "false", "TRUE", "other"] {
            assert!(!copilot_budget_extras_enabled(&BTreeMap::from([(
                "OMARCHY_AI_BAR_COPILOT_BUDGET_EXTRAS".to_owned(),
                value.to_owned(),
            )])));
        }
    }

    #[test]
    fn unspecified_provider_follows_detection_and_explicit_setting_wins() {
        assert!(!provider_enabled(None, ProviderId::Claude, false));
        assert!(provider_enabled(None, ProviderId::Claude, true));

        let config = AppConfig {
            schema_version: oab_storage::config::CURRENT_SCHEMA_VERSION,
            providers: vec![oab_storage::config::ProviderConfig {
                id: ProviderId::Claude,
                instance_id: ProviderInstanceId::new("default").expect("default instance"),
                enabled: false,
                endpoint: None,
                config_path: None,
                options: oab_storage::config::ProviderOptions::default(),
                accounts: Vec::new(),
            }],
            provider_order: vec![ProviderId::Claude],
        };
        assert!(!provider_enabled(Some(&config), ProviderId::Claude, true));
        assert!(!provider_enabled(Some(&config), ProviderId::Codex, false));
    }

    #[test]
    fn direct_browser_adapters_are_registered_as_ordered_fallbacks() {
        let environment = BTreeMap::new();
        let selected = selected_lazy_specs(&environment);

        for provider in [ProviderId::Amp, ProviderId::Kimi, ProviderId::MiniMax] {
            let spec = selected
                .iter()
                .find(|spec| spec.provider == provider)
                .expect("selected provider spec");
            assert!(spec.browser_fallback.is_some(), "{provider:?}");
        }

        for provider in [
            ProviderId::Abacus,
            ProviderId::CommandCode,
            ProviderId::Devin,
            ProviderId::Mistral,
            ProviderId::Notion,
            ProviderId::OpenCode,
            ProviderId::Perplexity,
            ProviderId::QwenCloud,
            ProviderId::T3Chat,
        ] {
            let spec = LAZY_PROVIDER_SPECS
                .iter()
                .find(|spec| spec.provider == provider)
                .expect("browser provider spec");
            assert_eq!(spec.source, ProviderSource::ManualCookie, "{provider:?}");
            assert!(spec.browser_fallback.is_some(), "{provider:?}");
        }
    }
}
