//! Side-effect-free production discovery for daemon-backed providers.

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use oab_domain::{AccountKey, AccountScope, ClassifiedError, ProviderId, ProviderInstanceId};
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
use oab_providers::providers::azureopenai::{AzureOpenAiProvider, AzureOpenAiSettings};
use oab_providers::providers::bedrock::{BedrockProvider, BedrockSettings};
use oab_providers::providers::chutes::{ChutesProvider, ChutesSettings};
use oab_providers::providers::claude::{ClaudeProvider, ClaudeSettings};
use oab_providers::providers::clawrouter::{ClawRouterProvider, ClawRouterSettings};
use oab_providers::providers::clinepass::ClinePassProvider;
use oab_providers::providers::codebuff::{CodebuffProvider, CodebuffSettings};
use oab_providers::providers::codex::CodexSourceMode;
use oab_providers::providers::codex_files::CodexCredentialPaths;
use oab_providers::providers::codex_provider::{
    CodexAccountSelection, CodexCoordinator, CodexCoordinatorSettings,
};
use oab_providers::providers::commandcode::CommandCodeProvider;
use oab_providers::providers::copilot::CopilotProvider;
use oab_providers::providers::crof::CrofProvider;
use oab_providers::providers::deepgram::{DeepgramProvider, DeepgramSettings};
use oab_providers::providers::deepinfra::DeepInfraProvider;
use oab_providers::providers::deepseek::DeepSeekProvider;
use oab_providers::providers::devin::DevinProvider;
use oab_providers::providers::doubao::DoubaoProvider;
use oab_providers::providers::elevenlabs::ElevenLabsProvider;
use oab_providers::providers::fireworks::{FireworksCredential, FireworksProvider};
use oab_providers::providers::grok::{GrokProvider, GrokSettings};
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
use oab_providers::providers::xai::{XaiCredential, XaiProvider};
use oab_providers::providers::zai::{ZaiProvider, ZaiSettings};
use oab_providers::providers::zenmux::ZenMuxProvider;
use oab_providers::providers::zoommate::ZoomMateProvider;
use oab_runtime::actor::RefreshRegistration;
use oab_runtime::actor::RefreshSource;
use thiserror::Error;

use crate::provider_refresh::{
    CodexRefreshSource, ConfiguredProvider, LazyAdapterBuilder, LazyProviderRefreshSource,
    ProviderRefreshBuildError, ProviderRefreshSource,
};

#[derive(Clone, Copy)]
struct LazyRegistrationSpec {
    provider: ProviderId,
    source: ProviderSource,
    builder: LazyAdapterBuilder,
}

const LAZY_PROVIDER_SPECS: [LazyRegistrationSpec; 49] = [
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
    lazy_spec(
        ProviderId::Abacus,
        ProviderSource::ManualCookie,
        build_abacus,
    ),
    lazy_spec(
        ProviderId::CommandCode,
        ProviderSource::ManualCookie,
        build_command_code,
    ),
    lazy_spec(ProviderId::Devin, ProviderSource::ManualCookie, build_devin),
    lazy_spec(
        ProviderId::LongCat,
        ProviderSource::ManualCookie,
        build_longcat,
    ),
    lazy_spec(ProviderId::Manus, ProviderSource::ManualCookie, build_manus),
    lazy_spec(
        ProviderId::Mistral,
        ProviderSource::ManualCookie,
        build_mistral,
    ),
    lazy_spec(
        ProviderId::Notion,
        ProviderSource::ManualCookie,
        build_notion,
    ),
    lazy_spec(
        ProviderId::OpenCode,
        ProviderSource::ManualCookie,
        build_opencode,
    ),
    lazy_spec(
        ProviderId::Perplexity,
        ProviderSource::ManualCookie,
        build_perplexity,
    ),
    lazy_spec(ProviderId::Qoder, ProviderSource::ManualCookie, build_qoder),
    lazy_spec(
        ProviderId::QwenCloud,
        ProviderSource::ManualCookie,
        build_qwencloud,
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
    lazy_spec(
        ProviderId::T3Chat,
        ProviderSource::ManualCookie,
        build_t3chat,
    ),
    lazy_spec(
        ProviderId::ZoomMate,
        ProviderSource::ManualCookie,
        build_zoommate,
    ),
    lazy_spec(ProviderId::Copilot, ProviderSource::OAuth, build_copilot),
    lazy_spec(ProviderId::DeepSeek, ProviderSource::ApiKey, build_deepseek),
    lazy_spec(ProviderId::Groq, ProviderSource::ApiKey, build_groq),
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
        lazy_spec(
            ProviderId::Amp,
            choose_source(
                environment_has_value(environment, "AMP_API_KEY"),
                ProviderSource::ApiKey,
                ProviderSource::Cli,
            ),
            build_amp,
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
        lazy_spec(
            ProviderId::MiniMax,
            choose_source(
                environment_has_any_value(environment, MINIMAX_API_KEYS),
                ProviderSource::ApiKey,
                ProviderSource::ManualCookie,
            ),
            build_minimax,
        ),
        lazy_spec(ProviderId::Kimi, kimi_source(environment), build_kimi),
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

/// Discovers production providers without reading credentials,
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
    let lazy_environment = Arc::new(child_environment);
    for spec in LAZY_PROVIDER_SPECS
        .into_iter()
        .chain(selected_lazy_specs(&lazy_environment))
    {
        let (scope, source) = discover_lazy(spec, Arc::clone(&lazy_environment))?;
        registrations.push(RefreshRegistration::new(scope.clone(), source));
        scopes.push(scope);
    }

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

fn discover_lazy(
    spec: LazyRegistrationSpec,
    environment: Arc<BTreeMap<String, String>>,
) -> Result<(AccountScope, Arc<dyn RefreshSource>), ProviderBootstrapError> {
    let scope = AccountScope::new(
        spec.provider,
        ProviderInstanceId::new("default").map_err(|_| ProviderBootstrapError::Identity)?,
        AccountKey::new("ambient").map_err(|_| ProviderBootstrapError::Identity)?,
    );
    let source = Arc::new(LazyProviderRefreshSource::new(
        scope.clone(),
        spec.source,
        environment,
        spec.builder,
    )?);
    Ok((scope, source))
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

fn build_copilot(
    scope: AccountScope,
    environment: &BTreeMap<String, String>,
) -> Result<Box<dyn ProviderAdapter>, ClassifiedError> {
    Ok(Box::new(CopilotProvider::new(
        scope,
        CopilotProvider::resolve_credential(environment)?,
        environment
            .get("OMARCHY_AI_BAR_COPILOT_ENTERPRISE_HOST")
            .map(String::as_str),
    )?))
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
