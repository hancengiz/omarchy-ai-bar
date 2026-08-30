//! Static provider metadata, sources, and first-run behavior.

use oab_domain::ProviderId;

use crate::capability::{CapabilitySet, ProviderCapability};

/// Provider-owned input mechanism selected for one account instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProviderSource {
    /// Host-attached key in an authorization or API-key header.
    ApiKey = 1 << 0,
    /// Exact approved configurable HTTP origin plus typed authentication.
    ConfigurableEndpoint = 1 << 1,
    /// User-supplied Cookie or Authorization capture.
    ManualCookie = 1 << 2,
    /// Isolated browser profile/session discovery.
    BrowserSession = 1 << 3,
    /// OAuth or device authorization.
    OAuth = 1 << 4,
    /// Bounded provider-owned command-line interface.
    Cli = 1 << 5,
    /// Read-only provider-owned local data.
    LocalData = 1 << 6,
    /// Signed cloud profile, workload, or service-account credentials.
    CloudCredentials = 1 << 7,
}

impl ProviderSource {
    const ALL: [Self; 8] = [
        Self::ApiKey,
        Self::ConfigurableEndpoint,
        Self::ManualCookie,
        Self::BrowserSession,
        Self::OAuth,
        Self::Cli,
        Self::LocalData,
        Self::CloudCredentials,
    ];

    /// Stable user-facing source label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::ConfigurableEndpoint => "Approved endpoint",
            Self::ManualCookie => "Manual session",
            Self::BrowserSession => "Browser session",
            Self::OAuth => "OAuth",
            Self::Cli => "Provider CLI",
            Self::LocalData => "Local provider data",
            Self::CloudCredentials => "Cloud credentials",
        }
    }
}

/// Compact immutable provider-source set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSet(u16);

impl SourceSet {
    const fn one(source: ProviderSource) -> Self {
        Self(source as u16)
    }

    const fn with(self, source: ProviderSource) -> Self {
        Self(self.0 | source as u16)
    }

    /// Reports whether a source is supported.
    #[must_use]
    pub const fn contains(self, source: ProviderSource) -> bool {
        self.0 & source as u16 != 0
    }

    /// Reports whether no source is declared.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Iterates sources in stable precedence-neutral declaration order.
    pub fn iter(self) -> impl Iterator<Item = ProviderSource> {
        ProviderSource::ALL
            .into_iter()
            .filter(move |source| self.contains(*source))
    }
}

/// First-run enablement behavior. Detection never performs a network request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultBehavior {
    /// Safe local detection may enable this provider.
    Detect,
    /// This provider remains disabled until explicitly configured.
    Disabled,
    /// Local detection is attempted and this provider is the no-signal fallback.
    Fallback,
}

/// Closed static descriptor for one first-party provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderDescriptor {
    /// Stable wire/config identifier.
    pub id: ProviderId,
    /// Stable display metadata.
    pub display_name: &'static str,
}

impl ProviderDescriptor {
    /// Normalized provider capabilities.
    #[must_use]
    pub const fn capabilities(self) -> CapabilitySet {
        capabilities_for(self.id)
    }

    /// Supported account-source mechanisms.
    #[must_use]
    pub const fn sources(self) -> SourceSet {
        sources_for(self.id)
    }

    /// First-run behavior without network probing.
    #[must_use]
    pub const fn default_behavior(self) -> DefaultBehavior {
        default_behavior_for(self.id)
    }
}

const fn default_behavior_for(id: ProviderId) -> DefaultBehavior {
    match id {
        ProviderId::Codex => DefaultBehavior::Fallback,
        ProviderId::Claude | ProviderId::Gemini | ProviderId::Antigravity => {
            DefaultBehavior::Detect
        }
        _ => DefaultBehavior::Disabled,
    }
}

const fn capabilities_for(id: ProviderId) -> CapabilitySet {
    let sources = sources_for(id);
    let mut capabilities = CapabilitySet::USAGE;
    if sources.contains(ProviderSource::ManualCookie)
        || sources.contains(ProviderSource::BrowserSession)
    {
        capabilities = capabilities.with(ProviderCapability::BrowserAuth);
    }
    if sources.contains(ProviderSource::OAuth) || sources.contains(ProviderSource::Cli) {
        capabilities = capabilities.with(ProviderCapability::LoginAction);
    }
    if sources.contains(ProviderSource::LocalData) {
        capabilities = capabilities.with(ProviderCapability::StorageReport);
    }
    match id {
        ProviderId::Codex
        | ProviderId::OpenAi
        | ProviderId::Claude
        | ProviderId::Gemini
        | ProviderId::OpenRouter => {
            capabilities = capabilities
                .with(ProviderCapability::Credits)
                .with(ProviderCapability::CostHistory);
        }
        ProviderId::Bedrock => {
            capabilities = capabilities.with(ProviderCapability::CostHistory);
        }
        _ => {}
    }
    match id {
        ProviderId::Codex | ProviderId::Claude | ProviderId::Gemini | ProviderId::Grok => {
            capabilities = capabilities.with(ProviderCapability::Sessions);
        }
        _ => {}
    }
    match id {
        ProviderId::Cursor | ProviderId::Factory | ProviderId::Augment => {
            capabilities = capabilities.with(ProviderCapability::Status);
        }
        _ => {}
    }
    capabilities
}

const fn sources_for(id: ProviderId) -> SourceSet {
    use ProviderId as Id;
    use ProviderSource as Source;

    match id {
        Id::OpenAi
        | Id::Fireworks
        | Id::DeepInfra
        | Id::Warp
        | Id::AiAnd
        | Id::IbmBob
        | Id::ClinePass
        | Id::Moonshot
        | Id::Synthetic
        | Id::Crof
        | Id::Venice
        | Id::Poe
        | Id::ZenMux
        | Id::Xai => SourceSet::one(Source::ApiKey),
        Id::AzureOpenAi
        | Id::ElevenLabs
        | Id::Deepgram
        | Id::Chutes
        | Id::Neuralwatt
        | Id::OpenRouter
        | Id::LlmProxy
        | Id::LiteLlm
        | Id::ClawRouter
        | Id::Sub2Api => SourceSet::one(Source::ConfigurableEndpoint).with(Source::ApiKey),
        Id::Wayfinder => SourceSet::one(Source::ConfigurableEndpoint),
        Id::Copilot => SourceSet::one(Source::OAuth),
        Id::Bedrock => SourceSet::one(Source::CloudCredentials),
        Id::Doubao => SourceSet::one(Source::CloudCredentials).with(Source::ApiKey),
        Id::VertexAi => SourceSet::one(Source::CloudCredentials).with(Source::Cli),
        Id::Amp | Id::Kilo | Id::Kiro | Id::JetBrains | Id::Codebuff => {
            SourceSet::one(Source::Cli).with(Source::LocalData)
        }
        Id::T3Chat
        | Id::Alibaba
        | Id::AlibabaTokenPlan
        | Id::QwenCloud
        | Id::OpenCode
        | Id::Devin
        | Id::MiniMax
        | Id::Manus
        | Id::Kimi
        | Id::Mimo
        | Id::Sakana
        | Id::Mistral
        | Id::CommandCode
        | Id::Qoder
        | Id::StepFun
        | Id::Perplexity
        | Id::LongCat
        | Id::ZoomMate
        | Id::Notion
        | Id::Abacus => SourceSet::one(Source::ManualCookie).with(Source::BrowserSession),
        Id::Codex | Id::Claude => SourceSet::one(Source::OAuth)
            .with(Source::Cli)
            .with(Source::LocalData)
            .with(Source::BrowserSession),
        Id::Gemini | Id::Antigravity => SourceSet::one(Source::OAuth)
            .with(Source::Cli)
            .with(Source::LocalData),
        Id::Grok => SourceSet::one(Source::ManualCookie)
            .with(Source::BrowserSession)
            .with(Source::LocalData),
        Id::Zai | Id::OpenCodeGo => SourceSet::one(Source::ConfigurableEndpoint)
            .with(Source::ApiKey)
            .with(Source::LocalData),
        Id::Factory => SourceSet::one(Source::OAuth).with(Source::BrowserSession),
        Id::Ollama => SourceSet::one(Source::ConfigurableEndpoint).with(Source::LocalData),
        Id::DeepSeek | Id::Groq => SourceSet::one(Source::ApiKey)
            .with(Source::ManualCookie)
            .with(Source::BrowserSession),
        Id::Zed => SourceSet::one(Source::LocalData).with(Source::ApiKey),
        Id::Augment | Id::Cursor | Id::Windsurf => SourceSet::one(Source::Cli)
            .with(Source::LocalData)
            .with(Source::ManualCookie)
            .with(Source::BrowserSession),
    }
}
