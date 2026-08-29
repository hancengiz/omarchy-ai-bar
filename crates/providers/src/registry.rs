use oab_domain::ProviderId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub id: ProviderId,
    pub display_name: &'static str,
}

pub const PROVIDERS: [ProviderMetadata; 69] = [
    ProviderMetadata {
        id: ProviderId::Codex,
        display_name: "Codex",
    },
    ProviderMetadata {
        id: ProviderId::OpenAi,
        display_name: "OpenAI",
    },
    ProviderMetadata {
        id: ProviderId::AzureOpenAi,
        display_name: "Azure OpenAI",
    },
    ProviderMetadata {
        id: ProviderId::Claude,
        display_name: "Claude",
    },
    ProviderMetadata {
        id: ProviderId::ClinePass,
        display_name: "ClinePass",
    },
    ProviderMetadata {
        id: ProviderId::Cursor,
        display_name: "Cursor",
    },
    ProviderMetadata {
        id: ProviderId::OpenCode,
        display_name: "OpenCode",
    },
    ProviderMetadata {
        id: ProviderId::OpenCodeGo,
        display_name: "OpenCode Go",
    },
    ProviderMetadata {
        id: ProviderId::Alibaba,
        display_name: "Alibaba Coding Plan",
    },
    ProviderMetadata {
        id: ProviderId::AlibabaTokenPlan,
        display_name: "Alibaba Token Plan",
    },
    ProviderMetadata {
        id: ProviderId::QwenCloud,
        display_name: "Qwen Cloud",
    },
    ProviderMetadata {
        id: ProviderId::Factory,
        display_name: "Droid",
    },
    ProviderMetadata {
        id: ProviderId::Fireworks,
        display_name: "Fireworks",
    },
    ProviderMetadata {
        id: ProviderId::Gemini,
        display_name: "Gemini",
    },
    ProviderMetadata {
        id: ProviderId::Antigravity,
        display_name: "Antigravity",
    },
    ProviderMetadata {
        id: ProviderId::Copilot,
        display_name: "Copilot",
    },
    ProviderMetadata {
        id: ProviderId::Devin,
        display_name: "Devin",
    },
    ProviderMetadata {
        id: ProviderId::Zai,
        display_name: "z.ai",
    },
    ProviderMetadata {
        id: ProviderId::MiniMax,
        display_name: "MiniMax",
    },
    ProviderMetadata {
        id: ProviderId::Manus,
        display_name: "Manus",
    },
    ProviderMetadata {
        id: ProviderId::Kimi,
        display_name: "Kimi Code",
    },
    ProviderMetadata {
        id: ProviderId::Kilo,
        display_name: "Kilo",
    },
    ProviderMetadata {
        id: ProviderId::Kiro,
        display_name: "Kiro",
    },
    ProviderMetadata {
        id: ProviderId::VertexAi,
        display_name: "Vertex AI",
    },
    ProviderMetadata {
        id: ProviderId::Augment,
        display_name: "Augment",
    },
    ProviderMetadata {
        id: ProviderId::JetBrains,
        display_name: "JetBrains AI",
    },
    ProviderMetadata {
        id: ProviderId::Moonshot,
        display_name: "Moonshot",
    },
    ProviderMetadata {
        id: ProviderId::Amp,
        display_name: "Amp",
    },
    ProviderMetadata {
        id: ProviderId::T3Chat,
        display_name: "T3 Chat",
    },
    ProviderMetadata {
        id: ProviderId::Ollama,
        display_name: "Ollama",
    },
    ProviderMetadata {
        id: ProviderId::Synthetic,
        display_name: "Synthetic",
    },
    ProviderMetadata {
        id: ProviderId::OpenRouter,
        display_name: "OpenRouter",
    },
    ProviderMetadata {
        id: ProviderId::ElevenLabs,
        display_name: "ElevenLabs",
    },
    ProviderMetadata {
        id: ProviderId::Warp,
        display_name: "Warp",
    },
    ProviderMetadata {
        id: ProviderId::Windsurf,
        display_name: "Windsurf",
    },
    ProviderMetadata {
        id: ProviderId::Zed,
        display_name: "Zed",
    },
    ProviderMetadata {
        id: ProviderId::Perplexity,
        display_name: "Perplexity",
    },
    ProviderMetadata {
        id: ProviderId::Mimo,
        display_name: "Xiaomi MiMo",
    },
    ProviderMetadata {
        id: ProviderId::Doubao,
        display_name: "Doubao",
    },
    ProviderMetadata {
        id: ProviderId::Sakana,
        display_name: "Sakana AI",
    },
    ProviderMetadata {
        id: ProviderId::Abacus,
        display_name: "Abacus AI",
    },
    ProviderMetadata {
        id: ProviderId::Mistral,
        display_name: "Mistral",
    },
    ProviderMetadata {
        id: ProviderId::DeepSeek,
        display_name: "DeepSeek",
    },
    ProviderMetadata {
        id: ProviderId::DeepInfra,
        display_name: "DeepInfra",
    },
    ProviderMetadata {
        id: ProviderId::Codebuff,
        display_name: "Codebuff",
    },
    ProviderMetadata {
        id: ProviderId::Crof,
        display_name: "Crof",
    },
    ProviderMetadata {
        id: ProviderId::Venice,
        display_name: "Venice",
    },
    ProviderMetadata {
        id: ProviderId::CommandCode,
        display_name: "Command Code",
    },
    ProviderMetadata {
        id: ProviderId::Qoder,
        display_name: "Qoder",
    },
    ProviderMetadata {
        id: ProviderId::StepFun,
        display_name: "StepFun",
    },
    ProviderMetadata {
        id: ProviderId::Bedrock,
        display_name: "AWS Bedrock",
    },
    ProviderMetadata {
        id: ProviderId::Grok,
        display_name: "Grok",
    },
    ProviderMetadata {
        id: ProviderId::Groq,
        display_name: "Groq",
    },
    ProviderMetadata {
        id: ProviderId::LlmProxy,
        display_name: "LLM Proxy",
    },
    ProviderMetadata {
        id: ProviderId::LiteLlm,
        display_name: "LiteLLM",
    },
    ProviderMetadata {
        id: ProviderId::Deepgram,
        display_name: "Deepgram",
    },
    ProviderMetadata {
        id: ProviderId::Poe,
        display_name: "Poe",
    },
    ProviderMetadata {
        id: ProviderId::Chutes,
        display_name: "Chutes",
    },
    ProviderMetadata {
        id: ProviderId::Neuralwatt,
        display_name: "Neuralwatt",
    },
    ProviderMetadata {
        id: ProviderId::ClawRouter,
        display_name: "ClawRouter",
    },
    ProviderMetadata {
        id: ProviderId::LongCat,
        display_name: "LongCat",
    },
    ProviderMetadata {
        id: ProviderId::Sub2Api,
        display_name: "sub2api",
    },
    ProviderMetadata {
        id: ProviderId::Wayfinder,
        display_name: "Wayfinder",
    },
    ProviderMetadata {
        id: ProviderId::ZenMux,
        display_name: "ZenMux",
    },
    ProviderMetadata {
        id: ProviderId::AiAnd,
        display_name: "ai&",
    },
    ProviderMetadata {
        id: ProviderId::ZoomMate,
        display_name: "ZoomMate",
    },
    ProviderMetadata {
        id: ProviderId::Xai,
        display_name: "xAI",
    },
    ProviderMetadata {
        id: ProviderId::Notion,
        display_name: "Notion AI",
    },
    ProviderMetadata {
        id: ProviderId::IbmBob,
        display_name: "IBM Bob",
    },
];
