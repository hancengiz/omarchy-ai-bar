use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

macro_rules! provider_ids {
    ($($variant:ident => $value:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ProviderId {
            $($variant),+
        }

        impl ProviderId {
            pub const ALL: [Self; 69] = [$(Self::$variant),+];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl FromStr for ProviderId {
            type Err = ParseProviderIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(ParseProviderIdError),
                }
            }
        }
    };
}

provider_ids! {
    Codex => "codex",
    OpenAi => "openai",
    AzureOpenAi => "azureopenai",
    Claude => "claude",
    ClinePass => "clinepass",
    Cursor => "cursor",
    OpenCode => "opencode",
    OpenCodeGo => "opencodego",
    Alibaba => "alibaba",
    AlibabaTokenPlan => "alibabatokenplan",
    QwenCloud => "qwencloud",
    Factory => "factory",
    Fireworks => "fireworks",
    Gemini => "gemini",
    Antigravity => "antigravity",
    Copilot => "copilot",
    Devin => "devin",
    Zai => "zai",
    MiniMax => "minimax",
    Manus => "manus",
    Kimi => "kimi",
    Kilo => "kilo",
    Kiro => "kiro",
    VertexAi => "vertexai",
    Augment => "augment",
    JetBrains => "jetbrains",
    Moonshot => "moonshot",
    Amp => "amp",
    T3Chat => "t3chat",
    Ollama => "ollama",
    Synthetic => "synthetic",
    OpenRouter => "openrouter",
    ElevenLabs => "elevenlabs",
    Warp => "warp",
    Windsurf => "windsurf",
    Zed => "zed",
    Perplexity => "perplexity",
    Mimo => "mimo",
    Doubao => "doubao",
    Sakana => "sakana",
    Abacus => "abacus",
    Mistral => "mistral",
    DeepSeek => "deepseek",
    DeepInfra => "deepinfra",
    Codebuff => "codebuff",
    Crof => "crof",
    Venice => "venice",
    CommandCode => "commandcode",
    Qoder => "qoder",
    StepFun => "stepfun",
    Bedrock => "bedrock",
    Grok => "grok",
    Groq => "groq",
    LlmProxy => "llmproxy",
    LiteLlm => "litellm",
    Deepgram => "deepgram",
    Poe => "poe",
    Chutes => "chutes",
    Neuralwatt => "neuralwatt",
    ClawRouter => "clawrouter",
    LongCat => "longcat",
    Sub2Api => "sub2api",
    Wayfinder => "wayfinder",
    ZenMux => "zenmux",
    AiAnd => "aiand",
    ZoomMate => "zoommate",
    Xai => "xai",
    Notion => "notion",
    IbmBob => "ibmbob",
}

impl Display for ProviderId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ProviderId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProviderIdError;

impl Display for ParseProviderIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown provider")
    }
}

impl Error for ParseProviderIdError {}
