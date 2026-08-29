use std::collections::BTreeSet;

use oab_domain::ProviderId;

const EXPECTED_PROVIDER_IDS: [&str; 69] = [
    "codex",
    "openai",
    "azureopenai",
    "claude",
    "clinepass",
    "cursor",
    "opencode",
    "opencodego",
    "alibaba",
    "alibabatokenplan",
    "qwencloud",
    "factory",
    "fireworks",
    "gemini",
    "antigravity",
    "copilot",
    "devin",
    "zai",
    "minimax",
    "manus",
    "kimi",
    "kilo",
    "kiro",
    "vertexai",
    "augment",
    "jetbrains",
    "moonshot",
    "amp",
    "t3chat",
    "ollama",
    "synthetic",
    "openrouter",
    "elevenlabs",
    "warp",
    "windsurf",
    "zed",
    "perplexity",
    "mimo",
    "doubao",
    "sakana",
    "abacus",
    "mistral",
    "deepseek",
    "deepinfra",
    "codebuff",
    "crof",
    "venice",
    "commandcode",
    "qoder",
    "stepfun",
    "bedrock",
    "grok",
    "groq",
    "llmproxy",
    "litellm",
    "deepgram",
    "poe",
    "chutes",
    "neuralwatt",
    "clawrouter",
    "longcat",
    "sub2api",
    "wayfinder",
    "zenmux",
    "aiand",
    "zoommate",
    "xai",
    "notion",
    "ibmbob",
];

#[test]
fn provider_registry_is_the_closed_baseline_set() {
    let actual: Vec<&str> = ProviderId::ALL
        .iter()
        .map(|provider| provider.as_str())
        .collect();

    assert_eq!(actual, EXPECTED_PROVIDER_IDS);
    assert_eq!(actual.iter().copied().collect::<BTreeSet<_>>().len(), 69);
}

#[test]
fn provider_ids_round_trip_and_unknown_ids_fail() {
    for provider in ProviderId::ALL {
        let json = serde_json::to_string(&provider).expect("provider should serialize");
        let decoded: ProviderId = serde_json::from_str(&json).expect("provider should deserialize");
        assert_eq!(decoded, provider);
    }

    let error = serde_json::from_str::<ProviderId>(r#""not-a-provider""#)
        .expect_err("unknown provider should fail");
    assert!(error.to_string().contains("unknown provider"));
}
