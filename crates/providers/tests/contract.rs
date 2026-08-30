use std::collections::BTreeSet;

use oab_domain::{
    AccountKey, AccountScope, ClassifiedError, ErrorKind, ProviderId, ProviderInstanceId,
};
use oab_providers::capability::ProviderCapability;
use oab_providers::context::{FetchOutcome, ProviderContext, preserve_last_good};
use oab_providers::descriptor::{DefaultBehavior, ProviderSource};
use oab_providers::registry::{PROVIDERS, descriptor_for};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::OpenAi,
        ProviderInstanceId::new("openai-primary").expect("provider instance"),
        AccountKey::new("account-opaque-1").expect("account key"),
    )
}

#[test]
fn every_first_party_descriptor_is_closed_stable_and_actionable() {
    assert_eq!(PROVIDERS.len(), ProviderId::ALL.len());
    let ids = PROVIDERS
        .iter()
        .map(|descriptor| descriptor.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids, ProviderId::ALL.into_iter().collect());

    for descriptor in &PROVIDERS {
        assert_eq!(descriptor_for(descriptor.id), descriptor);
        assert!(!descriptor.display_name.trim().is_empty());
        assert!(
            descriptor
                .capabilities()
                .contains(ProviderCapability::Usage)
        );
        assert!(!descriptor.sources().is_empty());
        for source in descriptor.sources().iter() {
            assert!(!source.label().trim().is_empty());
        }
    }
}

#[test]
fn completed_api_provider_sources_match_the_pinned_baseline() {
    for id in [
        ProviderId::OpenAi,
        ProviderId::Fireworks,
        ProviderId::DeepInfra,
        ProviderId::Warp,
        ProviderId::AiAnd,
        ProviderId::IbmBob,
        ProviderId::ClinePass,
        ProviderId::Crof,
        ProviderId::Moonshot,
        ProviderId::ZenMux,
        ProviderId::Xai,
        ProviderId::Synthetic,
        ProviderId::Venice,
        ProviderId::Poe,
    ] {
        assert_eq!(
            descriptor_for(id).sources().iter().collect::<Vec<_>>(),
            [ProviderSource::ApiKey],
            "source drift for {id:?}"
        );
    }
    for id in [
        ProviderId::ElevenLabs,
        ProviderId::AzureOpenAi,
        ProviderId::Deepgram,
        ProviderId::Chutes,
        ProviderId::Neuralwatt,
        ProviderId::LiteLlm,
        ProviderId::LlmProxy,
        ProviderId::Sub2Api,
        ProviderId::OpenRouter,
        ProviderId::ClawRouter,
    ] {
        assert_eq!(
            descriptor_for(id).sources().iter().collect::<Vec<_>>(),
            [ProviderSource::ApiKey, ProviderSource::ConfigurableEndpoint],
            "source drift for {id:?}"
        );
    }
    assert_eq!(
        descriptor_for(ProviderId::Zai)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [
            ProviderSource::ApiKey,
            ProviderSource::ConfigurableEndpoint,
            ProviderSource::LocalData
        ]
    );
    assert_eq!(
        descriptor_for(ProviderId::Wayfinder)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [ProviderSource::ConfigurableEndpoint]
    );
}

#[test]
fn bedrock_advertises_cost_history_without_credit_inventory() {
    let capabilities = descriptor_for(ProviderId::Bedrock).capabilities();

    assert!(capabilities.contains(ProviderCapability::Usage));
    assert!(capabilities.contains(ProviderCapability::CostHistory));
    assert!(!capabilities.contains(ProviderCapability::Credits));
}

#[test]
fn signed_cloud_provider_sources_are_exact_and_actionable() {
    assert_eq!(
        descriptor_for(ProviderId::Bedrock)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [ProviderSource::CloudCredentials]
    );
    assert_eq!(
        descriptor_for(ProviderId::Doubao)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [
            ProviderSource::ApiKey,
            ProviderSource::Cli,
            ProviderSource::CloudCredentials
        ]
    );
    assert_eq!(
        descriptor_for(ProviderId::VertexAi)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [ProviderSource::CloudCredentials]
    );
    assert!(
        descriptor_for(ProviderId::Doubao)
            .capabilities()
            .contains(ProviderCapability::LoginAction)
    );
    assert!(
        descriptor_for(ProviderId::VertexAi)
            .capabilities()
            .contains(ProviderCapability::LoginAction)
    );
}

#[test]
fn linux_cli_and_local_provider_sources_are_exact_and_actionable() {
    assert_eq!(
        descriptor_for(ProviderId::Amp)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [
            ProviderSource::ApiKey,
            ProviderSource::ManualCookie,
            ProviderSource::BrowserSession,
            ProviderSource::Cli,
        ]
    );
    assert_eq!(
        descriptor_for(ProviderId::Kilo)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [ProviderSource::ApiKey, ProviderSource::Cli]
    );
    assert_eq!(
        descriptor_for(ProviderId::Kiro)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [ProviderSource::Cli]
    );
    assert_eq!(
        descriptor_for(ProviderId::JetBrains)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [ProviderSource::LocalData]
    );
    assert_eq!(
        descriptor_for(ProviderId::Codebuff)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [ProviderSource::ApiKey, ProviderSource::LocalData]
    );
    for id in [ProviderId::Amp, ProviderId::Kilo, ProviderId::Kiro] {
        assert!(
            descriptor_for(id)
                .capabilities()
                .contains(ProviderCapability::LoginAction),
            "missing login action for {id:?}"
        );
    }
    assert!(
        descriptor_for(ProviderId::Amp)
            .capabilities()
            .contains(ProviderCapability::BrowserAuth)
    );
    for id in [ProviderId::Amp, ProviderId::Codebuff] {
        assert!(
            descriptor_for(id)
                .capabilities()
                .contains(ProviderCapability::Credits),
            "missing credits capability for {id:?}"
        );
    }
}

#[test]
fn browser_and_manual_provider_metadata_matches_the_pinned_baseline() {
    use ProviderSource as Source;

    for id in [
        ProviderId::T3Chat,
        ProviderId::QwenCloud,
        ProviderId::OpenCode,
        ProviderId::Devin,
        ProviderId::Manus,
        ProviderId::CommandCode,
        ProviderId::Qoder,
        ProviderId::Perplexity,
        ProviderId::LongCat,
        ProviderId::ZoomMate,
        ProviderId::Notion,
    ] {
        assert_eq!(
            descriptor_for(id).sources().iter().collect::<Vec<_>>(),
            [Source::ManualCookie, Source::BrowserSession],
            "source drift for {id:?}"
        );
    }

    assert_eq!(
        descriptor_for(ProviderId::Mistral)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [Source::ManualCookie, Source::BrowserSession]
    );
    for id in [ProviderId::Alibaba, ProviderId::MiniMax] {
        assert_eq!(
            descriptor_for(id).sources().iter().collect::<Vec<_>>(),
            [Source::ApiKey, Source::ManualCookie, Source::BrowserSession],
            "source drift for {id:?}"
        );
    }
    assert_eq!(
        descriptor_for(ProviderId::AlibabaTokenPlan)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [Source::ManualCookie, Source::BrowserSession, Source::Cli]
    );
    assert_eq!(
        descriptor_for(ProviderId::Mimo)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [
            Source::ManualCookie,
            Source::BrowserSession,
            Source::LocalData
        ]
    );
    for id in [ProviderId::Sakana, ProviderId::StepFun] {
        assert_eq!(
            descriptor_for(id).sources().iter().collect::<Vec<_>>(),
            [Source::ManualCookie],
            "source drift for {id:?}"
        );
    }
    assert_eq!(
        descriptor_for(ProviderId::Kimi)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        [
            Source::ApiKey,
            Source::ConfigurableEndpoint,
            Source::ManualCookie,
            Source::BrowserSession,
            Source::Cli,
            Source::LocalData,
        ]
    );
}

#[test]
fn browser_and_manual_provider_capabilities_match_the_pinned_baseline() {
    use ProviderCapability as Capability;

    assert_eq!(
        descriptor_for(ProviderId::Mistral)
            .capabilities()
            .iter()
            .collect::<Vec<_>>(),
        [
            Capability::Usage,
            Capability::CostHistory,
            Capability::BrowserAuth
        ]
    );
    for id in [
        ProviderId::Mimo,
        ProviderId::CommandCode,
        ProviderId::ZoomMate,
    ] {
        assert!(
            descriptor_for(id)
                .capabilities()
                .contains(Capability::Credits),
            "missing credits capability for {id:?}"
        );
    }
    assert!(
        descriptor_for(ProviderId::AlibabaTokenPlan)
            .capabilities()
            .contains(Capability::LoginAction)
    );
    for id in [ProviderId::Mimo, ProviderId::Kimi] {
        assert!(
            descriptor_for(id)
                .capabilities()
                .contains(Capability::StorageReport),
            "missing storage capability for {id:?}"
        );
    }
}

#[test]
fn first_run_behavior_is_explicit_and_nonprobing_by_default() {
    assert_eq!(
        descriptor_for(ProviderId::Codex).default_behavior(),
        DefaultBehavior::Fallback
    );
    for detected in [
        ProviderId::Claude,
        ProviderId::Gemini,
        ProviderId::Antigravity,
    ] {
        assert_eq!(
            descriptor_for(detected).default_behavior(),
            DefaultBehavior::Detect
        );
    }
    for descriptor in &PROVIDERS {
        if !matches!(
            descriptor.id,
            ProviderId::Codex | ProviderId::Claude | ProviderId::Gemini | ProviderId::Antigravity
        ) {
            assert_eq!(descriptor.default_behavior(), DefaultBehavior::Disabled);
        }
    }
}

#[test]
fn provider_context_keeps_exact_scope_source_and_cancellation() {
    let cancellation = CancellationToken::new();
    let context = ProviderContext::new(scope(), ProviderSource::ApiKey, cancellation.clone());
    assert_eq!(context.scope(), &scope());
    assert_eq!(context.source(), ProviderSource::ApiKey);
    assert!(!context.cancellation().is_cancelled());
    cancellation.cancel();
    assert!(context.cancellation().is_cancelled());
}

#[test]
fn generic_fetch_outcome_preserves_last_good_on_failure() {
    assert_eq!(
        preserve_last_good::<String>(None, Ok("fresh".into())),
        FetchOutcome::Fresh("fresh".into())
    );
    let error = ClassifiedError::new(ErrorKind::Network);
    assert_eq!(
        preserve_last_good(Some("cached".to_owned()), Err(error.clone())),
        FetchOutcome::Retained {
            last_good: "cached".to_owned(),
            error: error.clone(),
        }
    );
    assert_eq!(
        preserve_last_good::<String>(None, Err(error.clone())),
        FetchOutcome::Unavailable { error }
    );
}
