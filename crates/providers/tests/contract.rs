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
