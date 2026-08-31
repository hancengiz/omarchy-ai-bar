use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, BoundedText, ProviderId, ProviderInstanceId, Timestamp,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::ollama::OllamaProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Ollama,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[tokio::test]
async fn model_catalog_verifies_key_without_faking_quota_percent() {
    let body = br#"{"models":[{"name":"gpt-oss"},{"name":"qwen3"}]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let client = FixedApiClient::new_bearer(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fixture-ollama-key").expect("key"),
        TransportConfig::new(
            Duration::from_millis(250),
            Duration::from_millis(250),
            1024 * 1024,
            0,
            RetryPolicy::none(),
        )
        .expect("config"),
    )
    .expect("client")
    .with_source(ProviderSource::ConfigurableEndpoint)
    .expect("configured source");
    let provider = OllamaProvider::from_client(client).expect("provider");
    let context = ProviderContext::new(
        scope(),
        ProviderSource::ConfigurableEndpoint,
        CancellationToken::new(),
    );
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::from_unix_timestamp(1_800_000_000).expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::Ollama);
    assert_eq!(sample.primary().expect("primary").used_percent(), None);
    assert_eq!(
        sample
            .primary()
            .and_then(|window| window.reset_description())
            .map(BoundedText::as_str),
        Some("API key verified · 2 models")
    );
    assert_eq!(server.requests()[0].target(), "/api/tags");
}
