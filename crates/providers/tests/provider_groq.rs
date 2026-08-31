use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, BoundedText, ProviderId, ProviderInstanceId, Timestamp,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::groq::GroqProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Groq,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[tokio::test]
async fn four_metrics_are_projected_into_usage_windows() {
    let body = br#"{"status":"success","data":{"result":[{"value":[1800000000,"1"]}]}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, body.to_vec()),
        FakeHttpResponse::new(200, body.to_vec()),
        FakeHttpResponse::new(200, body.to_vec()),
        FakeHttpResponse::new(200, body.to_vec()),
    ])
    .await;
    let client = FixedApiClient::new_bearer(
        scope(),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fixture-groq-key").expect("key"),
        TransportConfig::new(
            Duration::from_millis(250),
            Duration::from_millis(250),
            1024 * 1024,
            0,
            RetryPolicy::none(),
        )
        .expect("config"),
    )
    .expect("client");
    let provider = GroqProvider::from_client(client).expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::ApiKey, CancellationToken::new());
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::from_unix_timestamp(1_800_000_000).expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::Groq);
    assert_eq!(
        sample
            .primary()
            .and_then(|window| window.reset_description())
            .map(BoundedText::as_str),
        Some("60.0 req/min")
    );
    assert_eq!(
        sample
            .secondary()
            .and_then(|window| window.reset_description())
            .map(BoundedText::as_str),
        Some("120 tok/min")
    );
    assert_eq!(server.requests().len(), 4);
    assert!(server.requests().iter().all(|request| {
        request
            .target()
            .starts_with("/v1/metrics/prometheus/api/v1/query?query=")
            && request.header("authorization") == Some("Bearer fixture-groq-key")
    }));
}
