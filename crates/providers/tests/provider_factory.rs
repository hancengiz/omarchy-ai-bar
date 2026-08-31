use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ProviderId, ProviderInstanceId, RateWindow, Timestamp, UsagePercent,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::factory::FactoryProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Factory,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn api_key_is_resolved_and_redacted() {
    let values = BTreeMap::from([("FACTORY_API_KEY".to_owned(), "fk-fixture-secret".to_owned())]);
    let credential = FactoryProvider::resolve_credential(&values).expect("credential");
    assert!(!format!("{credential:?}").contains("fk-fixture-secret"));
}

#[tokio::test]
async fn standard_and_premium_usage_are_normalized() {
    let auth = br#"{
      "userProfile":{"id":"usr_123","email":"droid@example.com"},
      "organization":{"name":"Factory Org","subscription":{"factoryTier":"pro","orbSubscription":{"plan":{"name":"Droid Pro"}}}}
    }"#;
    let usage = br#"{"usage":{"endDate":1788220800000,"standard":{"userTokens":25,"totalAllowance":100,"usedRatio":0.25},"premium":{"userTokens":10,"totalAllowance":20,"usedRatio":0.5}}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, auth.to_vec()),
        FakeHttpResponse::new(200, usage.to_vec()),
    ])
    .await;
    let client = FixedApiClient::new_bearer(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fk-fixture-secret").expect("key"),
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
    let provider = FactoryProvider::from_client(client).expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::ApiKey, CancellationToken::new());
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::parse("2026-08-31T00:00:00Z").expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::Factory);
    assert_eq!(percent(sample.primary()), Some(25.0));
    assert_eq!(percent(sample.secondary()), Some(50.0));
    let requests = server.requests();
    assert_eq!(requests[0].target(), "/api/app/auth/me");
    assert!(
        requests[1]
            .target()
            .starts_with("/api/organization/subscription/usage?useCache=true&userId=usr_123")
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fk-fixture-secret")
    );
}

fn percent(window: Option<&RateWindow>) -> Option<f64> {
    window
        .and_then(RateWindow::used_percent)
        .map(UsagePercent::get)
}
