use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ProviderId, ProviderInstanceId, RateWindow, Timestamp, UsagePercent,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::antigravity::{AntigravityProvider, AntigravitySettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Antigravity,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn remote_settings_redact_oauth_material() {
    let values = BTreeMap::from([
        (
            "ANTIGRAVITY_OAUTH_ACCESS_TOKEN".to_owned(),
            "fixture-antigravity-token".to_owned(),
        ),
        (
            "ANTIGRAVITY_PROJECT_ID".to_owned(),
            "private-project".to_owned(),
        ),
    ]);
    let settings = AntigravitySettings::resolve(&values).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains("fixture-antigravity-token"));
    assert!(!debug.contains("private-project"));
}

#[tokio::test]
async fn model_buckets_are_grouped_into_two_quota_families() {
    let body = br#"{"buckets":[
      {"modelId":"gemini-3-pro","remainingFraction":0.2,"resetTime":"2026-09-01T00:00:00Z"},
      {"modelId":"gemini-3-flash","remainingFraction":0.8,"resetTime":"2026-09-01T00:00:00Z"},
      {"modelId":"claude-opus-4","remainingFraction":0.4,"resetTime":"2026-09-02T00:00:00Z"},
      {"modelId":"gpt-5","remainingFraction":0.7,"resetTime":"2026-09-02T00:00:00Z"}
    ]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let client = FixedApiClient::new_bearer(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fixture-token").expect("token"),
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
    let provider = AntigravityProvider::from_client(client, Some("project".to_owned()), None)
        .expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::OAuth, CancellationToken::new());
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::parse("2026-08-31T00:00:00Z").expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::Antigravity);
    assert_eq!(percent(sample.primary()), Some(80.0));
    assert_eq!(percent(sample.secondary()), Some(60.0));
    assert_eq!(
        server.requests()[0].target(),
        "/v1internal:retrieveUserQuota"
    );
}

fn percent(window: Option<&RateWindow>) -> Option<f64> {
    window
        .and_then(RateWindow::used_percent)
        .map(UsagePercent::get)
}
