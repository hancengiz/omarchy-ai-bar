use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ProviderId, ProviderInstanceId, RateWindow, Timestamp, UsagePercent,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::gemini::{GeminiProvider, GeminiSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Gemini,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn explicit_oauth_settings_are_redacted() {
    let values = BTreeMap::from([
        (
            "GEMINI_OAUTH_ACCESS_TOKEN".to_owned(),
            "fixture-google-token".to_owned(),
        ),
        ("GEMINI_PROJECT_ID".to_owned(), "secret-project".to_owned()),
    ]);
    let settings = GeminiSettings::resolve(&values).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains("fixture-google-token"));
    assert!(!debug.contains("secret-project"));
}

#[tokio::test]
async fn lowest_model_bucket_per_tier_is_normalized() {
    let body = br#"{"buckets":[
      {"modelId":"gemini-2.5-pro","remainingFraction":0.80,"resetTime":"2026-09-01T00:00:00Z"},
      {"modelId":"gemini-2.5-pro","remainingFraction":0.25,"resetTime":"2026-09-01T01:00:00Z"},
      {"modelId":"gemini-2.5-flash","remainingFraction":0.60,"resetTime":"2026-09-01T02:00:00Z"},
      {"modelId":"gemini-2.5-flash-lite","remainingFraction":1.0,"resetTime":"2026-09-01T03:00:00Z"}
    ]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let client = FixedApiClient::new_bearer(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fixture-google-token").expect("token"),
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
    let provider = GeminiProvider::from_client(
        client,
        Some("fixture-project".to_owned()),
        Some("user@example.com".to_owned()),
    )
    .expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::OAuth, CancellationToken::new());
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::parse("2026-08-31T00:00:00Z").expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::Gemini);
    assert_eq!(percent(sample.primary()), Some(75.0));
    assert_eq!(percent(sample.secondary()), Some(40.0));
    assert_eq!(percent(sample.tertiary()), Some(0.0));
    assert_eq!(
        server.requests()[0].target(),
        "/v1internal:retrieveUserQuota"
    );
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Bearer fixture-google-token")
    );
    assert_eq!(
        std::str::from_utf8(server.requests()[0].body()).expect("request body"),
        r#"{"project":"fixture-project"}"#
    );
}

fn percent(window: Option<&RateWindow>) -> Option<f64> {
    window
        .and_then(RateWindow::used_percent)
        .map(UsagePercent::get)
}
