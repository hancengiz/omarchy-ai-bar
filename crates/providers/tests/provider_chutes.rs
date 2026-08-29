use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy, PrivacySurface,
    ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::chutes::{ChutesProvider, ChutesSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const SUBSCRIPTION: &[u8] = include_bytes!("../../../fixtures/providers/chutes/subscription.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/chutes/malformed.json");
const KEY_CANARY: &str = "fixture-chutes-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Chutes,
        ProviderInstanceId::new("chutes-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        4 * 1024 * 1024,
        0,
        RetryPolicy::none(),
    )
    .expect("fixture config")
}

fn context(account: &str) -> ProviderContext {
    ProviderContext::new(
        scope(account),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    )
}

fn provider(server: &FakeHttpServer, account: &str) -> ChutesProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    ChutesProvider::from_client(client).expect("Chutes provider")
}

#[test]
fn settings_normalize_https_and_redact_values() {
    let environment = BTreeMap::from([
        ("CHUTES_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "CHUTES_API_URL".to_owned(),
            "management.example.test/api".to_owned(),
        ),
    ]);
    let settings = ChutesSettings::resolve(&environment).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("management.example.test"));
    assert_eq!(
        ChutesSettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    let insecure = BTreeMap::from([
        ("CHUTES_API_KEY".to_owned(), "fixture".to_owned()),
        (
            "CHUTES_API_URL".to_owned(),
            "http://api.chutes.ai".to_owned(),
        ),
    ]);
    assert_eq!(
        ChutesSettings::resolve(&insecure)
            .expect_err("HTTP override")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn active_subscription_projects_rolling_monthly_identity_reset_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("subscription fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Chutes);
    let primary = sample.primary().expect("rolling quota");
    assert!((primary.used_percent().expect("percent").get() - 40.0).abs() < f64::EPSILON);
    assert_eq!(
        primary.duration().expect("rolling duration").seconds(),
        240 * 60
    );
    assert_eq!(
        primary.resets_at(),
        Some(Timestamp::parse("2026-06-13T18:00:00Z").expect("rolling reset"))
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("rolling detail")
            .as_str(),
        "40/100 requests"
    );
    let secondary = sample.secondary().expect("monthly quota");
    assert!((secondary.used_percent().expect("percent").get() - 25.0).abs() < f64::EPSILON);
    assert_eq!(
        secondary
            .reset_description()
            .expect("monthly detail")
            .as_str(),
        "250/1000 credits"
    );
    assert_eq!(
        sample.subscription_renews_at(),
        Some(Timestamp::parse("2026-07-01T00:00:00Z").expect("renewal"))
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Pro"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target(), "/users/me/subscription_usage");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-chutes-key-canary")
    );
    assert_eq!(requests[0].header("accept"), Some("application/json"));

    let ready = ProviderSnapshot::ready(sample, Freshness::Fresh, RefreshPhase::Idle, None)
        .expect("ready snapshot");
    let envelope = SnapshotEnvelopeV1::new(fetched_at, vec![ready]).expect("CLI envelope");
    let projected = envelope.project(
        PrivacyPolicy::ShowPersonalInfo,
        PrivacySurface::Cli,
        &PrivacyKey::from_bytes([7_u8; 32]),
    );
    let json = serde_json::to_value(projected).expect("CLI JSON");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["primary"]["reset_description"],
        "40/100 requests"
    );
}

#[tokio::test]
async fn inactive_subscription_enriches_per_chute_quota() {
    let subscription = br#"{"subscription":{"active":false,"status":"free"}}"#;
    let quotas = br#"[{"chute_id":"0","is_default":true,"quota":100}]"#;
    let usage = br#"{"quota":100,"used":10}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, subscription.to_vec()),
        FakeHttpResponse::new(200, quotas.to_vec()),
        FakeHttpResponse::new(200, usage.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("enriched quota");
    let primary = sample.primary().expect("quota");
    assert!((primary.used_percent().expect("percent").get() - 10.0).abs() < f64::EPSILON);
    assert_eq!(
        primary.reset_description().expect("detail").as_str(),
        "10/100 credits"
    );
    assert!(sample.secondary().is_none());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("subscription state")
            .as_str(),
        "No active subscription"
    );
    assert_eq!(
        server
            .requests()
            .iter()
            .map(oab_test_support::http::CapturedHttpRequest::target)
            .collect::<Vec<_>>(),
        [
            "/users/me/subscription_usage",
            "/users/me/quotas",
            "/users/me/quota_usage/0",
        ]
    );
}

#[tokio::test]
async fn partial_subscription_combines_monthly_with_rolling_fallback() {
    let subscription = br#"{"subscription":{"active":true,"plan_name":"Pro"},"monthly":{"used":250,"limit":1000,"unit":"credits"}}"#;
    let quotas =
        br#"{"rolling_window":{"requests":40,"limit":100,"window_minutes":240,"unit":"requests"}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, subscription.to_vec()),
        FakeHttpResponse::new(200, quotas.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("combined quota");
    assert_eq!(
        sample
            .primary()
            .expect("rolling")
            .reset_description()
            .expect("detail")
            .as_str(),
        "40/100 requests"
    );
    assert_eq!(
        sample
            .secondary()
            .expect("monthly")
            .reset_description()
            .expect("detail")
            .as_str(),
        "250/1000 credits"
    );
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn flexible_percent_and_distinct_fallback_windows_match_baseline() {
    let subscription = br#"{"subscription":{"active":true}}"#;
    let quotas = br#"{"quotas":[{"usage_percent":1,"window_minutes":240},{"percent_remaining":1,"window_minutes":43200}]}"#;
    let detail_one = br#"{"usage_percent":1,"window_minutes":240}"#;
    let detail_two = br#"{"percent_remaining":1,"window_minutes":43200}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, subscription.to_vec()),
        FakeHttpResponse::new(200, quotas.to_vec()),
        FakeHttpResponse::new(200, detail_one.to_vec()),
        FakeHttpResponse::new(200, detail_two.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("flexible percentages");
    assert!(
        (sample
            .primary()
            .expect("rolling")
            .used_percent()
            .expect("percent")
            .get()
            - 1.0)
            .abs()
            < f64::EPSILON
    );
    assert!(
        (sample
            .secondary()
            .expect("monthly")
            .used_percent()
            .expect("percent")
            .get()
            - 99.0)
            .abs()
            < f64::EPSILON
    );
}

#[tokio::test]
async fn optional_quota_failure_preserves_subscription_but_auth_is_authoritative() {
    let subscription = br#"{"subscription":{"active":false}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, subscription.to_vec()),
        FakeHttpResponse::new(503, Vec::new()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("optional failure fallback");
    assert!(sample.primary().is_none());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("inactive state")
            .as_str(),
        "No active subscription"
    );

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, subscription.to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
    ])
    .await;
    assert_eq!(
        provider(&server, "account-a")
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("quota auth failure")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
}

#[tokio::test]
async fn status_parse_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::truncated(200, SUBSCRIPTION.len() + 10, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::PermissionDenied,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Api,
        ErrorKind::Parse,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("scripted provider failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
    }
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1_800_000_001))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider
            .fetch_at(&provider_context, timestamp(1_800_000_002))
            .await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_003))
        .await
        .expect_err("cross-account context");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), 9);
}
