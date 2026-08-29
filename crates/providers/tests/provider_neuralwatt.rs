use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ExactDecimal, Freshness, PrivacyKey, PrivacyPolicy,
    PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::neuralwatt::{NeuralWattProvider, NeuralWattSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const QUOTA: &[u8] = include_bytes!("../../../fixtures/providers/neuralwatt/quota.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/neuralwatt/malformed.json");
const KEY_CANARY: &str = "fixture-neuralwatt-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Neuralwatt,
        ProviderInstanceId::new("neuralwatt-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(retry: RetryPolicy) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        2 * 1024 * 1024,
        0,
        retry,
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

fn provider_at(
    server: &FakeHttpServer,
    account: &str,
    base_path: &str,
    retry: RetryPolicy,
) -> NeuralWattProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url(base_path),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    NeuralWattProvider::from_client(client).expect("Neuralwatt provider")
}

fn provider(server: &FakeHttpServer, account: &str) -> NeuralWattProvider {
    provider_at(server, account, "/", RetryPolicy::none())
}

#[test]
fn settings_normalize_https_and_redact_values() {
    let environment = BTreeMap::from([
        ("NEURALWATT_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "NEURALWATT_API_URL".to_owned(),
            "quota.example.test/api".to_owned(),
        ),
    ]);
    let settings = NeuralWattSettings::resolve(&environment).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("quota.example.test"));
    assert_eq!(
        NeuralWattSettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    let insecure = BTreeMap::from([
        ("NEURALWATT_API_KEY".to_owned(), "fixture".to_owned()),
        (
            "NEURALWATT_API_URL".to_owned(),
            "http://api.neuralwatt.com".to_owned(),
        ),
    ]);
    assert_eq!(
        NeuralWattSettings::resolve(&insecure)
            .expect_err("HTTP override")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn quota_fixture_projects_subscription_balance_allowance_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("quota fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Neuralwatt);
    let primary = sample.primary().expect("subscription kWh");
    let expected = 13.9023 / 20.0 * 100.0;
    assert!((primary.used_percent().expect("percent").get() - expected).abs() < 1e-10);
    assert_eq!(
        primary.reset_description().expect("detail").as_str(),
        "13.90 / 20 kWh"
    );
    let period_end = Timestamp::parse("2026-05-11T05:05:25Z").expect("period end");
    assert_eq!(primary.resets_at(), Some(period_end));
    assert_eq!(
        primary.duration().expect("billing period").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(sample.subscription_renews_at(), Some(period_end));
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Standard plan"
    );
    let cost = sample.cost().expect("prepaid balance");
    assert_eq!(cost.used().amount(), decimal("32.6774"));
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("Neuralwatt prepaid balance"));
    assert_eq!(sample.extra_windows().len(), 1);
    let allowance = &sample.extra_windows()[0];
    assert_eq!(allowance.id().as_str(), "key-allowance");
    assert_eq!(allowance.title().as_str(), "Key Monthly");
    assert!(
        (allowance.window().used_percent().expect("percent").get() - 25.0).abs() < f64::EPSILON
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target(), "/v1/quota");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-neuralwatt-key-canary")
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
        json["snapshots"][0]["last_known_good"]["cost"]["used"]["amount"],
        "32.6774"
    );
}

#[tokio::test]
async fn prepaid_only_and_derived_values_remain_separate_from_subscription() {
    let body = br#"{
        "balance":{"credits_remaining_usd":30,"total_credits_usd":100,"accounting_method":"energy"},
        "usage":{"lifetime":{},"current_month":{}},
        "limits":{},"subscription":null,"key":{"name":"x","allowance":null}
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("prepaid fixture");
    assert!(sample.primary().is_none());
    assert!(sample.subscription_renews_at().is_none());
    assert!(sample.extra_windows().is_empty());
    assert_eq!(
        sample.cost().expect("balance").used().amount(),
        decimal("30")
    );
    assert_eq!(
        sample.identity().login_method().expect("method").as_str(),
        "Energy"
    );
}

#[tokio::test]
async fn zero_balance_nonrenewing_subscription_and_blocked_key_match_baseline() {
    let body = br#"{
        "balance":{"credits_remaining_usd":0,"total_credits_usd":0,"accounting_method":"energy"},
        "subscription":{"plan":"pro_energy","status":"active","auto_renew":false,
          "current_period_end":"2026-05-01T00:00:00Z","kwh_used":2.5,"kwh_remaining":7.5},
        "key":{"name":"blocked","allowance":{"blocked":true,"period":"monthly"}}
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("combined fixture");
    let primary = sample.primary().expect("subscription");
    assert!((primary.used_percent().expect("percent").get() - 25.0).abs() < f64::EPSILON);
    assert_eq!(
        primary.reset_description().expect("detail").as_str(),
        "2.50 / 10 kWh"
    );
    assert!(primary.resets_at().is_some());
    assert!(sample.subscription_renews_at().is_none());
    assert_eq!(
        sample.cost().expect("zero balance").used().amount(),
        decimal("0")
    );
    assert!(
        (sample.extra_windows()[0]
            .window()
            .used_percent()
            .expect("blocked")
            .get()
            - 100.0)
            .abs()
            < f64::EPSILON
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Pro Energy plan"
    );
}

#[tokio::test]
async fn v1_base_path_is_not_duplicated_and_other_paths_are_preserved() {
    let minimal = br#"{"balance":{"credits_remaining_usd":1}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, minimal.to_vec()),
        FakeHttpResponse::new(200, minimal.to_vec()),
    ])
    .await;
    provider_at(&server, "account-a", "/v1/", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("v1 base");
    provider_at(&server, "account-a", "/proxy", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_001))
        .await
        .expect("proxy base");
    assert_eq!(
        server
            .requests()
            .iter()
            .map(oab_test_support::http::CapturedHttpRequest::target)
            .collect::<Vec<_>>(),
        ["/v1/quota", "/proxy/v1/quota"]
    );
}

#[tokio::test]
async fn transient_quota_failure_is_retried_once() {
    let minimal = br#"{"balance":{"credits_remaining_usd":5}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, minimal.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::ZERO, Duration::ZERO);
    let sample = provider_at(&server, "account-a", "/", retry)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("retry success");
    assert_eq!(
        sample.cost().expect("balance").used().amount(),
        decimal("5")
    );
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn authentication_rate_provider_api_and_parse_failures_are_stable() {
    let missing_balance = br#"{"error":"temporarily unavailable"}"#;
    let missing_fields = br#"{"balance":{"credits_remaining_usd":-1}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::truncated(200, QUOTA.len() + 10, QUOTA.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, missing_balance.to_vec()),
        FakeHttpResponse::new(200, missing_fields.to_vec()),
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
}

#[tokio::test]
async fn malformed_refresh_retains_last_good_and_accounts_are_isolated() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1_800_000_000))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider
            .fetch_at(&provider_context, timestamp(1_800_000_001))
            .await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_002))
        .await
        .expect_err("cross-account context");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), 2);
}
