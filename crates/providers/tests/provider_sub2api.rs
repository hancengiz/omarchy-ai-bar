use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy, PrivacySurface,
    ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::sub2api::{Sub2ApiProvider, Sub2ApiSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const QUOTA: &[u8] = include_bytes!("../../../fixtures/providers/sub2api/quota.json");
const SUBSCRIPTION: &[u8] = include_bytes!("../../../fixtures/providers/sub2api/subscription.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/sub2api/malformed.json");
const KEY_CANARY: &str = "fixture-sub2api-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Sub2Api,
        ProviderInstanceId::new("sub2api-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(retry: RetryPolicy) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        2 * 1024 * 1024,
        3,
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

fn provider(
    server: &FakeHttpServer,
    base_path: &str,
    account: &str,
    retry: RetryPolicy,
) -> Sub2ApiProvider {
    let endpoint = ConfiguredEndpoint::parse(
        server.url(base_path).as_str(),
        ConfiguredHttpPolicy::LoopbackHttp,
    )
    .expect("fixture endpoint");
    let client = FixedApiClient::new_bearer(
        scope(account),
        endpoint.url().clone(),
        endpoint.class(),
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    Sub2ApiProvider::from_client(client, endpoint, "Europe/Istanbul").expect("sub2api provider")
}

fn detail_value<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a str {
    sample.detail_sections()[0]
        .rows()
        .iter()
        .find(|row| row.label() == label)
        .expect("detail row")
        .value()
}

#[test]
fn settings_require_both_values_allow_only_https_or_loopback_and_redact() {
    let environment = BTreeMap::from([
        ("SUB2API_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "SUB2API_BASE_URL".to_owned(),
            " \"https://sub2api.example.com/v1\" ".to_owned(),
        ),
        ("TZ".to_owned(), "Europe/Istanbul".to_owned()),
    ]);
    let settings = Sub2ApiSettings::resolve(&environment).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("sub2api.example.com"));
    assert!(debug.contains("Europe/Istanbul"));

    assert_eq!(
        Sub2ApiSettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    let key_only = BTreeMap::from([("SUB2API_API_KEY".to_owned(), KEY_CANARY.to_owned())]);
    assert_eq!(
        Sub2ApiSettings::resolve(&key_only)
            .expect_err("missing base URL")
            .kind(),
        ErrorKind::Api
    );
    for base_url in [
        "http://api.example.com",
        "http://10.0.0.4",
        "http://proxy.local",
    ] {
        let values = BTreeMap::from([
            ("SUB2API_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("SUB2API_BASE_URL".to_owned(), base_url.to_owned()),
        ]);
        assert_eq!(
            Sub2ApiSettings::resolve(&values)
                .expect_err("non-loopback HTTP")
                .kind(),
            ErrorKind::Api
        );
    }
    let loopback = BTreeMap::from([
        ("SUB2API_API_KEY".to_owned(), KEY_CANARY.to_owned()),
        (
            "SUB2API_BASE_URL".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
        ),
    ]);
    Sub2ApiSettings::resolve(&loopback).expect("loopback HTTP");
}

#[tokio::test]
async fn quota_fixture_projects_rate_limits_usage_details_expiry_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let provider = provider(&server, "/", "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("quota fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Sub2Api);
    assert!(
        (sample
            .primary()
            .expect("quota")
            .used_percent()
            .expect("percent")
            .get()
            - 25.0)
            .abs()
            < f64::EPSILON
    );
    assert_eq!(
        sample
            .primary()
            .expect("quota")
            .reset_description()
            .expect("description")
            .as_str(),
        "$25.00 / $100.00"
    );
    assert_eq!(sample.extra_windows().len(), 2);
    let five_hour = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == "5h")
        .expect("five hour limit");
    assert_eq!(five_hour.title().as_str(), "5 hour limit");
    assert_eq!(
        five_hour.window().duration().expect("duration").seconds(),
        18_000
    );
    assert_eq!(
        five_hour.window().resets_at(),
        Some(Timestamp::parse("2026-07-11T12:30:00Z").expect("reset"))
    );
    assert_eq!(detail_value(&sample, "Today requests"), "4");
    assert_eq!(detail_value(&sample, "Today tokens"), "1,200");
    let today_tokens = sample.detail_sections()[0]
        .rows()
        .iter()
        .find(|row| row.label() == "Today tokens")
        .expect("today tokens");
    assert_eq!(today_tokens.secondary_value(), Some("$1.25"));
    assert_eq!(detail_value(&sample, "All time requests"), "40");
    assert_eq!(
        sample.subscription_expires_at(),
        Some(Timestamp::parse("2026-08-01T00:00:00Z").expect("expiration"))
    );
    assert!(sample.cost().is_none());

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].target(),
        "/v1/usage?days=30&timezone=Europe%2FIstanbul"
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-sub2api-key-canary")
    );

    let ready = ProviderSnapshot::ready(sample, Freshness::Fresh, RefreshPhase::Idle, None)
        .expect("ready snapshot");
    let envelope = SnapshotEnvelopeV1::new(fetched_at, vec![ready]).expect("CLI envelope");
    let projected = envelope.project(
        PrivacyPolicy::ShowPersonalInfo,
        PrivacySurface::Cli,
        &PrivacyKey::from_bytes([7_u8; 32]),
    );
    assert_eq!(
        serde_json::to_value(projected).expect("CLI JSON")["schema_version"],
        1
    );
}

#[tokio::test]
async fn subscription_fixture_keeps_authoritative_daily_weekly_and_monthly_windows() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let sample = provider(&server, "/v1", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("subscription fixture");

    let percentages = [
        sample.primary().expect("daily"),
        sample.secondary().expect("weekly"),
        sample.tertiary().expect("monthly"),
    ]
    .map(|window| window.used_percent().expect("percent").get());
    assert!((percentages[0] - 100.0).abs() < f64::EPSILON);
    assert!((percentages[1] - (229.2 / 700.0 * 100.0)).abs() < 1e-10);
    assert!((percentages[2] - (1296.23 / 2800.0 * 100.0)).abs() < 1e-10);
    assert_eq!(
        sample
            .primary()
            .expect("daily")
            .reset_description()
            .expect("description")
            .as_str(),
        "$120.23 / $120.00"
    );
    assert_eq!(
        sample
            .tertiary()
            .expect("monthly")
            .reset_description()
            .expect("description")
            .as_str(),
        "$1,296.23 / $2,800.00"
    );
    assert_eq!(
        sample.identity().organization().expect("plan").as_str(),
        "Claude Team"
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Claude Team"
    );
    assert_eq!(
        sample.subscription_expires_at(),
        Some(Timestamp::parse("2026-08-15T00:00:00.123Z").expect("expiration"))
    );
}

#[tokio::test]
async fn wallet_and_non_usd_units_remain_detail_only() {
    let wallet = br#"{
      "mode":"unrestricted",
      "isValid":true,
      "planName":"Wallet plan",
      "unit":"EUR",
      "balance":42.5
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, wallet.to_vec())]).await;
    let sample = provider(&server, "/v1/usage", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("wallet fixture");
    assert!(sample.primary().is_none());
    assert!(sample.balance().is_none());
    assert_eq!(detail_value(&sample, "Balance"), "42.50 EUR");
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Wallet plan"
    );
    assert_eq!(
        server.requests()[0].target(),
        "/v1/usage?days=30&timezone=Europe%2FIstanbul"
    );
}

#[tokio::test]
async fn root_versioned_and_complete_bases_normalize_to_one_usage_path() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, QUOTA.to_vec()),
    ])
    .await;
    for base in ["/proxy", "/proxy/v1", "/proxy/v1/usage"] {
        provider(&server, base, "account-a", RetryPolicy::none())
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect("normalized usage path");
    }
    assert!(server.requests().iter().all(|request| {
        request
            .target()
            .starts_with("/proxy/v1/usage?days=30&timezone=")
    }));
}

#[tokio::test]
async fn response_authentication_and_strict_parse_failures_are_distinct() {
    let revoked = br#"{"mode":"unrestricted","isValid":false}"#;
    let fractional = br#"{"usage":{"today":{"requests":1.5}}}"#;
    let invalid_date = br#"{"expires_at":"not-a-date"}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, revoked.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, fractional.to_vec()),
        FakeHttpResponse::new(200, invalid_date.to_vec()),
    ])
    .await;
    let provider = provider(&server, "/", "account-a", RetryPolicy::none());
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::Parse,
        ErrorKind::Parse,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("scripted response failure");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?}").contains("response-canary"));
    }
}

#[tokio::test]
async fn status_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "/", "account-a", RetryPolicy::none());
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::AuthenticationExpired,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Api,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("scripted HTTP failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
    }

    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider.fetch_at(&provider_context, timestamp(2)).await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let before = server.requests().len();
    assert_eq!(
        provider
            .fetch_at(&context("account-b"), timestamp(3))
            .await
            .expect_err("cross-account context")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), before);
}

#[tokio::test]
async fn transient_failure_retries_and_cross_origin_redirect_is_rejected() {
    let retry_server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, QUOTA.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&retry_server, "/", "account-a", retry)
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("retried fixture");
    assert_eq!(retry_server.requests().len(), 2);

    let target = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let source =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let error = provider(&source, "/", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(target.requests().is_empty());
}
