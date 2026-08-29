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
use oab_providers::providers::zenmux::ZenMuxProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const SUBSCRIPTION: &[u8] = include_bytes!("../../../fixtures/providers/zenmux/subscription.json");
const BALANCE: &[u8] = include_bytes!("../../../fixtures/providers/zenmux/balance.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/zenmux/malformed.json");
const KEY_CANARY: &str = "fixture-zenmux-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::ZenMux,
        ProviderInstanceId::new("zenmux-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str, retry: RetryPolicy) -> ZenMuxProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/api/v1/management/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    ZenMuxProvider::from_client(client).expect("ZenMux provider")
}

fn assert_quota_windows(sample: &oab_domain::UsageSample) {
    let primary = sample.primary().expect("five hour");
    assert!((primary.used_percent().expect("percent").get() - 7.15).abs() < 0.0001);
    assert_eq!(primary.duration().expect("duration").seconds(), 18_000);
    assert_eq!(
        primary.reset_description().expect("detail").as_str(),
        "57.20 / 800 flows"
    );
    let secondary = sample.secondary().expect("weekly");
    assert!((secondary.used_percent().expect("percent").get() - 6.73).abs() < 0.0001);
    assert_eq!(secondary.duration().expect("duration").seconds(), 604_800);
    assert_eq!(
        secondary.reset_description().expect("detail").as_str(),
        "416.11 / 6182 flows"
    );
}

#[test]
fn management_credential_resolution_is_exact_and_redacted() {
    let environment = BTreeMap::from([(
        "ZENMUX_MANAGEMENT_API_KEY".to_owned(),
        format!(" '{KEY_CANARY}' "),
    )]);
    let credential = ZenMuxProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));
    assert_eq!(
        ZenMuxProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn subscription_and_balance_project_quota_expiry_identity_cost_and_cli_schema() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("ZenMux fixture");

    assert_eq!(provider.descriptor().id, ProviderId::ZenMux);
    assert_quota_windows(&sample);
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Ultra plan"
    );
    assert_eq!(
        sample.subscription_expires_at(),
        Some(Timestamp::parse("2026-04-12T08:26:56.000Z").expect("expiration"))
    );
    let cost = sample.cost().expect("PAYG balance");
    assert_eq!(cost.used().amount(), decimal("482.74"));
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("ZenMux PAYG balance"));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].target(),
        "/api/v1/management/subscription/detail"
    );
    assert_eq!(requests[1].target(), "/api/v1/management/payg/balance");
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-zenmux-key-canary")
            && request.header("accept") == Some("application/json")
    }));

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
async fn unhealthy_status_and_negative_overdue_balance_remain_visible() {
    let subscription = String::from_utf8(SUBSCRIPTION.to_vec())
        .expect("fixture UTF-8")
        .replace(
            "\"account_status\": \"healthy\"",
            "\"account_status\": \"monitored\"",
        );
    let balance = br#"{"success":true,"data":{"currency":"USD","total_credits":-12.34}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, subscription.into_bytes()),
        FakeHttpResponse::new(200, balance.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("unhealthy fixture");
    assert_eq!(
        sample.identity().login_method().expect("status").as_str(),
        "Ultra plan · Monitored"
    );
    assert_eq!(
        sample.cost().expect("overdue balance").used().amount(),
        decimal("-12.34")
    );
}

#[tokio::test]
async fn non_authentication_balance_failures_preserve_subscription_usage() {
    let non_usd = br#"{"success":true,"data":{"currency":"eur","total_credits":10}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, non_usd.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for _ in 0..2 {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect("best-effort balance");
        assert!(sample.primary().is_some());
        assert!(sample.cost().is_none());
    }
    assert_eq!(
        provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("balance auth failure")
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
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::AuthenticationExpired,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Api,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
        assert!(!debug.contains("response-canary"));
    }

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

    let before = server.requests().len();
    assert_eq!(
        provider
            .fetch_at(&context("account-b"), timestamp(1_800_000_002))
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
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&retry_server, "account-a", retry)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("retried fixture");
    assert_eq!(retry_server.requests().len(), 3);

    let target = FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let source =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let error = provider(&source, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(target.requests().is_empty());
}
