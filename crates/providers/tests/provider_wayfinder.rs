use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy, PrivacySurface,
    ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::wayfinder::{WayfinderProvider, WayfinderSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const HEALTH: &[u8] = include_bytes!("../../../fixtures/providers/wayfinder/health.json");
const MODELS: &[u8] = include_bytes!("../../../fixtures/providers/wayfinder/models.json");
const SAVINGS: &[u8] = include_bytes!("../../../fixtures/providers/wayfinder/savings.json");
const METRICS: &[u8] = include_bytes!("../../../fixtures/providers/wayfinder/metrics.txt");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/wayfinder/malformed.json");

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Wayfinder,
        ProviderInstanceId::new("wayfinder-primary").expect("provider instance"),
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
        ProviderSource::ConfigurableEndpoint,
        CancellationToken::new(),
    )
}

fn provider(
    server: &FakeHttpServer,
    base_path: &str,
    account: &str,
    retry: RetryPolicy,
) -> WayfinderProvider {
    let endpoint = ConfiguredEndpoint::parse(
        server.url(base_path).as_str(),
        ConfiguredHttpPolicy::LoopbackHttp,
    )
    .expect("fixture endpoint");
    WayfinderProvider::from_endpoint(scope(account), endpoint, config(retry))
        .expect("Wayfinder provider")
}

fn success_responses(metrics: FakeHttpResponse) -> [FakeHttpResponse; 4] {
    [
        FakeHttpResponse::new(200, HEALTH.to_vec()),
        FakeHttpResponse::new(200, MODELS.to_vec()),
        FakeHttpResponse::new(200, SAVINGS.to_vec()),
        metrics,
    ]
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
fn settings_default_without_credentials_and_reject_unsafe_overrides() {
    let defaults = WayfinderSettings::resolve(&BTreeMap::new()).expect("default endpoint");
    assert!(!format!("{defaults:?}").contains("127.0.0.1"));

    for endpoint in [
        "http://127.0.0.1:9090",
        "http://localhost:8088",
        "https://wayfinder.example.com/wf",
    ] {
        let environment =
            BTreeMap::from([("WAYFINDER_GATEWAY_URL".to_owned(), endpoint.to_owned())]);
        WayfinderSettings::resolve(&environment).expect("allowed gateway");
    }
    for endpoint in [
        "http://192.168.1.5:8088",
        "http://attacker.test",
        "http://user@127.0.0.1:8088",
        "https://wayfinder.example.com?secret=value",
    ] {
        let environment =
            BTreeMap::from([("WAYFINDER_GATEWAY_URL".to_owned(), endpoint.to_owned())]);
        assert_eq!(
            WayfinderSettings::resolve(&environment)
                .expect_err("unsafe gateway")
                .kind(),
            ErrorKind::Api
        );
    }
}

#[tokio::test]
async fn live_gateway_fixture_projects_health_routing_savings_latency_and_cli_schema() {
    let server = FakeHttpServer::start(success_responses(FakeHttpResponse::new(
        200,
        METRICS.to_vec(),
    )))
    .await;
    let provider = provider(&server, "/wf/", "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Wayfinder fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Wayfinder);
    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.cost().is_none());
    assert_eq!(sample.detail_sections()[0].title(), Some("Usage"));
    assert_eq!(detail_value(&sample, "Gateway"), "ok · 2 models");
    assert_eq!(detail_value(&sample, "Routed"), "local: 10 · cloud: 4");
    assert_eq!(
        detail_value(&sample, "Saved"),
        "<$0.01 · 61.5% vs highest-cost route"
    );
    assert_eq!(detail_value(&sample, "Avg decision"), "0.1 ms");
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("gateway organization")
            .as_str(),
        "2 models · local gateway"
    );
    assert_eq!(
        sample.identity().login_method().expect("status").as_str(),
        "Local gateway"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].target(), "/wf/healthz");
    assert_eq!(requests[1].target(), "/wf/router/models");
    assert_eq!(requests[2].target(), "/wf/v1/savings?period=30d");
    assert_eq!(requests[3].target(), "/wf/metrics");
    assert!(
        requests
            .iter()
            .all(|request| request.header("authorization").is_none())
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
async fn degraded_offline_and_dry_run_status_precedence_matches_baseline() {
    let degraded = br#"{"status":"degraded","offline":false,"missing_keys":["cloud"]}"#;
    let dry_models = br#"{"models":[{"name":"local"}],"dry_run":true}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, degraded.to_vec()),
        FakeHttpResponse::new(200, MODELS.to_vec()),
        FakeHttpResponse::new(200, SAVINGS.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, degraded.to_vec()),
        FakeHttpResponse::new(200, dry_models.to_vec()),
        FakeHttpResponse::new(200, SAVINGS.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    let provider = provider(&server, "/", "account-a", RetryPolicy::none());
    let degraded_sample = provider
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("degraded fixture");
    assert_eq!(
        degraded_sample
            .identity()
            .login_method()
            .expect("status")
            .as_str(),
        "Degraded — 1 key missing"
    );
    let dry_sample = provider
        .fetch_at(&context("account-a"), timestamp(2))
        .await
        .expect("dry-run fixture");
    assert_eq!(
        dry_sample
            .identity()
            .login_method()
            .expect("status")
            .as_str(),
        "Dry run"
    );
    assert_eq!(
        detail_value(&dry_sample, "Gateway"),
        "degraded · 1 model · dry run"
    );
}

#[tokio::test]
async fn unpriced_savings_hide_currency_and_metrics_failure_is_best_effort() {
    let unpriced = br#"{
      "priced":false,"requests":5,"tokens":420,"realized":1.8,"baseline":3.0,
      "saved":1.2,"saved_pct":40.0,
      "by_route":{"local":{"requests":4,"saved":1.2,"tokens":320}}
    }"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, HEALTH.to_vec()),
        FakeHttpResponse::new(200, MODELS.to_vec()),
        FakeHttpResponse::new(200, unpriced.to_vec()),
        FakeHttpResponse::new(503, Vec::new()),
    ])
    .await;
    let sample = provider(&server, "/", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("best-effort metrics");
    assert_eq!(detail_value(&sample, "Saved"), "40% vs highest-cost route");
    assert!(
        sample.detail_sections()[0]
            .rows()
            .iter()
            .all(|row| row.label() != "Avg decision")
    );
}

#[tokio::test]
async fn required_status_parse_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, HEALTH.to_vec()),
        FakeHttpResponse::new(200, MODELS.to_vec()),
        FakeHttpResponse::new(200, SAVINGS.to_vec()),
        FakeHttpResponse::new(200, METRICS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "/", "account-a", RetryPolicy::none());
    for expected in [
        ErrorKind::ProviderUnavailable,
        ErrorKind::Api,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("required endpoint failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains("fixture-error-canary"));
        assert!(!debug.contains("response-canary"));
    }

    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(2))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider.fetch_at(&provider_context, timestamp(3)).await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let before = server.requests().len();
    assert_eq!(
        provider
            .fetch_at(&context("account-b"), timestamp(4))
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
        FakeHttpResponse::new(200, HEALTH.to_vec()),
        FakeHttpResponse::new(200, MODELS.to_vec()),
        FakeHttpResponse::new(200, SAVINGS.to_vec()),
        FakeHttpResponse::new(200, METRICS.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&retry_server, "/", "account-a", retry)
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("retried fixture");
    assert_eq!(retry_server.requests().len(), 5);

    let target = FakeHttpServer::start([FakeHttpResponse::new(200, HEALTH.to_vec())]).await;
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
