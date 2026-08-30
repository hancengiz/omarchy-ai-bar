use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy, PrivacySurface,
    ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
    UsageSample,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::venice::VeniceProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const DIEM: &[u8] = include_bytes!("../../../fixtures/providers/venice/balance_diem.json");
const USD: &[u8] = include_bytes!("../../../fixtures/providers/venice/balance_usd.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/venice/malformed.json");
const KEY_CANARY: &str = "fixture-venice-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope_for(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(format!("{}-primary", provider.as_str()))
            .expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn scope(account: &str) -> AccountScope {
    scope_for(ProviderId::Venice, account)
}

fn config(max_response_bytes: usize) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        max_response_bytes,
        3,
        RetryPolicy::none(),
    )
    .expect("fixture config")
}

fn context_with_source(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn context(account: &str) -> ProviderContext {
    context_with_source(account, ProviderSource::ApiKey)
}

fn provider_with_limit(
    server: &FakeHttpServer,
    account: &str,
    max_response_bytes: usize,
) -> VeniceProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(max_response_bytes),
    )
    .expect("fixed API client");
    VeniceProvider::from_client(client).expect("Venice provider")
}

fn provider(server: &FakeHttpServer, account: &str) -> VeniceProvider {
    provider_with_limit(server, account, 5 * 1024 * 1024)
}

fn assert_window(sample: &UsageSample, expected_percent: f64, expected_description: &str) {
    let primary = sample.primary().expect("primary balance window");
    let actual = primary.used_percent().expect("known percent").get();
    assert!((actual - expected_percent).abs() < f64::EPSILON);
    assert!(primary.duration().is_none());
    assert!(primary.resets_at().is_none());
    assert_eq!(
        primary
            .reset_description()
            .expect("balance description")
            .as_str(),
        expected_description
    );
}

async fn fetch_body(body: &[u8]) -> Result<UsageSample, oab_domain::ClassifiedError> {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
}

#[test]
fn credential_aliases_preserve_precedence_cleanup_and_redaction() {
    let environment = BTreeMap::from([
        ("VENICE_API_KEY".to_owned(), format!("  \"{KEY_CANARY}\"  ")),
        ("VENICE_KEY".to_owned(), "not-selected".to_owned()),
    ]);
    let credential = VeniceProvider::resolve_credential(&environment).expect("primary credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));

    let alternate = BTreeMap::from([("VENICE_KEY".to_owned(), format!(" '{KEY_CANARY}' "))]);
    VeniceProvider::resolve_credential(&alternate).expect("fallback credential");

    for environment in [
        BTreeMap::new(),
        BTreeMap::from([("VENICE_API_KEY".to_owned(), "   ".to_owned())]),
        BTreeMap::from([("VENICE_API_KEY".to_owned(), "''".to_owned())]),
        BTreeMap::from([("VENICE_API_KEY".to_owned(), "line\nbreak".to_owned())]),
    ] {
        assert_eq!(
            VeniceProvider::resolve_credential(&environment)
                .expect_err("unusable key")
                .kind(),
            ErrorKind::MissingCredential
        );
    }

    let oversized = BTreeMap::from([("VENICE_API_KEY".to_owned(), "x".repeat(16 * 1024 + 1))]);
    assert_eq!(
        VeniceProvider::resolve_credential(&oversized)
            .expect_err("oversized key")
            .kind(),
        ErrorKind::MissingCredential
    );

    VeniceProvider::new(
        scope("account-a"),
        ApiKeyCredential::new(KEY_CANARY).expect("credential"),
    )
    .expect("fixed production client");
}

#[tokio::test]
async fn diem_fixture_matches_cutover_golden_and_exact_request_contract() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, DIEM.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_775_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Venice DIEM fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Venice);
    assert_window(&sample, 50.0, "DIEM 50.00 / 100.00 epoch allocation");
    assert!(sample.secondary().is_none());
    assert!(sample.tertiary().is_none());
    assert!(sample.extra_windows().is_empty());
    assert!(sample.balance().is_none());
    assert!(sample.cost().is_none());
    assert!(sample.cost_usage().is_none());
    assert!(sample.identity().email().is_none());
    assert!(sample.identity().organization().is_none());
    assert!(sample.identity().login_method().is_none());

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/api/v1/billing/balance");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-venice-key-canary")
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
        json["snapshots"][0]["last_known_good"]["primary"]["usage"]["used_percent"],
        50.0
    );
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["primary"]["reset_description"],
        "DIEM 50.00 / 100.00 epoch allocation"
    );
}

#[tokio::test]
async fn currency_and_balance_precedence_matches_the_pinned_plugin() {
    let cases: &[(&[u8], f64, &str)] = &[
        (USD, 0.0, "$25.75 USD remaining"),
        (
            br#"{"canConsume":true,"consumptionCurrency":"usd","balances":{"diem":50,"usd":12.34},"diemEpochAllocation":100}"#,
            0.0,
            "$12.34 USD remaining",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":" usd ","balances":{"diem":75,"usd":12.34},"diemEpochAllocation":100}"#,
            25.0,
            "DIEM 75.00 / 100.00 epoch allocation",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"USD","balances":{"diem":50,"usd":0},"diemEpochAllocation":100}"#,
            0.0,
            "DIEM 50.00 remaining",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"DIEM","balances":{"diem":50,"usd":null},"diemEpochAllocation":null}"#,
            0.0,
            "DIEM 50.00 remaining",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":null,"balances":{"diem":null,"usd":15.5},"diemEpochAllocation":null}"#,
            0.0,
            "$15.50 USD remaining",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"USD","balances":{"diem":0,"usd":0},"diemEpochAllocation":null}"#,
            100.0,
            "No Venice API balance available",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":null,"balances":{"diem":null,"usd":null},"diemEpochAllocation":null}"#,
            100.0,
            "No Venice API balance available",
        ),
        (
            br#"{"canConsume":false,"consumptionCurrency":"USD","balances":{"diem":null,"usd":100},"diemEpochAllocation":null}"#,
            100.0,
            "Balance unavailable for API calls",
        ),
    ];
    for (body, percent, description) in cases {
        let sample = fetch_body(body).await.expect("valid precedence fixture");
        assert_window(&sample, *percent, description);
    }
}

#[tokio::test]
async fn numeric_string_coercion_rounding_and_percentage_clamps_match_javascript() {
    let cases: &[(&[u8], f64, &str)] = &[
        (
            br#"{"canConsume":true,"consumptionCurrency":"DIEM","balances":{"diem":"90.50","usd":"25.75"},"diemEpochAllocation":"100.0"}"#,
            9.5,
            "DIEM 90.50 / 100.00 epoch allocation",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"DIEM","balances":{"diem":"0x10","usd":null},"diemEpochAllocation":"0x20"}"#,
            50.0,
            "DIEM 16.00 / 32.00 epoch allocation",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"DIEM","balances":{"diem":"  ","usd":null},"diemEpochAllocation":"1e2"}"#,
            100.0,
            "DIEM 0.00 / 100.00 epoch allocation",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"DIEM","balances":{"diem":150,"usd":null},"diemEpochAllocation":100}"#,
            0.0,
            "DIEM 150.00 / 100.00 epoch allocation",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"DIEM","balances":{"diem":-50,"usd":null},"diemEpochAllocation":100}"#,
            100.0,
            "DIEM -50.00 / 100.00 epoch allocation",
        ),
        (
            br#"{"canConsume":true,"consumptionCurrency":"DIEM","balances":{"diem":"","usd":"1.005"},"diemEpochAllocation":""}"#,
            0.0,
            "$1.00 USD remaining",
        ),
    ];
    for (body, percent, description) in cases {
        let sample = fetch_body(body).await.expect("valid numeric fixture");
        assert_window(&sample, *percent, description);
    }
}

#[tokio::test]
async fn malformed_or_incomplete_payloads_fail_closed_even_when_consumption_is_disabled() {
    let cases: &[&[u8]] = &[
        MALFORMED,
        br"[]",
        br"null",
        br"{}",
        br#"{"canConsume":1,"balances":{}}"#,
        br#"{"canConsume":true,"balances":[]}"#,
        br#"{"canConsume":true,"consumptionCurrency":3,"balances":{}}"#,
        br#"{"canConsume":true,"balances":{"diem":false}}"#,
        br#"{"canConsume":true,"balances":{"usd":{}}}"#,
        br#"{"canConsume":true,"balances":{},"diemEpochAllocation":[]}"#,
        br#"{"canConsume":false,"consumptionCurrency":"USD","balances":{"diem":"bad","usd":100}}"#,
        br"{ invalid json }",
    ];
    for body in cases {
        let error = fetch_body(body).await.expect_err("invalid Venice payload");
        assert_eq!(error.kind(), ErrorKind::Parse);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("not-a-number"));
    }
}

#[tokio::test]
async fn every_non_200_status_is_api_failure_and_input_is_bounded() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(201, USD.to_vec()),
        FakeHttpResponse::new(401, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(408, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
    ])
    .await;
    let adapter = provider(&server, "account-a");
    for _ in 0..6 {
        let error = adapter
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("non-200 response");
        assert_eq!(error.kind(), ErrorKind::Api);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
    }
    assert_eq!(server.requests().len(), 6);

    let truncated = FakeHttpServer::start([FakeHttpResponse::truncated(
        200,
        USD.len() + 10,
        USD.to_vec(),
    )])
    .await;
    assert_eq!(
        provider(&truncated, "account-a")
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("truncated response")
            .kind(),
        ErrorKind::Parse
    );

    let oversized = FakeHttpServer::start([FakeHttpResponse::new(200, USD.to_vec())]).await;
    assert_eq!(
        provider_with_limit(&oversized, "account-a", 64)
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("oversized response")
            .kind(),
        ErrorKind::Parse
    );

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    assert_eq!(
        provider(&stalled, "account-a")
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("request timeout")
            .kind(),
        ErrorKind::Network
    );
}

#[tokio::test]
async fn refresh_scope_source_and_provider_identity_are_isolated() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USD.to_vec()),
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

    let before = server.requests().len();
    for mismatched in [
        context("account-b"),
        context_with_source("account-a", ProviderSource::ConfigurableEndpoint),
    ] {
        assert_eq!(
            provider
                .fetch_at(&mismatched, timestamp(1_800_000_002))
                .await
                .expect_err("scope/source mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
    assert_eq!(server.requests().len(), before);

    let wrong_client = FixedApiClient::new_bearer(
        scope_for(ProviderId::Crof, "account-a"),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("credential"),
        config(1024),
    )
    .expect("wrong-provider client");
    let Err(error) = VeniceProvider::from_client(wrong_client) else {
        panic!("wrong provider was accepted");
    };
    assert_eq!(error.kind(), ErrorKind::Api);
}

#[tokio::test]
async fn cross_origin_redirect_is_rejected_before_the_key_reaches_the_target() {
    let target = FakeHttpServer::start([FakeHttpResponse::new(200, USD.to_vec())]).await;
    let source =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let error = provider(&source, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(source.requests().len(), 1);
    assert!(target.requests().is_empty());
}
