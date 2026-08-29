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
use oab_providers::providers::clinepass::ClinePassProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const LIMITS: &[u8] = include_bytes!("../../../fixtures/providers/clinepass/limits.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/clinepass/malformed.json");
const KEY_CANARY: &str = "fixture-clinepass-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::ClinePass,
        ProviderInstanceId::new("clinepass-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str, retry: RetryPolicy) -> ClinePassProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    ClinePassProvider::from_client(client).expect("ClinePass provider")
}

#[test]
fn credential_aliases_keep_baseline_precedence_and_redact_values() {
    let environment = BTreeMap::from([
        ("CLINE_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "CLINEPASS_API_KEY".to_owned(),
            "alternate-not-selected".to_owned(),
        ),
    ]);
    let credential = ClinePassProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));

    let alternate = BTreeMap::from([("CLINEPASS_API_KEY".to_owned(), KEY_CANARY.to_owned())]);
    ClinePassProvider::resolve_credential(&alternate).expect("alternate credential");
    assert_eq!(
        ClinePassProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn golden_fixture_projects_all_three_windows_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, LIMITS.to_vec())]).await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("ClinePass fixture");

    assert_eq!(provider.descriptor().id, ProviderId::ClinePass);
    let primary = sample.primary().expect("5-hour window");
    assert!((primary.used_percent().expect("percent").get() - 12.5).abs() < f64::EPSILON);
    assert_eq!(
        primary.duration().expect("5-hour duration").seconds(),
        5 * 60 * 60
    );
    assert_eq!(
        primary.resets_at(),
        Some(Timestamp::parse("2026-07-16T10:20:30Z").expect("5-hour reset"))
    );
    let secondary = sample.secondary().expect("weekly window");
    assert!((secondary.used_percent().expect("percent").get() - 34.0).abs() < f64::EPSILON);
    assert_eq!(
        secondary.duration().expect("weekly duration").seconds(),
        7 * 24 * 60 * 60
    );
    let tertiary = sample.tertiary().expect("monthly window");
    assert!((tertiary.used_percent().expect("percent").get() - 56.75).abs() < f64::EPSILON);
    assert_eq!(
        tertiary.duration().expect("monthly duration").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        sample.identity().login_method().expect("login").as_str(),
        "API key"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target(), "/api/v1/users/me/plan/usage-limits");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-clinepass-key-canary")
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
        json["snapshots"][0]["last_known_good"]["tertiary"]["duration_seconds"],
        2_592_000
    );
}

#[tokio::test]
async fn unknown_limits_are_ignored_known_values_clamp_and_last_duplicate_wins() {
    let payload = br#"{
      "success": true,
      "data": {"limits": [
        {"type":"weekly","percentUsed":-20,"resetsAt":null},
        {"type":"experimental_pool","percentUsed":"ignored","resetsAt":42},
        {"type":"weekly","percentUsed":125}
      ]}
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, payload.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("unknown and duplicate limits");
    assert!(sample.primary().is_none());
    assert!(sample.tertiary().is_none());
    assert!(
        (sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("percent")
            .get()
            - 100.0)
            .abs()
            < f64::EPSILON
    );
}

#[tokio::test]
async fn malformed_plugin_shapes_fail_closed_without_response_text() {
    let fixtures: [&[u8]; 8] = [
        MALFORMED,
        br#"{"success":false,"data":{"limits":[]}}"#,
        br#"{"data":{"limits":[]}}"#,
        br#"{"success":true,"data":[]}"#,
        br#"{"success":true,"data":{"limits":{}}}"#,
        br#"{"success":true,"data":{"limits":[null]}}"#,
        br#"{"success":true,"data":{"limits":[{"type":4}]}}"#,
        br#"{"success":true,"data":{"limits":[{"type":"weekly","percentUsed":4,"resetsAt":"bad"}]}}"#,
    ];
    let server = FakeHttpServer::start(
        fixtures
            .into_iter()
            .map(|body| FakeHttpResponse::new(200, body.to_vec())),
    )
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for _ in fixtures {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("malformed payload");
        assert_eq!(error.kind(), ErrorKind::Parse);
        assert!(!format!("{error:?}").contains("response-canary"));
    }
}

#[tokio::test]
async fn http_failures_retry_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(200, LIMITS.to_vec()),
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
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
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
async fn transient_failure_is_retried_once() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, LIMITS.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&server, "account-a", retry)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("retried fixture");
    assert_eq!(server.requests().len(), 2);
}
