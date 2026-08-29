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
use oab_providers::providers::crof::CrofProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const CREDITS: &[u8] = include_bytes!("../../../fixtures/providers/crof/credits.json");
const QUOTA: &[u8] = include_bytes!("../../../fixtures/providers/crof/quota.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/crof/malformed.json");
const KEY_CANARY: &str = "fixture-crof-key-canary";

fn timestamp(raw: &str) -> Timestamp {
    Timestamp::parse(raw).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Crof,
        ProviderInstanceId::new("crof-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str, retry: RetryPolicy) -> CrofProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    CrofProvider::from_client(client).expect("Crof provider")
}

#[test]
fn credential_aliases_keep_baseline_precedence_and_redact_values() {
    let environment = BTreeMap::from([
        ("CROF_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "CROFAI_API_KEY".to_owned(),
            "alternate-not-selected".to_owned(),
        ),
    ]);
    let credential = CrofProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));

    let alternate = BTreeMap::from([("CROFAI_API_KEY".to_owned(), KEY_CANARY.to_owned())]);
    CrofProvider::resolve_credential(&alternate).expect("alternate credential");
    assert_eq!(
        CrofProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn credits_only_fixture_floors_balance_and_projects_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    let fetched_at = timestamp("2026-07-15T12:00:00Z");
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Crof credits fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Crof);
    let primary = sample.primary().expect("credit window");
    assert!(primary.used_percent().expect("percent").get().abs() < f64::EPSILON);
    assert!(primary.duration().is_none());
    assert!(primary.resets_at().is_none());
    assert_eq!(
        primary
            .reset_description()
            .expect("credit balance")
            .as_str(),
        "$9.04"
    );
    assert!(sample.secondary().is_none());
    assert_eq!(
        sample.identity().login_method().expect("login").as_str(),
        "API key"
    );
    assert!(sample.cost().is_none());

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target(), "/usage_api/");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-crof-key-canary")
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
        "$9.04"
    );
}

#[tokio::test]
async fn request_quota_uses_primary_lane_and_next_chicago_midnight() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, QUOTA.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for (fetched_at, expected_reset) in [
        ("2026-07-15T12:00:00Z", "2026-07-16T05:00:00Z"),
        ("2026-03-08T07:00:00Z", "2026-03-09T05:00:00Z"),
        ("2026-11-01T05:30:00Z", "2026-11-02T06:00:00Z"),
    ] {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(fetched_at))
            .await
            .expect("request quota fixture");
        let primary = sample.primary().expect("request window");
        assert!((primary.used_percent().expect("percent").get() - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            primary.duration().expect("daily duration").seconds(),
            24 * 60 * 60
        );
        assert_eq!(primary.resets_at(), Some(timestamp(expected_reset)));
        assert_eq!(
            primary
                .reset_description()
                .expect("request detail")
                .as_str(),
            "998 requests left"
        );
        let secondary = sample.secondary().expect("credit window");
        assert_eq!(
            secondary
                .reset_description()
                .expect("credit detail")
                .as_str(),
            "$10.00"
        );
    }
}

#[tokio::test]
async fn balance_depletion_quota_clamping_and_fractional_requests_match_plugin() {
    let funded = br#"{"credits":9.9999,"requests_plan":null,"usable_requests":null}"#;
    let depleted = br#"{"credits":-4,"requests_plan":null,"usable_requests":null}"#;
    let fractional = br#"{"credits":1,"requests_plan":10,"usable_requests":8.125}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, funded.to_vec()),
        FakeHttpResponse::new(200, depleted.to_vec()),
        FakeHttpResponse::new(200, fractional.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());

    let funded = provider
        .fetch_at(&context("account-a"), timestamp("2026-07-15T12:00:00Z"))
        .await
        .expect("funded");
    assert_eq!(
        funded
            .primary()
            .expect("credits")
            .reset_description()
            .expect("balance")
            .as_str(),
        "$9.99"
    );
    let depleted = provider
        .fetch_at(&context("account-a"), timestamp("2026-07-15T12:00:00Z"))
        .await
        .expect("depleted");
    assert!(
        (depleted
            .primary()
            .expect("credits")
            .used_percent()
            .expect("percent")
            .get()
            - 100.0)
            .abs()
            < f64::EPSILON
    );
    assert_eq!(
        depleted
            .primary()
            .expect("credits")
            .reset_description()
            .expect("balance")
            .as_str(),
        "$0.00"
    );
    let fractional = provider
        .fetch_at(&context("account-a"), timestamp("2026-07-15T12:00:00Z"))
        .await
        .expect("fractional requests");
    assert_eq!(
        fractional
            .primary()
            .expect("requests")
            .reset_description()
            .expect("request detail")
            .as_str(),
        "8.13 requests left"
    );
}

#[tokio::test]
async fn optional_numbers_and_malformed_payloads_fail_closed() {
    let fixtures: [&[u8]; 5] = [
        MALFORMED,
        br"[]",
        br#"{"credits":null}"#,
        br#"{"credits":1,"requests_plan":"ten"}"#,
        br#"{"credits":1,"requests_plan":null,"usable_requests":"nine"}"#,
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
            .fetch_at(&context("account-a"), timestamp("2026-07-15T12:00:00Z"))
            .await
            .expect_err("malformed payload");
        assert_eq!(error.kind(), ErrorKind::Parse);
        assert!(!format!("{error:?}").contains("response-canary"));
    }
}

#[tokio::test]
async fn status_retry_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::PermissionDenied,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Api,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp("2026-07-15T12:00:00Z"))
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
    }

    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp("2026-07-15T12:00:00Z"))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider
            .fetch_at(&provider_context, timestamp("2026-07-15T12:00:01Z"))
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
            .fetch_at(&context("account-b"), timestamp("2026-07-15T12:00:02Z"))
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
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&server, "account-a", retry)
        .fetch_at(&context("account-a"), timestamp("2026-07-15T12:00:00Z"))
        .await
        .expect("retried fixture");
    assert_eq!(server.requests().len(), 2);
}
