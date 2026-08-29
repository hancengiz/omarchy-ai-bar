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
use oab_providers::providers::deepgram::{DeepgramProvider, DeepgramSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const PROJECTS: &[u8] = include_bytes!("../../../fixtures/providers/deepgram/projects.json");
const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/deepgram/usage.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/deepgram/malformed.json");
const KEY_CANARY: &str = "fixture-deepgram-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Deepgram,
        ProviderInstanceId::new("deepgram-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str, project: Option<&str>) -> DeepgramProvider {
    let client = FixedApiClient::new_authorization_scheme(
        scope(account),
        server.url("/v1"),
        EndpointClass::LoopbackDevelopment,
        "Token",
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    DeepgramProvider::from_client(client, project).expect("Deepgram provider")
}

fn row<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a oab_domain::DetailRow {
    sample.detail_sections()[0]
        .rows()
        .iter()
        .find(|row| row.label() == label)
        .expect("detail row")
}

#[test]
fn settings_normalize_bare_https_and_redact_values() {
    let environment = BTreeMap::from([
        ("DEEPGRAM_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "DEEPGRAM_PROJECT_ID".to_owned(),
            " 'fixture-project-canary' ".to_owned(),
        ),
        (
            "DEEPGRAM_API_URL".to_owned(),
            "management.example.test/v1".to_owned(),
        ),
    ]);
    let settings = DeepgramSettings::resolve(&environment).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("fixture-project-canary"));
    assert!(!debug.contains("management.example.test"));

    assert_eq!(
        DeepgramSettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    let insecure = BTreeMap::from([
        ("DEEPGRAM_API_KEY".to_owned(), "fixture".to_owned()),
        (
            "DEEPGRAM_API_URL".to_owned(),
            "http://api.deepgram.com/v1".to_owned(),
        ),
    ]);
    assert_eq!(
        DeepgramSettings::resolve(&insecure)
            .expect_err("HTTP override")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn configured_project_projects_usage_details_identity_request_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(&server, "account-a", Some("project/123"));
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Deepgram fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Deepgram);
    assert!(sample.primary().is_none());
    assert_eq!(sample.detail_sections()[0].title(), Some("Usage summary"));
    assert_eq!(row(&sample, "Requests").value(), "373,400");
    assert_eq!(row(&sample, "Audio").value(), "1,622.0 hours");
    assert_eq!(
        row(&sample, "Audio").secondary_value(),
        Some("1,625.2 billable hours")
    );
    assert_eq!(row(&sample, "Agent hours").value(), "41.3");
    assert_eq!(row(&sample, "Tokens").value(), "1,540");
    assert_eq!(row(&sample, "TTS characters").value(), "9,158,866");
    assert_eq!(row(&sample, "Period").value(), "2025-01-16 to 2025-01-23");
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("project identity")
            .as_str(),
        "Project: project/123"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].target(),
        "/v1/projects/project%2F123/usage/breakdown"
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some("Token fixture-deepgram-key-canary")
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
        json["snapshots"][0]["last_known_good"]["detail_sections"][0]["rows"][0]["value"],
        "373,400"
    );
}

#[tokio::test]
async fn discovery_aggregates_every_project_and_period() {
    let first = br#"{"start":"2025-01-16","end":"2025-01-23","results":[{"hours":1,"total_hours":2,"requests":3}]}"#;
    let second = br#"{"start":"2025-01-17","end":"2025-01-24","results":[{"hours":4,"total_hours":5,"requests":6}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, PROJECTS.to_vec()),
        FakeHttpResponse::new(200, first.to_vec()),
        FakeHttpResponse::new(200, second.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a", None)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("aggregate projects");
    assert_eq!(row(&sample, "Requests").value(), "9");
    assert_eq!(row(&sample, "Audio").value(), "5 hours");
    assert_eq!(
        row(&sample, "Audio").secondary_value(),
        Some("7 billable hours")
    );
    assert_eq!(row(&sample, "Period").value(), "2025-01-16 to 2025-01-24");
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("aggregate identity")
            .as_str(),
        "2 projects"
    );
    assert_eq!(
        server
            .requests()
            .iter()
            .map(oab_test_support::http::CapturedHttpRequest::target)
            .collect::<Vec<_>>(),
        [
            "/v1/projects",
            "/v1/projects/project-a/usage/breakdown",
            "/v1/projects/project-b/usage/breakdown",
        ]
    );
}

#[tokio::test]
async fn authentication_rate_provider_api_and_parse_failures_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::truncated(200, USAGE.len() + 10, USAGE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", Some("project-a"));
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
}

#[tokio::test]
async fn malformed_refresh_retains_last_good_for_exact_account() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", Some("project-a"));
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
}

#[tokio::test]
async fn empty_duplicate_and_cross_account_discovery_fail_closed() {
    let duplicate = br#"{"projects":[{"project_id":"same"},{"project_id":"same"}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, br#"{"projects":[]}"#.to_vec()),
        FakeHttpResponse::new(200, duplicate.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", None);
    assert_eq!(
        provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("empty projects")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("duplicate projects")
            .kind(),
        ErrorKind::Parse
    );
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-account context");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), 2);
}
