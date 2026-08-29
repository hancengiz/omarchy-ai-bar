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
use oab_providers::providers::warp::WarpProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/warp/usage.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/warp/malformed.json");
const KEY_CANARY: &str = "fixture-warp-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Warp,
        ProviderInstanceId::new("warp-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        2 * 1024 * 1024,
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

fn provider(server: &FakeHttpServer, account: &str) -> WarpProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    WarpProvider::from_client(client).expect("Warp provider")
}

#[test]
fn credential_resolution_is_ordered_and_redacted() {
    let environment = BTreeMap::from([
        ("WARP_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        ("WARP_TOKEN".to_owned(), "not-selected".to_owned()),
    ]);
    let credential = WarpProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));
    assert_eq!(
        WarpProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn fixture_projects_primary_bonus_reset_headers_body_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Warp fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Warp);
    let primary = sample.primary().expect("primary credits");
    assert!(
        (primary.used_percent().expect("primary percentage").get() - (100.0 / 300.0)).abs() < 1e-10
    );
    assert_eq!(
        primary.resets_at(),
        Some(Timestamp::parse("2026-09-01T00:00:00Z").expect("reset"))
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("primary detail")
            .as_str(),
        "5/1500 credits"
    );
    let secondary = sample.secondary().expect("add-on credits");
    assert!(
        (secondary
            .used_percent()
            .expect("secondary percentage")
            .get()
            - 57.5)
            .abs()
            < f64::EPSILON
    );
    assert_eq!(
        secondary
            .reset_description()
            .expect("bonus expiry detail")
            .as_str(),
        "12 credits expires on 2026-09-03T10:00:00Z"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method(), "POST");
    assert_eq!(request.target(), "/graphql/v2?op=GetRequestLimitInfo");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer fixture-warp-key-canary")
    );
    assert_eq!(request.header("user-agent"), Some("Warp/1.0"));
    assert_eq!(request.header("x-warp-client-id"), Some("warp-app"));
    assert_eq!(request.header("x-warp-os-category"), Some("Linux"));
    let body: serde_json::Value = serde_json::from_slice(request.body()).expect("request JSON");
    assert_eq!(body["operationName"], "GetRequestLimitInfo");
    assert!(
        body["query"]
            .as_str()
            .expect("GraphQL query")
            .contains("bonusGrantsInfo")
    );
    assert_eq!(
        body["variables"]["requestContext"]["osContext"]["category"],
        request.header("x-warp-os-category").expect("OS category")
    );
    assert_eq!(
        body["variables"]["requestContext"]["osContext"]["name"],
        request.header("x-warp-os-name").expect("OS name")
    );
    assert_eq!(
        body["variables"]["requestContext"]["osContext"]["version"],
        request.header("x-warp-os-version").expect("OS version")
    );

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
        json["snapshots"][0]["last_known_good"]["secondary"]["reset_description"],
        "12 credits expires on 2026-09-03T10:00:00Z"
    );
}

#[tokio::test]
async fn unlimited_usage_omits_reset_and_absent_bonus_lane() {
    let response = br#"{"data":{"user":{"__typename":"UserOutput","user":{"requestLimitInfo":{"isUnlimited":true,"nextRefreshTime":"2026-09-01T00:00:00Z","requestLimit":0,"requestsUsedSinceLastRefresh":0}}}}}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, response.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("unlimited fixture");
    let primary = sample.primary().expect("primary");
    assert!(primary.used_percent().expect("percentage").get().abs() < f64::EPSILON);
    assert_eq!(primary.resets_at(), None);
    assert_eq!(
        primary.reset_description().expect("detail").as_str(),
        "Unlimited"
    );
    assert!(sample.secondary().is_none());
}

#[tokio::test]
async fn exhausted_bonus_is_retained_as_a_full_secondary_lane() {
    let response = br#"{"data":{"user":{"__typename":"UserOutput","user":{"requestLimitInfo":{"isUnlimited":null,"requestLimit":"100","requestsUsedSinceLastRefresh":"5"},"bonusGrants":[{"requestCreditsGranted":"20","requestCreditsRemaining":"0"}]}}}}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, response.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("exhausted fixture");
    assert!(
        (sample
            .secondary()
            .expect("retained secondary")
            .used_percent()
            .expect("percentage")
            .get()
            - 100.0)
            .abs()
            < f64::EPSILON
    );
}

#[tokio::test]
async fn authentication_rate_provider_graphql_and_parse_failures_are_stable() {
    let graphql_error = br#"{"errors":[{"message":"fixture-graphql-canary"}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, b"Rate exceeded.".to_vec()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(200, graphql_error.to_vec()),
        FakeHttpResponse::truncated(200, USAGE.len() + 10, USAGE.to_vec()),
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
        assert!(!debug.contains("fixture-graphql-canary"));
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
}

#[tokio::test]
async fn account_identity_mismatch_fails_before_a_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-account context");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());
}
