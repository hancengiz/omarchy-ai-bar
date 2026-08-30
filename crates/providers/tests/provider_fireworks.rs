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
use oab_providers::providers::fireworks::{FireworksCredential, FireworksProvider};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const SUMMARY: &[u8] = include_bytes!("../../../fixtures/providers/fireworks/summary.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/fireworks/malformed.json");
const EMPTY_SUMMARY: &[u8] = br#"{"lineItems":[],"usageBuckets":[]}"#;
const KEY_CANARY: &str = "fixture-fireworks-key-canary";
const SLUG_CANARY: &str = "fixture-team-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Fireworks,
        ProviderInstanceId::new("fireworks-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str, slug: Option<&str>) -> FireworksProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    FireworksProvider::from_client(client, slug.map(str::to_owned)).expect("Fireworks provider")
}

#[test]
fn credential_resolution_uses_fireworks_precedence_and_rejects_unsafe_slugs() {
    let environment = BTreeMap::from([
        ("FIREWORKS_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        ("FIREWORKS_KEY".to_owned(), "not-selected".to_owned()),
        (
            "FIREWORKS_ACCOUNT_SLUG".to_owned(),
            format!(" \"{SLUG_CANARY}\" "),
        ),
    ]);
    let credential = FireworksCredential::resolve(&environment).expect("resolved credential");
    let debug = format!("{credential:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains(SLUG_CANARY));
    assert_eq!(
        FireworksCredential::new(
            ApiKeyCredential::new("key").expect("key"),
            Some("has/slash")
        )
        .expect_err("unsafe slug")
        .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        FireworksCredential::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn configured_summary_projects_exact_spend_window_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUMMARY.to_vec())]).await;
    let provider = provider(&server, "account-a", Some(SLUG_CANARY));
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Fireworks summary");

    assert_eq!(provider.descriptor().id, ProviderId::Fireworks);
    assert!(sample.primary().is_none());
    assert!(sample.balance().is_none());
    let cost = sample.cost().expect("cost summary");
    assert_eq!(cost.used().amount(), decimal("1.525548296"));
    assert_eq!(cost.used().unit().as_str(), "USD");
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("Last 30 days"));
    assert_eq!(
        cost.period_end().expect("period end"),
        timestamp(1_800_000_000)
    );
    assert_eq!(
        cost.period_start().expect("period start"),
        timestamp(1_797_408_000)
    );

    let request = &server.requests()[0];
    assert_eq!(request.method(), "GET");
    assert!(
        request
            .target()
            .starts_with("/v1/accounts/fixture-team-canary/billing/summary?")
    );
    assert!(request.target().contains("startTime="));
    assert!(request.target().contains("endTime="));
    assert_eq!(
        request.header("authorization"),
        Some("Bearer fixture-fireworks-key-canary")
    );
    assert_eq!(request.header("accept"), Some("application/json"));

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
        "1.525548296"
    );
}

#[tokio::test]
async fn missing_slug_discovers_single_account_before_billing() {
    let accounts = br#"{"accounts":[{"name":"accounts/discovered-team"}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, accounts.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", None);
    let sample = provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("auto-discovered account");
    assert_eq!(
        sample.cost().expect("cost").used().amount(),
        decimal("1.525548296")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target(), "/v1/accounts");
    assert!(
        requests[1]
            .target()
            .starts_with("/v1/accounts/discovered-team/billing/summary?")
    );
}

#[tokio::test]
async fn stale_configured_slug_discovers_the_sole_visible_replacement() {
    let accounts = br#"{"accounts":[{"accountId":"current-slug"}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(404, b"fixture-not-found-canary".to_vec()),
        FakeHttpResponse::new(200, accounts.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", Some("old-slug"));
    provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("replacement account");
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].target().contains("/old-slug/"));
    assert_eq!(requests[1].target(), "/v1/accounts");
    assert!(requests[2].target().contains("/current-slug/"));
}

#[tokio::test]
async fn ambiguous_or_wrong_accounts_fail_without_guessing() {
    let multiple = br#"{"accounts":[{"name":"accounts/zeta"},{"name":"accounts/alpha"}]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, multiple.to_vec())]).await;
    let error = provider(&server, "account-a", None)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("ambiguous accounts");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), 1);

    let actual = br#"{"accounts":[{"name":"accounts/actual-team"}]}"#;
    let wrong = FakeHttpServer::start([
        FakeHttpResponse::new(200, EMPTY_SUMMARY.to_vec()),
        FakeHttpResponse::new(200, actual.to_vec()),
    ])
    .await;
    let error = provider(&wrong, "account-a", Some("guessed-team"))
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("wrong configured account");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(wrong.requests().len(), 2);
}

#[tokio::test]
async fn pagination_is_bounded_and_repeated_tokens_are_rejected() {
    let page = br#"{"accounts":[],"nextPageToken":"cursor-canary"}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, page.to_vec()),
        FakeHttpResponse::new(200, page.to_vec()),
    ])
    .await;
    let error = provider(&server, "account-a", None)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("repeated cursor");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert_eq!(server.requests().len(), 2);
    assert!(
        server.requests()[1]
            .target()
            .contains("pageToken=cursor-canary")
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
        FakeHttpResponse::truncated(200, SUMMARY.len() + 10, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", Some(SLUG_CANARY));
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
        assert!(!debug.contains(SLUG_CANARY));
        assert!(!debug.contains("fixture-response-canary"));
        assert!(!debug.contains("fixture-error-canary"));
    }
}

#[tokio::test]
async fn malformed_refresh_retains_last_good_and_accounts_are_isolated() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let refresh_provider = provider(&server, "account-a", Some(SLUG_CANARY));
    let provider_context = context("account-a");
    let last_good = refresh_provider
        .fetch_at(&provider_context, timestamp(1_800_000_000))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        refresh_provider
            .fetch_at(&provider_context, timestamp(1_800_000_001))
            .await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let isolated = FakeHttpServer::start([FakeHttpResponse::new(200, SUMMARY.to_vec())]).await;
    let isolated_provider = provider(&isolated, "account-a", Some(SLUG_CANARY));
    let error = isolated_provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-account context");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(isolated.requests().is_empty());
}
