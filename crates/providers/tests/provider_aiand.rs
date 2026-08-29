use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, DataConfidence, ErrorKind, ExactDecimal, Freshness, PrivacyKey,
    PrivacyPolicy, PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::aiand::AiAndProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const FIRST_PAGE: &[u8] = include_bytes!("../../../fixtures/providers/aiand/first_page.json");
const FINAL_PAGE: &[u8] = include_bytes!("../../../fixtures/providers/aiand/final_page.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/aiand/malformed.json");
const KEY_CANARY: &str = "fixture-aiand-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::AiAnd,
        ProviderInstanceId::new("aiand-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str) -> AiAndProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    AiAndProvider::from_client(client).expect("ai& provider")
}

#[test]
fn credential_resolution_is_trimmed_unquoted_and_redacted() {
    let environment = BTreeMap::from([("AIAND_API_KEY".to_owned(), format!(" '{KEY_CANARY}' "))]);
    let credential = AiAndProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));
    assert_eq!(
        AiAndProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn final_page_projects_exact_spend_request_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, FINAL_PAGE.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("ai& fixture");

    assert_eq!(provider.descriptor().id, ProviderId::AiAnd);
    assert!(sample.primary().is_none());
    assert_eq!(sample.confidence(), DataConfidence::Exact);
    let cost = sample.cost().expect("30-day spend");
    assert_eq!(cost.used().amount(), decimal("8.12344"));
    assert_eq!(cost.used().unit().as_str(), "JPY");
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("Last 30 days"));
    assert_eq!(cost.period_end(), Some(fetched_at));
    assert_eq!(
        cost.period_start(),
        Some(timestamp(1_800_000_000 - 30 * 24 * 60 * 60))
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target(), "/logs?range=30days&limit=100");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-aiand-key-canary")
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
        "8.12344"
    );
}

#[tokio::test]
async fn pagination_sends_both_exact_cursors_and_sums_pages() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, FIRST_PAGE.to_vec()),
        FakeHttpResponse::new(200, FINAL_PAGE.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("paginated fixture");
    assert_eq!(
        sample.cost().expect("cost").used().amount(),
        decimal("20.62344")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[1].target(),
        "/logs?range=30days&limit=100&after=2026-07-17%2010:24:30.094374%2B00&after_id=912bf992-0000-4000-8000-000000000002"
    );
}

#[tokio::test]
async fn page_cap_and_missing_cursor_mark_spend_partial() {
    let capped =
        FakeHttpServer::start((0..10).map(|_| FakeHttpResponse::new(200, FIRST_PAGE.to_vec())))
            .await;
    let sample = provider(&capped, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("capped fixture");
    assert_eq!(capped.requests().len(), 10);
    assert_eq!(sample.confidence(), DataConfidence::Estimated);
    let cost = sample.cost().expect("partial cost");
    assert_eq!(cost.used().amount(), decimal("125"));
    assert_eq!(cost.period(), Some("Last 30 days (partial)"));

    let missing_cursor = br#"{"data":[{"cost":"2.5","currency":"jpy"}],"has_more":true,"next_after":null,"next_after_id":null}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, missing_cursor.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("missing cursor is a partial success");
    assert_eq!(sample.confidence(), DataConfidence::Estimated);
    assert_eq!(
        sample.cost().expect("partial cost").period(),
        Some("Last 30 days (partial)")
    );
}

#[tokio::test]
async fn newest_priced_currency_wins_and_empty_window_omits_cost() {
    let mixed = br#"{"data":[{"cost":"9.5","currency":"jpy"},{"cost":"1.25","currency":"usd"},{"cost":"0.5","currency":" JPY "}],"has_more":false}"#;
    let empty = br#"{"data":[{"cost":"4.2","currency":null},{"cost":"1","currency":"  "}],"has_more":false}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, mixed.to_vec()),
        FakeHttpResponse::new(200, empty.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let mixed_sample = provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("mixed currency");
    assert_eq!(
        mixed_sample.cost().expect("JPY cost").used().amount(),
        decimal("10")
    );
    assert_eq!(
        mixed_sample
            .cost()
            .expect("JPY cost")
            .used()
            .unit()
            .as_str(),
        "JPY"
    );
    let empty_sample = provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_001))
        .await
        .expect("empty priced window");
    assert!(empty_sample.cost().is_none());
    assert_eq!(empty_sample.confidence(), DataConfidence::Exact);
}

#[tokio::test]
async fn authentication_payment_rate_provider_api_and_parse_failures_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(402, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::truncated(200, FINAL_PAGE.len() + 10, FINAL_PAGE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::Api,
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
async fn malformed_refresh_retains_last_good_and_accounts_are_isolated() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, FINAL_PAGE.to_vec()),
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
