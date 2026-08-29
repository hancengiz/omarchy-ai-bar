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
use oab_providers::providers::openai::{OpenAiCredential, OpenAiProvider};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const COSTS: &[u8] = include_bytes!("../../../fixtures/providers/openai/costs.json");
const COMPLETIONS: &[u8] = include_bytes!("../../../fixtures/providers/openai/completions.json");
const CREDITS: &[u8] = include_bytes!("../../../fixtures/providers/openai/credits.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/openai/malformed.json");
const EMPTY_PAGE: &[u8] = br#"{"object":"page","data":[],"has_more":false,"next_page":null}"#;
const KEY_CANARY: &str = "fixture-openai-key-canary";
const PROJECT_CANARY: &str = "proj_fixture_canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::OpenAi,
        ProviderInstanceId::new("openai-primary").expect("provider instance"),
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

fn provider(
    server: &FakeHttpServer,
    account: &str,
    uses_admin_key: bool,
    project_id: Option<&str>,
    history_days: u16,
) -> OpenAiProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    OpenAiProvider::from_client(
        client,
        uses_admin_key,
        project_id.map(str::to_owned),
        history_days,
    )
    .expect("OpenAI provider")
}

#[test]
fn credential_resolution_prefers_admin_key_and_redacts_scope() {
    let environment = BTreeMap::from([
        ("OPENAI_API_KEY".to_owned(), "legacy-canary".to_owned()),
        ("OPENAI_ADMIN_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "OPENAI_PROJECT_ID".to_owned(),
            format!(" \"{PROJECT_CANARY}\" "),
        ),
    ]);
    let credential = OpenAiCredential::resolve(&environment).expect("resolved credential");
    let debug = format!("{credential:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("legacy-canary"));
    assert!(!debug.contains(PROJECT_CANARY));

    let error = OpenAiCredential::resolve(&BTreeMap::new()).expect_err("missing key");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);
}

#[tokio::test]
async fn admin_fixture_projects_exact_cost_tokens_project_scope_and_cli_schema() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, COSTS.to_vec()),
        FakeHttpResponse::new(200, COMPLETIONS.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", true, Some(PROJECT_CANARY), 30);
    let fetched_at = timestamp(1_700_179_200);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("OpenAI admin fixture");

    assert_eq!(provider.descriptor().id, ProviderId::OpenAi);
    assert_eq!(sample.scope(), &scope("account-a"));
    assert!(sample.primary().is_none());
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("project organization")
            .as_str(),
        "Project: proj_fixture_canary"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("login method")
            .as_str(),
        "Admin API: proj_fixture_canary"
    );
    let cost = sample.cost().expect("cost summary");
    assert_eq!(cost.used().amount(), decimal("18.75"));
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("Last 30 days"));
    let usage = sample.cost_usage().expect("typed usage");
    assert_eq!(usage.metered_amount(), Some(decimal("18.75")));
    assert_eq!(usage.history_days(), 30);
    assert_eq!(usage.history_label(), Some("30d"));
    assert_eq!(usage.daily().len(), 2);
    assert_eq!(usage.history().request_count(), Some(12));
    assert_eq!(usage.history().total_tokens(), Some(2330));
    assert_eq!(usage.history().token_mix().cache_read_tokens(), Some(250));
    assert_eq!(usage.daily()[0].line_items().len(), 2);
    assert_eq!(usage.daily()[0].models().len(), 2);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].target().starts_with("/v1/organization/costs?"));
    assert!(
        requests[1]
            .target()
            .starts_with("/v1/organization/usage/completions?")
    );
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-openai-key-canary")
            && request.target().contains("project_ids=proj_fixture_canary")
    }));
    assert!(requests[0].target().contains("group_by=line_item"));
    assert!(requests[1].target().contains("group_by=model"));

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
        json["snapshots"][0]["last_known_good"]["cost_usage"]["metered_amount"],
        "18.75"
    );
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["cost_usage"]["daily"][0]["models"][0]["name"],
        "gpt-5.2"
    );
}

#[tokio::test]
async fn credit_fallback_projects_balance_reset_and_percent() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", true, None, 30);
    let sample = provider
        .fetch_at(&context("account-a"), timestamp(1_700_179_200))
        .await
        .expect("credit fallback");

    assert_eq!(
        sample.primary().expect("primary").used_percent(),
        Some(oab_domain::UsagePercent::new(25.0).expect("percent"))
    );
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .reset_description()
            .expect("balance summary")
            .as_str(),
        "$75.00 available"
    );
    assert_eq!(
        sample.primary().expect("primary").resets_at(),
        Some(timestamp(1_750_000_000))
    );
    assert_eq!(sample.balance().expect("balance").amount(), decimal("75"));
    assert_eq!(sample.cost().expect("cost").limit(), decimal("100"));
    assert_eq!(sample.cost().expect("cost").used().amount(), decimal("25"));
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("balance identity")
            .as_str(),
        "API balance: $75.00"
    );
    assert_eq!(server.requests().len(), 2);
    assert_eq!(
        server.requests()[1].target(),
        "/v1/dashboard/billing/credit_grants"
    );
}

#[tokio::test]
async fn project_scoped_admin_failure_never_requests_unscoped_credits() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", true, Some(PROJECT_CANARY), 30);
    let error = provider
        .fetch_at(&context("account-a"), timestamp(1_700_179_200))
        .await
        .expect_err("project-scoped admin failure");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(server.requests().len(), 1);
    assert!(
        server.requests()[0]
            .target()
            .contains("project_ids=proj_fixture_canary")
    );
}

#[tokio::test]
async fn history_is_chunked_to_openai_daily_limit() {
    let responses = (0..6).map(|_| FakeHttpResponse::new(200, EMPTY_PAGE.to_vec()));
    let server = FakeHttpServer::start(responses).await;
    let provider = provider(&server, "account-a", true, Some(PROJECT_CANARY), 90);
    let sample = provider
        .fetch_at(&context("account-a"), timestamp(1_700_179_200))
        .await
        .expect("empty long history");
    assert_eq!(sample.cost_usage().expect("usage").history_days(), 90);
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    let limits = requests
        .iter()
        .map(|request| {
            let url = url::Url::parse(&format!("http://fixture{}", request.target()))
                .expect("captured target URL");
            url.query_pairs()
                .find(|(key, _)| key == "limit")
                .map(|(_, value)| value.parse::<u16>().expect("numeric limit"))
                .expect("limit query")
        })
        .collect::<Vec<_>>();
    assert_eq!(limits, [31, 31, 28, 31, 31, 28]);
}

#[tokio::test]
async fn pagination_is_followed_and_repeated_cursors_are_rejected() {
    let page_one = br#"{"data":[],"has_more":true,"next_page":"cursor-canary"}"#;
    let page_two = br#"{"data":[],"has_more":false,"next_page":null}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, page_one.to_vec()),
        FakeHttpResponse::new(200, page_two.to_vec()),
        FakeHttpResponse::new(200, EMPTY_PAGE.to_vec()),
    ])
    .await;
    let paginated_provider = provider(&server, "account-a", true, Some(PROJECT_CANARY), 1);
    paginated_provider
        .fetch_at(&context("account-a"), timestamp(1_700_179_200))
        .await
        .expect("paginated fixture");
    assert_eq!(server.requests().len(), 3);
    assert!(!server.requests()[0].target().contains("page="));
    assert!(server.requests()[1].target().contains("page=cursor-canary"));

    let repeated = FakeHttpServer::start([
        FakeHttpResponse::new(200, page_one.to_vec()),
        FakeHttpResponse::new(200, page_one.to_vec()),
    ])
    .await;
    let repeated_provider = provider(&repeated, "account-a", true, Some(PROJECT_CANARY), 1);
    let error = repeated_provider
        .fetch_at(&context("account-a"), timestamp(1_700_179_200))
        .await
        .expect_err("repeated cursor");
    assert_eq!(error.kind(), ErrorKind::Parse);
}

#[tokio::test]
async fn authentication_rate_limit_provider_and_parse_failures_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::truncated(200, COSTS.len() + 10, COSTS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", true, Some(PROJECT_CANARY), 30);

    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::PermissionDenied,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Parse,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_700_179_200))
            .await
            .expect_err("scripted provider failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains(PROJECT_CANARY));
        assert!(!debug.contains("fixture-response-canary"));
    }
}

#[tokio::test]
async fn fallback_error_selection_preserves_the_actionable_failure() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
    ])
    .await;
    let provider = provider(&server, "account-a", false, None, 30);
    let unavailable = provider
        .fetch_at(&context("account-a"), timestamp(1_700_179_200))
        .await
        .expect_err("admin outage preserved");
    assert_eq!(unavailable.kind(), ErrorKind::ProviderUnavailable);
    let fallback_permission = provider
        .fetch_at(&context("account-a"), timestamp(1_700_179_200))
        .await
        .expect_err("fallback credential error selected");
    assert_eq!(fallback_permission.kind(), ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn malformed_refresh_retains_last_good_for_the_exact_account() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, COSTS.to_vec()),
        FakeHttpResponse::new(200, COMPLETIONS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", true, Some(PROJECT_CANARY), 30);
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1_700_179_200))
        .await
        .expect("initial fixture");
    let failed = provider
        .fetch_at(&provider_context, timestamp(1_700_179_201))
        .await;
    let outcome = preserve_last_good(Some(last_good.clone()), failed);
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));
}

#[tokio::test]
async fn account_identity_mismatch_fails_before_a_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, COSTS.to_vec())]).await;
    let provider = provider(&server, "account-a", true, Some(PROJECT_CANARY), 30);
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_700_179_200))
        .await
        .expect_err("cross-account context must fail");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());
}
