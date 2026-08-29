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
use oab_providers::providers::deepinfra::DeepInfraProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const CHECKLIST: &[u8] = include_bytes!("../../../fixtures/providers/deepinfra/checklist.json");
const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/deepinfra/usage.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/deepinfra/malformed.json");
const KEY_CANARY: &str = "fixture-deepinfra-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::DeepInfra,
        ProviderInstanceId::new("deepinfra-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str) -> DeepInfraProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    DeepInfraProvider::from_client(client).expect("DeepInfra provider")
}

#[test]
fn credential_resolution_is_ordered_and_redacted() {
    let environment = BTreeMap::from([
        ("DEEPINFRA_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        ("DEEPINFRA_TOKEN".to_owned(), "not-selected".to_owned()),
    ]);
    let credential = DeepInfraProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));
    assert_eq!(
        DeepInfraProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn balance_fixture_projects_exact_cost_detail_and_cli_schema() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CHECKLIST.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("DeepInfra fixture");

    assert_eq!(provider.descriptor().id, ProviderId::DeepInfra);
    assert_eq!(
        sample.primary().expect("primary").used_percent(),
        Some(oab_domain::UsagePercent::new(0.0).expect("percent"))
    );
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .reset_description()
            .expect("detail")
            .as_str(),
        "$95.81 available · $3.94 spent this month"
    );
    assert_eq!(
        sample.balance().expect("balance").amount(),
        decimal("95.81")
    );
    let cost = sample.cost().expect("spending limit");
    assert_eq!(cost.used().amount(), decimal("3.94"));
    assert_eq!(cost.limit(), decimal("20"));
    assert_eq!(cost.period(), Some("Billing cycle"));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target(), "/payment/checklist?compute_owed=true");
    assert_eq!(requests[1].target(), "/payment/usage?from=current");
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-deepinfra-key-canary")
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
    let json = serde_json::to_value(projected).expect("CLI JSON");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["balance"]["amount"],
        "95.81"
    );
}

#[tokio::test]
async fn owed_and_suspended_accounts_are_exhausted_without_fake_budget() {
    let checklist = br#"{"stripe_balance":2.75,"recent":7,"limit":-1,"suspended":true,"suspend_reason":"Payment review"}"#;
    let usage = br#"{"months":[{"period":"2026-08","total_cost":650}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, checklist.to_vec()),
        FakeHttpResponse::new(200, usage.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("owed fixture");
    assert_eq!(
        sample.primary().expect("primary").used_percent(),
        Some(oab_domain::UsagePercent::new(100.0).expect("percent"))
    );
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .reset_description()
            .expect("detail")
            .as_str(),
        "Suspended: Payment review · $9.75 owed · $6.50 spent this month"
    );
    assert_eq!(sample.balance().expect("balance").amount(), decimal("0"));
    assert!(sample.cost().is_none());
}

#[tokio::test]
async fn authentication_rate_provider_api_and_parse_failures_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::truncated(200, CHECKLIST.len() + 10, CHECKLIST.to_vec()),
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
        assert!(!debug.contains("fixture-response-canary"));
        assert!(!debug.contains("fixture-error-canary"));
    }
}

#[tokio::test]
async fn malformed_usage_refresh_retains_last_good_for_exact_account() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CHECKLIST.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, CHECKLIST.to_vec()),
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
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CHECKLIST.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-account context");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());
}
