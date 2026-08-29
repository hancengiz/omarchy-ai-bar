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
use oab_providers::providers::moonshot::{MoonshotProvider, MoonshotRegion, MoonshotSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const BALANCE: &[u8] = include_bytes!("../../../fixtures/providers/moonshot/balance.json");
const DEFICIT: &[u8] = include_bytes!("../../../fixtures/providers/moonshot/deficit.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/moonshot/malformed.json");
const KEY_CANARY: &str = "fixture-moonshot-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Moonshot,
        ProviderInstanceId::new("moonshot-primary").expect("provider instance"),
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

fn provider(server: &FakeHttpServer, account: &str, retry: RetryPolicy) -> MoonshotProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    MoonshotProvider::from_client(client).expect("Moonshot provider")
}

#[test]
fn regional_settings_preserve_key_precedence_binding_and_redaction() {
    let environment = BTreeMap::from([
        ("MOONSHOT_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "MOONSHOT_KEY".to_owned(),
            "fallback-not-selected".to_owned(),
        ),
        ("MOONSHOT_REGION".to_owned(), " 'china' ".to_owned()),
    ]);
    assert_eq!(
        MoonshotRegion::from_environment(&environment),
        MoonshotRegion::China
    );
    let settings = MoonshotSettings::resolve(&environment).expect("China settings");
    assert!(!format!("{settings:?}").contains(KEY_CANARY));
    assert_eq!(
        MoonshotSettings::resolve_for_region(MoonshotRegion::International, &environment)
            .expect_err("regional mismatch")
            .kind(),
        ErrorKind::MissingCredential
    );

    let unscoped = BTreeMap::from([("MOONSHOT_API_KEY".to_owned(), KEY_CANARY.to_owned())]);
    assert_eq!(
        MoonshotRegion::from_environment(&unscoped),
        MoonshotRegion::International
    );
    MoonshotSettings::resolve_for_region(MoonshotRegion::International, &unscoped)
        .expect("international default");
    assert_eq!(
        MoonshotSettings::resolve_for_region(MoonshotRegion::China, &unscoped)
            .expect_err("unscoped key cannot reach China")
            .kind(),
        ErrorKind::MissingCredential
    );
    assert_eq!(
        MoonshotRegion::International.api_origin(),
        "https://api.moonshot.ai"
    );
    assert_eq!(
        MoonshotRegion::China.api_origin(),
        "https://api.moonshot.cn"
    );
}

#[tokio::test]
async fn documented_balance_is_identity_only_and_projects_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, BALANCE.to_vec())]).await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Moonshot balance fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Moonshot);
    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.tertiary().is_none());
    assert!(sample.balance().is_none());
    assert!(sample.cost().is_none());
    assert_eq!(
        sample.identity().login_method().expect("balance").as_str(),
        "Balance: $49.58"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target(), "/v1/users/me/balance");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-moonshot-key-canary")
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
        json["snapshots"][0]["last_known_good"]["identity"]["login_method"],
        "Balance: $49.58"
    );
}

#[tokio::test]
async fn negative_cash_balance_surfaces_the_deficit() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, DEFICIT.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("deficit fixture");
    assert_eq!(
        sample.identity().login_method().expect("balance").as_str(),
        "Balance: $49.58 · $0.42 in deficit"
    );
}

#[tokio::test]
async fn provider_envelope_failures_and_malformed_values_are_distinct() {
    let rejected = br#"{
      "code":401,
      "data":{"available_balance":0,"voucher_balance":0,"cash_balance":0},
      "scode":"provider-message-canary",
      "status":false
    }"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, rejected.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    let api = provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("provider envelope failure");
    assert_eq!(api.kind(), ErrorKind::Api);
    assert!(!format!("{api:?}").contains("provider-message-canary"));
    let malformed = provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("malformed response");
    assert_eq!(malformed.kind(), ErrorKind::Parse);
    assert!(!format!("{malformed:?}").contains("response-canary"));
}

#[tokio::test]
async fn status_retry_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
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
        FakeHttpResponse::new(200, BALANCE.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&server, "account-a", retry)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("retried fixture");
    assert_eq!(server.requests().len(), 2);
}
