use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy, PrivacySurface,
    ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::elevenlabs::ElevenLabsProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const SUCCESS: &[u8] = include_bytes!("../../../fixtures/providers/elevenlabs/subscription.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/elevenlabs/malformed.json");
const KEY_CANARY: &str = "fixture-elevenlabs-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::ElevenLabs,
        ProviderInstanceId::new("elevenlabs-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        1024 * 1024,
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

fn provider(server: &FakeHttpServer, account: &str) -> ElevenLabsProvider {
    let client = FixedApiClient::new(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "xi-api-key",
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    ElevenLabsProvider::from_client(client).expect("ElevenLabs provider")
}

#[tokio::test]
async fn success_fixture_projects_counts_reset_voices_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUCCESS.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("ElevenLabs fixture");

    assert_eq!(provider.descriptor().id, ProviderId::ElevenLabs);
    assert_eq!(sample.scope(), &scope("account-a"));
    assert_eq!(
        sample.primary().expect("primary").used_percent(),
        Some(oab_domain::UsagePercent::new(25.0).expect("percent"))
    );
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .reset_description()
            .expect("summary")
            .as_str(),
        "25,000 / 100,000 credits"
    );
    assert_eq!(
        sample.primary().expect("primary").resets_at(),
        Some(timestamp(1_738_356_858))
    );
    assert_eq!(sample.extra_windows().len(), 2);
    assert_eq!(
        sample.identity().login_method().expect("tier").as_str(),
        "Creator"
    );

    let request = &server.requests()[0];
    assert_eq!(request.target(), "/v1/user/subscription");
    assert_eq!(request.header("xi-api-key"), Some(KEY_CANARY));

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
        json["snapshots"][0]["last_known_good"]["scope"]["provider"],
        "elevenlabs"
    );
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["primary"]["usage"]["used_percent"],
        25.0
    );
}

#[tokio::test]
async fn versioned_base_path_is_not_duplicated_or_replaced() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUCCESS.to_vec())]).await;
    let client = FixedApiClient::new(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        "xi-api-key",
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("versioned client");
    let provider = ElevenLabsProvider::from_client(client).expect("ElevenLabs provider");

    provider
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("versioned fixture");
    assert_eq!(server.requests()[0].target(), "/v1/user/subscription");
}

#[test]
fn missing_credential_is_stable_and_redacted() {
    let error = ApiKeyCredential::new("   ").expect_err("missing key must fail");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);
    assert!(!format!("{error:?}").contains(KEY_CANARY));
}

#[tokio::test]
async fn authentication_rate_limit_provider_and_parse_failures_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::truncated(200, SUCCESS.len() + 10, SUCCESS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");

    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::PermissionDenied,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Parse,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("scripted provider failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-response-canary"));
    }
}

#[tokio::test]
async fn malformed_refresh_retains_last_good_for_the_exact_account() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SUCCESS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1))
        .await
        .expect("initial fixture");
    let failed = provider.fetch_at(&provider_context, timestamp(2)).await;
    let outcome = preserve_last_good(Some(last_good.clone()), failed);
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));
}

#[tokio::test]
async fn account_identity_mismatch_fails_before_a_second_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUCCESS.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1))
        .await
        .expect_err("cross-account context must fail");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());
}
