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
use oab_providers::providers::azureopenai::{AzureOpenAiProvider, AzureOpenAiSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const SUCCESS: &[u8] = include_bytes!("../../../fixtures/providers/azureopenai/completion.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/azureopenai/malformed.json");
const KEY_CANARY: &str = "fixture-azure-key-canary";
const DEPLOYMENT_CANARY: &str = "chat-prod-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::AzureOpenAi,
        ProviderInstanceId::new("azureopenai-primary").expect("provider instance"),
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

fn provider(
    server: &FakeHttpServer,
    account: &str,
    base_path: &str,
    deployment: &str,
    api_version: &str,
) -> AzureOpenAiProvider {
    let client = FixedApiClient::new(
        scope(account),
        server.url(base_path),
        EndpointClass::LoopbackDevelopment,
        "api-key",
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(),
    )
    .expect("fixed API client");
    AzureOpenAiProvider::from_client(client, deployment, api_version)
        .expect("Azure OpenAI provider")
}

#[test]
fn settings_trim_defaults_normalize_https_and_redact_personal_values() {
    let environment = BTreeMap::from([
        (
            "AZURE_OPENAI_API_KEY".to_owned(),
            format!(" '{KEY_CANARY}' "),
        ),
        (
            "AZURE_OPENAI_ENDPOINT".to_owned(),
            "fixture-resource.openai.azure.com/base".to_owned(),
        ),
        (
            "AZURE_OPENAI_DEPLOYMENT_NAME".to_owned(),
            format!(" \"{DEPLOYMENT_CANARY}\" "),
        ),
    ]);
    let settings = AzureOpenAiSettings::resolve(&environment).expect("Azure settings");
    let debug = format!("{settings:?}");
    assert!(debug.contains("2024-10-21"));
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("fixture-resource"));
    assert!(!debug.contains(DEPLOYMENT_CANARY));
    AzureOpenAiProvider::new(scope("account-a"), settings).expect("production client");

    let missing = AzureOpenAiSettings::resolve(&BTreeMap::new()).expect_err("missing key");
    assert_eq!(missing.kind(), ErrorKind::MissingCredential);
    let invalid_endpoint = BTreeMap::from([
        ("AZURE_OPENAI_API_KEY".to_owned(), "key".to_owned()),
        (
            "AZURE_OPENAI_ENDPOINT".to_owned(),
            "http://127.0.0.1:31337".to_owned(),
        ),
        (
            "AZURE_OPENAI_DEPLOYMENT_NAME".to_owned(),
            "deployment".to_owned(),
        ),
    ]);
    assert_eq!(
        AzureOpenAiSettings::resolve(&invalid_endpoint)
            .expect_err("insecure endpoint")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn deployment_probe_matches_baseline_request_and_projects_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUCCESS.to_vec())]).await;
    let provider = provider(
        &server,
        "account-a",
        "/base/",
        DEPLOYMENT_CANARY,
        "2024-10-21",
    );
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Azure deployment probe");

    assert_eq!(provider.descriptor().id, ProviderId::AzureOpenAi);
    assert_eq!(sample.scope(), &scope("account-a"));
    assert_eq!(
        sample.primary().expect("primary").used_percent(),
        Some(oab_domain::UsagePercent::new(0.0).expect("percent"))
    );
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .reset_description()
            .expect("deployment detail")
            .as_str(),
        "Deployment: chat-prod-canary · Model: gpt-4o-mini"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("deployment identity")
            .as_str(),
        "Deployment: chat-prod-canary"
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("endpoint host")
            .as_str(),
        "127.0.0.1"
    );

    let request = &server.requests()[0];
    assert_eq!(request.method(), "POST");
    assert_eq!(
        request.target(),
        "/base/openai/deployments/chat-prod-canary/chat/completions?api-version=2024-10-21"
    );
    assert_eq!(request.header("api-key"), Some(KEY_CANARY));
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(request.header("content-type"), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(request.body()).expect("probe JSON");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "ping");
    assert_eq!(body["max_tokens"], 1);
    assert!(body.get("temperature").is_none());
    assert!(body.get("reasoning_effort").is_none());

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
        "azureopenai"
    );
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["primary"]["usage"]["used_percent"],
        0.0
    );
}

#[tokio::test]
async fn v1_probe_uses_openai_compatible_path_model_and_token_cap() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUCCESS.to_vec())]).await;
    let provider = provider(&server, "account-a", "/base/openai/v1/", "chat prod", "v1");
    provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("v1 deployment probe");
    let request = &server.requests()[0];
    assert_eq!(request.target(), "/base/openai/v1/chat/completions");
    let body: serde_json::Value = serde_json::from_slice(request.body()).expect("probe JSON");
    assert_eq!(body["model"], "chat prod");
    assert_eq!(body["max_completion_tokens"], 64);
    assert!(body.get("max_tokens").is_none());
}

#[tokio::test]
async fn endpoint_path_is_preserved_suffix_is_not_duplicated_and_deployment_is_escaped() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUCCESS.to_vec())]).await;
    let provider = provider(
        &server,
        "account-a",
        "/base/openai/",
        "chat prod",
        "2024-10-21",
    );
    provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("path-preserving probe");
    assert_eq!(
        server.requests()[0].target(),
        "/base/openai/deployments/chat%20prod/chat/completions?api-version=2024-10-21"
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
        FakeHttpResponse::truncated(200, SUCCESS.len() + 10, SUCCESS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", "/", DEPLOYMENT_CANARY, "2024-10-21");

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
        assert!(!debug.contains(DEPLOYMENT_CANARY));
        assert!(!debug.contains("fixture-response-canary"));
        assert!(!debug.contains("fixture-error-canary"));
    }
}

#[tokio::test]
async fn malformed_refresh_retains_last_good_for_the_exact_account() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, SUCCESS.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", "/", DEPLOYMENT_CANARY, "2024-10-21");
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1_800_000_000))
        .await
        .expect("initial fixture");
    let failed = provider
        .fetch_at(&provider_context, timestamp(1_800_000_001))
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
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUCCESS.to_vec())]).await;
    let provider = provider(&server, "account-a", "/", DEPLOYMENT_CANARY, "2024-10-21");
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-account context must fail");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());
}
