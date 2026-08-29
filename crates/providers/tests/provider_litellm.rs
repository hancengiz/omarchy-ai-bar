use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ExactDecimal, Freshness, PrivacyKey, PrivacyPolicy,
    PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::litellm::{LiteLlmProvider, LiteLlmSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const KEY_USER: &[u8] = include_bytes!("../../../fixtures/providers/litellm/key-user.json");
const USER_INFO: &[u8] = include_bytes!("../../../fixtures/providers/litellm/user-info.json");
const KEY_TEAM: &[u8] = include_bytes!("../../../fixtures/providers/litellm/key-team.json");
const TEAM_INFO: &[u8] = include_bytes!("../../../fixtures/providers/litellm/team-info.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/litellm/malformed.json");
const KEY_CANARY: &str = "fixture-litellm-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::LiteLlm,
        ProviderInstanceId::new("litellm-primary").expect("provider instance"),
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

fn provider(
    server: &FakeHttpServer,
    base_path: &str,
    account: &str,
    retry: RetryPolicy,
) -> LiteLlmProvider {
    let endpoint = ConfiguredEndpoint::parse(
        server.url(base_path).as_str(),
        ConfiguredHttpPolicy::PrivateNetworkHttp,
    )
    .expect("fixture endpoint");
    let client = FixedApiClient::new_bearer(
        scope(account),
        endpoint.url().clone(),
        endpoint.class(),
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    LiteLlmProvider::from_client(client, endpoint).expect("LiteLLM provider")
}

#[test]
fn settings_require_both_values_apply_private_http_policy_and_redact() {
    let environment = BTreeMap::from([
        ("LITELLM_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "LITELLM_BASE_URL".to_owned(),
            " \"https://litellm.example.com/v1\" ".to_owned(),
        ),
    ]);
    let settings = LiteLlmSettings::resolve(&environment).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("litellm.example.com"));

    assert_eq!(
        LiteLlmSettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    let key_only = BTreeMap::from([("LITELLM_API_KEY".to_owned(), KEY_CANARY.to_owned())]);
    assert_eq!(
        LiteLlmSettings::resolve(&key_only)
            .expect_err("missing base URL")
            .kind(),
        ErrorKind::Api
    );
    for base_url in ["http://api.example.com", "http://8.8.8.8"] {
        let values = BTreeMap::from([
            ("LITELLM_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("LITELLM_BASE_URL".to_owned(), base_url.to_owned()),
        ]);
        assert_eq!(
            LiteLlmSettings::resolve(&values)
                .expect_err("public HTTP")
                .kind(),
            ErrorKind::Api
        );
    }
    for base_url in ["http://10.0.0.4/v1", "http://litellm.local/v1"] {
        let values = BTreeMap::from([
            ("LITELLM_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("LITELLM_BASE_URL".to_owned(), base_url.to_owned()),
        ]);
        LiteLlmSettings::resolve(&values).expect("private HTTP");
    }
}

#[tokio::test]
async fn user_fixture_projects_personal_team_expiry_identity_and_cli_schema() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, KEY_USER.to_vec()),
        FakeHttpResponse::new(200, USER_INFO.to_vec()),
    ])
    .await;
    let provider = provider(&server, "/litellm/v1/", "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("LiteLLM user fixture");

    assert_eq!(provider.descriptor().id, ProviderId::LiteLlm);
    assert!(
        (sample
            .primary()
            .expect("personal budget")
            .used_percent()
            .expect("known percent")
            .get()
            - 70.784_572_083_333_27)
            .abs()
            < 1e-10
    );
    assert_eq!(
        sample
            .primary()
            .expect("personal budget")
            .reset_description()
            .expect("personal detail")
            .as_str(),
        "$212.35 / $300.00"
    );
    assert_eq!(
        sample
            .secondary()
            .expect("team budget")
            .reset_description()
            .expect("team detail")
            .as_str(),
        "Team ai: $215.32 / $1,000.00"
    );
    assert_eq!(
        sample.secondary().expect("team budget").resets_at(),
        Some(Timestamp::parse("2026-06-15T00:00:00Z").expect("team reset"))
    );
    assert_eq!(
        sample.identity().email().expect("email").as_str(),
        "litellm-user@example.com"
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("team alias")
            .as_str(),
        "ai"
    );
    assert_eq!(
        sample.identity().login_method().expect("login").as_str(),
        "api"
    );
    assert_eq!(
        sample.subscription_expires_at(),
        Some(Timestamp::parse("2026-09-11T00:12:55.950000+00:00").expect("key expiration"))
    );
    let cost = sample.cost().expect("personal cost");
    assert_eq!(cost.used().amount(), decimal("212.3537162499998"));
    assert_eq!(cost.limit(), decimal("300"));
    assert_eq!(cost.period(), Some("Personal budget"));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target(), "/litellm/key/info");
    assert_eq!(requests[1].target(), "/litellm/user/info?user_id=user-123");
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-litellm-key-canary")
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
        json["snapshots"][0]["last_known_good"]["identity"]["email"],
        "litellm-user@example.com"
    );
}

#[tokio::test]
async fn team_only_key_keeps_budget_on_secondary_lane_and_uses_team_cost() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, KEY_TEAM.to_vec()),
        FakeHttpResponse::new(200, TEAM_INFO.to_vec()),
    ])
    .await;
    let sample = provider(&server, "/v1", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("team-only fixture");

    assert!(sample.primary().is_none());
    assert!(
        (sample
            .secondary()
            .expect("team budget")
            .used_percent()
            .expect("known percent")
            .get()
            - 25.0)
            .abs()
            < f64::EPSILON
    );
    assert_eq!(
        sample
            .secondary()
            .expect("team budget")
            .reset_description()
            .expect("team detail")
            .as_str(),
        "Team platform: $25.00 / $100.00"
    );
    let cost = sample.cost().expect("team cost");
    assert_eq!(cost.used().amount(), decimal("25"));
    assert_eq!(cost.limit(), decimal("100"));
    assert_eq!(cost.period(), Some("Team budget"));
    assert_eq!(server.requests()[1].target(), "/team/info?team_id=team-456");
}

#[tokio::test]
async fn spend_without_a_budget_remains_visible_without_a_quota_lane() {
    let key = br#"{"info":{"user_id":"user-123","spend":12.5}}"#;
    let user = br#"{"user_id":"user-123","user_info":{"user_id":"user-123","max_budget":null,"spend":12.5}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, key.to_vec()),
        FakeHttpResponse::new(200, user.to_vec()),
    ])
    .await;
    let sample = provider(&server, "/", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("unbudgeted spend");
    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    let cost = sample.cost().expect("spend remains visible");
    assert_eq!(cost.used().amount(), decimal("12.5"));
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("Personal spend"));
}

#[tokio::test]
async fn returned_ids_and_required_key_identity_are_validated() {
    let user_mismatch = br#"{"user_info":{"user_id":"other","spend":1}}"#;
    let team_mismatch = br#"{"team_info":{"team_id":"other","spend":1}}"#;
    let no_identity = br#"{"info":{"spend":1}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, KEY_USER.to_vec()),
        FakeHttpResponse::new(200, user_mismatch.to_vec()),
        FakeHttpResponse::new(200, KEY_TEAM.to_vec()),
        FakeHttpResponse::new(200, team_mismatch.to_vec()),
        FakeHttpResponse::new(200, no_identity.to_vec()),
    ])
    .await;
    let provider = provider(&server, "/", "account-a", RetryPolicy::none());
    for _ in 0..3 {
        assert_eq!(
            provider
                .fetch_at(&context("account-a"), timestamp(1_800_000_000))
                .await
                .expect_err("identity mismatch")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn status_parse_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, KEY_USER.to_vec()),
        FakeHttpResponse::new(200, USER_INFO.to_vec()),
        FakeHttpResponse::new(200, KEY_USER.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "/", "account-a", RetryPolicy::none());
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::PermissionDenied,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Api,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
        assert!(!debug.contains("response-canary"));
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
async fn transient_key_info_failure_is_retried_once() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, KEY_USER.to_vec()),
        FakeHttpResponse::new(200, USER_INFO.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&server, "/v1", "account-a", retry)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("retried fixture");
    assert_eq!(server.requests().len(), 3);
}

#[tokio::test]
async fn cross_origin_redirect_is_rejected_before_the_key_reaches_the_target() {
    let target = FakeHttpServer::start([FakeHttpResponse::new(200, KEY_USER.to_vec())]).await;
    let source =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let error = provider(&source, "/v1", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(target.requests().is_empty());
}
