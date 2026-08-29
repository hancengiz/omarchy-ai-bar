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
use oab_providers::providers::ibmbob::{IBMBobProvider, IBMBobSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const PROFILE: &[u8] = include_bytes!("../../../fixtures/providers/ibmbob/profile.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/ibmbob/malformed.json");
const KEY_CANARY: &str = "fixture-ibmbob-key-canary";
const JWT_CANARY: &str = "header.eyJzdWIiOiJ1c2VyIn0.signature";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::IbmBob,
        ProviderInstanceId::new("ibmbob-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(retry: RetryPolicy) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        2 * 1024 * 1024,
        0,
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

fn provider_with(
    server: &FakeHttpServer,
    account: &str,
    credential: &str,
    bearer: bool,
    retry: RetryPolicy,
) -> IBMBobProvider {
    let credential = ApiKeyCredential::new(credential).expect("fixture credential");
    let client = if bearer {
        FixedApiClient::new_bearer(
            scope(account),
            server.url("/"),
            EndpointClass::LoopbackDevelopment,
            credential,
            config(retry),
        )
    } else {
        FixedApiClient::new_authorization_scheme(
            scope(account),
            server.url("/"),
            EndpointClass::LoopbackDevelopment,
            "Apikey",
            credential,
            config(retry),
        )
    }
    .expect("fixed API client");
    IBMBobProvider::from_client(client).expect("IBM Bob provider")
}

fn provider(server: &FakeHttpServer, account: &str) -> IBMBobProvider {
    provider_with(server, account, KEY_CANARY, false, RetryPolicy::none())
}

#[test]
fn settings_clean_keys_detect_jwt_and_redact_values() {
    let api_environment =
        BTreeMap::from([("BOBSHELL_API_KEY".to_owned(), format!(" \"{KEY_CANARY}\" "))]);
    let api_settings = IBMBobSettings::resolve(&api_environment).expect("API key settings");
    let api_debug = format!("{api_settings:?}");
    assert!(api_debug.contains("api-key"));
    assert!(!api_debug.contains(KEY_CANARY));

    let jwt_environment = BTreeMap::from([("BOBSHELL_API_KEY".to_owned(), JWT_CANARY.to_owned())]);
    let jwt_settings = IBMBobSettings::resolve(&jwt_environment).expect("JWT settings");
    let jwt_debug = format!("{jwt_settings:?}");
    assert!(jwt_debug.contains("bearer"));
    assert!(!jwt_debug.contains(JWT_CANARY));
    assert!(
        ApiKeyCredential::new(JWT_CANARY)
            .expect("JWT")
            .is_structured_jwt()
    );
    assert!(
        !ApiKeyCredential::new("header.invalid.signature")
            .expect("opaque key")
            .is_structured_jwt()
    );
    assert!(
        ApiKeyCredential::new("header.e30=.signature")
            .expect("padded JWT")
            .is_structured_jwt()
    );
    assert!(
        !ApiKeyCredential::new("header.MTIz.signature")
            .expect("scalar payload")
            .is_structured_jwt()
    );
    assert_eq!(
        IBMBobSettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn profile_and_team_budgets_project_usage_details_headers_and_cli_schema() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, PROFILE.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":10}"#.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":25}"#.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("IBM Bob fixture");

    assert_eq!(provider.descriptor().id, ProviderId::IbmBob);
    let primary = sample.primary().expect("monthly Bobcoin lane");
    assert!((primary.used_percent().expect("percent").get() - 17.5).abs() < f64::EPSILON);
    assert_eq!(
        primary.duration().expect("monthly duration").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        primary.resets_at(),
        Some(Timestamp::parse("2026-09-01T00:00:00Z").expect("reset"))
    );
    assert_eq!(
        primary.reset_description().expect("summary").as_str(),
        "35 / 200 Bobcoins"
    );
    assert_eq!(
        sample.identity().organization().expect("plans").as_str(),
        "Enterprise, Pro+"
    );
    assert_eq!(
        sample.identity().login_method().expect("login").as_str(),
        "API key"
    );
    let details = &sample.detail_sections()[0];
    assert_eq!(details.title(), Some("Bobcoin usage"));
    assert_eq!(details.rows().len(), 2);
    assert_eq!(details.rows()[0].label(), "Personal · Solo");
    assert_eq!(details.rows()[0].value(), "10 / 40 Bobcoins");
    assert_eq!(details.rows()[0].secondary_value(), Some("Pro+"));

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].target(), "/admin/v1/profile");
    assert_eq!(
        requests[1].target(),
        "/admin/v1/teams/team-one/users/user-one"
    );
    assert_eq!(
        requests[2].target(),
        "/admin/v1/teams/team-two/users/user-two"
    );
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Apikey fixture-ibmbob-key-canary")
            && request.header("accept") == Some("application/json")
            && request.header("content-type") == Some("application/json")
            && request.header("user-agent") == Some("omarchy-ai-bar")
    }));
    assert_eq!(requests[1].header("x-instance-id"), Some("instance-one"));
    assert_eq!(requests[1].header("x-team-id"), Some("team-one"));

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
        json["snapshots"][0]["last_known_good"]["primary"]["reset_description"],
        "35 / 200 Bobcoins"
    );
}

#[tokio::test]
async fn response_budget_overrides_profile_and_unlimited_team_uses_usage_only_summary() {
    let profile = br#"{"instances":[{"instance_id":"instance-one","instance_name":"Personal",
      "user_id":"user-one","refresh_at":1788220800,"teams":[{"id":"team-one","name":"Personal","budget_limit":40}]}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, profile.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":12.5,"budget_limit":null}"#.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("unlimited team");
    let primary = sample.primary().expect("monthly lane");
    assert!((primary.used_percent().expect("percent").get() - 31.25).abs() < f64::EPSILON);
    assert_eq!(
        primary.reset_description().expect("summary").as_str(),
        "12.50 / 40 Bobcoins"
    );
    assert_eq!(sample.detail_sections()[0].rows()[0].label(), "Personal");

    let profile = br#"{"instances":[{"instance_id":"instance-one","user_id":"user-one",
      "teams":[{"id":"team-one"}]}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, profile.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":7}"#.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("usage-only team");
    assert_eq!(
        sample
            .primary()
            .expect("monthly lane")
            .reset_description()
            .expect("summary")
            .as_str(),
        "7 Bobcoins used"
    );
}

#[tokio::test]
async fn jwt_credentials_use_bearer_authorization() {
    let profile = br#"{"instances":[{"instance_id":"one","user_id":"user",
      "teams":[{"id":"team","budget_limit":10}]}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, profile.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":4}"#.to_vec()),
    ])
    .await;
    provider_with(&server, "account-a", JWT_CANARY, true, RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("JWT fixture");
    assert!(server.requests().iter().all(|request| {
        request.header("authorization") == Some(&format!("Bearer {JWT_CANARY}"))
    }));
}

#[test]
fn regional_hosts_are_exactly_limited_to_bob_ibm_domain() {
    for (input, expected) in [
        ("us-east.bob.ibm.com", "api.us-east.bob.ibm.com"),
        ("api.eu-de.bob.ibm.com", "api.eu-de.bob.ibm.com"),
        ("bob.ibm.com", "api.bob.ibm.com"),
    ] {
        let url = IBMBobProvider::trusted_region_url(input).expect("trusted IBM Bob region");
        assert_eq!(url.host_str(), Some(expected));
        assert_eq!(url.scheme(), "https");
    }
    for input in [
        "evil.example",
        "evil.example/x.bob.ibm.com",
        "bob.ibm.com.evil.example",
        "x@evil.example",
        "evil.example/path/.bob.ibm.com",
        "evil.example?next=.bob.ibm.com",
        "evil.example#.bob.ibm.com",
        "evil.example@us-east.bob.ibm.com",
        "us-east.bob.ibm.com:443",
    ] {
        assert_eq!(
            IBMBobProvider::trusted_region_url(input)
                .expect_err("untrusted region")
                .kind(),
            ErrorKind::Api,
            "unexpectedly trusted {input}"
        );
    }
}

#[tokio::test]
async fn untrusted_profile_region_is_rejected_before_a_team_request() {
    let profile = br#"{"instances":[{"instance_id":"one","user_id":"user",
      "region_domain":"evil.example","teams":[{"id":"team","budget_limit":10}]}]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, profile.to_vec())]).await;
    let error = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("untrusted region");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn transient_profile_failure_is_retried_once() {
    let profile = br#"{"instances":[{"instance_id":"one","user_id":"user",
      "teams":[{"id":"team","budget_limit":10}]}]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, profile.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":4}"#.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::ZERO, Duration::ZERO);
    let sample = provider_with(&server, "account-a", KEY_CANARY, false, retry)
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("retry success");
    assert_eq!(
        sample
            .primary()
            .expect("monthly lane")
            .reset_description()
            .expect("summary")
            .as_str(),
        "4 / 10 Bobcoins"
    );
    assert_eq!(server.requests().len(), 3);
}

#[tokio::test]
async fn status_parse_no_subscription_last_good_and_account_boundaries_are_stable() {
    let empty = br#"{"instances":[]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::truncated(200, PROFILE.len() + 10, PROFILE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, empty.to_vec()),
        FakeHttpResponse::new(200, PROFILE.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":10}"#.to_vec()),
        FakeHttpResponse::new(200, br#"{"usage":25}"#.to_vec()),
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
        ErrorKind::Api,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("scripted provider failure");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?}").contains("fixture-error-canary"));
    }
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1_800_000_001))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider
            .fetch_at(&provider_context, timestamp(1_800_000_002))
            .await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));
    let request_count = server.requests().len();
    let error = provider
        .fetch_at(&context("account-b"), timestamp(1_800_000_003))
        .await
        .expect_err("cross-account context");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), request_count);
}
