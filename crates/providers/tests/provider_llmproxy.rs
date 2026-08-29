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
use oab_providers::providers::llmproxy::{LlmProxyProvider, LlmProxySettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const QUOTA_STATS: &[u8] = include_bytes!("../../../fixtures/providers/llmproxy/quota-stats.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/llmproxy/malformed.json");
const KEY_CANARY: &str = "fixture-llmproxy-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::LlmProxy,
        ProviderInstanceId::new("llmproxy-primary").expect("provider instance"),
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
) -> LlmProxyProvider {
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
    LlmProxyProvider::from_client(client, endpoint).expect("LLM Proxy provider")
}

#[test]
fn settings_require_both_values_apply_private_http_policy_and_redact() {
    let environment = BTreeMap::from([
        ("LLM_PROXY_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "LLM_PROXY_BASE_URL".to_owned(),
            " \"https://proxy.example.com/v1\" ".to_owned(),
        ),
    ]);
    let settings = LlmProxySettings::resolve(&environment).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("proxy.example.com"));

    assert_eq!(
        LlmProxySettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    let key_only = BTreeMap::from([("LLM_PROXY_API_KEY".to_owned(), KEY_CANARY.to_owned())]);
    assert_eq!(
        LlmProxySettings::resolve(&key_only)
            .expect_err("missing base URL")
            .kind(),
        ErrorKind::Api
    );
    for base_url in ["http://api.example.com", "http://8.8.8.8"] {
        let values = BTreeMap::from([
            ("LLM_PROXY_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("LLM_PROXY_BASE_URL".to_owned(), base_url.to_owned()),
        ]);
        assert_eq!(
            LlmProxySettings::resolve(&values)
                .expect_err("public HTTP")
                .kind(),
            ErrorKind::Api
        );
    }
    for base_url in ["http://10.0.0.4/v1", "http://proxy.local/v1"] {
        let values = BTreeMap::from([
            ("LLM_PROXY_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("LLM_PROXY_BASE_URL".to_owned(), base_url.to_owned()),
        ]);
        LlmProxySettings::resolve(&values).expect("private HTTP");
    }
}

#[tokio::test]
async fn quota_fixture_projects_aggregate_lanes_cost_identity_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA_STATS.to_vec())]).await;
    let provider = provider(&server, "/proxy/v1/", "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("LLM Proxy fixture");

    assert_eq!(provider.descriptor().id, ProviderId::LlmProxy);
    assert!(
        (sample
            .primary()
            .expect("remaining quota")
            .used_percent()
            .expect("known percent")
            .get()
            - 58.0)
            .abs()
            < f64::EPSILON
    );
    assert_eq!(
        sample.primary().expect("primary").resets_at(),
        Some(Timestamp::parse("2026-05-18T12:00:00.123Z").expect("reset"))
    );
    assert_eq!(
        sample
            .secondary()
            .expect("requests")
            .reset_description()
            .expect("request detail")
            .as_str(),
        "160 requests"
    );
    assert_eq!(
        sample
            .tertiary()
            .expect("tokens")
            .reset_description()
            .expect("token detail")
            .as_str(),
        "7,000 tokens"
    );
    assert_eq!(sample.extra_windows().len(), 2);
    let openai = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == "openai")
        .expect("OpenAI summary");
    assert_eq!(openai.title().as_str(), "openai");
    assert_eq!(
        openai
            .window()
            .reset_description()
            .expect("provider summary")
            .as_str(),
        "120 req · 6,000 tok · $12.50"
    );
    let cost = sample.cost().expect("approximate cost");
    assert_eq!(cost.used().amount(), decimal("15.5"));
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("Approx. spend"));
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("active key summary")
            .as_str(),
        "3/4 active keys"
    );
    assert_eq!(
        sample.identity().login_method().expect("method").as_str(),
        "quota-stats"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target(), "/proxy/v1/quota-stats");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-llmproxy-key-canary")
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
        json["snapshots"][0]["last_known_good"]["identity"]["organization"],
        "3/4 active keys"
    );
}

#[tokio::test]
async fn root_and_versioned_bases_normalize_to_the_same_quota_path() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA_STATS.to_vec()),
        FakeHttpResponse::new(200, QUOTA_STATS.to_vec()),
    ])
    .await;
    for base in ["/proxy", "/proxy/v1"] {
        provider(&server, base, "account-a", RetryPolicy::none())
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect("normalized path");
    }
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.target() == "/proxy/v1/quota-stats")
    );
}

#[tokio::test]
async fn fallback_totals_quota_shapes_and_future_reset_semantics_match_baseline() {
    let fallback = br#"{
      "providers": {
        "alpha": {
          "credential_count": 2,
          "active_count": 1,
          "total_requests": 5,
          "tokens": {"input_cached": 1, "input_uncached": 2, "output": 3},
          "approx_cost": 1.25,
          "quota_groups": {
            "stale": {"remaining_percent": 5, "reset_time": "2023-11-01T00:00:00Z"},
            "next": {"remaining_percent": 25, "reset_time": "2023-11-20T00:00:00Z"}
          }
        },
        "beta": {
          "credential_count": 1,
          "active_count": 1,
          "total_requests": 9,
          "tokens": {"output": 4},
          "approx_cost": 2,
          "quota_groups": [{"remaining_percent": 80, "reset_time": "2023-12-25T00:00:00Z"}]
        },
        "ignored-groups": {
          "quota_groups": "not-a-supported-shape"
        }
      }
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, fallback.to_vec())]).await;
    let sample = provider(&server, "/", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_700_000_000))
        .await
        .expect("fallback fixture");

    assert!(
        (sample
            .primary()
            .expect("minimum quota")
            .used_percent()
            .expect("percent")
            .get()
            - 95.0)
            .abs()
            < f64::EPSILON
    );
    assert_eq!(
        sample.primary().expect("primary").resets_at(),
        Some(Timestamp::parse("2023-11-20T00:00:00Z").expect("future reset"))
    );
    assert_eq!(
        sample
            .secondary()
            .expect("requests")
            .reset_description()
            .expect("detail")
            .as_str(),
        "14 requests"
    );
    assert_eq!(
        sample
            .tertiary()
            .expect("tokens")
            .reset_description()
            .expect("detail")
            .as_str(),
        "10 tokens"
    );
    assert_eq!(
        sample.cost().expect("summed cost").used().amount(),
        decimal("3.25")
    );
}

#[tokio::test]
async fn all_past_or_invalid_reset_times_leave_the_reset_empty() {
    let body = br#"{
      "providers": {
        "p": {
          "quota_groups": [
            {"remaining_percent": 50, "reset_time": "2023-11-01T00:00:00Z"},
            {"remaining_percent": 60, "reset_time": "not-a-date"}
          ]
        }
      }
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let sample = provider(&server, "/", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_700_000_000))
        .await
        .expect("stale reset fixture");
    assert_eq!(sample.primary().expect("primary").resets_at(), None);
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
        FakeHttpResponse::new(200, QUOTA_STATS.to_vec()),
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
            .fetch_at(&context("account-a"), timestamp(1))
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
        .fetch_at(&provider_context, timestamp(1))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider.fetch_at(&provider_context, timestamp(2)).await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let before = server.requests().len();
    assert_eq!(
        provider
            .fetch_at(&context("account-b"), timestamp(3))
            .await
            .expect_err("cross-account context")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), before);
}

#[tokio::test]
async fn transient_failure_retries_and_cross_origin_redirect_is_rejected() {
    let retry_server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, QUOTA_STATS.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    provider(&retry_server, "/v1", "account-a", retry)
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("retried fixture");
    assert_eq!(retry_server.requests().len(), 2);

    let target = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA_STATS.to_vec())]).await;
    let source =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let error = provider(&source, "/v1", "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(target.requests().is_empty());
}
