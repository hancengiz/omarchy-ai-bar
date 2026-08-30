use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy, PrivacySurface,
    ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::copilot::{
    CopilotDeviceFlow, CopilotProvider, DeviceFlowClock, normalize_enterprise_host, usage_url,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{HttpTransport, TransportConfig};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/copilot/usage.json");
const MONTHLY: &[u8] = include_bytes!("../../../fixtures/providers/copilot/monthly.json");
const UNLIMITED: &[u8] = include_bytes!("../../../fixtures/providers/copilot/unlimited.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/copilot/malformed.json");
const TOKEN_CANARY: &str = "fixture-copilot-oauth-token-canary";
const DEVICE_CODE_CANARY: &str = "fixture-copilot-device-code-canary";

#[derive(Clone, Default)]
struct FakeDeviceFlowClock {
    state: Arc<Mutex<FakeDeviceFlowClockState>>,
}

#[derive(Default)]
struct FakeDeviceFlowClockState {
    now: Duration,
    sleeps: Vec<Duration>,
    expire_next_request: bool,
}

impl FakeDeviceFlowClock {
    fn sleeps(&self) -> Vec<Duration> {
        self.state.lock().expect("clock state").sleeps.clone()
    }

    fn advance(&self, duration: Duration) {
        let mut state = self.state.lock().expect("clock state");
        state.now = state.now.saturating_add(duration);
    }

    fn expire_next_request(&self) {
        self.state.lock().expect("clock state").expire_next_request = true;
    }
}

impl DeviceFlowClock for FakeDeviceFlowClock {
    fn monotonic_now(&self) -> Duration {
        self.state.lock().expect("clock state").now
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("clock state");
            state.now = state.now.saturating_add(duration);
            state.sleeps.push(duration);
        })
    }

    fn run_before_timeout<'a, F, T>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Option<T>> + Send + 'a>>
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        let expires = {
            let mut state = self.state.lock().expect("clock state");
            let expires = std::mem::take(&mut state.expire_next_request);
            if expires {
                state.now = state.now.saturating_add(duration);
            }
            expires
        };
        Box::pin(async move { if expires { None } else { Some(future.await) } })
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope_for(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(format!("{}-primary", provider.as_str())).expect("instance"),
        AccountKey::new(account).expect("account"),
    )
}

fn scope(account: &str) -> AccountScope {
    scope_for(ProviderId::Copilot, account)
}

fn context_with_source(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn context(account: &str) -> ProviderContext {
    context_with_source(account, ProviderSource::OAuth)
}

fn config(max_response_bytes: usize) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        max_response_bytes,
        0,
        RetryPolicy::none(),
    )
    .expect("transport config")
}

fn provider(server: &FakeHttpServer, account: &str) -> CopilotProvider {
    let client = FixedApiClient::new_authorization_scheme(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        ApiKeyCredential::new(TOKEN_CANARY).expect("credential"),
        config(2 * 1024 * 1024),
    )
    .expect("OAuth client")
    .with_source(ProviderSource::OAuth)
    .expect("Copilot OAuth source");
    CopilotProvider::from_client(client).expect("Copilot provider")
}

fn device_flow(
    server: &FakeHttpServer,
    clock: FakeDeviceFlowClock,
) -> CopilotDeviceFlow<FakeDeviceFlowClock> {
    let endpoints = EndpointPolicy::new([(server.origin(), EndpointClass::LoopbackDevelopment)])
        .expect("loopback device endpoints");
    let transport =
        HttpTransport::new(endpoints, config(2 * 1024 * 1024)).expect("device transport");
    CopilotDeviceFlow::with_test_transport(&server.url("/"), transport, clock)
        .expect("loopback device flow")
}

fn device_code_response(expires_in: u64, interval: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "device_code": DEVICE_CODE_CANARY,
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://github.com/login/device",
        "verification_uri_complete": "https://github.com/login/device?user_code=ABCD-EFGH",
        "expires_in": expires_in,
        "interval": interval,
    }))
    .expect("device-code fixture")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn row<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a oab_domain::DetailRow {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .expect("detail row")
}

#[test]
fn token_resolution_and_enterprise_hosts_are_bounded_normalized_and_redacted() {
    let environment = BTreeMap::from([(
        "COPILOT_API_TOKEN".to_owned(),
        format!("  '{TOKEN_CANARY}'  "),
    )]);
    let credential = CopilotProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(TOKEN_CANARY));
    assert_eq!(
        CopilotProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing token")
            .kind(),
        ErrorKind::MissingCredential
    );

    assert_eq!(
        normalize_enterprise_host(None).expect("default"),
        "github.com"
    );
    assert_eq!(
        normalize_enterprise_host(Some(" https://OctoCorp.GHE.com:8443/login "))
            .expect("enterprise"),
        "octocorp.ghe.com:8443"
    );
    assert_eq!(
        usage_url(None).expect("default usage").as_str(),
        "https://api.github.com/copilot_internal/user"
    );
    assert_eq!(
        usage_url(Some("api.octocorp.ghe.com:8443"))
            .expect("enterprise usage")
            .as_str(),
        "https://api.octocorp.ghe.com:8443/copilot_internal/user"
    );
    for invalid in ["foo bar", "https://user@example.com", "file:///tmp/socket"] {
        assert_eq!(
            normalize_enterprise_host(Some(invalid))
                .expect_err("invalid host")
                .kind(),
            ErrorKind::Api
        );
    }

    CopilotProvider::new(scope("account-a"), credential, None).expect("production client");
    CopilotProvider::new(
        scope("enterprise-account"),
        ApiKeyCredential::new(TOKEN_CANARY).expect("enterprise credential"),
        Some("github.internal.local"),
    )
    .expect("private HTTPS enterprise client");

    let device_flow = CopilotDeviceFlow::new(None).expect("production device flow");
    assert_eq!(
        device_flow.device_code_url().as_str(),
        "https://github.com/login/device/code"
    );
    assert_eq!(
        device_flow.access_token_url().as_str(),
        "https://github.com/login/oauth/access_token"
    );
    assert!(CopilotDeviceFlow::new(Some("127.0.0.1")).is_err());
}

#[tokio::test]
async fn device_code_request_is_exact_bounded_and_redacted() {
    let response = device_code_response(900, 5);
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, response)]).await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let challenge = flow
        .request_device_code(&CancellationToken::new())
        .await
        .expect("device challenge");

    assert_eq!(challenge.user_code(), "ABCD-EFGH");
    assert_eq!(challenge.expires_in(), Duration::from_mins(15));
    assert_eq!(challenge.interval(), Duration::from_secs(5));
    assert_eq!(
        challenge.verification_url_to_open().as_str(),
        "https://github.com/login/device?user_code=ABCD-EFGH"
    );
    let debug = format!("{challenge:?}");
    assert!(!debug.contains(DEVICE_CODE_CANARY));
    assert!(!debug.contains("ABCD-EFGH"));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/login/device/code");
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(
        requests[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        requests[0].body(),
        b"client_id=Iv1.b507a08c87ecfe98&scope=read%3Auser"
    );
    assert!(clock.sleeps().is_empty());
}

#[tokio::test]
async fn malformed_or_unbounded_device_challenges_fail_closed() {
    let base = || {
        serde_json::json!({
            "device_code": DEVICE_CODE_CANARY,
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://github.com/login/device",
            "verification_uri_complete": null,
            "expires_in": 900,
            "interval": 5,
        })
    };
    let mut cases = Vec::new();
    for (field, replacement) in [
        ("device_code", serde_json::json!("bad\ncode")),
        ("user_code", serde_json::json!("")),
        (
            "verification_uri",
            serde_json::json!("http://github.com/login/device"),
        ),
        ("expires_in", serde_json::json!(0)),
        ("expires_in", serde_json::json!(86_401)),
        ("interval", serde_json::json!(0)),
        ("interval", serde_json::json!(301)),
    ] {
        let mut payload = base();
        payload[field] = replacement;
        cases.push(payload);
    }
    let mut oversized_code = base();
    oversized_code["device_code"] = serde_json::json!("x".repeat(16 * 1024 + 1));
    cases.push(oversized_code);
    let mut insecure_complete = base();
    insecure_complete["verification_uri_complete"] =
        serde_json::json!("https://github.com/login/device#secret");
    cases.push(insecure_complete);

    for body in cases {
        let server = FakeHttpServer::start([FakeHttpResponse::new(
            200,
            serde_json::to_vec(&body).expect("invalid fixture"),
        )])
        .await;
        let flow = device_flow(&server, FakeDeviceFlowClock::default());

        assert_eq!(
            flow.request_device_code(&CancellationToken::new())
                .await
                .expect_err("invalid challenge")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn device_poll_handles_pending_slow_down_and_returns_redacted_credential() {
    let challenge_response = device_code_response(900, 2);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, challenge_response),
        FakeHttpResponse::new(200, br#"{"error":"authorization_pending"}"#.to_vec()),
        FakeHttpResponse::new(400, br#"{"error":"slow_down"}"#.to_vec()),
        FakeHttpResponse::new(
            200,
            format!(
                r#"{{"access_token":"{TOKEN_CANARY}","token_type":"bearer","scope":"read:user"}}"#
            )
            .into_bytes(),
        ),
    ])
    .await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    let credential = flow
        .poll_for_token(&challenge, &cancellation)
        .await
        .expect("authorized token");
    assert!(!format!("{credential:?}").contains(TOKEN_CANARY));
    assert_eq!(
        clock.sleeps(),
        vec![
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_secs(2),
        ]
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    for request in &requests[1..] {
        assert_eq!(request.method(), "POST");
        assert_eq!(request.target(), "/login/oauth/access_token");
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(
            request.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            request.body(),
            b"client_id=Iv1.b507a08c87ecfe98&device_code=fixture-copilot-device-code-canary&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
    }

    let usage_server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let client = FixedApiClient::new_authorization_scheme(
        scope("account-a"),
        usage_server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        credential,
        config(2 * 1024 * 1024),
    )
    .expect("client from device credential")
    .with_source(ProviderSource::OAuth)
    .expect("OAuth source");
    CopilotProvider::from_client(client)
        .expect("provider")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("usage with device token");
    assert_eq!(
        usage_server.requests()[0].header("authorization"),
        Some("token fixture-copilot-oauth-token-canary")
    );
}

#[tokio::test]
async fn device_poll_enforces_expiry_without_an_extra_request() {
    let challenge_response = device_code_response(3, 2);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, challenge_response),
        FakeHttpResponse::new(200, br#"{"error":"authorization_pending"}"#.to_vec()),
    ])
    .await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");

    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge expires")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(
        clock.sleeps(),
        vec![Duration::from_secs(2), Duration::from_secs(1)]
    );
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn device_expiry_includes_time_spent_waiting_before_polling() {
    let server =
        FakeHttpServer::start([FakeHttpResponse::new(200, device_code_response(3, 2))]).await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    clock.advance(Duration::from_secs(2));

    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge expires while waiting")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(1)]);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn device_in_flight_expiry_uses_the_injected_clock() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, device_code_response(60, 1)),
        FakeHttpResponse::stall(),
    ])
    .await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    clock.expire_next_request();

    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("request reaches challenge deadline")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(1)]);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn device_poll_maps_denial_expired_token_and_cancellation_safely() {
    for (oauth_error, expected) in [
        ("access_denied", ErrorKind::PermissionDenied),
        ("expired_token", ErrorKind::AuthenticationExpired),
        ("incorrect_device_code", ErrorKind::AuthenticationExpired),
    ] {
        let challenge_response = device_code_response(60, 1);
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, challenge_response),
            FakeHttpResponse::new(400, format!(r#"{{"error":"{oauth_error}"}}"#).into_bytes()),
        ])
        .await;
        let flow = device_flow(&server, FakeDeviceFlowClock::default());
        let cancellation = CancellationToken::new();
        let challenge = flow
            .request_device_code(&cancellation)
            .await
            .expect("device challenge");
        assert_eq!(
            flow.poll_for_token(&challenge, &cancellation)
                .await
                .expect_err("OAuth error")
                .kind(),
            expected
        );
    }

    let challenge_response = device_code_response(60, 1);
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, challenge_response)]).await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    cancellation.cancel();
    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("cancelled poll")
            .kind(),
        ErrorKind::Network
    );
    assert!(clock.sleeps().is_empty());
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn device_success_requires_the_complete_github_token_schema() {
    for incomplete in [
        format!(r#"{{"access_token":"{TOKEN_CANARY}"}}"#),
        format!(r#"{{"access_token":"{TOKEN_CANARY}","token_type":"bearer"}}"#),
    ] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, device_code_response(60, 1)),
            FakeHttpResponse::new(200, incomplete.into_bytes()),
        ])
        .await;
        let flow = device_flow(&server, FakeDeviceFlowClock::default());
        let cancellation = CancellationToken::new();
        let challenge = flow
            .request_device_code(&cancellation)
            .await
            .expect("device challenge");

        assert_eq!(
            flow.poll_for_token(&challenge, &cancellation)
                .await
                .expect_err("incomplete token schema")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn device_challenge_cannot_cross_forward_to_another_origin() {
    let issuer =
        FakeHttpServer::start([FakeHttpResponse::new(200, device_code_response(60, 1))]).await;
    let unrelated = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        format!(r#"{{"access_token":"{TOKEN_CANARY}","token_type":"bearer","scope":"read:user"}}"#)
            .into_bytes(),
    )])
    .await;
    let issuer_flow = device_flow(&issuer, FakeDeviceFlowClock::default());
    let unrelated_clock = FakeDeviceFlowClock::default();
    let unrelated_flow = device_flow(&unrelated, unrelated_clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = issuer_flow
        .request_device_code(&cancellation)
        .await
        .expect("issuer challenge");

    assert_eq!(
        unrelated_flow
            .poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge remains origin-bound")
            .kind(),
        ErrorKind::Api
    );
    assert!(unrelated.requests().is_empty());
    assert!(unrelated_clock.sleeps().is_empty());

    let same_origin_clock = FakeDeviceFlowClock::default();
    let same_origin_other_flow = device_flow(&issuer, same_origin_clock.clone());
    assert_eq!(
        same_origin_other_flow
            .poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge remains issuing-flow-bound")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(issuer.requests().len(), 1);
    assert!(same_origin_clock.sleeps().is_empty());
}

#[tokio::test]
async fn usage_fixture_projects_premium_chat_credits_request_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_788_220_800);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Copilot usage");

    assert_eq!(provider.descriptor().id, ProviderId::Copilot);
    assert_percent(
        sample
            .primary()
            .expect("premium")
            .used_percent()
            .expect("percent")
            .get(),
        21.9,
    );
    assert_percent(
        sample
            .secondary()
            .expect("chat")
            .used_percent()
            .expect("percent")
            .get(),
        20.0,
    );
    assert!(sample.tertiary().is_none());
    assert_eq!(
        sample.primary().expect("premium").resets_at(),
        Some(Timestamp::parse("2026-09-01T00:00:00Z").expect("reset"))
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Individual"
    );
    assert_eq!(row(&sample, "Credits used").value(), "31");
    assert_eq!(sample.provenance()[0].strategy(), "oauth");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/copilot_internal/user");
    assert_eq!(
        requests[0].header("authorization"),
        Some("token fixture-copilot-oauth-token-canary")
    );
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(requests[0].header("editor-version"), Some("vscode/1.96.2"));
    assert_eq!(
        requests[0].header("editor-plugin-version"),
        Some("copilot-chat/0.26.7")
    );
    assert_eq!(
        requests[0].header("user-agent"),
        Some("GitHubCopilotChat/0.26.7")
    );
    assert_eq!(
        requests[0].header("x-github-api-version"),
        Some("2025-04-01")
    );
    assert!(requests[0].header("content-type").is_none());

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
        json["snapshots"][0]["last_known_good"]["secondary"]["usage"]["used_percent"],
        20.0
    );
}

#[tokio::test]
async fn monthly_fallback_merges_with_direct_chat_and_keeps_slot_labels() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, MONTHLY.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("monthly fallback");

    assert_percent(
        sample
            .primary()
            .expect("completion fallback")
            .used_percent()
            .expect("percent")
            .get(),
        80.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("direct chat")
            .used_percent()
            .expect("percent")
            .get(),
        62.5,
    );
}

#[tokio::test]
async fn token_billing_and_unlimited_quotas_are_identity_only_but_keep_credits() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, UNLIMITED.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("unlimited token billing");

    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert_eq!(row(&sample, "Credits used").value(), "31");
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Business"
    );
}

#[tokio::test]
async fn dynamic_keys_are_deterministic_overage_is_raw_and_placeholders_do_not_win() {
    let body = br#"{
      "copilot_plan":"paid",
      "quota_snapshots":{
        "premium_interactions":{},
        "zeta_bucket":{"entitlement":100,"remaining":40,"percent_remaining":40},
        "alpha_bucket":{"entitlement":500,"remaining":-75,"percent_remaining":-15}
      }
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("dynamic fallback");

    assert!(sample.primary().is_none());
    let chat = sample.secondary().expect("sorted first fallback");
    assert_percent(chat.used_percent().expect("percent").get(), 115.0);
    assert_eq!(
        chat.reset_description().expect("overage").as_str(),
        "115% used"
    );
}

#[tokio::test]
async fn statuses_parse_bounds_last_good_and_source_account_isolation_are_stable() {
    for status in [401, 403] {
        let server =
            FakeHttpServer::start([FakeHttpResponse::new(status, b"secret".to_vec())]).await;
        assert_eq!(
            provider(&server, "account-a")
                .fetch_at(&context("account-a"), timestamp(1))
                .await
                .expect_err("expired OAuth")
                .kind(),
            ErrorKind::AuthenticationExpired
        );
    }
    let server = FakeHttpServer::start([FakeHttpResponse::new(201, USAGE.to_vec())]).await;
    assert_eq!(
        provider(&server, "account-a")
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("exact status")
            .kind(),
        ErrorKind::Api
    );

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1))
        .await
        .expect("last good");
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
    for wrong in [
        context("account-b"),
        context_with_source("account-a", ProviderSource::ApiKey),
    ] {
        assert_eq!(
            provider
                .fetch_at(&wrong, timestamp(3))
                .await
                .expect_err("context isolation")
                .kind(),
            ErrorKind::Api
        );
    }
    assert_eq!(server.requests().len(), before);

    let wrong = FixedApiClient::new_authorization_scheme(
        scope_for(ProviderId::OpenAi, "account-a"),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        ApiKeyCredential::new(TOKEN_CANARY).expect("credential"),
        config(1024),
    )
    .expect("wrong client");
    assert_eq!(
        CopilotProvider::from_client(wrong)
            .err()
            .expect("wrong provider")
            .kind(),
        ErrorKind::Api
    );

    let wrong_source = FixedApiClient::new_authorization_scheme(
        scope("account-a"),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        ApiKeyCredential::new(TOKEN_CANARY).expect("credential"),
        config(1024),
    )
    .expect("Copilot client with default source");
    assert_eq!(
        CopilotProvider::from_client(wrong_source)
            .err()
            .expect("wrong source")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn malformed_optional_date_metadata_fails_like_the_typed_baseline_decoder() {
    for field in [r#""quota_reset_date":7"#, r#""assigned_date":{}"#] {
        let body = format!(
            r#"{{
                "copilot_plan":"individual",
                {field},
                "quota_snapshots":{{
                    "chat":{{"entitlement":100,"remaining":50,"percent_remaining":50}}
                }}
            }}"#
        );
        let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.into_bytes())]).await;

        assert_eq!(
            provider(&server, "account-a")
                .fetch_at(&context("account-a"), timestamp(1))
                .await
                .expect_err("date metadata type mismatch")
                .kind(),
            ErrorKind::Parse
        );
    }
}
