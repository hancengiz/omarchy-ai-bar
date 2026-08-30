use std::time::Duration;

use nix::sys::utsname::uname;
use oab_domain::ErrorKind;
use oab_providers::providers::codex::{
    CodexAttemptFailure, CodexBearerKind, CodexCredentialSource, parse_codex_bearer,
    parse_native_codex_pat,
};
use oab_providers::providers::codex_http::{
    CodexAdditionalRateLimit, CodexHttpClient, CodexHttpError, CodexHttpRoutes, CodexPlanType,
    CodexUsageResponse, CodexWindowSnapshot, codex_cli_user_agent, parse_codex_usage_response,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use url::Url;

const PAT_CANARY: &str = "fixture-codex-pat-secret-canary";
const OAUTH_CANARY: &str = "fixture-codex-oauth-secret-canary";
const RESPONSE_CANARY: &str = "fixture-codex-response-secret-canary";

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
        1024 * 1024,
        3,
        RetryPolicy::none(),
    )
    .expect("fixture transport config")
}

fn client(server: &FakeHttpServer) -> CodexHttpClient {
    client_for_routes(
        server.url("/api/accounts/v1/user-auth-credential/whoami"),
        server.url("/backend-api/wham/usage"),
    )
}

fn client_for_routes(whoami: Url, usage: Url) -> CodexHttpClient {
    let routes = CodexHttpRoutes::loopback(whoami, usage).expect("loopback Codex routes");
    CodexHttpClient::with_transport_config(routes, config()).expect("fixture Codex client")
}

fn pat_credentials() -> oab_providers::providers::codex::CodexPatCredentials {
    parse_native_codex_pat(format!(r#"{{"personal_access_token":"{PAT_CANARY}"}}"#).as_bytes())
        .expect("fixture PAT")
}

fn bearer_credentials() -> oab_providers::providers::codex::CodexBearerCredentials {
    parse_codex_bearer(
        format!(
            r#"{{"tokens":{{"access_token":"{OAUTH_CANARY}","refresh_token":"refresh","account_id":"credential-account"}}}}"#
        )
        .as_bytes(),
        CodexCredentialSource::Native,
    )
    .expect("fixture OAuth")
}

fn assert_response_debug_redacted(
    usage: &CodexUsageResponse,
    additional: &CodexAdditionalRateLimit,
) {
    let diagnostics = format!("{usage:?} {additional:?}");
    for canary in [
        "snake-account",
        "fixture-unknown-plan-secret-canary",
        "fixture-limit-name-secret-canary",
        "fixture-metered-feature-secret-canary",
    ] {
        assert!(!diagnostics.contains(canary));
    }
}

fn usage_body(used_percent: i64) -> Vec<u8> {
    format!(
        r#"{{
            "account_id":"response-account",
            "plan_type":"team",
            "rate_limit":{{
                "primary_window":{{
                    "used_percent":{used_percent},
                    "reset_at":1782864000,
                    "limit_window_seconds":18000
                }},
                "secondary_window":null
            }}
        }}"#
    )
    .into_bytes()
}

#[test]
fn pat_user_agent_matches_the_pinned_linux_shape_and_bare_cli_quirk() {
    let release = uname().expect("fixture uname");
    let release = release.release().to_str().expect("UTF-8 kernel release");
    let mut components = release
        .split(|character: char| !character.is_ascii_digit())
        .filter(|component| !component.is_empty())
        .map(|component| component.parse::<u32>().expect("numeric kernel component"));
    let major = components.next().expect("kernel major");
    let minor = components.next().unwrap_or(0);
    let patch = components.next().unwrap_or(0);
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => "unknown",
    };

    assert_eq!(
        codex_cli_user_agent(Some("codex-cli 1.2.3 extra")).expect("versioned UA"),
        format!("codex_cli_rs/1.2.3 (Linux {major}.{minor}.{patch}; {architecture})")
    );
    assert_eq!(
        codex_cli_user_agent(None).expect("unversioned UA"),
        format!("codex_cli_rs (Linux {major}.{minor}.{patch}; {architecture})")
    );
    assert_eq!(
        codex_cli_user_agent(Some("codex-cli")).expect("pinned bare-token behavior"),
        format!("codex_cli_rs/codex-cli (Linux {major}.{minor}.{patch}; {architecture})")
    );
    assert_eq!(
        codex_cli_user_agent(Some("1.2\ninjected")).expect_err("line-breaking version is rejected"),
        CodexHttpError::Configuration
    );
}

#[test]
fn core_parser_is_lossy_bounded_and_preserves_limit_precedence() {
    let payload = br#"{
        "account_id":"snake-account",
        "accountId":"camel-must-not-win",
        "plan_type":"fixture-unknown-plan-secret-canary",
        "rate_limit":{
            "primary_window":{
                "used_percent":22,
                "reset_at":1766948068,
                "limit_window_seconds":18000
            },
            "secondary_window":{"used_percent":"bad"},
            "individual_limit":{
                "limit":"100000",
                "used":7761,
                "remaining_percent":"92.239",
                "reset_at":1782864000.9
            }
        },
        "credits":{"has_credits":true,"unlimited":false,"balance":"14.5"},
        "individual_limit":{"limit":"500","used":"10","resets_at":"1788220800.9"},
        "spend_control":{
            "individual_limit":{"limit":1000,"remainingPercent":96,"resetsAt":"1788220800"}
        },
        "additional_rate_limits":[
            "malformed sibling",
            {
                "limit_name":"fixture-limit-name-secret-canary",
                "metered_feature":"fixture-metered-feature-secret-canary",
                "rate_limit":{
                    "primary_window":{
                        "used_percent":30,
                        "reset_at":1766948068,
                        "limit_window_seconds":18000
                    },
                    "secondary_window":{"used_percent":"bad"}
                }
            },
            {"limit_name":42,"rate_limit":"bad"}
        ]
    }"#;

    let usage = parse_codex_usage_response(payload).expect("lossy core response");
    assert_eq!(usage.account_id(), Some("snake-account"));
    assert_eq!(
        usage.plan_type(),
        Some(&CodexPlanType::Unknown(
            "fixture-unknown-plan-secret-canary".to_owned()
        ))
    );

    let rate = usage.rate_limit().expect("rate limits");
    assert_eq!(rate.primary_window().expect("primary").used_percent(), 22);
    assert_eq!(rate.secondary_window(), None);
    assert!(!rate.primary_window_decode_failed());
    assert!(rate.secondary_window_decode_failed());
    assert_eq!(
        rate.individual_limit().expect("rate limit cap").limit(),
        Some(100_000.0)
    );
    assert_eq!(
        rate.individual_limit().expect("rate limit cap").resets_at(),
        Some(1_782_864_000)
    );

    let credits = usage.credits().expect("credits");
    assert!(credits.has_credits());
    assert!(!credits.unlimited());
    assert_eq!(credits.balance(), Some(14.5));
    assert!(usage.spend_control_present());
    assert_eq!(
        usage
            .spend_control_individual_limit()
            .expect("spend control")
            .limit(),
        Some(1000.0)
    );
    let root_limit = usage.resolved_individual_limit().expect("root wins");
    assert_eq!(root_limit.limit(), Some(500.0));
    assert_eq!(
        root_limit.resets_at(),
        None,
        "fractional numeric strings remain invalid even though numeric doubles truncate"
    );

    let additional = usage.additional_rate_limits().expect("additional array");
    assert_eq!(additional.len(), 2);
    assert_eq!(
        additional[0].metered_feature(),
        Some("fixture-metered-feature-secret-canary")
    );
    assert_eq!(
        additional[0]
            .rate_limit()
            .and_then(|limit| limit.primary_window())
            .map(CodexWindowSnapshot::used_percent),
        Some(30)
    );
    assert!(additional[0].has_window_decode_failure());
    assert!(additional[1].has_window_decode_failure());
    assert!(usage.additional_rate_limits_decode_failed());

    assert_response_debug_redacted(&usage, &additional[0]);
}

#[test]
fn optional_shapes_fail_soft_but_document_bounds_fail_closed() {
    let empty = parse_codex_usage_response(b"{}").expect("empty keyed response remains decodable");
    assert!(empty.rate_limit().is_none());
    assert!(empty.credits().is_none());
    assert!(empty.additional_rate_limits().is_none());
    assert!(!empty.additional_rate_limits_decode_failed());

    let malformed_optional = parse_codex_usage_response(
        br#"{
            "plan_type":42,
            "rate_limit":"bad",
            "credits":{"has_credits":"bad","balance":{}},
            "spend_control":null,
            "additional_rate_limits":"bad"
        }"#,
    )
    .expect("optional malformed fields stay lossy");
    assert!(malformed_optional.plan_type().is_none());
    assert!(malformed_optional.rate_limit().is_none());
    let credits = malformed_optional.credits().expect("lossy credits object");
    assert!(!credits.has_credits());
    assert_eq!(credits.balance(), None);
    assert!(malformed_optional.spend_control_present());
    assert!(malformed_optional.additional_rate_limits().is_none());
    assert!(malformed_optional.additional_rate_limits_decode_failed());

    let shadowing = parse_codex_usage_response(
        br#"{
            "individual_limit":{},
            "rate_limit":{"individual_limit":{"limit":200}},
            "spend_control":{"individual_limit":{"limit":300}}
        }"#,
    )
    .expect("empty root cap is still decoded");
    assert_eq!(
        shadowing
            .resolved_individual_limit()
            .expect("decoded root shadows lower sources")
            .limit(),
        None
    );

    let wrapper_shadowing = parse_codex_usage_response(
        br#"{
            "spend_control":{},
            "spendControl":{"individualLimit":{"limit":300}}
        }"#,
    )
    .expect("decoded snake wrapper shadows camel wrapper");
    assert!(wrapper_shadowing.spend_control_present());
    assert_eq!(wrapper_shadowing.spend_control_individual_limit(), None);

    let mut nested = json!({});
    for _ in 0..30 {
        nested = json!({"nested": nested});
    }
    let nested = serde_json::to_vec(&nested).expect("nested fixture");
    assert_eq!(
        parse_codex_usage_response(&nested).expect_err("depth bound"),
        CodexHttpError::InvalidResponse
    );
    assert_eq!(
        parse_codex_usage_response(&vec![b'x'; 1024 * 1024 + 1]).expect_err("body bound"),
        CodexHttpError::InvalidResponse
    );

    let entries = vec![json!({}); 129];
    let bounded = serde_json::to_vec(&json!({"additional_rate_limits": entries}))
        .expect("bounded additional fixture");
    let bounded = parse_codex_usage_response(&bounded).expect("bounded additional parser");
    assert_eq!(
        bounded
            .additional_rate_limits()
            .expect("bounded array")
            .len(),
        128
    );
    assert!(bounded.additional_rate_limits_decode_failed());
}

#[test]
fn bounded_additional_metadata_signals_loss_without_erasing_valid_windows() {
    let oversized = "x".repeat(513);
    let payload = serde_json::to_vec(&json!({
        "additional_rate_limits": [{
            "limit_name": oversized,
            "metered_feature": "feature",
            "rate_limit": {
                "primary_window": {
                    "used_percent": 19,
                    "reset_at": 1_782_864_000_i64,
                    "limit_window_seconds": 18_000
                }
            }
        }]
    }))
    .expect("bounded metadata fixture");
    let usage = parse_codex_usage_response(&payload).expect("lossy bounded metadata");
    let additional = usage.additional_rate_limits().expect("additional limits");
    assert_eq!(additional.len(), 1);
    assert!(additional[0].limit_name().is_none());
    assert_eq!(additional[0].metered_feature(), Some("feature"));
    assert_eq!(
        additional[0]
            .rate_limit()
            .and_then(|limit| limit.primary_window())
            .map(CodexWindowSnapshot::used_percent),
        Some(19)
    );
    assert!(usage.additional_rate_limits_decode_failed());
}

#[test]
fn usage_url_resolution_matches_both_pinned_styles_and_rejects_unsafe_config() {
    let default = CodexHttpRoutes::from_config_text(None).expect("default routes");
    assert_eq!(
        default.usage_url().as_str(),
        "https://chatgpt.com/backend-api/wham/usage"
    );
    assert_eq!(
        default.whoami_url().as_str(),
        "https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami"
    );

    let chat = CodexHttpRoutes::from_config_text(Some(
        "# fixture\nchatgpt_base_url = 'https://chat.openai.com/' # comment\n",
    ))
    .expect("ChatGPT-style base");
    assert_eq!(
        chat.usage_url().as_str(),
        "https://chat.openai.com/backend-api/wham/usage"
    );

    let api =
        CodexHttpRoutes::from_config_text(Some("chatgpt_base_url = \"https://api.openai.com\""))
            .expect("API-style base");
    assert_eq!(
        api.usage_url().as_str(),
        "https://api.openai.com/api/codex/usage"
    );

    let prefixed = CodexHttpRoutes::from_config_text(Some(
        "chatgpt_base_url=https://proxy.example.test/openai",
    ))
    .expect("bounded custom prefix");
    assert_eq!(
        prefixed.usage_url().as_str(),
        "https://proxy.example.test/openai/api/codex/usage"
    );

    let multiline = CodexHttpRoutes::from_config_text(Some(
        "model_instructions = \"\"\"\nignore = this\n\"\"\"\nchatgpt_base_url = \"https://api.openai.com\"",
    ))
    .expect("unrelated multiline TOML remains irrelevant");
    assert_eq!(
        multiline.usage_url().as_str(),
        "https://api.openai.com/api/codex/usage"
    );

    for unsafe_config in [
        "chatgpt_base_url=http://api.openai.com",
        "chatgpt_base_url=https://user:pass@api.openai.com",
        "chatgpt_base_url=https://api.openai.com?token=secret",
        "chatgpt_base_url='https://api.openai.com#fragment'",
        "chatgpt_base_url='https://api.openai.com",
        "chatgpt_base_url=https://one.example\nchatgpt_base_url=https://two.example",
    ] {
        assert_eq!(
            CodexHttpRoutes::from_config_text(Some(unsafe_config))
                .expect_err("unsafe explicit config fails closed"),
            CodexHttpError::Configuration,
            "config={unsafe_config:?}"
        );
    }
}

#[tokio::test]
async fn pat_is_strictly_whoami_then_usage_with_token_owned_account_scope() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(
            200,
            br#"{
                "chatgpt_account_id":"  pat-account  ",
                "chatgpt_plan_type":" team ",
                "email":" pat@example.test "
            }"#
            .to_vec(),
        ),
        FakeHttpResponse::new(200, usage_body(68)),
    ])
    .await;
    let fetched = client(&server)
        .fetch_pat_usage(
            &pat_credentials(),
            Some("codex-cli 1.2.3 extra"),
            &CancellationToken::new(),
        )
        .await
        .expect("PAT usage");

    let whoami = fetched.whoami().expect("whoami result");
    assert_eq!(whoami.account_id(), Some("pat-account"));
    assert_eq!(whoami.email(), Some("pat@example.test"));
    assert_eq!(whoami.plan_type(), Some("team"));
    assert_eq!(
        fetched
            .usage()
            .rate_limit()
            .and_then(|limit| limit.primary_window())
            .map(CodexWindowSnapshot::used_percent),
        Some(68)
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].target(),
        "/api/accounts/v1/user-auth-credential/whoami"
    );
    assert_eq!(requests[1].target(), "/backend-api/wham/usage");
    for request in &requests {
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request.header("authorization"),
            Some("Bearer fixture-codex-pat-secret-canary")
        );
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("originator"), Some("codex_cli_rs"));
        assert!(
            request
                .header("user-agent")
                .is_some_and(|value| value.starts_with("codex_cli_rs/1.2.3 (Linux "))
        );
        assert_eq!(request.header("cookie"), None);
        assert_eq!(request.header("content-type"), None);
    }
    assert_eq!(requests[0].header("chatgpt-account-id"), None);
    assert_eq!(
        requests[1].header("chatgpt-account-id"),
        Some("pat-account")
    );
}

#[tokio::test]
async fn pat_never_attempts_usage_after_whoami_failure() {
    for response in [
        FakeHttpResponse::new(401, b"unauthorized".to_vec()),
        FakeHttpResponse::new(200, br#"{"chatgpt_account_id":42}"#.to_vec()),
    ] {
        let server =
            FakeHttpServer::start([response, FakeHttpResponse::new(200, usage_body(1))]).await;
        let error = client(&server)
            .fetch_pat_usage(&pat_credentials(), Some("1.2.3"), &CancellationToken::new())
            .await
            .expect_err("whoami failure must stop the flow");
        assert!(matches!(
            error,
            CodexHttpError::Unauthorized | CodexHttpError::InvalidResponse
        ));
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn oauth_uses_managed_override_without_pat_only_headers() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, usage_body(7))]).await;
    let credentials = bearer_credentials();
    assert_eq!(credentials.kind(), CodexBearerKind::OAuth);
    let usage = client(&server)
        .fetch_oauth_usage(
            &credentials,
            Some("  managed-account  "),
            &CancellationToken::new(),
        )
        .await
        .expect("managed OAuth usage");
    assert_eq!(
        usage
            .rate_limit()
            .and_then(|limit| limit.primary_window())
            .map(CodexWindowSnapshot::used_percent),
        Some(7)
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method(), "GET");
    assert_eq!(request.target(), "/backend-api/wham/usage");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer fixture-codex-oauth-secret-canary")
    );
    assert_eq!(request.header("user-agent"), Some("omarchy-ai-bar"));
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(
        request.header("chatgpt-account-id"),
        Some("managed-account")
    );
    assert_eq!(request.header("originator"), None);
    assert_eq!(request.header("openai-beta"), None);
    assert_eq!(request.header("content-type"), None);
    assert_eq!(request.header("cookie"), None);
}

#[tokio::test]
async fn oauth_blank_override_uses_credential_account() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, usage_body(9))]).await;
    client(&server)
        .fetch_oauth_usage(&bearer_credentials(), Some("  "), &CancellationToken::new())
        .await
        .expect("credential-scoped OAuth usage");
    assert_eq!(
        server.requests()[0].header("chatgpt-account-id"),
        Some("credential-account")
    );
}

#[tokio::test]
async fn status_parse_server_network_and_cancellation_classes_are_closed() {
    for status in [401, 403] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(status, Vec::new())]).await;
        let error = client(&server)
            .fetch_oauth_usage(&bearer_credentials(), None, &CancellationToken::new())
            .await
            .expect_err("authentication status");
        assert_eq!(error, CodexHttpError::Unauthorized);
        assert_eq!(error.attempt_failure(), CodexAttemptFailure::Unauthorized);
        assert_eq!(error.classified().kind(), ErrorKind::AuthenticationExpired);
    }

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(500, RESPONSE_CANARY.as_bytes().to_vec()),
        FakeHttpResponse::new(200, usage_body(1)),
    ])
    .await;
    let error = client(&server)
        .fetch_oauth_usage(&bearer_credentials(), None, &CancellationToken::new())
        .await
        .expect_err("server failure");
    assert_eq!(error, CodexHttpError::Server { status: Some(500) });
    assert_eq!(error.attempt_failure(), CodexAttemptFailure::Server);
    assert_eq!(server.requests().len(), 1, "Codex HTTP never retries");
    assert!(!format!("{error:?}").contains(RESPONSE_CANARY));

    let malformed = FakeHttpServer::start([FakeHttpResponse::new(200, b"not-json".to_vec())]).await;
    let error = client(&malformed)
        .fetch_oauth_usage(&bearer_credentials(), None, &CancellationToken::new())
        .await
        .expect_err("parse failure");
    assert_eq!(error, CodexHttpError::InvalidResponse);
    assert_eq!(
        error.attempt_failure(),
        CodexAttemptFailure::InvalidResponse
    );

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let short = TransportConfig::new(
        Duration::from_millis(100),
        Duration::from_millis(20),
        1024,
        0,
        RetryPolicy::none(),
    )
    .expect("short timeout");
    let routes = CodexHttpRoutes::loopback(
        stalled.url("/whoami"),
        stalled.url("/backend-api/wham/usage"),
    )
    .expect("stalled routes");
    let stalled_client =
        CodexHttpClient::with_transport_config(routes, short).expect("stalled client");
    let error = stalled_client
        .fetch_oauth_usage(&bearer_credentials(), None, &CancellationToken::new())
        .await
        .expect_err("bounded timeout");
    assert_eq!(error, CodexHttpError::Network);
    assert_eq!(error.attempt_failure(), CodexAttemptFailure::Network);

    let cancelled_server = FakeHttpServer::start([FakeHttpResponse::new(200, usage_body(2))]).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let error = client(&cancelled_server)
        .fetch_oauth_usage(&bearer_credentials(), None, &cancellation)
        .await
        .expect_err("pre-cancelled request");
    assert_eq!(error, CodexHttpError::Cancelled);
    assert_eq!(error.attempt_failure(), CodexAttemptFailure::Network);
    assert!(cancelled_server.requests().is_empty());
}

#[tokio::test]
async fn redirects_are_same_origin_and_credentials_never_reach_an_unapproved_target() {
    let same_origin = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/final"),
        FakeHttpResponse::new(200, usage_body(11)),
    ])
    .await;
    client(&same_origin)
        .fetch_oauth_usage(&bearer_credentials(), None, &CancellationToken::new())
        .await
        .expect("same-origin redirect");
    let requests = same_origin.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].target(), "/final");
    assert_eq!(
        requests[1].header("authorization"),
        Some("Bearer fixture-codex-oauth-secret-canary")
    );

    let target = FakeHttpServer::start([FakeHttpResponse::new(200, usage_body(12))]).await;
    let redirect = FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
        .header("Location", target.url("/credential-theft").as_str())])
    .await;
    let error = client(&redirect)
        .fetch_oauth_usage(&bearer_credentials(), None, &CancellationToken::new())
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error, CodexHttpError::Configuration);
    assert!(target.requests().is_empty());
}

#[tokio::test]
async fn pat_redirects_cannot_cross_between_its_two_approved_origins() {
    let usage = FakeHttpServer::start([FakeHttpResponse::new(200, usage_body(1))]).await;
    let whoami = FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
        .header("Location", usage.url("/whoami-credential-theft").as_str())])
    .await;
    let error = client_for_routes(whoami.url("/whoami"), usage.url("/usage"))
        .fetch_pat_usage(&pat_credentials(), None, &CancellationToken::new())
        .await
        .expect_err("whoami transport must reject usage origin");
    assert_eq!(error, CodexHttpError::Configuration);
    assert!(usage.requests().is_empty());

    let whoami = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        br#"{"chatgpt_account_id":"pat-account"}"#.to_vec(),
    )])
    .await;
    let usage = FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
        .header("Location", whoami.url("/usage-credential-theft").as_str())])
    .await;
    let error = client_for_routes(whoami.url("/whoami"), usage.url("/usage"))
        .fetch_pat_usage(&pat_credentials(), None, &CancellationToken::new())
        .await
        .expect_err("usage transport must reject whoami origin");
    assert_eq!(error, CodexHttpError::Configuration);
    assert_eq!(
        whoami.requests().len(),
        1,
        "redirect target was not reached"
    );
    assert_eq!(usage.requests().len(), 1);
}

#[test]
fn loopback_seam_rejects_non_loopback_routes() {
    let public = Url::parse("https://api.openai.com/api/codex/usage").expect("public URL");
    assert_eq!(
        CodexHttpRoutes::loopback(public.clone(), public).expect_err("not loopback"),
        CodexHttpError::Configuration
    );
}
