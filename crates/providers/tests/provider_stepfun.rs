use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::stepfun::{StepFunProvider, StepFunRouteSet, parse_stepfun_usage};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use url::Url;

const ROLLING: &[u8] = include_bytes!("../../../fixtures/providers/stepfun/rolling.json");
const CREDIT: &[u8] = include_bytes!("../../../fixtures/providers/stepfun/credit.json");
const PLAN: &[u8] = include_bytes!("../../../fixtures/providers/stepfun/plan.json");
const REFRESH: &[u8] = include_bytes!("../../../fixtures/providers/stepfun/refresh.json");
const REGISTER: &[u8] = include_bytes!("../../../fixtures/providers/stepfun/register.json");
const LOGIN: &[u8] = include_bytes!("../../../fixtures/providers/stepfun/login.json");

const NOW_SECONDS: i64 = 1_780_000_000;
const DEFAULT_WEB_ID: &str = "c8a1002d2c457e758785a9979832217c7c0b884c";
const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
);

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::StepFun,
        ProviderInstanceId::new("stepfun-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn wrong_scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Sakana,
        ProviderInstanceId::new("sakana-primary").expect("provider instance"),
        AccountKey::new("account-a").expect("account key"),
    )
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn context_with_cancellation(
    account: &str,
    source: ProviderSource,
    cancellation: CancellationToken,
) -> ProviderContext {
    ProviderContext::new(scope(account), source, cancellation)
}

fn routes(server: &FakeHttpServer) -> StepFunRouteSet {
    StepFunRouteSet::loopback(server.url("/ignored?discard=true")).expect("loopback routes")
}

fn manual_provider(server: &FakeHttpServer, capture: &str) -> StepFunProvider {
    StepFunProvider::from_manual_capture_routes(scope("account-a"), capture, routes(server))
        .expect("manual StepFun provider")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn jwt(device_id: &str) -> String {
    let payload = serde_json::to_vec(&json!({ "device_id": device_id })).expect("JWT JSON");
    format!("header.{}.signature", URL_SAFE_NO_PAD.encode(payload))
}

fn token_response(access: &str, refresh: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "accessToken": { "raw": access },
        "refreshToken": { "raw": refresh }
    }))
    .expect("token fixture")
}

#[test]
fn golden_rolling_response_maps_windows_plan_and_provenance() {
    let sample = parse_stepfun_usage(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        ROLLING,
        Some("  Coding Plan Pro  "),
    )
    .expect("rolling response");

    let primary = sample.primary().expect("five-hour window");
    assert_percent(primary.used_percent().expect("five-hour usage").get(), 20.0);
    assert_eq!(
        primary.duration().expect("five-hour duration").seconds(),
        5 * 60 * 60
    );
    assert_eq!(
        primary
            .resets_at()
            .expect("five-hour reset")
            .unix_timestamp(),
        1_780_000_300
    );
    let secondary = sample.secondary().expect("weekly window");
    assert_percent(secondary.used_percent().expect("weekly usage").get(), 40.0);
    assert_eq!(
        secondary.duration().expect("weekly duration").seconds(),
        7 * 24 * 60 * 60
    );
    assert_eq!(
        secondary
            .resets_at()
            .expect("weekly reset")
            .unix_timestamp(),
        1_780_604_800
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("plan name")
            .as_str(),
        "Coding Plan Pro"
    );
    assert_eq!(sample.provenance()[0].source(), "stepfun");
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");
}

#[test]
fn golden_credit_response_weights_buckets_and_activates_monthly_pace() {
    let sample = parse_stepfun_usage(scope("account-a"), timestamp(NOW_SECONDS), CREDIT, None)
        .expect("credit response");

    let primary = sample.primary().expect("credit window");
    assert_percent(primary.used_percent().expect("credit usage").get(), 42.5);
    assert_eq!(
        primary.duration().expect("monthly duration").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        primary.resets_at().expect("credit reset").unix_timestamp(),
        1_782_864_000
    );
    assert!(sample.secondary().is_none());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("fallback plan")
            .as_str(),
        "password"
    );
}

#[test]
fn credit_shape_precedence_and_fallbacks_match_the_pinned_provider() {
    let live_window = br#"{
      "status":1,
      "five_hour_usage_left_rate":0.8,"five_hour_usage_reset_time":"1780000300",
      "weekly_usage_left_rate":0.6,"weekly_usage_reset_time":"1780604800",
      "plan_family":2,
      "plan_credit_rate_limit":{"subscription_credit_left_rate":1}
    }"#;
    let live = parse_stepfun_usage(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        live_window,
        None,
    )
    .expect("live windows win");
    assert_eq!(
        live.primary()
            .expect("five-hour")
            .duration()
            .expect("duration")
            .seconds(),
        18_000
    );
    assert!(live.secondary().is_some());

    let incomplete_buckets = br#"{
      "status":1,"plan_family":2,
      "plan_credit_rate_limit":{
        "subscription_credit_left_rate":0.6,"topup_credit_left_rate":0.4,
        "credit_buckets":[{"credit_total":"100"}]
      }
    }"#;
    let fallback = parse_stepfun_usage(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        incomplete_buckets,
        None,
    )
    .expect("subscription fallback");
    assert_percent(
        fallback
            .primary()
            .expect("credit")
            .used_percent()
            .expect("usage")
            .get(),
        40.0,
    );

    for payload in [
        br#"{"status":1,"plan_credit_rate_limit":{"subscription_credit_left_rate":0}}"#.as_slice(),
        br#"{"status":1,"plan_credit_rate_limit":{"topup_credit_left_rate":0}}"#.as_slice(),
    ] {
        let exhausted =
            parse_stepfun_usage(scope("account-a"), timestamp(NOW_SECONDS), payload, None)
                .expect("zero credit remains a credit plan");
        assert_percent(
            exhausted
                .primary()
                .expect("credit")
                .used_percent()
                .expect("usage")
                .get(),
            100.0,
        );
        assert!(exhausted.secondary().is_none());
    }
}

#[test]
fn flexible_fields_zero_reset_and_percentage_clamping_match_baseline() {
    let payload = br#"{
      "status":1,
      "five_hour_usage_left_rate":"-5","five_hour_usage_reset_time":"1780000300",
      "weekly_usage_left_rate":9,"weekly_usage_reset_time":1780604800
    }"#;
    let sample = parse_stepfun_usage(scope("account-a"), timestamp(NOW_SECONDS), payload, None)
        .expect("flexible numbers");
    assert_percent(
        sample
            .primary()
            .expect("primary")
            .used_percent()
            .expect("known")
            .get(),
        100.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("secondary")
            .used_percent()
            .expect("known")
            .get(),
        0.0,
    );

    let no_reset = br#"{
      "status":1,"plan_family":2,
      "plan_credit_rate_limit":{
        "subscription_credit_left_rate":"0.5",
        "subscription_credit_reset_time":"0"
      }
    }"#;
    let sample = parse_stepfun_usage(scope("account-a"), timestamp(NOW_SECONDS), no_reset, None)
        .expect("credit without reset");
    let primary = sample.primary().expect("credit window");
    assert_percent(primary.used_percent().expect("known").get(), 50.0);
    assert!(primary.duration().is_none());
    assert!(primary.resets_at().is_none());
}

#[test]
fn parse_failures_and_authentication_messages_are_classified_without_secrets() {
    for payload in [
        br#"{"status":1}"#.as_slice(),
        b"not-json".as_slice(),
        br#"{"status":0,"message":"token plan status temporarily unavailable"}"#.as_slice(),
    ] {
        let error = parse_stepfun_usage(scope("account-a"), timestamp(NOW_SECONDS), payload, None)
            .expect_err("invalid response");
        assert!(matches!(error.kind(), ErrorKind::Parse | ErrorKind::Api));
    }

    for payload in [
        br#"{"status":0,"code":401}"#.as_slice(),
        br#"{"status":0,"desc":"token expired: secret-canary"}"#.as_slice(),
    ] {
        let error = parse_stepfun_usage(scope("account-a"), timestamp(NOW_SECONDS), payload, None)
            .expect_err("expired response");
        assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
    }

    let wrong = parse_stepfun_usage(wrong_scope(), timestamp(NOW_SECONDS), ROLLING, None)
        .expect_err("wrong provider scope");
    assert_eq!(wrong.kind(), ErrorKind::Api);
}

#[test]
fn json_limits_and_identity_bounds_fail_closed() {
    let oversized = vec![b' '; 2 * 1024 * 1024 + 1];
    let error = parse_stepfun_usage(scope("account-a"), timestamp(NOW_SECONDS), &oversized, None)
        .expect_err("oversized response");
    assert_eq!(error.kind(), ErrorKind::Parse);

    let mut nested = String::from("{\"status\":1,\"plan_family\":2,\"x\":");
    nested.push_str(&"[".repeat(42));
    nested.push_str("null");
    nested.push_str(&"]".repeat(42));
    nested.push('}');
    let error = parse_stepfun_usage(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        nested.as_bytes(),
        None,
    )
    .expect_err("deep response");
    assert_eq!(error.kind(), ErrorKind::Parse);

    let long_plan = "p".repeat(257);
    let sample = parse_stepfun_usage(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        ROLLING,
        Some(&long_plan),
    )
    .expect("long optional plan is ignored");
    assert_eq!(
        sample.identity().login_method().expect("fallback").as_str(),
        "password"
    );
}

#[tokio::test]
async fn manual_inputs_normalize_bare_cookie_quoted_and_curl_forms() {
    for capture in [
        "manual-access...manual-refresh".to_owned(),
        "Cookie: Oasis-Token=manual-access...manual-refresh; Oasis-Webid=ignored".to_owned(),
        "'manual-access...manual-refresh'".to_owned(),
        "curl 'https://platform.stepfun.com/plan-usage?ignored=true' -H 'Cookie: Oasis-Token=manual-access...manual-refresh; other=x'".to_owned(),
    ] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, ROLLING.to_vec()),
            FakeHttpResponse::new(200, PLAN.to_vec()),
        ])
        .await;
        let provider = manual_provider(&server, &capture);
        provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("normalized credential fetch");
        assert_eq!(
            server.requests()[0].header("cookie"),
            Some(
                "Oasis-Token=manual-access...manual-refresh; \
                 Oasis-Webid=c8a1002d2c457e758785a9979832217c7c0b884c"
            )
        );
    }

    let server = FakeHttpServer::start([]).await;
    for capture in [
        "",
        "token with spaces",
        "bad;value",
        "curl 'https://evil.example/' -H 'Cookie: Oasis-Token=secret-canary'",
    ] {
        let error = StepFunProvider::from_manual_capture_routes(
            scope("account-a"),
            capture,
            routes(&server),
        )
        .expect_err("unsafe credential");
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
    }
}

#[tokio::test]
async fn manual_fetch_sends_exact_routes_headers_body_and_refresh_half_web_id() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
    ])
    .await;
    let device_jwt = jwt("registered-device");
    let token = format!("access-token...{device_jwt}");
    let provider = manual_provider(&server, &token);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert_eq!(provider.descriptor().id, ProviderId::StepFun);
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Token Plan Plus"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(
        requests[0].target(),
        "/api/step.openapi.devcenter.Dashboard/QueryStepPlanRateLimit"
    );
    assert_eq!(requests[0].body(), b"{}");
    assert_eq!(requests[0].header("content-type"), Some("application/json"));
    assert_eq!(requests[0].header("oasis-appid"), Some("10300"));
    assert_eq!(requests[0].header("oasis-platform"), Some("web"));
    assert_eq!(requests[0].header("oasis-webid"), Some("registered-device"));
    assert_eq!(requests[0].header("user-agent"), Some(USER_AGENT));
    assert_eq!(
        requests[0].header("cookie"),
        Some(format!("Oasis-Token={token}; Oasis-Webid=registered-device").as_str())
    );
    assert_eq!(
        requests[1].target(),
        "/api/step.openapi.devcenter.Dashboard/GetStepPlanStatus"
    );
}

#[tokio::test]
async fn optional_plan_failure_keeps_required_usage_and_cancellation_is_authoritative() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(500, b"optional failure".to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "token");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("usage survives optional failure");
    assert_eq!(
        sample.identity().login_method().expect("fallback").as_str(),
        "password"
    );

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = Arc::new(manual_provider(&stalled, "token"));
    let cancellation = CancellationToken::new();
    let task_provider = Arc::clone(&provider);
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move {
        task_provider
            .fetch_at(
                &context_with_cancellation(
                    "account-a",
                    ProviderSource::ManualCookie,
                    task_cancellation,
                ),
                timestamp(NOW_SECONDS),
            )
            .await
    });
    stalled.wait_for_request_count(1).await;
    cancellation.cancel();
    let error = task
        .await
        .expect("fetch task")
        .expect_err("cancelled fetch");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[tokio::test]
async fn expired_manual_token_refreshes_once_persists_and_retries_usage() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, REFRESH.to_vec()),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "old-access...old-refresh");
    let run_context = context("account-a", ProviderSource::ManualCookie);
    for _ in 0..2 {
        provider
            .fetch_at(&run_context, timestamp(NOW_SECONDS))
            .await
            .expect("refreshed usage");
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(
        requests[1].target(),
        "/passport/proto.api.passport.v1.PassportService/RefreshToken"
    );
    assert_eq!(
        requests[1].header("oasis-token"),
        Some("old-access...old-refresh")
    );
    assert!(
        requests[0]
            .header("cookie")
            .expect("old cookie")
            .contains("old-access...old-refresh")
    );
    for request in &requests[2..] {
        assert!(
            request
                .header("cookie")
                .expect("refreshed cookie")
                .contains("new-access...new-refresh")
        );
    }
}

#[tokio::test]
async fn payload_authentication_errors_recover_but_non_auth_statuses_do_not() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, br#"{"status":0,"message":"expired token"}"#.to_vec()),
        FakeHttpResponse::new(200, REFRESH.to_vec()),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "old-access...old-refresh");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("payload auth recovery");
    assert_eq!(
        server.requests()[1].target(),
        "/passport/proto.api.passport.v1.PassportService/RefreshToken"
    );

    for response in [
        FakeHttpResponse::new(429, Vec::new()),
        FakeHttpResponse::new(
            200,
            br#"{"status":0,"message":"token plan status temporarily unavailable"}"#.to_vec(),
        ),
    ] {
        let server = FakeHttpServer::start([response]).await;
        let provider = manual_provider(&server, "old-access...old-refresh");
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("non-auth API status");
        assert_eq!(error.kind(), ErrorKind::Api);
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn recovery_does_not_rewrite_post_refresh_errors_or_login_for_manual_tokens() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, REFRESH.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "old-access...old-refresh");
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("post-refresh API failure");
    assert_eq!(error.kind(), ErrorKind::Api);
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("refreshed token remains current after non-auth failure");
    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(
        requests[3]
            .header("cookie")
            .expect("persisted refreshed token")
            .contains("new-access...new-refresh")
    );

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(401, Vec::new()),
    ])
    .await;
    let provider = manual_provider(&server, "old-access...old-refresh");
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("manual refresh failure");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn password_login_performs_exact_three_step_flow_with_registered_web_id() {
    let device_jwt = jwt("registered-device");
    let anonymous = token_response("anonymous-access", &device_jwt);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"{}".to_vec()).header(
            "Set-Cookie",
            "INGRESSCOOKIE=ingress-cookie; Path=/; HttpOnly",
        ),
        FakeHttpResponse::new(200, anonymous),
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
    ])
    .await;
    let provider = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user@example.com",
        "password-canary",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect("password provider");
    let debug = format!("{provider:?}");
    assert!(!debug.contains("password-canary"));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("password usage");
    assert_eq!(sample.provenance()[0].strategy(), "password_login");

    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/");
    assert_eq!(requests[0].header("oasis-webid"), Some(DEFAULT_WEB_ID));
    assert_eq!(
        requests[1].target(),
        "/passport/proto.api.passport.v1.PassportService/RegisterDevice"
    );
    assert_eq!(
        requests[1].header("cookie"),
        Some("INGRESSCOOKIE=ingress-cookie")
    );
    assert_eq!(requests[1].body(), b"{}");
    assert_eq!(
        requests[2].target(),
        "/passport/proto.api.passport.v1.PassportService/SignInByPassword"
    );
    assert_eq!(requests[2].header("oasis-webid"), Some("registered-device"));
    assert_eq!(
        requests[2].header("cookie"),
        Some(
            format!(
                "Oasis-Token=anonymous-access...{device_jwt}; \
                 Oasis-Webid=registered-device; INGRESSCOOKIE=ingress-cookie"
            )
            .as_str()
        )
    );
    let sign_in_body: serde_json::Value =
        serde_json::from_slice(requests[2].body()).expect("sign-in JSON");
    assert_eq!(sign_in_body["username"], "user@example.com");
    assert_eq!(sign_in_body["password"], "password-canary");
    assert!(
        requests[3]
            .header("cookie")
            .expect("authenticated token")
            .contains("login-access...login-refresh")
    );
}

#[tokio::test]
async fn password_provider_relogs_in_when_refresh_is_expired() {
    let first_anon = token_response("anon-a", &jwt("device-a"));
    let second_anon = token_response("anon-b", &jwt("device-b"));
    let second_login = token_response("login-b", "refresh-b");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, Vec::new())
            .header("Set-Cookie", "INGRESSCOOKIE=ingress-a; Path=/"),
        FakeHttpResponse::new(200, first_anon),
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, Vec::new())
            .header("Set-Cookie", "INGRESSCOOKIE=ingress-b; Path=/"),
        FakeHttpResponse::new(200, second_anon),
        FakeHttpResponse::new(200, second_login),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
    ])
    .await;
    let provider = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user@example.com",
        "secret",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect("password provider");
    let run_context = context("account-a", ProviderSource::ManualCookie);
    for _ in 0..2 {
        provider
            .fetch_at(&run_context, timestamp(NOW_SECONDS))
            .await
            .expect("recovered usage");
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 12);
    assert_eq!(
        requests[4].target(),
        "/passport/proto.api.passport.v1.PassportService/RefreshToken"
    );
    assert_eq!(requests[5].method(), "GET");
    assert_eq!(requests[5].target(), "/");
    assert!(
        requests[8]
            .header("cookie")
            .expect("relogin token")
            .contains("login-b...refresh-b")
    );
    assert!(
        requests[10]
            .header("cookie")
            .expect("persisted relogin token")
            .contains("login-b...refresh-b")
    );
}

#[tokio::test]
async fn password_provider_relogs_in_when_refreshed_usage_is_still_expired() {
    let first_anon = token_response("anon-a", &jwt("device-a"));
    let second_anon = token_response("anon-b", &jwt("device-b"));
    let refreshed = token_response("refreshed-access", "refreshed-refresh");
    let second_login = token_response("login-b", "refresh-b");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, Vec::new())
            .header("Set-Cookie", "INGRESSCOOKIE=ingress-a; Path=/"),
        FakeHttpResponse::new(200, first_anon),
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, refreshed),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, Vec::new())
            .header("Set-Cookie", "INGRESSCOOKIE=ingress-b; Path=/"),
        FakeHttpResponse::new(200, second_anon),
        FakeHttpResponse::new(200, second_login),
        FakeHttpResponse::new(200, ROLLING.to_vec()),
        FakeHttpResponse::new(200, PLAN.to_vec()),
    ])
    .await;
    let provider = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user@example.com",
        "secret",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect("password provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("relogin after refreshed auth failure");

    let requests = server.requests();
    assert_eq!(requests.len(), 11);
    assert!(
        requests[5]
            .header("cookie")
            .expect("refreshed token")
            .contains("refreshed-access...refreshed-refresh")
    );
    assert!(
        requests[9]
            .header("cookie")
            .expect("relogin token")
            .contains("login-b...refresh-b")
    );
}

#[tokio::test]
async fn authenticated_post_redirects_are_rejected_without_forwarding_tokens() {
    for location in ["/same-origin-target", "https://evil.example/collect"] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(302, Vec::new()).header("Location", location)
        ])
        .await;
        let provider = manual_provider(&server, "token-canary");
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("credentialed POST redirect");
        assert_eq!(error.kind(), ErrorKind::Parse);
        assert_eq!(server.requests().len(), 1);
        assert!(!format!("{error:?} {error}").contains("token-canary"));
    }
}

#[tokio::test]
async fn homepage_redirects_are_same_origin_bounded_and_keep_ingress_cookie() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new())
            .header("Location", "/landing")
            .header("Set-Cookie", "INGRESSCOOKIE=redirect-cookie; Path=/"),
        FakeHttpResponse::new(200, Vec::new()),
        FakeHttpResponse::new(200, REGISTER.to_vec()),
        FakeHttpResponse::new(200, LOGIN.to_vec()),
    ])
    .await;
    StepFunProvider::from_password_routes(
        scope("account-a"),
        "user",
        "password",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect("same-origin redirect login");
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].target(), "/landing");
    assert_eq!(
        requests[1].header("cookie"),
        Some("INGRESSCOOKIE=redirect-cookie")
    );
    assert_eq!(
        requests[2].header("cookie"),
        Some("INGRESSCOOKIE=redirect-cookie")
    );

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", "https://evil.example/")
    ])
    .await;
    let error = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user-canary",
        "password-canary",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), 1);
    assert!(!format!("{error:?} {error}").contains("password-canary"));

    let redirects =
        (0..6).map(|_| FakeHttpResponse::new(302, Vec::new()).header("Location", "/another-hop"));
    let server = FakeHttpServer::start(redirects).await;
    let error = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user",
        "password",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect_err("redirect limit");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert_eq!(server.requests().len(), 6);
}

#[tokio::test]
async fn password_login_validates_credentials_ingress_tokens_sizes_and_cancellation() {
    let server = FakeHttpServer::start([]).await;
    for (username, password) in [("", "password"), ("user", ""), (" \t", "password")] {
        let error = StepFunProvider::from_password_routes(
            scope("account-a"),
            username,
            password,
            routes(&server),
            &CancellationToken::new(),
        )
        .await
        .expect_err("empty credential");
        assert_eq!(error.kind(), ErrorKind::MissingCredential);
    }
    assert!(server.requests().is_empty());

    let server = FakeHttpServer::start([]).await;
    let oversized_username = "u".repeat(16 * 1024 + 1);
    let error = StepFunProvider::from_password_routes(
        scope("account-a"),
        &oversized_username,
        "password",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect_err("oversized credential");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);
    assert!(server.requests().is_empty());

    let server = FakeHttpServer::start([FakeHttpResponse::new(200, Vec::new())]).await;
    let error = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user",
        "password",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect_err("missing ingress cookie");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, Vec::new())
            .header("Set-Cookie", "INGRESSCOOKIE=ingress; Path=/"),
        FakeHttpResponse::new(200, br#"{"refreshToken":{"raw":"refresh"}}"#.to_vec()),
    ])
    .await;
    let error = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user",
        "password",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect_err("missing register access token");
    assert_eq!(error.kind(), ErrorKind::Api);

    let server = FakeHttpServer::start([FakeHttpResponse::truncated(
        200,
        2 * 1024 * 1024 + 1,
        Vec::new(),
    )])
    .await;
    let error = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user",
        "password",
        routes(&server),
        &CancellationToken::new(),
    )
    .await
    .expect_err("oversized homepage");
    assert_eq!(error.kind(), ErrorKind::Parse);

    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let error = StepFunProvider::from_password_routes(
        scope("account-a"),
        "user",
        "password",
        routes(&server),
        &cancellation,
    )
    .await
    .expect_err("pre-cancelled login");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn context_scope_source_routes_and_response_limits_fail_closed() {
    let server = FakeHttpServer::start([]).await;
    let provider = manual_provider(&server, "token");
    let wrong_account = provider
        .fetch_at(
            &context("account-b", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("wrong account");
    assert_eq!(wrong_account.kind(), ErrorKind::Api);
    let wrong_source = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("wrong source");
    assert_eq!(wrong_source.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());

    let invalid_routes =
        StepFunRouteSet::loopback(Url::parse("https://example.com/not-loopback").expect("URL"))
            .expect_err("non-loopback seam");
    assert_eq!(invalid_routes.kind(), ErrorKind::Api);

    let server = FakeHttpServer::start([FakeHttpResponse::truncated(
        200,
        2 * 1024 * 1024 + 1,
        ROLLING.to_vec(),
    )])
    .await;
    let provider = manual_provider(&server, "token");
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("oversized usage response");
    assert_eq!(error.kind(), ErrorKind::Parse);
}
