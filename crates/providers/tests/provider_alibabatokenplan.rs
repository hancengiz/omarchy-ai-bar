use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::alibabatokenplan::{
    AlibabaTokenPlanCliSettings, AlibabaTokenPlanProvider, AlibabaTokenPlanRegion,
    AlibabaTokenPlanRouteSet, cli_arguments, extract_sec_token, parse_cli_usage_response,
    parse_personal_usage_responses, parse_team_usage_response,
};
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use serde_json::Value;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const PERSONAL_USAGE: &[u8] =
    include_bytes!("../../../fixtures/providers/alibabatokenplan/personal_usage.json");
const PERSONAL_SUBSCRIPTION: &[u8] =
    include_bytes!("../../../fixtures/providers/alibabatokenplan/personal_subscription.json");
const PERSONAL_QUOTA: &[u8] =
    include_bytes!("../../../fixtures/providers/alibabatokenplan/personal_quota_config.json");
const TEAM_SUMMARY: &[u8] =
    include_bytes!("../../../fixtures/providers/alibabatokenplan/team_summary.json");
const CLI_USAGE: &[u8] =
    include_bytes!("../../../fixtures/providers/alibabatokenplan/cli_usage.json");
const NOW_SECONDS: i64 = 1_700_000_000;
const COOKIE_CANARY: &str = "token-plan-cookie-canary";
const DASHBOARD_CANARY: &str = "token-plan-dashboard-canary";
const USER_INFO_CANARY: &str = "token-plan-user-info-canary";
const API_CANARY: &str = "token-plan-api-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn provider_scope(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(format!("{}-primary", provider.as_str())).expect("instance"),
        AccountKey::new(account).expect("account"),
    )
}

fn scope(account: &str) -> AccountScope {
    provider_scope(ProviderId::AlibabaTokenPlan, account)
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn localhost_origin(server: &FakeHttpServer) -> Url {
    let mut url = server.url("/");
    url.set_host(Some("localhost"))
        .expect("localhost loopback host");
    url
}

fn routes(gateway: &FakeHttpServer, personal: &FakeHttpServer) -> AlibabaTokenPlanRouteSet {
    let gateway = gateway.url("/");
    let personal = localhost_origin(personal);
    AlibabaTokenPlanRouteSet::loopback(gateway.clone(), personal.clone(), gateway, personal)
        .expect("loopback Token Plan routes")
}

fn cookie_record(
    name: &str,
    value: &str,
    domain: &str,
    path: &str,
    secure: bool,
    expires_at: Option<OffsetDateTime>,
) -> CookieRecord {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain,
        domain_kind: CookieDomainKind::HostOnly,
        path,
        secure,
        expires_at,
    })
    .expect("cookie record")
}

fn cookie_jar(records: Vec<CookieRecord>) -> CookieJar {
    let source = CookieSourceId::new(31);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn form_fields(body: &[u8]) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body)
        .into_owned()
        .collect::<BTreeMap<_, _>>()
}

fn query_fields(target: &str) -> BTreeMap<String, String> {
    Url::parse(&format!("http://fixture.invalid{target}"))
        .expect("captured target")
        .query_pairs()
        .into_owned()
        .collect()
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

#[test]
fn personal_fixtures_map_windows_tier_totals_and_resets() {
    let sample = parse_personal_usage_responses(
        scope("personal"),
        timestamp(NOW_SECONDS),
        PERSONAL_USAGE,
        Some(PERSONAL_SUBSCRIPTION),
        Some(PERSONAL_QUOTA),
        ProviderSource::ManualCookie,
    )
    .expect("Personal fixtures");
    let primary = sample.primary().expect("five-hour window");
    assert_percent(
        primary.used_percent().expect("five-hour percent").get(),
        0.099_730_833_333_333_33,
    );
    assert_eq!(
        primary.duration().expect("five-hour duration").seconds(),
        5 * 60 * 60
    );
    assert_eq!(
        primary
            .resets_at()
            .expect("five-hour reset")
            .unix_timestamp(),
        1_784_813_220
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("five-hour detail")
            .as_str(),
        "11.97 / 12,000 credits used"
    );
    let weekly = sample.secondary().expect("weekly window");
    assert_percent(
        weekly.used_percent().expect("weekly percent").get(),
        0.030_147_25,
    );
    assert_eq!(
        weekly.duration().expect("weekly duration").seconds(),
        7 * 24 * 60 * 60
    );
    assert_eq!(
        weekly.resets_at().expect("weekly reset").unix_timestamp(),
        1_785_234_900
    );
    assert_eq!(
        sample.identity().login_method().expect("tier").as_str(),
        "Pro"
    );
}

#[test]
fn personal_parser_accepts_independent_windows_and_best_effort_metadata() {
    let weekly_only = br#"{
      "successResponse":true,
      "data":{"per1WeekPercentage":0.10007527475,"per1WeekResetTime":1785234900000}}
    "#;
    let sample = parse_personal_usage_responses(
        scope("weekly"),
        timestamp(NOW_SECONDS),
        weekly_only,
        Some(b"not-json"),
        Some(&vec![b'x'; 2 * 1024 * 1024 + 1]),
        ProviderSource::BrowserSession,
    )
    .expect("weekly-only response");
    assert!(sample.primary().is_none());
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        10.007_527_475,
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("fallback plan")
            .as_str(),
        "Personal"
    );
}

#[test]
fn team_fixture_and_nested_body_map_credit_balance() {
    let sample = parse_team_usage_response(
        scope("team"),
        timestamp(NOW_SECONDS),
        TEAM_SUMMARY,
        ProviderSource::ManualCookie,
    )
    .expect("Team fixture");
    let primary = sample.primary().expect("monthly credit window");
    assert_percent(primary.used_percent().expect("known").get(), 12.5);
    assert_eq!(
        primary.duration().expect("monthly marker").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        primary
            .resets_at()
            .expect("nearest expiry")
            .unix_timestamp(),
        1_701_000_000
    );
    assert_eq!(
        primary.reset_description().expect("credit detail").as_str(),
        "125 / 1,000 credits used"
    );

    let embedded = serde_json::json!({
        "successResponse": {
            "body": "{\"success\":true,\"data\":{\"totalCount\":1,\"totalSurplusValue\":750,\"totalValue\":1000}}"
        }
    })
    .to_string();
    let nested = parse_team_usage_response(
        scope("nested"),
        timestamp(NOW_SECONDS),
        embedded.as_bytes(),
        ProviderSource::BrowserSession,
    )
    .expect("embedded Team response");
    assert_percent(
        nested
            .primary()
            .expect("nested quota")
            .used_percent()
            .expect("known")
            .get(),
        25.0,
    );
}

#[test]
fn team_empty_subscription_and_balance_only_remain_visible_without_window() {
    for body in [
        br#"{"Success":true,"Data":{"TotalCount":0}}"#.as_slice(),
        br#"{"Success":true,"Data":{"remainingQuota":700}}"#.as_slice(),
    ] {
        let sample = parse_team_usage_response(
            scope("empty"),
            timestamp(NOW_SECONDS),
            body,
            ProviderSource::ManualCookie,
        )
        .expect("non-graphable authenticated summary");
        assert!(sample.primary().is_none());
    }
}

#[test]
fn cli_parser_is_top_level_strict_and_windows_are_independent() {
    let sample = parse_cli_usage_response(
        scope("cli"),
        timestamp(NOW_SECONDS),
        CLI_USAGE,
        ProviderSource::Cli,
    )
    .expect("CLI fixture");
    assert_percent(
        sample
            .primary()
            .expect("five-hour")
            .used_percent()
            .expect("known")
            .get(),
        25.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        70.0,
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Token Plan"
    );

    let weekly = parse_cli_usage_response(
        scope("weekly-cli"),
        timestamp(NOW_SECONDS),
        br#"{"per5HourPercentage":"0.1","per1WeekPercentage":0.7}"#,
        ProviderSource::Cli,
    )
    .expect("weekly CLI window");
    assert!(weekly.primary().is_none());
    assert!(weekly.secondary().is_some());
    for invalid in [
        br#"{"per5HourPercentage":true,"per1WeekPercentage":-0.1}"#.as_slice(),
        br#"{"data":{"per5HourPercentage":0.5}}"#.as_slice(),
        br#""{\"per5HourPercentage\":0.5}""#.as_slice(),
        b"not-json".as_slice(),
    ] {
        assert_eq!(
            parse_cli_usage_response(
                scope("bad-cli"),
                timestamp(NOW_SECONDS),
                invalid,
                ProviderSource::Cli,
            )
            .expect_err("invalid CLI payload")
            .kind(),
            ErrorKind::Parse
        );
    }
}

#[test]
fn payload_failures_are_stable_redacted_and_workspace_errors_remain_api() {
    for (body, expected) in [
        (
            br#"{"code":"ConsoleNeedLogin","message":"login-secret-canary","successResponse":false}"#.as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            br#"{"statusCode":403,"message":"forbidden-secret-canary"}"#.as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            br#"{"successResponse":true,"data":{"success":false,"errorCode":"BailianGateway.Workspace.NotAuthorised","errorMsg":"workspace-secret-canary"}}"#.as_slice(),
            ErrorKind::Api,
        ),
        (b"not-json".as_slice(), ErrorKind::Parse),
    ] {
        let error = parse_team_usage_response(
            scope("error"),
            timestamp(NOW_SECONDS),
            body,
            ProviderSource::ManualCookie,
        )
        .expect_err("scripted payload error");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
    }
}

#[test]
fn required_parser_bounds_depth_width_strings_embedded_layers_and_bytes() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let mut deep = "{\"TotalCount\":0}".to_owned();
    for _ in 0..45 {
        deep = format!("[{deep}]");
    }
    let wide = format!(
        "{{\"TotalCount\":0,\"values\":[{}]}}",
        vec!["0"; 33_000].join(",")
    );
    let long =
        serde_json::json!({"TotalCount": 0, "value": "x".repeat(512 * 1024 + 1)}).to_string();
    let mut embedded = serde_json::json!({"TotalCount": 0}).to_string();
    for _ in 0..8 {
        embedded = serde_json::to_string(&embedded).expect("embedded JSON");
    }
    for body in [
        oversized.as_slice(),
        deep.as_bytes(),
        wide.as_bytes(),
        long.as_bytes(),
        embedded.as_bytes(),
        &[0xff, 0xfe],
    ] {
        assert_eq!(
            parse_team_usage_response(
                scope("bounds"),
                timestamp(NOW_SECONDS),
                body,
                ProviderSource::ManualCookie,
            )
            .expect_err("bounded rejection")
            .kind(),
            ErrorKind::Parse
        );
    }
}

#[test]
fn region_arguments_and_sec_token_shapes_match_baseline() {
    assert_eq!(
        cli_arguments(AlibabaTokenPlanRegion::ChinaTeam),
        [
            "usage",
            "token-plan",
            "--console-region",
            "cn-beijing",
            "--console-site",
            "domestic",
            "--output",
            "json",
        ]
    );
    assert_eq!(
        cli_arguments(AlibabaTokenPlanRegion::ChinaPersonal),
        cli_arguments(AlibabaTokenPlanRegion::ChinaTeam)
    );
    assert_eq!(
        cli_arguments(AlibabaTokenPlanRegion::InternationalPersonal),
        cli_arguments(AlibabaTokenPlanRegion::InternationalTeam)
    );
    for (html, expected) in [
        (
            r#"window.ALIYUN_CONSOLE_CONFIG = { SEC_TOKEN: "upper-token" };"#,
            "upper-token",
        ),
        (r#"{"secToken":"camel-token"}"#, "camel-token"),
        ("var x = { sec_token: 'snake-token' };", "snake-token"),
    ] {
        assert_eq!(
            extract_sec_token(html).as_deref().map(String::as_str),
            Some(expected)
        );
    }
    assert!(extract_sec_token("<html>no token</html>").is_none());
}

#[tokio::test]
async fn manual_team_flow_uses_exact_summary_contract() {
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(
            200,
            br#"<script>window.x={SEC_TOKEN:"fresh-team-token"}</script>"#.to_vec(),
        ),
        FakeHttpResponse::new(200, TEAM_SUMMARY.to_vec()),
    ])
    .await;
    let personal = FakeHttpServer::start([]).await;
    let capture = format!(
        "curl 'https://modelstudio.console.alibabacloud.com/ap-southeast-1/?ignored=1' -H 'Cookie: session={COOKIE_CANARY}; cna=anonymous; login_aliyunid_csrf=csrf-canary'"
    );
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("team-http"),
        AlibabaTokenPlanRegion::InternationalTeam,
        &capture,
        routes(&gateway, &personal),
    )
    .expect("manual Team provider");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);
    assert!(!format!("{provider:?}").contains(COOKIE_CANARY));
    let sample = provider
        .fetch_at(
            &context("team-http", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("Team HTTP flow");
    assert!(sample.primary().is_some());
    assert!(personal.requests().is_empty());
    let requests = gateway.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/ap-southeast-1/?tab=plan");
    assert_eq!(requests[0].header("sec-fetch-site"), Some("same-origin"));
    assert_eq!(requests[0].header("sec-fetch-mode"), Some("navigate"));
    assert_eq!(requests[0].header("sec-fetch-dest"), Some("document"));
    let summary = &requests[1];
    assert_eq!(summary.method(), "POST");
    let query = query_fields(summary.target());
    assert_eq!(
        query.get("action").map(String::as_str),
        Some("GetSubscriptionSummary")
    );
    assert_eq!(
        query.get("product").map(String::as_str),
        Some("BssOpenAPI-V3")
    );
    assert_eq!(summary.header("accept"), Some("*/*"));
    assert_eq!(summary.header("x-xsrf-token"), Some("csrf-canary"));
    assert!(
        summary
            .header("referer")
            .is_some_and(|value| value.ends_with("?tab=plan#/efm/subscription/token-plan"))
    );
    assert!(
        summary
            .header("cookie")
            .is_some_and(|value| value.contains(COOKIE_CANARY))
    );
    let fields = form_fields(summary.body());
    assert_eq!(
        fields.get("product").map(String::as_str),
        Some("BssOpenAPI-V3")
    );
    assert_eq!(
        fields.get("action").map(String::as_str),
        Some("GetSubscriptionSummary")
    );
    assert_eq!(
        fields.get("region").map(String::as_str),
        Some("ap-southeast-1")
    );
    assert_eq!(
        fields.get("sec_token").map(String::as_str),
        Some("fresh-team-token")
    );
    let params: Value = serde_json::from_str(fields.get("params").expect("params")).expect("JSON");
    assert_eq!(params["ProductCode"], "sfm_tokenplanteams_dp_intl");
}

#[tokio::test]
async fn same_origin_dashboard_redirect_preserves_only_the_dashboard_cookie() {
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/redirected-shell"),
        FakeHttpResponse::new(
            200,
            br#"<script>window.x={SEC_TOKEN:"redirect-token"}</script>"#.to_vec(),
        ),
        FakeHttpResponse::new(200, TEAM_SUMMARY.to_vec()),
    ])
    .await;
    let personal = FakeHttpServer::start([]).await;
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("dashboard-redirect"),
        AlibabaTokenPlanRegion::InternationalTeam,
        &format!("session={DASHBOARD_CANARY}; login_aliyunid_csrf=csrf"),
        routes(&gateway, &personal),
    )
    .expect("provider");

    provider
        .fetch_at(
            &context("dashboard-redirect", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("same-origin navigation redirect");

    let requests = gateway.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].target(), "/ap-southeast-1/?tab=plan");
    assert_eq!(requests[1].target(), "/redirected-shell");
    for request in &requests[..2] {
        assert_eq!(request.method(), "GET");
        assert!(
            request
                .header("cookie")
                .is_some_and(|value| value.contains(DASHBOARD_CANARY))
        );
    }
    assert_eq!(
        form_fields(requests[2].body())
            .get("sec_token")
            .map(String::as_str),
        Some("redirect-token")
    );
    assert!(personal.requests().is_empty());
}

#[tokio::test]
async fn dashboard_cross_origin_redirect_is_rejected_before_cookie_reaches_target() {
    let target = FakeHttpServer::start([]).await;
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/credential-canary").as_str()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, TEAM_SUMMARY.to_vec()),
    ])
    .await;
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("cross-origin-redirect"),
        AlibabaTokenPlanRegion::ChinaTeam,
        &format!("session={DASHBOARD_CANARY}"),
        routes(&gateway, &target),
    )
    .expect("provider");

    provider
        .fetch_at(
            &context("cross-origin-redirect", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("credential-free fallback after rejected redirect");

    assert!(
        target.requests().is_empty(),
        "unapproved redirect target must never receive a request"
    );
    let requests = gateway.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[1].target(), "/tool/user/info.json");
    assert_eq!(requests[2].method(), "POST");
}

#[tokio::test]
async fn dashboard_redirect_chain_stops_at_the_provider_bound() {
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/redirect-one"),
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/redirect-two"),
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/redirect-three"),
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/must-not-follow"),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, TEAM_SUMMARY.to_vec()),
    ])
    .await;
    let personal = FakeHttpServer::start([]).await;
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("redirect-bound"),
        AlibabaTokenPlanRegion::InternationalTeam,
        &format!("session={DASHBOARD_CANARY}"),
        routes(&gateway, &personal),
    )
    .expect("provider");

    provider
        .fetch_at(
            &context("redirect-bound", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("bounded navigation fallback");

    let requests = gateway.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[0].target(), "/ap-southeast-1/?tab=plan");
    assert_eq!(requests[1].target(), "/redirect-one");
    assert_eq!(requests[2].target(), "/redirect-two");
    assert_eq!(requests[3].target(), "/redirect-three");
    assert_eq!(requests[4].target(), "/tool/user/info.json");
    assert_eq!(requests[5].method(), "POST");
    assert!(
        requests
            .iter()
            .all(|request| request.target() != "/must-not-follow")
    );
}

fn assert_personal_request(request: &CapturedHttpRequest, api: &str) {
    assert_eq!(request.method(), "POST");
    let query = query_fields(request.target());
    assert_eq!(
        query.get("action").map(String::as_str),
        Some("BroadScopeAspnGateway")
    );
    assert_eq!(
        query.get("product").map(String::as_str),
        Some("sfm_bailian")
    );
    assert_eq!(query.get("api").map(String::as_str), Some(api));
    assert_eq!(query.get("_v").map(String::as_str), Some("undefined"));
    assert_eq!(
        request.header("accept"),
        Some("application/json, text/plain, */*")
    );
    assert_eq!(request.header("x-requested-with"), Some("XMLHttpRequest"));
    assert!(
        request
            .header("cookie")
            .is_some_and(|value| value.contains(COOKIE_CANARY))
    );
    let fields = form_fields(request.body());
    assert_eq!(
        fields.get("product").map(String::as_str),
        Some("sfm_bailian")
    );
    assert_eq!(
        fields.get("action").map(String::as_str),
        Some("BroadScopeAspnGateway")
    );
    assert_eq!(fields.get("region").map(String::as_str), Some("cn-beijing"));
    assert_eq!(fields.get("language").map(String::as_str), Some("en-US"));
    assert_eq!(
        fields.get("sec_token").map(String::as_str),
        Some("fresh-personal-token")
    );
    let params: Value = serde_json::from_str(fields.get("params").expect("params")).expect("JSON");
    assert_eq!(params["Api"], api);
    assert_eq!(params["V"], "1.0");
    assert_eq!(
        params["Data"]["cornerstoneParam"]["consoleSite"],
        "BAILIAN_ALIYUN"
    );
    assert_eq!(params["Data"]["cornerstoneParam"]["domain"], "127.0.0.1");
    assert!(
        params["Data"]["cornerstoneParam"]["feURL"]
            .as_str()
            .is_some_and(|value| value
                .ends_with("?tab=plan#/efm/subscription/token-plan/personal"))
    );
    assert_eq!(params["Data"]["cornerstoneParam"]["switchUserType"], 3);
    assert_eq!(
        params["Data"]["cornerstoneParam"]["X-Anonymous-Id"],
        "anonymous"
    );
    assert!(
        params["Data"]["cornerstoneParam"]
            .get("switchAgent")
            .is_none()
    );
}

#[tokio::test]
async fn manual_personal_flow_resolves_token_and_uses_three_exact_apis() {
    let gateway = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        br#"<script>SEC_TOKEN: "fresh-personal-token"</script>"#.to_vec(),
    )])
    .await;
    let personal = FakeHttpServer::start([
        FakeHttpResponse::new(200, PERSONAL_SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, PERSONAL_QUOTA.to_vec()),
        FakeHttpResponse::new(200, PERSONAL_USAGE.to_vec()),
    ])
    .await;
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("personal-http"),
        AlibabaTokenPlanRegion::ChinaPersonal,
        &format!("session={COOKIE_CANARY}; cna=anonymous; csrf=csrf-canary"),
        routes(&gateway, &personal),
    )
    .expect("manual Personal provider");
    let sample = provider
        .fetch_at(
            &context("personal-http", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("Personal HTTP flow");
    assert_eq!(
        sample.identity().login_method().expect("tier").as_str(),
        "Pro"
    );
    let requests = personal.requests();
    assert_eq!(requests.len(), 3);
    for (request, api) in requests.iter().zip([
        "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/subscription",
        "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/quota-config",
        "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage",
    ]) {
        assert_personal_request(request, api);
    }
    let subscription = form_fields(requests[0].body());
    let params: Value = serde_json::from_str(subscription.get("params").expect("params"))
        .expect("subscription JSON");
    assert_eq!(
        params["Data"]["commodityCode"],
        "sfm_tokenplansolo_public_cn"
    );
}

#[tokio::test]
async fn personal_empty_success_retries_and_optional_metadata_is_best_effort() {
    let empty = br#"{"code":"SUCCESS","successResponse":true,"msg":"Success.","data":{}}"#;
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"<html>no token</html>".to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    let personal = FakeHttpServer::start([
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(201, PERSONAL_QUOTA.to_vec()),
        FakeHttpResponse::new(200, empty.to_vec()),
        FakeHttpResponse::new(200, PERSONAL_USAGE.to_vec()),
    ])
    .await;
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("retry"),
        AlibabaTokenPlanRegion::ChinaPersonal,
        "session=secret",
        routes(&gateway, &personal),
    )
    .expect("provider");
    let sample = provider
        .fetch_at(
            &context("retry", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("retry recovers");
    assert!(sample.primary().is_some());
    assert_eq!(
        sample.identity().login_method().expect("fallback").as_str(),
        "Personal"
    );
    assert_eq!(personal.requests().len(), 4);
}

#[tokio::test]
async fn personal_cookie_token_fallback_and_empty_success_retry_are_bounded() {
    let empty = br#"{"code":"SUCCESS","successResponse":true,"msg":"Success.","data":{}}"#;
    let optional = br#"{"code":"200","successResponse":true}"#;
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"<html>no token</html>".to_vec()),
        FakeHttpResponse::new(200, optional.to_vec()),
    ])
    .await;
    let personal = FakeHttpServer::start([
        FakeHttpResponse::new(200, optional.to_vec()),
        FakeHttpResponse::new(200, optional.to_vec()),
        FakeHttpResponse::new(200, empty.to_vec()),
        FakeHttpResponse::new(200, empty.to_vec()),
        FakeHttpResponse::new(200, empty.to_vec()),
    ])
    .await;
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("empty-retry"),
        AlibabaTokenPlanRegion::InternationalPersonal,
        "session=secret; sec_token=cookie-token",
        routes(&gateway, &personal),
    )
    .expect("provider");
    let error = provider
        .fetch_at(
            &context("empty-retry", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("three empty-success attempts are bounded");
    assert_eq!(error.kind(), ErrorKind::Parse);
    let requests = personal.requests();
    assert_eq!(requests.len(), 5);
    for request in requests {
        assert_eq!(
            form_fields(request.body())
                .get("sec_token")
                .map(String::as_str),
            Some("cookie-token")
        );
    }
}

#[tokio::test]
async fn browser_cookies_are_routed_per_dashboard_user_info_and_quota_host() {
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"<html>no token</html>".to_vec()),
        FakeHttpResponse::new(
            200,
            br#"{"data":{"token":"generic","nested":{"secToken":"user-info-token"}}}"#.to_vec(),
        ),
    ])
    .await;
    let personal = FakeHttpServer::start([
        FakeHttpResponse::new(200, PERSONAL_SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, PERSONAL_QUOTA.to_vec()),
        FakeHttpResponse::new(200, PERSONAL_USAGE.to_vec()),
    ])
    .await;
    let jar = cookie_jar(vec![
        cookie_record(
            "dashboard_only",
            DASHBOARD_CANARY,
            "127.0.0.1",
            "/cn-beijing",
            false,
            None,
        ),
        cookie_record(
            "userinfo_only",
            USER_INFO_CANARY,
            "127.0.0.1",
            "/tool",
            false,
            None,
        ),
        cookie_record("api_only", API_CANARY, "localhost", "/data", false, None),
        cookie_record(
            "login_aliyunid_ticket",
            "ticket",
            "localhost",
            "/data",
            false,
            None,
        ),
        cookie_record("login_current_pk", "account", "127.0.0.1", "/", false, None),
        cookie_record(
            "secure_only",
            "must-not-cross",
            "localhost",
            "/",
            true,
            None,
        ),
        cookie_record(
            "expired",
            "must-not-cross",
            "127.0.0.1",
            "/",
            false,
            Some(now() - time::Duration::seconds(1)),
        ),
    ]);
    let provider = AlibabaTokenPlanProvider::from_browser_jar_routes(
        scope("browser"),
        AlibabaTokenPlanRegion::ChinaPersonal,
        &jar,
        now(),
        routes(&gateway, &personal),
    )
    .expect("browser provider");
    assert_eq!(provider.source(), ProviderSource::BrowserSession);
    provider
        .fetch_at(
            &context("browser", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser flow");
    let gateway_requests = gateway.requests();
    assert_eq!(gateway_requests.len(), 2);
    assert!(
        gateway_requests[0].header("cookie").is_some_and(|value| {
            value.contains(DASHBOARD_CANARY) && !value.contains(API_CANARY)
        })
    );
    assert!(
        gateway_requests[1].header("cookie").is_some_and(|value| {
            value.contains(USER_INFO_CANARY) && !value.contains(API_CANARY)
        })
    );
    for request in personal.requests() {
        let cookie = request.header("cookie").expect("API cookie");
        assert!(cookie.contains(API_CANARY));
        assert!(cookie.contains("login_aliyunid_ticket=ticket"));
        assert!(!cookie.contains(DASHBOARD_CANARY));
        assert!(!cookie.contains(USER_INFO_CANARY));
        assert!(!cookie.contains("must-not-cross"));
        assert_eq!(
            form_fields(request.body())
                .get("sec_token")
                .map(String::as_str),
            Some("user-info-token")
        );
    }
}

#[tokio::test]
async fn browser_missing_expired_and_unauthenticated_sessions_fail_closed() {
    let gateway = FakeHttpServer::start([]).await;
    let personal = FakeHttpServer::start([]).await;
    for (jar, expected) in [
        (cookie_jar(Vec::new()), ErrorKind::MissingCredential),
        (
            cookie_jar(vec![cookie_record(
                "unmatched",
                "secret",
                "example.invalid",
                "/",
                false,
                None,
            )]),
            ErrorKind::AuthenticationExpired,
        ),
        (
            cookie_jar(vec![
                cookie_record("dashboard", "present", "127.0.0.1", "/", false, None),
                cookie_record("api", "present", "localhost", "/data", false, None),
            ]),
            ErrorKind::AuthenticationExpired,
        ),
        (
            cookie_jar(vec![
                cookie_record(
                    "login_aliyunid_ticket",
                    "ticket",
                    "localhost",
                    "/data",
                    false,
                    Some(now() - time::Duration::seconds(1)),
                ),
                cookie_record("login_current_pk", "account", "127.0.0.1", "/", false, None),
            ]),
            ErrorKind::AuthenticationExpired,
        ),
    ] {
        let error = AlibabaTokenPlanProvider::from_browser_jar_routes(
            scope("missing"),
            AlibabaTokenPlanRegion::ChinaPersonal,
            &jar,
            now(),
            routes(&gateway, &personal),
        )
        .expect_err("browser session rejection");
        assert_eq!(error.kind(), expected);
    }
    assert!(gateway.requests().is_empty());
    assert!(personal.requests().is_empty());
}

#[test]
fn capture_route_scope_and_source_authority_fail_closed() {
    let routes = AlibabaTokenPlanRouteSet::loopback(
        Url::parse("http://127.0.0.1:32111").expect("loopback"),
        Url::parse("http://localhost:32112").expect("loopback"),
        Url::parse("http://127.0.0.1:32113").expect("loopback"),
        Url::parse("http://localhost:32114").expect("loopback"),
    )
    .expect("routes");
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("capture"),
        AlibabaTokenPlanRegion::InternationalPersonal,
        "curl 'https://bailian-singapore-cs.alibabacloud.com/data/api.json?ignored=1' -b 'session=secret'",
        routes,
    )
    .expect("exact capture host");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);

    let routes = AlibabaTokenPlanRouteSet::loopback(
        Url::parse("http://127.0.0.1:32111").expect("loopback"),
        Url::parse("http://localhost:32112").expect("loopback"),
        Url::parse("http://127.0.0.1:32113").expect("loopback"),
        Url::parse("http://localhost:32114").expect("loopback"),
    )
    .expect("routes");
    let error = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("capture"),
        AlibabaTokenPlanRegion::InternationalPersonal,
        "curl 'https://bailian-singapore-cs.alibabacloud.com.evil.invalid/' -b 'session=secret-canary'",
        routes,
    )
    .expect_err("suffix host rejected");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?} {error}").contains("secret-canary"));
    assert!(
        AlibabaTokenPlanRouteSet::loopback(
            Url::parse("https://example.com").expect("public"),
            Url::parse("http://localhost:32112").expect("loopback"),
            Url::parse("http://127.0.0.1:32113").expect("loopback"),
            Url::parse("http://localhost:32114").expect("loopback"),
        )
        .is_err()
    );
}

#[tokio::test]
async fn scope_source_and_provider_mismatch_precede_network_or_process_io() {
    let gateway = FakeHttpServer::start([]).await;
    let personal = FakeHttpServer::start([]).await;
    let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
        scope("bound"),
        AlibabaTokenPlanRegion::ChinaTeam,
        "session=secret",
        routes(&gateway, &personal),
    )
    .expect("provider");
    for bad in [
        context("other", ProviderSource::ManualCookie),
        context("bound", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&bad, timestamp(NOW_SECONDS))
                .await
                .expect_err("isolation")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(gateway.requests().is_empty());
    assert!(personal.requests().is_empty());
    assert_eq!(provider.descriptor().id, ProviderId::AlibabaTokenPlan);

    let routes = AlibabaTokenPlanRouteSet::loopback(
        Url::parse("http://127.0.0.1:32121").expect("loopback"),
        Url::parse("http://localhost:32122").expect("loopback"),
        Url::parse("http://127.0.0.1:32123").expect("loopback"),
        Url::parse("http://localhost:32124").expect("loopback"),
    )
    .expect("routes");
    assert_eq!(
        AlibabaTokenPlanProvider::from_manual_capture_routes(
            provider_scope(ProviderId::Alibaba, "wrong"),
            AlibabaTokenPlanRegion::ChinaTeam,
            "session=secret",
            routes,
        )
        .expect_err("wrong provider")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn required_http_status_redirect_truncation_and_oversize_are_stable() {
    for (response, expected) in [
        (
            FakeHttpResponse::new(401, b"auth-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, b"forbidden-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(201, TEAM_SUMMARY.to_vec()),
            ErrorKind::Api,
        ),
        (
            FakeHttpResponse::new(429, b"rate-canary".to_vec()),
            ErrorKind::RateLimited,
        ),
        (
            FakeHttpResponse::new(302, Vec::new()).header("Location", "/redirected"),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::truncated(200, 100, b"short".to_vec()),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1]),
            ErrorKind::Parse,
        ),
    ] {
        let gateway = FakeHttpServer::start([
            FakeHttpResponse::new(200, br#"<script>SEC_TOKEN:"t"</script>"#.to_vec()),
            response,
        ])
        .await;
        let personal = FakeHttpServer::start([]).await;
        let provider = AlibabaTokenPlanProvider::from_manual_capture_routes(
            scope("http-error"),
            AlibabaTokenPlanRegion::ChinaTeam,
            &format!("session={COOKIE_CANARY}"),
            routes(&gateway, &personal),
        )
        .expect("provider");
        let error = provider
            .fetch_at(
                &context("http-error", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("HTTP failure");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains(COOKIE_CANARY));
        assert_eq!(
            gateway.requests().len(),
            2,
            "credentialed API POST redirect was not followed"
        );
    }
}

#[tokio::test]
async fn cli_executes_exact_argv_with_allowlisted_environment_only() {
    let directory = TestDirectory::new("cli-success");
    let executable = directory.path().join("bl");
    let fixture = shell_quote(std::str::from_utf8(CLI_USAGE).expect("UTF-8 fixture"));
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n[ \"$*\" = 'usage token-plan --console-region cn-beijing --console-site domestic --output json' ] || exit 21\n[ \"${{HOME:-}}\" = '/tmp/token-plan-home' ] || exit 22\n[ \"${{HTTPS_PROXY:-}}\" = 'http://proxy.test:8080' ] || exit 23\n[ -z \"${{DASHSCOPE_API_KEY+x}}\" ] || exit 24\n[ -z \"${{ALIBABA_TOKEN_PLAN_COOKIE+x}}\" ] || exit 25\nprintf '%s' '{fixture}'\n"
        ),
    );
    let environment = BTreeMap::from([
        ("HOME".to_owned(), "/tmp/token-plan-home".to_owned()),
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        (
            "HTTPS_PROXY".to_owned(),
            "http://proxy.test:8080".to_owned(),
        ),
        ("DASHSCOPE_API_KEY".to_owned(), "ambient-secret".to_owned()),
        (
            "ALIBABA_TOKEN_PLAN_COOKIE".to_owned(),
            "ambient-cookie".to_owned(),
        ),
        ("SSH_AUTH_SOCK".to_owned(), "/tmp/agent.sock".to_owned()),
    ]);
    let settings = AlibabaTokenPlanCliSettings::new(executable, &environment).expect("settings");
    assert!(!format!("{settings:?}").contains("ambient-secret"));
    let provider = AlibabaTokenPlanProvider::new_cli(
        scope("cli-run"),
        AlibabaTokenPlanRegion::ChinaPersonal,
        settings,
    )
    .expect("CLI provider");
    let sample = provider
        .fetch_at(
            &context("cli-run", ProviderSource::Cli),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("CLI usage");
    assert_percent(
        sample
            .primary()
            .expect("five-hour")
            .used_percent()
            .expect("known")
            .get(),
        25.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        70.0,
    );
}

#[tokio::test]
async fn cli_discovery_errors_timeout_output_nonzero_and_cancellation_are_bounded() {
    assert_eq!(
        AlibabaTokenPlanCliSettings::resolve(&BTreeMap::from([(
            "PATH".to_owned(),
            "relative/path".to_owned(),
        )]))
        .expect_err("relative PATH does not discover")
        .kind(),
        ErrorKind::MissingCredential
    );

    for (index, command, expected, timeout, cap) in [
        (
            0,
            "sleep 5",
            ErrorKind::Network,
            Duration::from_millis(50),
            64,
        ),
        (
            1,
            "/usr/bin/head -c 128 /dev/zero",
            ErrorKind::Parse,
            Duration::from_secs(1),
            64,
        ),
        (
            2,
            "printf '%s' 'not logged in; secret-canary' >&2; exit 1",
            ErrorKind::AuthenticationExpired,
            Duration::from_secs(1),
            64,
        ),
        (
            3,
            "printf '%s' 'generic secret-canary' >&2; exit 2",
            ErrorKind::Api,
            Duration::from_secs(1),
            64,
        ),
    ] {
        let directory = TestDirectory::new(&format!("cli-error-{index}"));
        let executable = directory.path().join("bl");
        write_executable(&executable, &format!("#!/bin/sh\n{command}\n"));
        let settings = AlibabaTokenPlanCliSettings::new(executable, &BTreeMap::new())
            .expect("settings")
            .with_test_limits(timeout, cap, cap)
            .expect("limits");
        let account = format!("cli-error-{index}");
        let provider = AlibabaTokenPlanProvider::new_cli(
            scope(&account),
            AlibabaTokenPlanRegion::InternationalTeam,
            settings,
        )
        .expect("provider");
        let error = provider
            .fetch_at(
                &context(&account, ProviderSource::Cli),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("CLI failure");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
    }

    let directory = TestDirectory::new("cli-cancelled");
    let executable = directory.path().join("bl");
    let marker = directory.path().join("started");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n: > '{}'\nsleep 5\n",
            shell_quote(marker.to_string_lossy().as_ref())
        ),
    );
    let provider = AlibabaTokenPlanProvider::new_cli(
        scope("cancelled"),
        AlibabaTokenPlanRegion::InternationalTeam,
        AlibabaTokenPlanCliSettings::new(executable, &BTreeMap::new()).expect("settings"),
    )
    .expect("provider");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let context = ProviderContext::new(scope("cancelled"), ProviderSource::Cli, cancellation);
    assert_eq!(
        provider
            .fetch_at(&context, timestamp(NOW_SECONDS))
            .await
            .expect_err("cancelled")
            .kind(),
        ErrorKind::Network
    );
    assert!(!marker.exists(), "pre-cancellation prevents spawn");
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-alibaba-token-plan-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable");
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("permissions");
}

fn shell_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}
