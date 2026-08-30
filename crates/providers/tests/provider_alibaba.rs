use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::alibaba::{
    AlibabaProvider, AlibabaRegion, AlibabaRouteSet, parse_usage_response, resolve_api_key,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::Value;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const QUOTA: &[u8] = include_bytes!("../../../fixtures/providers/alibaba/quota.json");
const NOW_SECONDS: i64 = 1_700_000_000;
const API_CANARY: &str = "alibaba-api-key-canary";
const DASHBOARD_CANARY: &str = "dashboard-cookie-canary";
const USER_INFO_CANARY: &str = "userinfo-cookie-canary";
const RPC_CANARY: &str = "rpc-cookie-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Alibaba,
        ProviderInstanceId::new("alibaba-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
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

fn same_region_routes(gateway: &FakeHttpServer, rpc: &FakeHttpServer) -> AlibabaRouteSet {
    let gateway_origin = gateway.url("/");
    let rpc_origin = localhost_origin(rpc);
    AlibabaRouteSet::loopback(
        gateway_origin.clone(),
        rpc_origin.clone(),
        gateway_origin,
        rpc_origin,
    )
    .expect("loopback Alibaba routes")
}

fn routes(
    international_gateway: &FakeHttpServer,
    international_rpc: &FakeHttpServer,
    china_gateway: &FakeHttpServer,
    china_rpc: &FakeHttpServer,
) -> AlibabaRouteSet {
    AlibabaRouteSet::loopback(
        international_gateway.url("/"),
        localhost_origin(international_rpc),
        china_gateway.url("/"),
        localhost_origin(china_rpc),
    )
    .expect("regional loopback routes")
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
    let source = CookieSourceId::new(11);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn independently_routed_browser_jar() -> CookieJar {
    cookie_jar(vec![
        cookie_record(
            "dashboard_cookie",
            DASHBOARD_CANARY,
            "127.0.0.1",
            "/ap-southeast-1/",
            false,
            None,
        ),
        cookie_record(
            "login_aliyunid_ticket",
            "browser-ticket",
            "127.0.0.1",
            "/",
            false,
            None,
        ),
        cookie_record(
            "login_aliyunid_pk",
            "browser-account",
            "127.0.0.1",
            "/",
            false,
            None,
        ),
        cookie_record(
            "userinfo_cookie",
            USER_INFO_CANARY,
            "127.0.0.1",
            "/tool",
            false,
            None,
        ),
        cookie_record("rpc_cookie", RPC_CANARY, "localhost", "/data", false, None),
        cookie_record(
            "cna",
            "anonymous-browser",
            "localhost",
            "/data",
            false,
            None,
        ),
        cookie_record(
            "login_aliyunid_csrf",
            "browser-csrf",
            "localhost",
            "/data",
            false,
            None,
        ),
        cookie_record(
            "secure_only",
            "must-not-cross",
            "127.0.0.1",
            "/",
            true,
            None,
        ),
        cookie_record(
            "expired",
            "must-not-cross",
            "localhost",
            "/",
            false,
            Some(now() - time::Duration::seconds(1)),
        ),
    ])
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn form_fields(body: &[u8]) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body)
        .into_owned()
        .collect::<BTreeMap<_, _>>()
}

#[test]
fn fixture_maps_three_quota_windows_plan_and_reset_semantics() {
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        QUOTA,
        ProviderSource::ApiKey,
    )
    .expect("Alibaba fixture");
    let primary = sample.primary().expect("five-hour window");
    assert_percent(
        primary.used_percent().expect("five-hour percent").get(),
        5.2,
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
        1_700_000_300
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("five-hour detail")
            .as_str(),
        "52 / 1000 used"
    );

    let weekly = sample.secondary().expect("weekly window");
    assert_percent(weekly.used_percent().expect("weekly percent").get(), 16.0);
    assert_eq!(
        weekly.duration().expect("weekly duration").seconds(),
        7 * 24 * 60 * 60
    );
    let monthly = sample.tertiary().expect("monthly window");
    assert_percent(monthly.used_percent().expect("monthly percent").get(), 6.0);
    assert_eq!(
        monthly.duration().expect("monthly duration").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("plan name")
            .as_str(),
        "Alibaba Coding Plan Pro"
    );

    let stale = br#"{
      "data":{"codingPlanInstanceInfos":[{"planName":"Lite","status":"VALID"}],
      "codingPlanQuotaInfo":{"per5HourUsedQuota":70,"per5HourTotalQuota":1200,
      "per5HourQuotaNextRefreshTime":1699999900000}},"status_code":0}"#;
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        stale,
        ProviderSource::ManualCookie,
    )
    .expect("stale reset fixture");
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .resets_at()
            .expect("shifted reset")
            .unix_timestamp(),
        1_700_017_900
    );
}

#[test]
fn embedded_json_active_selection_and_non_quantitative_fallback_match_baseline() {
    let inner = r#"{"data":{"codingPlanInstanceInfos":[{"planName":"Expired Starter","status":"EXPIRED","codingPlanQuotaInfo":{"per5HourUsedQuota":7,"per5HourTotalQuota":100}},{"planName":"Active Pro","status":"VALID","codingPlanQuotaInfo":{"per5HourUsedQuota":52,"per5HourTotalQuota":1000}}]},"statusCode":200}"#;
    let wrapped = serde_json::json!({"successResponse":{"body":inner}}).to_string();
    let sample = parse_usage_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        wrapped.as_bytes(),
        ProviderSource::BrowserSession,
    )
    .expect("embedded response");
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("active plan")
            .as_str(),
        "Active Pro"
    );
    assert_percent(
        sample
            .primary()
            .expect("selected active quota")
            .used_percent()
            .expect("known")
            .get(),
        5.2,
    );

    let no_borrow = br#"{
      "data":{"codingPlanInstanceInfos":[
        {"planName":"Expired Starter","status":"EXPIRED","codingPlanQuotaInfo":{"per5HourUsedQuota":7,"per5HourTotalQuota":100}},
        {"planName":"Active Pro","status":"VALID"}]},"status_code":0}"#;
    let sample = parse_usage_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        no_borrow,
        ProviderSource::ManualCookie,
    )
    .expect("active plan-only fallback");
    assert!(sample.primary().is_none());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("active plan")
            .as_str(),
        "Active Pro"
    );

    let unproven = br#"{"data":{"status":"VALID","codingPlanInstanceInfos":[{"planName":"Expired","status":"EXPIRED"},{"planName":"No Proof"}]},"status_code":0}"#;
    assert_eq!(
        parse_usage_response(
            scope("a"),
            timestamp(NOW_SECONDS),
            unproven,
            ProviderSource::ManualCookie,
        )
        .expect_err("payload status cannot relabel an instance")
        .kind(),
        ErrorKind::Parse
    );
}

#[test]
fn login_payload_is_source_specific_and_diagnostics_are_redacted() {
    let login =
        br#"{"code":"ConsoleNeedLogin","message":"You need to log in","secret":"response-canary"}"#;
    let api_error = parse_usage_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        login,
        ProviderSource::ApiKey,
    )
    .expect_err("API-key regional limitation");
    assert_eq!(api_error.kind(), ErrorKind::PermissionDenied);
    let web_error = parse_usage_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        login,
        ProviderSource::BrowserSession,
    )
    .expect_err("console session expired");
    assert_eq!(web_error.kind(), ErrorKind::AuthenticationExpired);
    assert!(!format!("{api_error:?} {web_error:?}").contains("response-canary"));
}

#[test]
fn parser_rejects_oversize_deep_wide_and_excessively_embedded_payloads() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let mut deep = "{\"planName\":\"x\"}".to_owned();
    for _ in 0..45 {
        deep = format!("[{deep}]");
    }
    let wide = format!(
        "{{\"codingPlanQuotaInfo\":{{\"per5HourTotalQuota\":1}},\"values\":[{}]}}",
        vec!["0"; 33_000].join(",")
    );
    let mut embedded = serde_json::json!({"planName":"x"}).to_string();
    for _ in 0..8 {
        embedded = serde_json::to_string(&embedded).expect("embedded JSON");
    }
    for body in [
        oversized.as_slice(),
        deep.as_bytes(),
        wide.as_bytes(),
        embedded.as_bytes(),
        &[0xff, 0xfe],
    ] {
        assert_eq!(
            parse_usage_response(
                scope("a"),
                timestamp(NOW_SECONDS),
                body,
                ProviderSource::ApiKey,
            )
            .expect_err("bounded parse rejection")
            .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn api_key_resolution_preserves_alias_precedence_and_redaction() {
    let environment = BTreeMap::from([
        ("DASHSCOPE_API_KEY".to_owned(), "dashscope".to_owned()),
        ("ALIBABA_QWEN_API_KEY".to_owned(), "qwen".to_owned()),
        (
            "ALIBABA_CODING_PLAN_API_KEY".to_owned(),
            "\"coding-plan\"".to_owned(),
        ),
    ]);
    let credential = resolve_api_key(&environment).expect("resolved key");
    assert!(!format!("{credential:?}").contains("coding-plan"));

    let gateway = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let rpc = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let provider = AlibabaProvider::from_api_environment_routes(
        scope("a"),
        AlibabaRegion::ChinaMainland,
        &environment,
        same_region_routes(&gateway, &rpc),
    )
    .expect("environment API provider");
    provider
        .fetch_at(
            &context("a", ProviderSource::ApiKey),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("environment credential fetch");
    assert_eq!(
        gateway.requests()[0].header("authorization"),
        Some("Bearer coding-plan")
    );
}

#[tokio::test]
async fn api_request_is_exact_and_international_retries_mainland_once() {
    let international_gateway =
        FakeHttpServer::start([FakeHttpResponse::new(403, b"forbidden-canary".to_vec())]).await;
    let international_rpc = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let china_gateway = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let china_rpc = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let provider = AlibabaProvider::from_api_key_routes(
        scope("account-a"),
        AlibabaRegion::International,
        API_CANARY,
        routes(
            &international_gateway,
            &international_rpc,
            &china_gateway,
            &china_rpc,
        ),
    )
    .expect("API provider");
    assert!(!format!("{provider:?}").contains(API_CANARY));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ApiKey),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("regional fallback");
    assert_eq!(provider.descriptor().id, ProviderId::Alibaba);
    assert!(sample.primary().is_some());

    let international = &international_gateway.requests()[0];
    assert!(
        international
            .target()
            .contains("currentRegionId=ap-southeast-1")
    );
    assert_eq!(international.method(), "POST");
    assert_eq!(international.header("accept"), Some("application/json"));
    assert_eq!(
        international.header("content-type"),
        Some("application/json")
    );
    assert_eq!(
        international.header("authorization"),
        Some("Bearer alibaba-api-key-canary")
    );
    assert_eq!(international.header("x-api-key"), Some(API_CANARY));
    assert_eq!(
        international.header("x-dashscope-api-key"),
        Some(API_CANARY)
    );
    assert_eq!(
        international.header("origin"),
        Some("https://modelstudio.console.alibabacloud.com")
    );
    let international_body: Value =
        serde_json::from_slice(international.body()).expect("international body");
    assert_eq!(
        international_body["queryCodingPlanInstanceInfoRequest"]["commodityCode"],
        "sfm_codingplan_public_intl"
    );

    let china = &china_gateway.requests()[0];
    assert!(china.target().contains("currentRegionId=cn-beijing"));
    assert_eq!(
        china.header("origin"),
        Some("https://bailian.console.aliyun.com")
    );
    let china_body: Value = serde_json::from_slice(china.body()).expect("China body");
    assert_eq!(
        china_body["queryCodingPlanInstanceInfoRequest"]["commodityCode"],
        "sfm_codingplan_public_cn"
    );
    assert!(international_rpc.requests().is_empty());
    assert!(china_rpc.requests().is_empty());
}

#[tokio::test]
async fn manual_full_curl_builds_exact_console_form_and_headers() {
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"<html>no token</html>".to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    let rpc = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let curl = "curl 'https://bailian-singapore-cs.alibabacloud.com/data/api.json?action=ignored' \
        -H 'Cookie: sec_token=manual-sec; login_aliyunid_ticket=ticket; login_aliyunid_pk=user; login_aliyunid_csrf=csrf-canary; cna=anonymous-canary'";
    let provider = AlibabaProvider::from_manual_capture_routes(
        scope("account-a"),
        AlibabaRegion::International,
        curl,
        same_region_routes(&gateway, &rpc),
    )
    .expect("manual provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");

    let gateway_requests = gateway.requests();
    assert_eq!(gateway_requests.len(), 2);
    assert_eq!(gateway_requests[0].method(), "GET");
    assert_eq!(
        gateway_requests[0].header("accept"),
        Some("text/html,application/xhtml+xml")
    );
    assert!(gateway_requests[0].target().starts_with("/ap-southeast-1/"));
    assert_eq!(
        gateway_requests[1].header("accept"),
        Some("application/json")
    );
    assert_eq!(gateway_requests[1].target(), "/tool/user/info.json");

    let rpc_request = &rpc.requests()[0];
    assert_eq!(rpc_request.method(), "POST");
    assert!(
        rpc_request
            .target()
            .contains("action=IntlBroadScopeAspnGateway")
    );
    assert_eq!(rpc_request.header("accept"), Some("*/*"));
    assert_eq!(
        rpc_request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        rpc_request.header("x-requested-with"),
        Some("XMLHttpRequest")
    );
    assert_eq!(rpc_request.header("x-xsrf-token"), Some("csrf-canary"));
    assert_eq!(rpc_request.header("x-csrf-token"), Some("csrf-canary"));
    assert_eq!(
        rpc_request.header("origin"),
        Some("https://modelstudio.console.alibabacloud.com")
    );
    assert_eq!(
        rpc_request.header("referer"),
        Some("https://modelstudio.console.alibabacloud.com/ap-southeast-1/?tab=coding-plan")
    );
    let fields = form_fields(rpc_request.body());
    assert_eq!(
        fields.get("region").map(String::as_str),
        Some("ap-southeast-1")
    );
    assert_eq!(
        fields.get("sec_token").map(String::as_str),
        Some("manual-sec")
    );
    let params: Value = serde_json::from_str(fields.get("params").expect("params JSON"))
        .expect("decoded params JSON");
    assert_eq!(
        params["Api"],
        "zeldaEasy.broadscope-bailian.codingPlan.queryCodingPlanInstanceInfoV2"
    );
    assert_eq!(params["V"], "1.0");
    assert_eq!(
        params["Data"]["queryCodingPlanInstanceInfoRequest"]["commodityCode"],
        "sfm_codingplan_public_intl"
    );
    assert_eq!(
        params["Data"]["queryCodingPlanInstanceInfoRequest"]["onlyLatestOne"],
        true
    );
    let cornerstone = &params["Data"]["cornerstoneParam"];
    assert_eq!(
        cornerstone["domain"],
        "modelstudio.console.alibabacloud.com"
    );
    assert_eq!(cornerstone["consoleSite"], "MODELSTUDIO_ALIBABACLOUD");
    assert_eq!(cornerstone["X-Anonymous-Id"], "anonymous-canary");
    assert_eq!(
        cornerstone["feURL"],
        "https://modelstudio.console.alibabacloud.com/ap-southeast-1/?tab=coding-plan#/efm/coding_plan"
    );
    assert_eq!(
        cornerstone["feTraceId"].as_str().expect("trace ID").len(),
        36
    );
}

#[test]
fn manual_capture_is_bound_to_selected_regional_hosts() {
    let gateway_url = Url::parse("http://127.0.0.1:32001").expect("loopback origin");
    let rpc_url = Url::parse("http://localhost:32002").expect("loopback origin");
    let route_set =
        AlibabaRouteSet::loopback(gateway_url.clone(), rpc_url.clone(), gateway_url, rpc_url)
            .expect("loopback routes");
    let error = AlibabaProvider::from_manual_capture_routes(
        scope("a"),
        AlibabaRegion::ChinaMainland,
        "curl https://modelstudio.console.alibabacloud.com/data/api.json -H 'Cookie: session=secret-canary'",
        route_set,
    )
    .expect_err("China capture cannot authorize an international URL");
    assert_eq!(error.kind(), ErrorKind::Parse);
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("secret-canary"));
    assert!(!diagnostic.contains("modelstudio"));
}

#[tokio::test]
async fn browser_cookie_jar_routes_dashboard_userinfo_and_rpc_independently() {
    let gateway = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"<html>no token</html>".to_vec()),
        FakeHttpResponse::new(
            200,
            br#"{"data":{"secToken":"userinfo-sec-token"}}"#.to_vec(),
        ),
    ])
    .await;
    let rpc = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let jar = independently_routed_browser_jar();
    let provider = AlibabaProvider::from_browser_jar_routes(
        scope("account-a"),
        AlibabaRegion::International,
        &jar,
        now(),
        same_region_routes(&gateway, &rpc),
    )
    .expect("browser provider");
    let debug = format!("{provider:?}");
    for canary in [DASHBOARD_CANARY, USER_INFO_CANARY, RPC_CANARY] {
        assert!(!debug.contains(canary));
    }
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fetch");

    let gateway_requests = gateway.requests();
    assert_eq!(gateway_requests.len(), 2);
    assert_eq!(
        gateway_requests[0].header("cookie"),
        Some(
            "dashboard_cookie=dashboard-cookie-canary; login_aliyunid_pk=browser-account; login_aliyunid_ticket=browser-ticket"
        )
    );
    assert_eq!(
        gateway_requests[1].header("cookie"),
        Some(
            "userinfo_cookie=userinfo-cookie-canary; login_aliyunid_pk=browser-account; login_aliyunid_ticket=browser-ticket"
        )
    );
    for request in &gateway_requests {
        assert!(
            !request
                .header("cookie")
                .unwrap_or_default()
                .contains(RPC_CANARY)
        );
        assert!(
            !request
                .header("cookie")
                .unwrap_or_default()
                .contains("must-not-cross")
        );
    }
    let rpc_request = &rpc.requests()[0];
    assert_eq!(
        rpc_request.header("cookie"),
        Some(
            "cna=anonymous-browser; login_aliyunid_csrf=browser-csrf; rpc_cookie=rpc-cookie-canary"
        )
    );
    assert!(
        !rpc_request
            .header("cookie")
            .unwrap_or_default()
            .contains(DASHBOARD_CANARY)
    );
    assert!(
        !rpc_request
            .header("cookie")
            .unwrap_or_default()
            .contains(USER_INFO_CANARY)
    );
    assert_eq!(
        form_fields(rpc_request.body())
            .get("sec_token")
            .map(String::as_str),
        Some("userinfo-sec-token")
    );
}

#[tokio::test]
async fn browser_rpc_only_cookie_never_reaches_dashboard_and_dashboard_only_never_reaches_rpc() {
    let gateway = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let rpc = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let rpc_only = cookie_jar(vec![
        cookie_record(
            "login_aliyunid_ticket",
            "rpc-ticket",
            "localhost",
            "/data",
            false,
            None,
        ),
        cookie_record(
            "login_aliyunid_pk",
            "rpc-account",
            "localhost",
            "/data",
            false,
            None,
        ),
        cookie_record("rpc_only", RPC_CANARY, "localhost", "/data", false, None),
        cookie_record(
            "sec_token",
            "rpc-cookie-sec",
            "localhost",
            "/data",
            false,
            None,
        ),
    ]);
    let provider = AlibabaProvider::from_browser_jar_routes(
        scope("a"),
        AlibabaRegion::International,
        &rpc_only,
        now(),
        same_region_routes(&gateway, &rpc),
    )
    .expect("RPC-only provider");
    provider
        .fetch_at(
            &context("a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("RPC cookie SEC-token fallback");
    assert!(gateway.requests().is_empty());
    assert_eq!(
        rpc.requests()[0].header("cookie"),
        Some(
            "login_aliyunid_pk=rpc-account; login_aliyunid_ticket=rpc-ticket; rpc_only=rpc-cookie-canary; sec_token=rpc-cookie-sec"
        )
    );

    let unused_gateway = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let unused_rpc = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let dashboard_only = cookie_jar(vec![
        cookie_record(
            "dashboard_only",
            DASHBOARD_CANARY,
            "127.0.0.1",
            "/ap-southeast-1/",
            false,
            None,
        ),
        cookie_record(
            "login_aliyunid_ticket",
            "dashboard-ticket",
            "127.0.0.1",
            "/ap-southeast-1/",
            false,
            None,
        ),
        cookie_record(
            "login_aliyunid_pk",
            "dashboard-account",
            "127.0.0.1",
            "/ap-southeast-1/",
            false,
            None,
        ),
    ]);
    let provider = AlibabaProvider::from_browser_jar_routes(
        scope("a"),
        AlibabaRegion::International,
        &dashboard_only,
        now(),
        same_region_routes(&unused_gateway, &unused_rpc),
    )
    .expect("dashboard-only provider");
    assert_eq!(
        provider
            .fetch_at(
                &context("a", ProviderSource::BrowserSession),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("dashboard cookie cannot authorize RPC")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert!(unused_gateway.requests().is_empty());
    assert!(unused_rpc.requests().is_empty());
}

#[test]
fn browser_empty_unmatched_and_expired_jars_are_classified_without_network() {
    let first = Url::parse("http://127.0.0.1:32101").expect("loopback origin");
    let second = Url::parse("http://localhost:32102").expect("loopback origin");
    let make_routes = || {
        AlibabaRouteSet::loopback(first.clone(), second.clone(), first.clone(), second.clone())
            .expect("loopback routes")
    };
    let empty = cookie_jar(Vec::new());
    assert_eq!(
        AlibabaProvider::from_browser_jar_routes(
            scope("a"),
            AlibabaRegion::ChinaMainland,
            &empty,
            now(),
            make_routes(),
        )
        .expect_err("empty jar")
        .kind(),
        ErrorKind::MissingCredential
    );
    for jar in [
        cookie_jar(vec![cookie_record(
            "wrong_host",
            "value",
            "example.com",
            "/",
            false,
            None,
        )]),
        cookie_jar(vec![cookie_record(
            "expired",
            "value",
            "localhost",
            "/data",
            false,
            Some(now() - time::Duration::seconds(1)),
        )]),
        cookie_jar(vec![cookie_record(
            "locale_only",
            "anonymous-value",
            "localhost",
            "/data",
            false,
            None,
        )]),
    ] {
        assert_eq!(
            AlibabaProvider::from_browser_jar_routes(
                scope("a"),
                AlibabaRegion::ChinaMainland,
                &jar,
                now(),
                make_routes(),
            )
            .expect_err("unusable imported jar")
            .kind(),
            ErrorKind::AuthenticationExpired
        );
    }
}

#[tokio::test]
async fn status_redirect_oversize_and_cancellation_are_stable() {
    for (response, expected) in [
        (
            FakeHttpResponse::new(401, b"auth-body-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(429, b"rate-body-canary".to_vec()),
            ErrorKind::RateLimited,
        ),
        (FakeHttpResponse::new(201, QUOTA.to_vec()), ErrorKind::Api),
        (
            FakeHttpResponse::new(302, Vec::new()).header("Location", "/redirected"),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1]),
            ErrorKind::Parse,
        ),
    ] {
        let gateway = FakeHttpServer::start([response]).await;
        let rpc = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
        let provider = AlibabaProvider::from_api_key_routes(
            scope("a"),
            AlibabaRegion::ChinaMainland,
            API_CANARY,
            same_region_routes(&gateway, &rpc),
        )
        .expect("API provider");
        let error = provider
            .fetch_at(
                &context("a", ProviderSource::ApiKey),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains(API_CANARY));
        assert!(!diagnostic.contains("body-canary"));
        assert_eq!(gateway.requests().len(), 1, "redirect was not followed");
    }

    let gateway = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let rpc = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let provider = AlibabaProvider::from_api_key_routes(
        scope("a"),
        AlibabaRegion::ChinaMainland,
        API_CANARY,
        same_region_routes(&gateway, &rpc),
    )
    .expect("API provider");
    let cancellation = CancellationToken::new();
    let provider_context =
        ProviderContext::new(scope("a"), ProviderSource::ApiKey, cancellation.clone());
    let fetch = provider.fetch_at(&provider_context, timestamp(NOW_SECONDS));
    tokio::pin!(fetch);
    tokio::select! {
        result = &mut fetch => panic!("stalled request completed early: {result:?}"),
        result = tokio::time::timeout(
            Duration::from_millis(200),
            gateway.wait_for_request_count(1),
        ) => result.expect("request reached fixture server"),
    }
    cancellation.cancel();
    assert_eq!(
        fetch.await.expect_err("cancelled fetch").kind(),
        ErrorKind::Network
    );
}

#[tokio::test]
async fn source_scope_and_provider_isolation_precede_network() {
    let gateway = FakeHttpServer::start([FakeHttpResponse::new(200, QUOTA.to_vec())]).await;
    let rpc = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let provider = AlibabaProvider::from_api_key_routes(
        scope("account-a"),
        AlibabaRegion::ChinaMainland,
        API_CANARY,
        same_region_routes(&gateway, &rpc),
    )
    .expect("API provider");
    for rejected in [
        context("account-b", ProviderSource::ApiKey),
        context("account-a", ProviderSource::ManualCookie),
    ] {
        assert_eq!(
            provider
                .fetch_at(&rejected, timestamp(NOW_SECONDS))
                .await
                .expect_err("scope/source mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(gateway.requests().is_empty());

    let wrong_scope = AccountScope::new(
        ProviderId::OpenAi,
        ProviderInstanceId::new("wrong-provider").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    assert_eq!(
        AlibabaProvider::from_api_key_routes(
            wrong_scope,
            AlibabaRegion::ChinaMainland,
            API_CANARY,
            same_region_routes(&gateway, &rpc),
        )
        .expect_err("wrong provider scope")
        .kind(),
        ErrorKind::Api
    );
}
