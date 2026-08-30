use std::collections::BTreeMap;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::qwencloud::{
    QwenCloudProvider, QwenCloudRouteSet, parse_usage_response, parse_usage_responses,
};
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use serde_json::Value;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const CURRENT_USAGE: &[u8] =
    include_bytes!("../../../fixtures/providers/qwencloud/current_usage.json");
const SUBSCRIPTION: &[u8] =
    include_bytes!("../../../fixtures/providers/qwencloud/subscription.json");
const QUOTA_CONFIG: &[u8] =
    include_bytes!("../../../fixtures/providers/qwencloud/quota_config.json");
const NESTED_LEGACY: &[u8] =
    include_bytes!("../../../fixtures/providers/qwencloud/nested_equity_list.json");
const FLAT_LEGACY: &[u8] =
    include_bytes!("../../../fixtures/providers/qwencloud/flat_subscription_summary.json");
const NO_SUBSCRIPTION: &[u8] =
    include_bytes!("../../../fixtures/providers/qwencloud/no_active_subscription.json");
const NOW_SECONDS: i64 = 1_700_000_000;
const COOKIE_CANARY: &str = "qwen-cookie-canary";
const DASHBOARD_CANARY: &str = "dashboard-cookie-canary";
const USER_INFO_CANARY: &str = "user-info-cookie-canary";
const DATA_CANARY: &str = "data-cookie-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn scope(account: &str) -> AccountScope {
    provider_scope(ProviderId::QwenCloud, account)
}

fn provider_scope(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(format!("{provider}-primary")).expect("provider instance"),
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

fn routes(dashboard: &FakeHttpServer, data: &FakeHttpServer) -> QwenCloudRouteSet {
    QwenCloudRouteSet::loopback(dashboard.url("/"), localhost_origin(data))
        .expect("loopback Qwen routes")
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
    let source = CookieSourceId::new(21);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn empty_cookie_jar() -> CookieJar {
    cookie_jar(Vec::new())
}

fn form_fields(body: &[u8]) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(body)
        .into_owned()
        .collect::<BTreeMap<_, _>>()
}

fn query_fields(target: &str) -> BTreeMap<String, String> {
    let url =
        Url::parse(&format!("http://fixture.invalid{target}")).expect("captured target parses");
    url.query_pairs().into_owned().collect()
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn assert_api_request(request: &CapturedHttpRequest, expected_api: &str) {
    assert_eq!(request.method(), "POST");
    let query = query_fields(request.target());
    assert_eq!(
        query.get("action").map(String::as_str),
        Some("IntlBroadScopeAspnGateway")
    );
    assert_eq!(
        query.get("product").map(String::as_str),
        Some("sfm_bailian")
    );
    assert_eq!(query.get("api").map(String::as_str), Some(expected_api));
    assert_eq!(query.get("_v").map(String::as_str), Some("undefined"));
    assert_eq!(
        request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(request.header("x-requested-with"), Some("XMLHttpRequest"));
    assert_eq!(request.header("x-xsrf-token"), Some("csrf-canary"));
    assert_eq!(request.header("x-csrf-token"), Some("csrf-canary"));
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
        Some("IntlBroadScopeAspnGateway")
    );
    assert_eq!(
        fields.get("sec_token").map(String::as_str),
        Some("fresh-html-token")
    );
    assert_eq!(
        fields.get("region").map(String::as_str),
        Some("ap-southeast-1")
    );
    assert_eq!(fields.get("language").map(String::as_str), Some("en-US"));
    let params: Value =
        serde_json::from_str(fields.get("params").expect("params")).expect("params JSON");
    assert_eq!(params["Api"], expected_api);
    assert_eq!(params["V"], "1.0");
    assert_eq!(
        params["Data"]["cornerstoneParam"]["consoleSite"],
        "QWENCLOUD"
    );
    assert_eq!(params["Data"]["cornerstoneParam"]["domain"], "127.0.0.1");
    assert_eq!(
        params["Data"]["cornerstoneParam"]["X-Anonymous-Id"],
        "anonymous-canary"
    );
    assert_eq!(
        params["Data"]["cornerstoneParam"]["feTraceId"]
            .as_str()
            .expect("trace ID")
            .len(),
        36
    );
}

fn independently_routed_jar() -> CookieJar {
    cookie_jar(vec![
        cookie_record(
            "dashboard_only",
            DASHBOARD_CANARY,
            "127.0.0.1",
            "/billing/subscription/",
            false,
            None,
        ),
        cookie_record(
            "userinfo_only",
            USER_INFO_CANARY,
            "127.0.0.1",
            "/tool/",
            false,
            None,
        ),
        cookie_record("data_only", DATA_CANARY, "localhost", "/data/", false, None),
        cookie_record(
            "login_aliyunid_ticket",
            "authenticated-session",
            "localhost",
            "/data/",
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

#[test]
fn current_fixtures_map_windows_totals_resets_and_plan() {
    let sample = parse_usage_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        CURRENT_USAGE,
        Some(SUBSCRIPTION),
        Some(QUOTA_CONFIG),
        ProviderSource::ManualCookie,
    )
    .expect("current Qwen response");
    let primary = sample.primary().expect("five-hour window");
    assert_percent(
        primary.used_percent().expect("five-hour percent").get(),
        3.0,
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
        1_700_003_600
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("five-hour detail")
            .as_str(),
        "150 / 5,000 credits used"
    );
    let weekly = sample.secondary().expect("weekly window");
    assert_percent(weekly.used_percent().expect("weekly percent").get(), 1.0);
    assert_eq!(
        weekly.duration().expect("weekly duration").seconds(),
        7 * 24 * 60 * 60
    );
    assert_eq!(
        weekly.reset_description().expect("weekly detail").as_str(),
        "500 / 50,000 credits used"
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Standard"
    );
}

#[test]
fn legacy_fixtures_map_nested_flat_and_no_subscription_shapes() {
    let nested = parse_usage_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        NESTED_LEGACY,
        ProviderSource::BrowserSession,
    )
    .expect("nested legacy response");
    let primary = nested.primary().expect("legacy quota");
    assert_percent(
        primary.used_percent().expect("known legacy percent").get(),
        12.5,
    );
    assert_eq!(
        primary.reset_description().expect("legacy detail").as_str(),
        "125 / 1,000 credits used"
    );
    assert_eq!(
        primary.resets_at().expect("legacy reset").unix_timestamp(),
        1_701_000_000
    );

    let flat = parse_usage_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        FLAT_LEGACY,
        ProviderSource::ManualCookie,
    )
    .expect("flat legacy response");
    assert_percent(
        flat.primary()
            .expect("flat quota")
            .used_percent()
            .expect("known")
            .get(),
        25.0,
    );

    let empty = parse_usage_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        NO_SUBSCRIPTION,
        ProviderSource::ManualCookie,
    )
    .expect("authenticated account without subscription");
    assert!(empty.primary().is_none());
}

#[test]
fn payload_auth_and_parse_failures_are_stable_and_redacted() {
    for (body, expected) in [
        (
            br#"{"code":"ConsoleNeedLogin","message":"login-secret-canary"}"#.as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            br#"{"statusCode":403,"message":"forbidden-secret-canary"}"#.as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            br#"{"errorCode":"ConsoleNeedLogin","message":"outer-login-secret-canary","data":{"success":false}}"#
                .as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (b"not-json".as_slice(), ErrorKind::Parse),
    ] {
        let error = parse_usage_response(
            scope("a"),
            timestamp(NOW_SECONDS),
            body,
            ProviderSource::ManualCookie,
        )
        .expect_err("scripted payload failure");
        assert_eq!(error.kind(), expected);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("secret-canary"));
    }
}

#[test]
fn parser_bounds_deep_wide_long_embedded_and_optional_payloads() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let mut deep = "{\"per5HourPercentage\":0.1}".to_owned();
    for _ in 0..45 {
        deep = format!("[{deep}]");
    }
    let wide = format!(
        "{{\"per5HourPercentage\":0.1,\"values\":[{}]}}",
        vec!["0"; 33_000].join(",")
    );
    let long = serde_json::json!({
        "per5HourPercentage": 0.1,
        "value": "x".repeat(512 * 1024 + 1),
    })
    .to_string();
    let mut embedded = serde_json::json!({"per5HourPercentage": 0.1}).to_string();
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
            parse_usage_response(
                scope("a"),
                timestamp(NOW_SECONDS),
                body,
                ProviderSource::ManualCookie,
            )
            .expect_err("bounded rejection")
            .kind(),
            ErrorKind::Parse
        );
    }

    let sample = parse_usage_responses(
        scope("a"),
        timestamp(NOW_SECONDS),
        CURRENT_USAGE,
        Some(&oversized),
        Some(b"not-json"),
        ProviderSource::ManualCookie,
    )
    .expect("optional metadata remains best effort and bounded");
    assert_percent(
        sample
            .primary()
            .expect("current usage remains authoritative")
            .used_percent()
            .expect("known")
            .get(),
        3.0,
    );
}

#[tokio::test]
async fn manual_curl_runs_exact_dashboard_and_three_api_request_flow() {
    let dashboard = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        br#"<html><script>sec_token = "fresh-html-token";</script></html>"#.to_vec(),
    )])
    .await;
    let data = FakeHttpServer::start([
        FakeHttpResponse::new(200, CURRENT_USAGE.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, QUOTA_CONFIG.to_vec()),
    ])
    .await;
    let capture = format!(
        "curl 'https://home.qwencloud.com/billing/subscription/token-plan-individual?ignored=1' -H 'Cookie: session={COOKIE_CANARY}; sec_token=stale-cookie-token; cna=anonymous-canary; login_aliyunid_csrf=csrf-canary'"
    );
    let provider = QwenCloudProvider::from_manual_capture_routes(
        scope("account-a"),
        &capture,
        routes(&dashboard, &data),
    )
    .expect("manual provider");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);
    assert!(!format!("{provider:?}").contains(COOKIE_CANARY));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Standard"
    );

    let dashboard_request = &dashboard.requests()[0];
    assert_eq!(dashboard_request.method(), "GET");
    assert_eq!(
        dashboard_request.target(),
        "/billing/subscription/token-plan-individual"
    );
    assert_eq!(
        dashboard_request.header("accept"),
        Some("text/html,application/xhtml+xml")
    );
    assert!(
        dashboard_request
            .header("cookie")
            .is_some_and(|value| value.contains(COOKIE_CANARY))
    );

    let requests = data.requests();
    assert_eq!(requests.len(), 3);
    for (request, expected_api) in requests.iter().zip([
        "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage",
        "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/subscription",
        "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/quota-config",
    ]) {
        assert_api_request(request, expected_api);
    }
    let subscription_fields = form_fields(requests[1].body());
    let subscription_params: Value = serde_json::from_str(
        subscription_fields
            .get("params")
            .expect("subscription params"),
    )
    .expect("subscription JSON");
    assert_eq!(
        subscription_params["Data"]["commodityCode"],
        "sfm_tokenplansolo_public_intl"
    );
}

#[tokio::test]
async fn browser_jar_routes_dashboard_user_info_and_data_cookies_independently() {
    let dashboard = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"<html>no token</html>".to_vec()),
        FakeHttpResponse::new(
            200,
            br#"{"data":{"token":"generic","nested":{"secToken":"preferred-token"}}}"#.to_vec(),
        ),
    ])
    .await;
    let data = FakeHttpServer::start([
        FakeHttpResponse::new(200, CURRENT_USAGE.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(200, QUOTA_CONFIG.to_vec()),
    ])
    .await;
    let jar = independently_routed_jar();
    let provider = QwenCloudProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&dashboard, &data),
    )
    .expect("browser provider");
    assert_eq!(provider.source(), ProviderSource::BrowserSession);
    let debug = format!("{provider:?}");
    for canary in [DASHBOARD_CANARY, USER_INFO_CANARY, DATA_CANARY] {
        assert!(!debug.contains(canary));
    }
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fetch");

    let dashboard_requests = dashboard.requests();
    assert_eq!(dashboard_requests.len(), 2);
    assert_eq!(
        dashboard_requests[0].header("cookie"),
        Some("dashboard_only=dashboard-cookie-canary")
    );
    assert_eq!(
        dashboard_requests[1].header("cookie"),
        Some("userinfo_only=user-info-cookie-canary")
    );
    for request in &dashboard_requests {
        let cookie = request.header("cookie").unwrap_or_default();
        assert!(!cookie.contains(DATA_CANARY));
        assert!(!cookie.contains("must-not-cross"));
    }
    for request in data.requests() {
        let cookie = request.header("cookie").expect("data cookie header");
        assert!(cookie.contains("data_only=data-cookie-canary"));
        assert!(cookie.contains("login_aliyunid_ticket=authenticated-session"));
        assert!(!cookie.contains(DASHBOARD_CANARY));
        assert!(!cookie.contains(USER_INFO_CANARY));
        assert_eq!(
            form_fields(request.body())
                .get("sec_token")
                .map(String::as_str),
            Some("preferred-token")
        );
    }
}

#[tokio::test]
async fn browser_missing_expired_and_cross_host_only_sessions_fail_closed() {
    let dashboard = FakeHttpServer::start([]).await;
    let data = FakeHttpServer::start([]).await;
    for (jar, expected) in [
        (empty_cookie_jar(), ErrorKind::MissingCredential),
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
            cookie_jar(vec![cookie_record(
                "expired",
                "secret",
                "localhost",
                "/data/",
                false,
                Some(now() - time::Duration::seconds(1)),
            )]),
            ErrorKind::AuthenticationExpired,
        ),
        (
            cookie_jar(vec![cookie_record(
                "dashboard_only",
                "secret",
                "127.0.0.1",
                "/billing/",
                false,
                None,
            )]),
            ErrorKind::AuthenticationExpired,
        ),
    ] {
        let error = QwenCloudProvider::from_browser_jar_routes(
            scope("a"),
            &jar,
            now(),
            routes(&dashboard, &data),
        )
        .expect_err("missing data-gateway cookie");
        assert_eq!(error.kind(), expected);
    }
    assert!(dashboard.requests().is_empty());
    assert!(data.requests().is_empty());
}

#[tokio::test]
async fn browser_auth_ticket_qualification_matches_baseline() {
    let dashboard = FakeHttpServer::start([]).await;
    let data = FakeHttpServer::start([]).await;
    let logged_out = cookie_jar(vec![
        cookie_record("data_only", DATA_CANARY, "localhost", "/data/", false, None),
        cookie_record("locale", "en-US", "localhost", "/data/", false, None),
        cookie_record(
            "login_aliyunid_csrf",
            "csrf-only",
            "localhost",
            "/data/",
            false,
            None,
        ),
        cookie_record(
            "LOGIN_QWENCLOUD_TICKET",
            "wrong-case-ticket",
            "localhost",
            "/data/",
            false,
            None,
        ),
    ]);
    let error = QwenCloudProvider::from_browser_jar_routes(
        scope("a"),
        &logged_out,
        now(),
        routes(&dashboard, &data),
    )
    .expect_err("logged-out profile cookies are not an authenticated session");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);

    let api_ticket_only = cookie_jar(vec![cookie_record(
        "login_qwencloud_ticket",
        "api-ticket",
        "localhost",
        "/data/",
        false,
        None,
    )]);
    let error = QwenCloudProvider::from_browser_jar_routes(
        scope("a"),
        &api_ticket_only,
        now(),
        routes(&dashboard, &data),
    )
    .expect_err("API ticket without a dashboard cookie is incomplete");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);

    for ticket_name in [
        "login_aliyunid_ticket",
        "login_qwencloud_ticket",
        "qwen_sso_ticket",
    ] {
        let authenticated = cookie_jar(vec![
            cookie_record(
                ticket_name,
                "api-ticket",
                "localhost",
                "/data/",
                false,
                None,
            ),
            cookie_record(
                ticket_name,
                "dashboard-ticket",
                "127.0.0.1",
                "/billing/",
                false,
                None,
            ),
        ]);
        let provider = QwenCloudProvider::from_browser_jar_routes(
            scope("a"),
            &authenticated,
            now(),
            routes(&dashboard, &data),
        )
        .expect("recognized Qwen auth ticket");
        assert_eq!(provider.source(), ProviderSource::BrowserSession);
    }
    assert!(dashboard.requests().is_empty());
    assert!(data.requests().is_empty());
}

#[tokio::test]
async fn browser_empty_auth_ticket_fails_closed() {
    let dashboard = FakeHttpServer::start([]).await;
    let data = FakeHttpServer::start([]).await;
    let empty_ticket = cookie_jar(vec![
        cookie_record(
            "login_aliyunid_ticket",
            "",
            "localhost",
            "/data/",
            false,
            None,
        ),
        cookie_record(
            "dashboard_only",
            "present",
            "127.0.0.1",
            "/billing/",
            false,
            None,
        ),
    ]);
    let error = QwenCloudProvider::from_browser_jar_routes(
        scope("a"),
        &empty_ticket,
        now(),
        routes(&dashboard, &data),
    )
    .expect_err("empty Qwen auth ticket does not prove a session");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert!(dashboard.requests().is_empty());
    assert!(data.requests().is_empty());
}

#[test]
fn capture_and_route_authority_are_exact() {
    let dashboard_url = Url::parse("http://127.0.0.1:32011").expect("loopback origin");
    let data_url = Url::parse("http://localhost:32012").expect("loopback origin");
    let routes = QwenCloudRouteSet::loopback(dashboard_url, data_url).expect("loopback routes");
    let provider = QwenCloudProvider::from_manual_capture_routes(
        scope("a"),
        "curl 'https://cs-data.qwencloud.com/data/api.json?action=x' -b 'session=secret'",
        routes,
    )
    .expect("exact data host capture");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);

    let dashboard_url = Url::parse("http://127.0.0.1:32011").expect("loopback origin");
    let data_url = Url::parse("http://localhost:32012").expect("loopback origin");
    let routes = QwenCloudRouteSet::loopback(dashboard_url, data_url).expect("loopback routes");
    let error = QwenCloudProvider::from_manual_capture_routes(
        scope("a"),
        "curl 'https://home.qwencloud.com.evil.invalid/' -b 'session=secret-canary'",
        routes,
    )
    .expect_err("suffix host is not authorized");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?} {error}").contains("secret-canary"));

    assert!(
        QwenCloudRouteSet::loopback(
            Url::parse("https://example.com").expect("public origin"),
            Url::parse("http://localhost:32012").expect("loopback origin"),
        )
        .is_err()
    );
}

#[tokio::test]
async fn scope_source_and_provider_isolation_precede_network() {
    let dashboard = FakeHttpServer::start([]).await;
    let data = FakeHttpServer::start([]).await;
    let provider = QwenCloudProvider::from_manual_capture_routes(
        scope("account-a"),
        "session=secret",
        routes(&dashboard, &data),
    )
    .expect("manual provider");
    for context in [
        context("account-b", ProviderSource::ManualCookie),
        context("account-a", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&context, timestamp(NOW_SECONDS))
                .await
                .expect_err("scope/source mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(dashboard.requests().is_empty());
    assert!(data.requests().is_empty());
    assert_eq!(provider.descriptor().id, ProviderId::QwenCloud);

    let dashboard_url = Url::parse("http://127.0.0.1:32021").expect("loopback origin");
    let data_url = Url::parse("http://localhost:32022").expect("loopback origin");
    let error = QwenCloudProvider::from_manual_capture_routes(
        provider_scope(ProviderId::Alibaba, "a"),
        "session=secret",
        QwenCloudRouteSet::loopback(dashboard_url, data_url).expect("routes"),
    )
    .expect_err("wrong provider scope");
    assert_eq!(error.kind(), ErrorKind::Api);
}

#[tokio::test]
async fn required_status_redirect_truncation_and_oversize_are_stable() {
    for (response, expected) in [
        (
            FakeHttpResponse::new(401, b"auth-body-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, b"forbidden-body-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(201, CURRENT_USAGE.to_vec()),
            ErrorKind::Api,
        ),
        (
            FakeHttpResponse::new(429, b"rate-body-canary".to_vec()),
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
        let dashboard = FakeHttpServer::start([FakeHttpResponse::new(
            200,
            b"<html>no token</html>".to_vec(),
        )])
        .await;
        let data = FakeHttpServer::start([response]).await;
        let provider = QwenCloudProvider::from_manual_capture_routes(
            scope("a"),
            &format!("session={COOKIE_CANARY}; sec_token=cookie-token"),
            routes(&dashboard, &data),
        )
        .expect("provider");
        let error = provider
            .fetch_at(
                &context("a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains(COOKIE_CANARY));
        assert!(!diagnostic.contains("body-canary"));
        assert_eq!(data.requests().len(), 1, "redirect was not followed");
    }
}

#[tokio::test]
async fn optional_failures_are_best_effort_and_cancellation_wins() {
    let dashboard = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        b"<html>no token</html>".to_vec(),
    )])
    .await;
    let data = FakeHttpServer::start([
        FakeHttpResponse::new(200, CURRENT_USAGE.to_vec()),
        FakeHttpResponse::new(201, SUBSCRIPTION.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    let provider = QwenCloudProvider::from_manual_capture_routes(
        scope("a"),
        "session=secret; sec_token=cookie-token",
        routes(&dashboard, &data),
    )
    .expect("provider");
    let sample = provider
        .fetch_at(
            &context("a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("optional metadata failures are ignored");
    assert!(sample.primary().is_some());
    assert!(sample.identity().login_method().is_none());

    let dashboard = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        b"<html>no token</html>".to_vec(),
    )])
    .await;
    let data = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = QwenCloudProvider::from_manual_capture_routes(
        scope("a"),
        "session=secret; sec_token=cookie-token",
        routes(&dashboard, &data),
    )
    .expect("provider");
    let cancellation = CancellationToken::new();
    let provider_context = ProviderContext::new(
        scope("a"),
        ProviderSource::ManualCookie,
        cancellation.clone(),
    );
    let fetch = provider.fetch_at(&provider_context, timestamp(NOW_SECONDS));
    tokio::pin!(fetch);
    tokio::select! {
        () = data.wait_for_request_count(1) => {}
        result = &mut fetch => panic!("fetch completed before cancellation: {result:?}"),
    }
    cancellation.cancel();
    let error = fetch.await.expect_err("cancelled request");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[tokio::test]
async fn dashboard_server_failure_is_retained_when_token_fallbacks_are_empty() {
    let dashboard = FakeHttpServer::start([
        FakeHttpResponse::new(503, b"dashboard-secret-canary".to_vec()),
        FakeHttpResponse::new(200, b"{}".to_vec()),
    ])
    .await;
    let data = FakeHttpServer::start([]).await;
    let provider = QwenCloudProvider::from_manual_capture_routes(
        scope("a"),
        "session=secret",
        routes(&dashboard, &data),
    )
    .expect("provider");
    let error = provider
        .fetch_at(
            &context("a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("dashboard network failure remains authoritative");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(!format!("{error:?} {error}").contains("dashboard-secret-canary"));
    assert_eq!(dashboard.requests().len(), 2);
    assert!(data.requests().is_empty());
}
