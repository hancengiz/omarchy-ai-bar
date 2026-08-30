use std::collections::BTreeMap;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::manus::{ManusProvider, ManusRouteSet, parse_usage_response};
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const DIRECT: &[u8] = include_bytes!("../../../fixtures/providers/manus/direct.json");
const WRAPPED: &[u8] = include_bytes!("../../../fixtures/providers/manus/wrapped.json");

const NOW_SECONDS: i64 = 1_700_000_000;
const TOKEN_CANARY: &str = "manus-session-token-canary";
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";

fn scope_for(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Manus,
        ProviderInstanceId::new("manus-primary").expect("provider instance"),
        AccountKey::new(account).expect("account"),
    )
}

fn scope() -> AccountScope {
    scope_for("default")
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope_for(account), source, CancellationToken::new())
}

fn localhost_origin(server: &FakeHttpServer) -> Url {
    let mut origin = server.url("/");
    origin
        .set_host(Some("localhost"))
        .expect("localhost loopback host");
    origin
}

fn routes(server: &FakeHttpServer) -> ManusRouteSet {
    ManusRouteSet::loopback(server.url("/"), server.url("/"), localhost_origin(server))
        .expect("loopback Manus routes")
}

fn manual_provider(server: &FakeHttpServer, capture: &str) -> ManusProvider {
    ManusProvider::from_manual_capture_routes(scope(), capture, routes(server))
        .expect("manual Manus provider")
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
    let source = CookieSourceId::new(41);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn empty_cookie_jar() -> CookieJar {
    cookie_jar(Vec::new())
}

fn assert_request(request: &CapturedHttpRequest, expected_token: &str) {
    let expected_authorization = format!("Bearer {expected_token}");
    assert_eq!(request.method(), "POST");
    assert_eq!(request.target(), "/user.v1.UserService/GetAvailableCredits");
    assert_eq!(request.body(), b"{}");
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.header("authorization"),
        Some(expected_authorization.as_str())
    );
    assert_eq!(request.header("origin"), Some("https://manus.im"));
    assert_eq!(request.header("referer"), Some("https://manus.im/"));
    assert_eq!(request.header("connect-protocol-version"), Some("1"));
    assert_eq!(request.header("user-agent"), Some(USER_AGENT));
}

#[test]
fn parses_direct_credit_payload_into_balance_and_two_windows() {
    let sample = parse_usage_response(
        scope(),
        timestamp(1_700_000_000),
        DIRECT,
        ProviderSource::ManualCookie,
    )
    .expect("direct payload");

    let primary = sample.primary().expect("primary window");
    assert!((primary.used_percent().expect("known").get() - 65.775).abs() < 0.000_001);
    assert_eq!(
        primary.reset_description().expect("description").as_str(),
        "Total 2,869 • Free 1,500"
    );
    assert!(primary.duration().is_none());
    assert!(primary.resets_at().is_none());

    let secondary = sample.secondary().expect("secondary window");
    assert_percent(secondary.used_percent().expect("known").get(), 100.0);
    assert_eq!(
        secondary.reset_description().expect("description").as_str(),
        "Daily: 0 / 300"
    );
    assert_eq!(
        secondary.resets_at().map(Timestamp::unix_timestamp),
        Some(1_776_038_400)
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .map(oab_domain::BoundedText::as_str),
        Some("Balance: 2,869 credits")
    );
    assert_eq!(sample.provenance()[0].source(), "manus");
    assert_eq!(sample.provenance()[0].strategy(), "web");
}

#[test]
fn parses_supported_data_envelope_and_rejects_unrelated_direct_objects() {
    let sample = parse_usage_response(
        scope(),
        timestamp(1_700_000_000),
        WRAPPED,
        ProviderSource::BrowserSession,
    )
    .expect("wrapped payload");

    assert_percent(
        sample
            .primary()
            .expect("primary")
            .used_percent()
            .expect("known")
            .get(),
        75.0,
    );
    assert_eq!(
        sample
            .secondary()
            .expect("secondary")
            .reset_description()
            .expect("description")
            .as_str(),
        "Every Day: 5 / 10"
    );

    let error = parse_usage_response(
        scope(),
        timestamp(1_700_000_000),
        br#"{"message":"ok"}"#,
        ProviderSource::ManualCookie,
    )
    .expect_err("unrelated direct object must not become an all-zero balance");
    assert_eq!(error.kind(), ErrorKind::Parse);
}

#[test]
fn envelope_precedence_numeric_dates_rounding_and_optional_fields_match_baseline() {
    let envelope = br#"{
        "data": {},
        "result": {"totalCredits": 999},
        "response": null
    }"#;
    let sample = parse_usage_response(
        scope(),
        timestamp(NOW_SECONDS),
        envelope,
        ProviderSource::ManualCookie,
    )
    .expect("first non-null envelope wins even when sparse");
    assert_eq!(
        sample.identity().login_method().expect("balance").as_str(),
        "Balance: 0 credits"
    );
    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());

    let direct_after_invalid_envelope = br#"{
        "data": "not-an-envelope",
        "totalCredits": 2.5,
        "freeCredits": -2.5,
        "proMonthlyCredits": 100,
        "periodicCredits": 200,
        "maxRefreshCredits": 10,
        "refreshCredits": -5,
        "nextRefreshTime": 0,
        "refreshInterval": 42
    }"#;
    let sample = parse_usage_response(
        scope(),
        timestamp(NOW_SECONDS),
        direct_after_invalid_envelope,
        ProviderSource::ManualCookie,
    )
    .expect("malformed envelope falls back to a valid direct object");
    assert_eq!(
        sample.identity().login_method().expect("balance").as_str(),
        "Balance: 3 credits"
    );
    let primary = sample.primary().expect("primary");
    assert_percent(primary.used_percent().expect("known").get(), 0.0);
    assert_eq!(
        primary.reset_description().expect("description").as_str(),
        "Total 3 • Free -3"
    );
    let secondary = sample.secondary().expect("secondary");
    assert_percent(secondary.used_percent().expect("known").get(), 100.0);
    assert_eq!(
        secondary
            .resets_at()
            .expect("numeric Cocoa date")
            .unix_timestamp(),
        978_307_200
    );
    assert_eq!(
        secondary.reset_description().expect("description").as_str(),
        "-5 / 10"
    );

    let malformed_later_field = br#"{
        "data": {"totalCredits": 1},
        "result": "invalid"
    }"#;
    assert_eq!(
        parse_usage_response(
            scope(),
            timestamp(NOW_SECONDS),
            malformed_later_field,
            ProviderSource::ManualCookie,
        )
        .expect_err("the pinned envelope decoder validates every envelope field")
        .kind(),
        ErrorKind::Parse
    );
}

#[test]
fn lossy_numbers_and_optional_enrichment_remain_bounded() {
    let long_interval = "x".repeat(129);
    let body = serde_json::json!({
        "totalCredits": " 12 ",
        "freeCredits": "not-a-number",
        "periodicCredits": true,
        "addonCredits": [],
        "eventCredits": {},
        "proMonthlyCredits": "20",
        "refreshCredits": "5",
        "maxRefreshCredits": "10",
        "nextRefreshTime": "not-a-date",
        "refreshInterval": long_interval,
    })
    .to_string();
    let sample = parse_usage_response(
        scope(),
        timestamp(NOW_SECONDS),
        body.as_bytes(),
        ProviderSource::ManualCookie,
    )
    .expect("lossy numeric fields and optional metadata");
    assert_eq!(
        sample.identity().login_method().expect("balance").as_str(),
        "Balance: 12 credits"
    );
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .reset_description()
            .expect("description")
            .as_str(),
        "Total 12 • Free 0"
    );
    let secondary = sample.secondary().expect("secondary");
    assert!(secondary.resets_at().is_none());
    assert_eq!(
        secondary.reset_description().expect("description").as_str(),
        "5 / 10"
    );

    for non_finite in ["NaN", "inf", "-Infinity", "1e9999"] {
        let body = serde_json::json!({"totalCredits": non_finite}).to_string();
        assert_eq!(
            parse_usage_response(
                scope(),
                timestamp(NOW_SECONDS),
                body.as_bytes(),
                ProviderSource::ManualCookie,
            )
            .expect_err("non-finite credit values must fail closed")
            .kind(),
            ErrorKind::Parse
        );
    }
}

#[test]
fn parser_enforces_response_depth_node_string_and_scope_bounds() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let mut nested = "0".to_owned();
    for _ in 0..45 {
        nested = format!("[{nested}]");
    }
    let deep = format!("{{\"totalCredits\":1,\"nested\":{nested}}}");
    let wide = format!(
        "{{\"totalCredits\":1,\"values\":[{}]}}",
        vec!["0"; 33_000].join(",")
    );
    let long = serde_json::json!({
        "totalCredits": 1,
        "unknown": "x".repeat(512 * 1024 + 1),
    })
    .to_string();
    for body in [
        oversized.as_slice(),
        deep.as_bytes(),
        wide.as_bytes(),
        long.as_bytes(),
        b"".as_slice(),
        b"[]".as_slice(),
        b"not-json".as_slice(),
        &[0xff, 0xfe],
    ] {
        let error = parse_usage_response(
            scope(),
            timestamp(NOW_SECONDS),
            body,
            ProviderSource::ManualCookie,
        )
        .expect_err("bounded parser rejection");
        assert_eq!(error.kind(), ErrorKind::Parse);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("totalCredits"));
    }

    let wrong_scope = AccountScope::new(
        ProviderId::QwenCloud,
        ProviderInstanceId::new("wrong-primary").expect("instance"),
        AccountKey::new("default").expect("account"),
    );
    assert_eq!(
        parse_usage_response(
            wrong_scope,
            timestamp(NOW_SECONDS),
            DIRECT,
            ProviderSource::ManualCookie,
        )
        .expect_err("provider scope isolation")
        .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        parse_usage_response(
            scope(),
            timestamp(NOW_SECONDS),
            DIRECT,
            ProviderSource::ApiKey,
        )
        .expect_err("source isolation")
        .kind(),
        ErrorKind::Api
    );
}

#[test]
fn manual_provider_accepts_a_bare_session_token_without_exposing_it() {
    let provider =
        ManusProvider::new_manual(scope(), "manus-secret-session").expect("manual provider");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);
    let debug = format!("{provider:?}");
    assert!(!debug.contains("manus-secret-session"));
}

#[test]
fn loopback_route_seam_rejects_non_origins_credentials_and_non_loopback_hosts() {
    let valid = Url::parse("http://127.0.0.1:31000/").expect("valid loopback");
    for invalid in [
        Url::parse("http://127.0.0.1:31000/path").expect("path URL"),
        Url::parse("http://user@127.0.0.1:31000/").expect("credential URL"),
        Url::parse("http://127.0.0.1:31000/?query=1").expect("query URL"),
        Url::parse("http://192.0.2.1:31000/").expect("non-loopback URL"),
        Url::parse("https://api.manus.im/").expect("production URL"),
    ] {
        let error = ManusRouteSet::loopback(invalid, valid.clone(), valid.clone())
            .expect_err("invalid loopback route");
        assert_eq!(error.kind(), ErrorKind::Api);
    }
}

#[tokio::test]
async fn manual_cookie_and_curl_captures_rebuild_the_exact_fixed_request() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, DIRECT.to_vec()),
        FakeHttpResponse::new(200, DIRECT.to_vec()),
    ])
    .await;

    let provider = manual_provider(
        &server,
        &format!("foo=bar; Session_ID={TOKEN_CANARY}; ignored=value"),
    );
    provider
        .fetch_at(
            &context("default", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual cookie fetch");

    let curl_token = "manus-curl-token-canary";
    let capture = format!(
        "curl 'https://api.manus.im/an-ignored-path?ignored=true' -H 'Cookie: foo=bar; session_id={curl_token}'"
    );
    let provider = manual_provider(&server, &capture);
    provider
        .fetch_at(
            &context("default", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual cURL fetch");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_request(&requests[0], TOKEN_CANARY);
    assert_request(&requests[1], curl_token);
    for request in &requests {
        let debug = format!("{request:?}");
        assert!(!debug.contains("token-canary"));
        assert!(!request.target().contains("ignored"));
    }
}

#[test]
fn invalid_manual_captures_fail_closed_without_fallback_or_secret_diagnostics() {
    for (case, (raw, expected)) in [
        ("", ErrorKind::MissingCredential),
        ("foo=bar", ErrorKind::Parse),
        ("session_id=", ErrorKind::Parse),
        ("Cookie: session_id=has space", ErrorKind::Parse),
        (
            "session_id=control-canary; other=line\nbreak",
            ErrorKind::Parse,
        ),
        (
            "curl 'https://manus.im.evil.invalid/' -H 'Cookie: session_id=host-suffix-canary'",
            ErrorKind::Parse,
        ),
        (
            "curl 'https://api.manus.im/' -H 'Authorization: Bearer auth-canary'",
            ErrorKind::Parse,
        ),
        (
            "curl $(printf https://api.manus.im/) -H 'Cookie: session_id=expansion-canary'",
            ErrorKind::Parse,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let error = ManusProvider::new_manual(scope(), raw).expect_err("invalid manual capture");
        assert_eq!(error.kind(), expected, "capture case {case}");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("canary"));
        assert!(!diagnostic.contains("manus.im.evil"));
    }

    let wrong_scope = AccountScope::new(
        ProviderId::QwenCloud,
        ProviderInstanceId::new("wrong-primary").expect("instance"),
        AccountKey::new("default").expect("account"),
    );
    assert_eq!(
        ManusProvider::new_manual(wrong_scope, TOKEN_CANARY)
            .expect_err("wrong provider scope")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn environment_aliases_preserve_precedence_and_never_enter_debug_output() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, DIRECT.to_vec()),
        FakeHttpResponse::new(200, DIRECT.to_vec()),
    ])
    .await;
    let mut environment = BTreeMap::new();
    environment.insert(
        "MANUS_SESSION_TOKEN".to_owned(),
        "'primary-environment-canary'".to_owned(),
    );
    environment.insert(
        "manus_session_token".to_owned(),
        "lower-priority-canary".to_owned(),
    );
    environment.insert(
        "MANUS_COOKIE".to_owned(),
        "session_id=cookie-fallback-canary".to_owned(),
    );
    let provider = ManusProvider::from_environment_routes(scope(), &environment, routes(&server))
        .expect("environment provider")
        .expect("configured environment");
    provider
        .fetch_at(
            &context("default", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("environment fetch");
    assert!(!format!("{provider:?}").contains("environment-canary"));

    environment.insert("MANUS_SESSION_TOKEN".to_owned(), "  ".to_owned());
    let provider = ManusProvider::from_environment_routes(scope(), &environment, routes(&server))
        .expect("fallback environment provider")
        .expect("cookie fallback");
    provider
        .fetch_at(
            &context("default", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("cookie environment fetch");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_request(&requests[0], "primary-environment-canary");
    assert_request(&requests[1], "cookie-fallback-canary");

    assert!(
        ManusProvider::from_environment_routes(scope(), &BTreeMap::new(), routes(&server))
            .expect("empty environment")
            .is_none()
    );

    let mut hostile_environment = BTreeMap::new();
    hostile_environment.insert(
        "MANUS_COOKIE".to_owned(),
        format!("session_id={TOKEN_CANARY}; other={}", "x".repeat(64 * 1024)),
    );
    assert!(
        ManusProvider::from_environment_routes(scope(), &hostile_environment, routes(&server),)
            .expect("oversized environment remains a stable absence")
            .is_none()
    );
}

#[tokio::test]
async fn browser_sessions_select_only_active_host_path_and_security_matching_tokens() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, DIRECT.to_vec())]).await;
    let jar = cookie_jar(vec![
        cookie_record("Session_ID", TOKEN_CANARY, "127.0.0.1", "/", false, None),
        cookie_record(
            "session_id",
            "wrong-path-canary",
            "127.0.0.1",
            "/app",
            false,
            None,
        ),
        cookie_record(
            "session_id",
            "secure-only-canary",
            "localhost",
            "/",
            true,
            None,
        ),
        cookie_record(
            "session_id",
            "expired-canary",
            "localhost",
            "/",
            false,
            Some(now() - time::Duration::seconds(1)),
        ),
        cookie_record(
            "session_id",
            "wrong-host-canary",
            "example.com",
            "/",
            false,
            None,
        ),
    ]);
    let provider =
        ManusProvider::from_browser_jars_routes(scope(), &[&jar], now(), routes(&server))
            .expect("browser Manus provider");
    assert_eq!(provider.source(), ProviderSource::BrowserSession);
    provider
        .fetch_at(
            &context("default", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fetch");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], TOKEN_CANARY);
    let authorization = requests[0].header("authorization").expect("authorization");
    for rejected in [
        "wrong-path-canary",
        "secure-only-canary",
        "expired-canary",
        "wrong-host-canary",
    ] {
        assert!(!authorization.contains(rejected));
    }
}

#[test]
fn browser_session_construction_distinguishes_missing_and_expired_credentials() {
    let empty = empty_cookie_jar();
    let dummy_api = Url::parse("http://127.0.0.1:31001/").expect("API URL");
    let dummy_manus = Url::parse("http://127.0.0.1:31002/").expect("Manus URL");
    let dummy_www = Url::parse("http://localhost:31003/").expect("www URL");
    let route_factory = || {
        ManusRouteSet::loopback(dummy_api.clone(), dummy_manus.clone(), dummy_www.clone())
            .expect("loopback routes")
    };
    assert_eq!(
        ManusProvider::from_browser_jars_routes(scope(), &[&empty], now(), route_factory())
            .expect_err("empty jar")
            .kind(),
        ErrorKind::MissingCredential
    );
    let excessive_profiles = vec![&empty; 65];
    assert_eq!(
        ManusProvider::from_browser_jars_routes(
            scope(),
            &excessive_profiles,
            now(),
            route_factory(),
        )
        .expect_err("profile count is bounded")
        .kind(),
        ErrorKind::Api
    );

    let scripted = [
        cookie_record("session_id", "", "127.0.0.1", "/", false, None),
        cookie_record(
            "session_id",
            "expired-canary",
            "127.0.0.1",
            "/",
            false,
            Some(now() - time::Duration::seconds(1)),
        ),
        cookie_record(
            "session_id",
            "wrong-host-canary",
            "example.com",
            "/",
            false,
            None,
        ),
    ];
    for record in scripted {
        let jar = cookie_jar(vec![record]);
        let error =
            ManusProvider::from_browser_jars_routes(scope(), &[&jar], now(), route_factory())
                .expect_err("nonempty jar without usable token");
        assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
        assert!(!format!("{error:?} {error}").contains("canary"));
    }
}

#[tokio::test]
async fn ordered_browser_tokens_continue_only_after_401_or_403_and_deduplicate() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, b"first-auth-canary".to_vec()),
        FakeHttpResponse::new(403, b"second-auth-canary".to_vec()),
        FakeHttpResponse::new(200, DIRECT.to_vec()),
    ])
    .await;
    let first = cookie_jar(vec![cookie_record(
        "session_id",
        "first-token-canary",
        "127.0.0.1",
        "/",
        false,
        None,
    )]);
    let duplicate = cookie_jar(vec![cookie_record(
        "session_id",
        "first-token-canary",
        "127.0.0.1",
        "/",
        false,
        None,
    )]);
    let second = cookie_jar(vec![cookie_record(
        "session_id",
        "second-token-canary",
        "127.0.0.1",
        "/",
        false,
        None,
    )]);
    let third = cookie_jar(vec![cookie_record(
        "session_id",
        "third-token-canary",
        "localhost",
        "/",
        false,
        None,
    )]);
    let provider = ManusProvider::from_browser_jars_routes(
        scope(),
        &[&first, &duplicate, &second, &third],
        now(),
        routes(&server),
    )
    .expect("multi-profile browser provider");
    provider
        .fetch_at(
            &context("default", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("third token succeeds");

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[0], "first-token-canary");
    assert_request(&requests[1], "second-token-canary");
    assert_request(&requests[2], "third-token-canary");
}

#[tokio::test]
async fn browser_token_iteration_stops_on_non_authentication_failure() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(500, b"unavailable-canary".to_vec()),
        FakeHttpResponse::new(200, DIRECT.to_vec()),
    ])
    .await;
    let first = cookie_jar(vec![cookie_record(
        "session_id",
        "first-token-canary",
        "127.0.0.1",
        "/",
        false,
        None,
    )]);
    let second = cookie_jar(vec![cookie_record(
        "session_id",
        "second-token-canary",
        "localhost",
        "/",
        false,
        None,
    )]);
    let provider = ManusProvider::from_browser_jars_routes(
        scope(),
        &[&first, &second],
        now(),
        routes(&server),
    )
    .expect("multi-profile browser provider");
    let error = provider
        .fetch_at(
            &context("default", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("server failure stops token iteration");
    assert_eq!(error.kind(), ErrorKind::ProviderUnavailable);
    assert_eq!(server.requests().len(), 1);
    assert!(!format!("{error:?} {error}").contains("canary"));
}

#[tokio::test]
async fn http_statuses_are_exactly_classified_without_retries_or_body_leaks() {
    for (status, expected) in [
        (401, ErrorKind::AuthenticationExpired),
        (403, ErrorKind::AuthenticationExpired),
        (429, ErrorKind::RateLimited),
        (500, ErrorKind::ProviderUnavailable),
        (201, ErrorKind::Api),
        (204, ErrorKind::Api),
    ] {
        let body_canary = format!("status-{status}-body-canary");
        let server = FakeHttpServer::start([FakeHttpResponse::new(
            status,
            body_canary.as_bytes().to_vec(),
        )])
        .await;
        let provider = manual_provider(&server, TOKEN_CANARY);
        let error = provider
            .fetch_at(
                &context("default", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("scripted status failure");
        assert_eq!(error.kind(), expected, "HTTP {status}");
        assert_eq!(server.requests().len(), 1, "HTTP {status} must not retry");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("canary"));
        assert!(!diagnostic.contains(&body_canary));
    }
}

#[tokio::test]
async fn redirects_truncation_oversize_and_invalid_success_json_fail_as_parse() {
    let cases = [
        FakeHttpResponse::new(302, Vec::new()).header(
            "Location",
            "/user.v1.UserService/GetAvailableCredits?redirect-canary=true",
        ),
        FakeHttpResponse::truncated(200, DIRECT.len() + 10, DIRECT.to_vec()),
        FakeHttpResponse::new(200, b"not-json-response-canary".to_vec()),
        FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1]),
    ];
    for response in cases {
        let server = FakeHttpServer::start([response]).await;
        let provider = manual_provider(&server, TOKEN_CANARY);
        let error = provider
            .fetch_at(
                &context("default", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("malformed response");
        assert_eq!(error.kind(), ErrorKind::Parse);
        assert_eq!(server.requests().len(), 1);
        assert!(!format!("{error:?} {error}").contains("canary"));
    }
}

#[tokio::test]
async fn cancellation_interrupts_a_stalled_request_without_trying_another_token() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::stall(),
        FakeHttpResponse::new(200, DIRECT.to_vec()),
    ])
    .await;
    let first = cookie_jar(vec![cookie_record(
        "session_id",
        "first-token-canary",
        "127.0.0.1",
        "/",
        false,
        None,
    )]);
    let second = cookie_jar(vec![cookie_record(
        "session_id",
        "second-token-canary",
        "localhost",
        "/",
        false,
        None,
    )]);
    let provider = ManusProvider::from_browser_jars_routes(
        scope(),
        &[&first, &second],
        now(),
        routes(&server),
    )
    .expect("browser provider");
    let cancellation = CancellationToken::new();
    let fetch_cancellation = cancellation.clone();
    let task = tokio::spawn(async move {
        let context =
            ProviderContext::new(scope(), ProviderSource::BrowserSession, fetch_cancellation);
        provider.fetch_at(&context, timestamp(NOW_SECONDS)).await
    });
    server.wait_for_request_count(1).await;
    cancellation.cancel();
    let error = tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .expect("cancelled fetch completes")
        .expect("fetch task")
        .expect_err("cancellation is a failure");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn account_and_source_mismatches_are_rejected_before_network_access() {
    let server = FakeHttpServer::start([]).await;
    let provider = manual_provider(&server, TOKEN_CANARY);
    assert_eq!(provider.descriptor().id, ProviderId::Manus);

    for context in [
        context("other-account", ProviderSource::ManualCookie),
        context("default", ProviderSource::BrowserSession),
    ] {
        let error = provider
            .fetch_at(&context, timestamp(NOW_SECONDS))
            .await
            .expect_err("scope/source mismatch");
        assert_eq!(error.kind(), ErrorKind::Api);
    }
    assert!(server.requests().is_empty());
    let debug = format!("{provider:?}");
    assert!(!debug.contains(TOKEN_CANARY));
    assert!(!debug.contains("default"));
}
