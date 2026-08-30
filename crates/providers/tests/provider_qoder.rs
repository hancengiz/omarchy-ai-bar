use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::qoder::{
    QoderProvider, QoderRouteSet, QoderSite, manual_site, parse_usage_response,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const CAMEL: &[u8] = include_bytes!("../../../fixtures/providers/qoder/quota-camel.json");
const SHARED: &[u8] = include_bytes!("../../../fixtures/providers/qoder/quota-shared-snake.json");
const COOKIE_CANARY: &str = "qoder-session-cookie-canary";
const CHINA_CANARY: &str = "qoder-china-cookie-canary";
const NOW_SECONDS: i64 = 1_719_206_400;

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Qoder,
        ProviderInstanceId::new("qoder-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn timestamp() -> Timestamp {
    Timestamp::from_unix_timestamp(NOW_SECONDS).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn routes(global: &FakeHttpServer, china: &FakeHttpServer) -> QoderRouteSet {
    QoderRouteSet::loopback(global.url("/"), china.url("/")).expect("loopback Qoder routes")
}

fn cookie_record(name: &str, value: &str, domain: &str) -> CookieRecord {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain,
        domain_kind: CookieDomainKind::HostOnly,
        path: "/",
        secure: true,
        expires_at: Some(now() + time::Duration::days(1)),
    })
    .expect("cookie record")
}

fn cookie_jar(records: Vec<CookieRecord>) -> CookieJar {
    let source = CookieSourceId::new(31);
    let order = CookieImportOrder::new([source]).expect("cookie order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

#[test]
fn golden_camel_and_shared_snake_payloads_match_pinned_mapping() {
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(),
        CAMEL,
        ProviderSource::ManualCookie,
    )
    .expect("camel fixture");
    let primary = sample.primary().expect("credit window");
    assert_percent(primary.used_percent().expect("known percent").get(), 25.0);
    assert!(primary.duration().is_none());
    assert_eq!(
        primary.resets_at().expect("reset").unix_timestamp(),
        1_725_148_800
    );
    assert_eq!(
        primary.reset_description().expect("credit detail").as_str(),
        "125 / 500 credits"
    );
    assert!(sample.secondary().is_none());
    assert!(sample.identity().email().is_none());
    assert!(sample.identity().organization().is_none());
    assert!(sample.identity().login_method().is_none());
    assert_eq!(sample.provenance()[0].source(), "qoder");
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");

    let shared = parse_usage_response(
        scope("account-a"),
        timestamp(),
        SHARED,
        ProviderSource::BrowserSession,
    )
    .expect("shared snake fixture");
    let primary = shared.primary().expect("merged credit window");
    assert_percent(primary.used_percent().expect("known percent").get(), 68.0);
    assert_eq!(
        primary.reset_description().expect("merged detail").as_str(),
        "1,700 / 2,500 credits"
    );
    assert_eq!(shared.provenance()[0].strategy(), "browser_session");
}

#[test]
fn parser_preserves_zero_quota_and_fraction_formatting_rules() {
    let zero =
        br#"{"totalQuota":{"quotaSummary":{"usedValue":0,"limitValue":0,"remainingValue":0}}}"#;
    let sample = parse_usage_response(scope("a"), timestamp(), zero, ProviderSource::ManualCookie)
        .expect("zero quota");
    let primary = sample.primary().expect("primary");
    assert_percent(primary.used_percent().expect("known").get(), 100.0);
    assert_eq!(
        primary.reset_description().expect("detail").as_str(),
        "0 / 0 credits"
    );

    let fractional = br#"{"totalQuota":{"quotaSummary":{"usedValue":12.345,"limitValue":100.5,"usagePercentage":-3}}}"#;
    let sample = parse_usage_response(
        scope("a"),
        timestamp(),
        fractional,
        ProviderSource::ManualCookie,
    )
    .expect("fractional quota");
    let primary = sample.primary().expect("primary");
    assert_percent(primary.used_percent().expect("clamped").get(), 0.0);
    assert_eq!(
        primary.reset_description().expect("detail").as_str(),
        "12.35 / 100.5 credits"
    );

    let empty_shared =
        br#"{"totalQuota":{"quotaSummary":{"usedValue":1,"limitValue":4}},"sharedQuota":{}}"#;
    let sample = parse_usage_response(
        scope("a"),
        timestamp(),
        empty_shared,
        ProviderSource::ManualCookie,
    )
    .expect("missing optional shared summary is ignored");
    assert_percent(
        sample
            .primary()
            .expect("primary")
            .used_percent()
            .expect("known")
            .get(),
        25.0,
    );
}

#[test]
fn parser_rejects_negative_impossible_missing_deep_and_oversized_payloads() {
    for body in [
        br#"{"totalQuota":{"quotaSummary":{"usedValue":-1,"limitValue":2}}}"#.as_slice(),
        br#"{"totalQuota":{"quotaSummary":{"usedValue":1,"limitValue":0,"remainingValue":0}}}"#,
        br#"{"totalQuota":{}}"#,
    ] {
        assert_eq!(
            parse_usage_response(scope("a"), timestamp(), body, ProviderSource::ManualCookie,)
                .expect_err("invalid quota")
                .kind(),
            ErrorKind::Parse
        );
    }
    let deep_value = "[".repeat(50) + &"]".repeat(50);
    let deep = [
        r#"{"totalQuota":{"quotaSummary":{"usedValue":0,"limitValue":1},"x":"#,
        deep_value.as_str(),
        "}}",
    ]
    .concat();
    assert_eq!(
        parse_usage_response(
            scope("a"),
            timestamp(),
            deep.as_bytes(),
            ProviderSource::ManualCookie,
        )
        .expect_err("deep JSON")
        .kind(),
        ErrorKind::Parse
    );
    let oversized = vec![b' '; 2 * 1024 * 1024 + 1];
    assert_eq!(
        parse_usage_response(
            scope("a"),
            timestamp(),
            &oversized,
            ProviderSource::ManualCookie,
        )
        .expect_err("oversized JSON")
        .kind(),
        ErrorKind::Parse
    );
    assert_eq!(
        parse_usage_response(scope("a"), timestamp(), CAMEL, ProviderSource::ApiKey)
            .expect_err("invalid parser source")
            .kind(),
        ErrorKind::Api
    );
}

#[test]
fn manual_domain_routing_uses_only_authoritative_capture_metadata() {
    let global = [
        "sid=abc",
        "sid=qoder.com.cn-looking-value",
        "sid=abc; note=curl https://qoder.com.cn",
        "sid=abc; Domain=.qoder.com",
        "GET /account/usage HTTP/1.1\r\nHost: qoder.com\r\nCookie: sid=abc",
        "curl https://qoder.com -H 'Cookie: sid=abc'",
    ];
    for raw in global {
        assert_eq!(
            manual_site(raw).expect("global route"),
            QoderSite::International
        );
    }
    let china = [
        "sid=abc; Domain=.qoder.com.cn",
        "sid=abc; Domain=www.qoder.com.cn",
        "GET https://qoder.com.cn/account/usage HTTP/1.1\r\nCookie: sid=abc",
        "GET /account/usage HTTP/1.1\r\nHost: qoder.com.cn:443\r\nCookie: sid=abc",
        "HTTPS_PROXY=http://127.0.0.1:8080 curl --url https://qoder.com.cn -H 'Cookie: sid=abc'",
        "curl https://www.qoder.com.cn -fsSLHHost:qoder.com.cn -H 'Cookie: sid=abc'",
    ];
    for raw in china {
        assert_eq!(manual_site(raw).expect("China route"), QoderSite::China);
    }
}

#[test]
fn manual_domain_routing_rejects_ambiguous_foreign_and_shell_capabilities() {
    let invalid = [
        "sid=abc; Domain=qoder.com; Domain=qoder.com.cn",
        "sid=abc; Domain=..qoder.com.cn",
        "sid=abc; Domain=evil.example",
        "GET /account/usage HTTP/1.1\r\nHost: qoder.com.cn:evil\r\nCookie: sid=abc",
        "GET https://qoder.com/account/usage HTTP/1.1\r\nHost: qoder.com.cn\r\nCookie: sid=abc",
        "TRACE /account/usage HTTP/1.1\r\nHost: qoder.com\r\nCookie: sid=abc",
        "curl https://qoder.com https://qoder.com.cn -H 'Cookie: sid=abc'",
        "curl https://example.com -H 'Cookie: sid=abc'",
        "curl https://qoder.com -H 'Host: qoder.com.cn' -H 'Cookie: sid=abc'",
        "curl https://qoder.com --config secrets -H 'Cookie: sid=abc'",
        "curl https://qoder.com --location-trusted -H 'Cookie: sid=abc'",
        "curl https://qoder.com ; echo -H 'Cookie: sid=stolen'",
        "curl https://qoder.com -A $AGENT -H 'Cookie: sid=abc'",
    ];
    for raw in invalid {
        assert_eq!(
            manual_site(raw)
                .expect_err("capture must be rejected")
                .kind(),
            ErrorKind::AuthenticationExpired,
            "accepted {raw:?}"
        );
    }
    assert_eq!(
        manual_site("GET / HTTP/1.1\r\nHost: qoder.com\r\nX-Bad: \0\r\nCookie: sid=abc")
            .expect_err("control-bearing capture")
            .kind(),
        ErrorKind::Parse
    );
    for raw in [
        "curl https://qoder.com\n-H 'Cookie: sid=abc'",
        "curl\thttps://qoder.com -H 'Cookie: sid=abc'",
    ] {
        assert_eq!(
            manual_site(raw)
                .expect_err("unescaped cURL control whitespace")
                .kind(),
            ErrorKind::AuthenticationExpired
        );
    }
}

#[tokio::test]
async fn manual_capture_sends_exact_global_request_headers_and_normalized_cookie() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(200, CAMEL.to_vec())]).await;
    let china = FakeHttpServer::start([]).await;
    let provider = QoderProvider::from_manual_capture_at(
        scope("account-a"),
        &format!(
            "curl https://qoder.com/account/usage -H 'Cookie: sid={COOKIE_CANARY}; theme=dark'"
        ),
        &routes(&global, &china),
    )
    .expect("manual Qoder provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("manual fetch");
    assert_eq!(provider.descriptor().id, ProviderId::Qoder);
    assert_percent(
        sample
            .primary()
            .expect("primary")
            .used_percent()
            .expect("known")
            .get(),
        25.0,
    );
    assert!(china.requests().is_empty());
    let requests = global.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method(), "GET");
    assert_eq!(request.target(), "/api/v2/me/usages/big_model_credits");
    assert_eq!(
        request.header("cookie"),
        Some(format!("sid={COOKIE_CANARY}; theme=dark").as_str())
    );
    assert_eq!(
        request.header("accept"),
        Some("application/json, text/plain, */*")
    );
    assert_eq!(request.header("accept-language"), Some("en-US,en;q=0.9"));
    assert_eq!(request.header("origin"), Some("https://qoder.com"));
    assert_eq!(
        request.header("referer"),
        Some("https://qoder.com/account/usage")
    );
    assert_eq!(request.header("x-requested-with"), Some("XMLHttpRequest"));
    assert_eq!(request.header("bx-v"), Some("2.5.35"));
    assert_eq!(
        request.header("user-agent"),
        Some(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
        )
    );
    assert!(request.body().is_empty());
}

#[tokio::test]
async fn manual_cookie_order_duplicates_and_set_cookie_flags_match_pinned_capture() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(200, CAMEL.to_vec())]).await;
    let china = FakeHttpServer::start([]).await;
    let expected = "z=1; a=2; sid=old; sid=new; Domain=qoder.com; Path=/; Secure; HttpOnly";
    let provider = QoderProvider::from_manual_capture_at(
        scope("account-a"),
        &format!("curl https://qoder.com -H 'Cookie: {expected}' -H 'Cookie: sid=ignored'"),
        &routes(&global, &china),
    )
    .expect("opaque pinned cookie normalization");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("opaque cookie fetch");
    assert_eq!(global.requests()[0].header("cookie"), Some(expected));
}

#[tokio::test]
async fn environment_prefixed_and_quoted_curl_forms_extract_only_cookie_data() {
    for raw in [
        format!(
            "HTTPS_PROXY=http://127.0.0.1:8080 curl https://qoder.com -H 'Cookie: sid={COOKIE_CANARY}'"
        ),
        format!("'/usr/bin/curl' https://qoder.com -fsSLH 'Cookie: sid={COOKIE_CANARY}'"),
    ] {
        let global = FakeHttpServer::start([FakeHttpResponse::new(200, CAMEL.to_vec())]).await;
        let china = FakeHttpServer::start([]).await;
        let provider = QoderProvider::from_manual_capture_at(
            scope("account-a"),
            &raw,
            &routes(&global, &china),
        )
        .expect("supported copied cURL form");
        provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(),
            )
            .await
            .expect("cURL fetch");
        assert_eq!(
            global.requests()[0].header("cookie"),
            Some("sid=qoder-session-cookie-canary")
        );
    }
}

#[tokio::test]
async fn raw_http_manual_capture_targets_china_without_global_retry() {
    let global = FakeHttpServer::start([]).await;
    let china = FakeHttpServer::start([FakeHttpResponse::new(200, CAMEL.to_vec())]).await;
    let provider = QoderProvider::from_manual_capture_at(
        scope("account-a"),
        &format!(
            "GET /account/usage HTTP/1.1\r\nHost: qoder.com.cn\r\nCookie: sid={CHINA_CANARY}\r\n"
        ),
        &routes(&global, &china),
    )
    .expect("HTTP capture");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("China fetch");
    assert!(global.requests().is_empty());
    let requests = china.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header("cookie"),
        Some("sid=qoder-china-cookie-canary")
    );
    assert_eq!(requests[0].header("origin"), Some("https://qoder.com.cn"));
}

#[tokio::test]
async fn browser_candidates_are_site_isolated_and_retry_in_pinned_order() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(401, Vec::new())]).await;
    let china = FakeHttpServer::start([FakeHttpResponse::new(200, SHARED.to_vec())]).await;
    let jar = cookie_jar(vec![
        cookie_record("sid", COOKIE_CANARY, "qoder.com"),
        cookie_record("sid", CHINA_CANARY, "qoder.com.cn"),
        cookie_record("leak", "www-only", "www.qoder.com"),
    ]);
    let provider = QoderProvider::from_browser_jar_at(
        scope("account-a"),
        &jar,
        now(),
        &routes(&global, &china),
    )
    .expect("browser Qoder provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(),
        )
        .await
        .expect("browser fallback");
    assert_percent(
        sample
            .primary()
            .expect("primary")
            .used_percent()
            .expect("known")
            .get(),
        68.0,
    );
    assert_eq!(
        global.requests()[0].header("cookie"),
        Some("sid=qoder-session-cookie-canary; leak=www-only")
    );
    assert_eq!(
        china.requests()[0].header("cookie"),
        Some("sid=qoder-china-cookie-canary")
    );
}

#[tokio::test]
async fn browser_accepts_www_only_host_sessions_without_crossing_qoder_sites() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(200, CAMEL.to_vec())]).await;
    let china = FakeHttpServer::start([]).await;
    let jar = cookie_jar(vec![cookie_record("sid", COOKIE_CANARY, "www.qoder.com")]);
    let provider = QoderProvider::from_browser_jar_at(
        scope("account-a"),
        &jar,
        now(),
        &routes(&global, &china),
    )
    .expect("www-only browser Qoder provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(),
        )
        .await
        .expect("www-only session fetch");
    assert_eq!(
        global.requests()[0].header("cookie"),
        Some("sid=qoder-session-cookie-canary")
    );
    assert!(china.requests().is_empty());
}

#[tokio::test]
async fn browser_exhaustion_prefers_latest_non_auth_failure_over_auth() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(401, Vec::new())]).await;
    let china = FakeHttpServer::start([FakeHttpResponse::new(503, Vec::new())]).await;
    let jar = cookie_jar(vec![
        cookie_record("sid", COOKIE_CANARY, "qoder.com"),
        cookie_record("sid", CHINA_CANARY, "qoder.com.cn"),
    ]);
    let provider = QoderProvider::from_browser_jar_at(
        scope("account-a"),
        &jar,
        now(),
        &routes(&global, &china),
    )
    .expect("browser provider");
    assert_eq!(
        provider
            .fetch_at(
                &context("account-a", ProviderSource::BrowserSession),
                timestamp(),
            )
            .await
            .expect_err("candidates exhausted")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn statuses_redirects_truncation_and_response_bounds_are_stable() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let cases = [
        (
            FakeHttpResponse::new(401, oversized.clone()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, oversized.clone()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(302, oversized.clone()).header("Location", "/login"),
            ErrorKind::Api,
        ),
        (
            FakeHttpResponse::new(429, oversized.clone()),
            ErrorKind::Api,
        ),
        (
            FakeHttpResponse::new(500, oversized.clone()),
            ErrorKind::Api,
        ),
        (FakeHttpResponse::new(200, oversized), ErrorKind::Parse),
        (
            FakeHttpResponse::truncated(200, CAMEL.len() + 20, CAMEL.to_vec()),
            ErrorKind::Network,
        ),
    ];
    for (response, expected) in cases {
        let global = FakeHttpServer::start([response]).await;
        let china = FakeHttpServer::start([]).await;
        let provider = QoderProvider::from_manual_capture_at(
            scope("account-a"),
            &format!("sid={COOKIE_CANARY}"),
            &routes(&global, &china),
        )
        .expect("manual provider");
        assert_eq!(
            provider
                .fetch_at(
                    &context("account-a", ProviderSource::ManualCookie),
                    timestamp(),
                )
                .await
                .expect_err("response must fail")
                .kind(),
            expected
        );
    }
}

#[tokio::test]
async fn scope_source_cancellation_missing_credentials_and_diagnostics_are_isolated() {
    let global = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let china = FakeHttpServer::start([]).await;
    let provider = QoderProvider::from_manual_capture_at(
        scope("account-a"),
        &format!("sid={COOKIE_CANARY}"),
        &routes(&global, &china),
    )
    .expect("manual provider");
    for wrong in [
        context("account-b", ProviderSource::ManualCookie),
        context("account-a", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&wrong, timestamp())
                .await
                .expect_err("context isolation")
                .kind(),
            ErrorKind::Api
        );
    }

    let token = CancellationToken::new();
    let cancelled = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        token.clone(),
    );
    let future = provider.fetch_at(&cancelled, timestamp());
    tokio::pin!(future);
    tokio::select! {
        result = &mut future => panic!("stalled request completed early: {result:?}"),
        () = async {
            global.wait_for_request_count(1).await;
            token.cancel();
        } => {}
        () = tokio::time::sleep(Duration::from_secs(1)) => panic!("request did not start"),
    }
    let error = tokio::time::timeout(Duration::from_secs(1), future)
        .await
        .expect("prompt cancellation")
        .expect_err("cancelled request");
    assert_eq!(error.kind(), ErrorKind::Network);
    let diagnostics = format!("{provider:?} {error:?} {error}");
    for canary in [COOKIE_CANARY, "account-a", global.origin().as_str()] {
        assert!(!diagnostics.contains(canary), "diagnostic leaked {canary}");
    }

    let empty = cookie_jar(Vec::new());
    assert_eq!(
        QoderProvider::from_browser_jar_at(
            scope("account-a"),
            &empty,
            now(),
            &routes(&global, &china),
        )
        .expect_err("empty browser jar")
        .kind(),
        ErrorKind::MissingCredential
    );
}
