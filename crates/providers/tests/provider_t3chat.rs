use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId, CookieUrlPolicy,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::providers::t3chat::{T3ChatProvider, parse_json_lines};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const CUSTOMER_DATA: &[u8] =
    include_bytes!("../../../fixtures/providers/t3chat/customer_data.jsonl");
const COOKIE_CANARY: &str = "fixture-t3-cookie-canary";
const HEADER_CANARY: &str = "fixture-t3-context-canary";
const NOW_SECONDS: i64 = 1_778_000_000;

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "{actual} != {expected}"
    );
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::T3Chat,
        ProviderInstanceId::new("t3chat-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn manual_provider(server: &FakeHttpServer, raw: &str) -> T3ChatProvider {
    T3ChatProvider::from_manual_capture_at(
        scope("account-a"),
        raw,
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual T3 provider")
}

fn cookie_record(
    name: &str,
    value: &str,
    domain: &str,
    path: &str,
    expires_at: Option<OffsetDateTime>,
) -> CookieRecord {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain,
        domain_kind: CookieDomainKind::HostOnly,
        path,
        secure: false,
        expires_at,
    })
    .expect("cookie record")
}

fn cookie_jar(records: Vec<CookieRecord>) -> CookieJar {
    let source = CookieSourceId::new(7);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

#[test]
fn golden_fixture_maps_base_overage_identity_and_resets() {
    let sample = parse_json_lines(scope("account-a"), timestamp(NOW_SECONDS), CUSTOMER_DATA)
        .expect("T3 fixture");

    let primary = sample.primary().expect("base window");
    assert_percent(primary.used_percent().expect("base percentage").get(), 12.5);
    assert_eq!(
        primary.duration().expect("four-hour duration").seconds(),
        4 * 60 * 60
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("base description")
            .as_str(),
        "Base - max"
    );
    assert_eq!(
        primary.resets_at().expect("base reset").unix_timestamp(),
        1_779_366_216
    );

    let secondary = sample.secondary().expect("overage window");
    assert_percent(
        secondary.used_percent().expect("overage percentage").get(),
        34.25,
    );
    assert!(secondary.duration().is_none());
    assert_eq!(
        secondary
            .resets_at()
            .expect("subscription reset")
            .unix_timestamp(),
        1_780_763_009
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Pro Team"
    );
}

#[test]
fn period_fallback_missing_percentages_and_timestamp_semantics_match_baseline() {
    let fallback = br#"{"json":[[{"subTier":"free-tier","usageFourHourPercentage":5,"usagePeriodPercentage":65,"usageWindowNextResetAt":1779366216920,"billingNextResetAt":1999999999000}]]}"#;
    let sample = parse_json_lines(scope("a"), timestamp(NOW_SECONDS), fallback).expect("fallback");
    assert_percent(
        sample
            .secondary()
            .expect("overage")
            .used_percent()
            .expect("known")
            .get(),
        65.0,
    );
    assert!(sample.secondary().expect("overage").resets_at().is_none());
    assert_eq!(
        sample
            .primary()
            .expect("base")
            .resets_at()
            .expect("fallback reset")
            .unix_timestamp(),
        1_779_366_216
    );
    assert_eq!(
        sample.identity().login_method().expect("tier").as_str(),
        "Free Tier"
    );

    for (raw_end, expected) in [
        ("1780763009", 1_780_763_009),
        ("1780763009000", 1_780_763_009),
    ] {
        let body = format!(
            "{{\"subscription\":{{\"currentPeriodEnd\":{raw_end}}},\"usageBand\":\"base\"}}"
        );
        let sample = parse_json_lines(scope("b"), timestamp(NOW_SECONDS), body.as_bytes())
            .expect("seconds-or-milliseconds reset");
        assert_eq!(
            sample
                .secondary()
                .expect("overage")
                .resets_at()
                .expect("period end")
                .unix_timestamp(),
            expected,
        );
        assert_percent(
            sample
                .primary()
                .expect("known zero base")
                .used_percent()
                .expect("known")
                .get(),
            0.0,
        );
        assert_percent(
            sample
                .secondary()
                .expect("known zero overage")
                .used_percent()
                .expect("known")
                .get(),
            0.0,
        );
    }
}

#[tokio::test]
async fn manual_raw_cookie_sends_exact_fixed_request_and_defaults() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CUSTOMER_DATA.to_vec())]).await;
    let provider = manual_provider(&server, &format!("session={COOKIE_CANARY}"));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert_eq!(provider.descriptor().id, ProviderId::T3Chat);
    assert_percent(
        sample
            .primary()
            .expect("base")
            .used_percent()
            .expect("known")
            .get(),
        12.5,
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method(), "GET");
    let request_url =
        Url::parse(&format!("http://fixture{}", request.target())).expect("captured request URL");
    assert_eq!(request_url.path(), "/api/trpc/getCustomerData");
    assert_eq!(
        request_url.query_pairs().collect::<Vec<_>>(),
        vec![
            ("batch".into(), "1".into()),
            (
                "input".into(),
                r#"{"0":{"json":{"sessionId":null},"meta":{"values":{"sessionId":["undefined"]}}}}"#
                    .into(),
            ),
        ]
    );
    assert_eq!(
        request.header("cookie"),
        Some("session=fixture-t3-cookie-canary")
    );
    assert_eq!(request.header("accept"), Some("*/*"));
    assert_eq!(request.header("trpc-accept"), Some("application/jsonl"));
    assert_eq!(request.header("x-trpc-source"), Some("web-client"));
    assert_eq!(request.header("x-trpc-batch"), Some("true"));
    assert_eq!(request.header("sec-fetch-site"), Some("same-origin"));
    assert_eq!(request.header("origin"), Some("https://t3.chat"));
    assert_eq!(request.body(), b"");
}

#[tokio::test]
async fn full_curl_ignores_captured_query_and_forwards_only_explicit_metadata() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CUSTOMER_DATA.to_vec())]).await;
    let curl = format!(
        "curl 'https://t3.chat/api/trpc/getCustomerData?batch=evil&input=evil' \
         -H 'Accept: application/json' \
         -H 'User-Agent: Firefox/151.0' \
         -H 'X-Client-Context: {HEADER_CANARY}' \
         -H 'X-Deployment-Id: dpl_fixture' \
         -H 'X-Not-Allowed: ignored-canary' \
         -H 'Cookie: session={COOKIE_CANARY}'"
    );
    let provider = manual_provider(&server, &curl);
    assert!(!format!("{provider:?}").contains(HEADER_CANARY));
    assert!(!format!("{provider:?}").contains(COOKIE_CANARY));
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("full cURL fetch");

    let request = &server.requests()[0];
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(request.header("user-agent"), Some("Firefox/151.0"));
    assert_eq!(request.header("x-client-context"), Some(HEADER_CANARY));
    assert_eq!(request.header("x-deployment-id"), Some("dpl_fixture"));
    assert_eq!(request.header("x-not-allowed"), None);
    let url = Url::parse(&format!("http://fixture{}", request.target())).expect("request URL");
    assert_eq!(url.query_pairs().next(), Some(("batch".into(), "1".into())));
}

#[test]
fn unsupported_captured_accept_and_unsafe_hosts_fail_before_network() {
    let endpoint = Url::parse("http://127.0.0.1:32123").expect("loopback origin");
    let unsupported = "curl https://t3.chat/api/trpc/getCustomerData -H 'Accept: application/xml' -H 'Cookie: session=abc'";
    assert_eq!(
        T3ChatProvider::from_manual_capture_at(
            scope("a"),
            unsupported,
            endpoint.clone(),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("unsupported Accept")
        .kind(),
        ErrorKind::Api
    );
    for raw in [
        "curl https://evil.example/api -H 'Cookie: session=abc'",
        "curl http://t3.chat/api -H 'Cookie: session=abc'",
        "curl 'https://user:pass@t3.chat/api' -H 'Cookie: session=abc'",
    ] {
        let error = T3ChatProvider::from_manual_capture_at(
            scope("a"),
            raw,
            endpoint.clone(),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("unsafe capture URL");
        assert_eq!(error.kind(), ErrorKind::Parse);
    }

    let unbound_origin = Url::parse("https://example.com").expect("unbound public origin");
    assert_eq!(
        T3ChatProvider::from_manual_capture_at(
            scope("a"),
            "session=abc",
            unbound_origin,
            EndpointClass::PublicHttps,
        )
        .expect_err("public seam must remain bound to t3.chat")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn browser_jar_selection_honors_host_path_expiry_and_injected_time() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CUSTOMER_DATA.to_vec())]).await;
    let target = T3ChatProvider::browser_target(server.url("/"), CookieUrlPolicy::LoopbackHttp)
        .expect("browser target");
    let host = target.url().host_str().expect("target host");
    let jar = cookie_jar(vec![
        cookie_record("wrong_host", "no", "localhost", "/", None),
        cookie_record("wrong_path", "no", host, "/other", None),
        cookie_record(
            "expired",
            "no",
            host,
            "/api/trpc",
            Some(now() - time::Duration::seconds(1)),
        ),
        cookie_record(
            "session",
            COOKIE_CANARY,
            host,
            "/api/trpc",
            Some(now() + time::Duration::hours(1)),
        ),
        cookie_record("root", "root-value", host, "/", None),
    ]);
    let provider = T3ChatProvider::from_browser_jar_at(
        scope("account-a"),
        &jar,
        &target,
        now(),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("browser provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fetch");
    assert_eq!(
        server.requests()[0].header("cookie"),
        Some("session=fixture-t3-cookie-canary; root=root-value")
    );
}

#[test]
fn browser_missing_and_expired_sessions_are_distinct() {
    let origin = Url::parse("http://127.0.0.1:32123").expect("loopback origin");
    let target = T3ChatProvider::browser_target(origin, CookieUrlPolicy::LoopbackHttp)
        .expect("browser target");
    let empty = cookie_jar(Vec::new());
    assert_eq!(
        T3ChatProvider::from_browser_jar_at(
            scope("a"),
            &empty,
            &target,
            now(),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("empty jar")
        .kind(),
        ErrorKind::MissingCredential
    );

    let expired = cookie_jar(vec![cookie_record(
        "session",
        COOKIE_CANARY,
        target.url().host_str().expect("host"),
        "/api/trpc",
        Some(now() - time::Duration::seconds(1)),
    )]);
    assert_eq!(
        T3ChatProvider::from_browser_jar_at(
            scope("a"),
            &expired,
            &target,
            now(),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("expired jar")
        .kind(),
        ErrorKind::AuthenticationExpired
    );
}

#[tokio::test]
async fn authentication_rate_limit_challenge_and_parse_failures_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, b"auth-body-canary".to_vec()),
        FakeHttpResponse::new(403, b"forbidden-body-canary".to_vec()),
        FakeHttpResponse::new(429, b"rate-body-canary".to_vec()),
        FakeHttpResponse::new(429, b"challenge-body-canary".to_vec())
            .header("x-vercel-mitigated", "challenge"),
        FakeHttpResponse::new(200, b"{malformed-response-canary".to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, &format!("session={COOKIE_CANARY}"));
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::AuthenticationExpired,
        ErrorKind::RateLimited,
        ErrorKind::PermissionDenied,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?} {error}");
        assert!(!debug.contains(COOKIE_CANARY));
        assert!(!debug.contains("body-canary"));
        assert!(!debug.contains("malformed-response-canary"));
    }
}

#[tokio::test]
async fn truncation_oversize_and_redirects_fail_without_following() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let server = FakeHttpServer::start([
        FakeHttpResponse::truncated(200, 100, b"short".to_vec()),
        FakeHttpResponse::new(200, oversized),
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/redirected"),
    ])
    .await;
    let provider = manual_provider(&server, "session=abc");
    for _ in 0..3 {
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("bounded response failure");
        assert_eq!(error.kind(), ErrorKind::Parse);
    }
    assert_eq!(server.requests().len(), 3, "redirect was not followed");
}

#[tokio::test]
async fn cancellation_wins_a_stalled_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(&server, "session=abc");
    let cancellation = CancellationToken::new();
    let provider_context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation.clone(),
    );
    let fetch = provider.fetch_at(&provider_context, timestamp(NOW_SECONDS));
    tokio::pin!(fetch);
    tokio::select! {
        result = &mut fetch => panic!("stalled request completed early: {result:?}"),
        result = tokio::time::timeout(
            Duration::from_millis(200),
            server.wait_for_request_count(1),
        ) => result.expect("request reached fixture server"),
    }
    cancellation.cancel();
    let error = fetch.await.expect_err("cancelled fetch");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[tokio::test]
async fn source_scope_and_provider_isolation_precede_network() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CUSTOMER_DATA.to_vec())]).await;
    let provider = manual_provider(&server, "session=abc");
    for rejected in [
        context("account-a", ProviderSource::BrowserSession),
        context("account-b", ProviderSource::ManualCookie),
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
    assert!(server.requests().is_empty());

    let wrong_scope = AccountScope::new(
        ProviderId::OpenAi,
        ProviderInstanceId::new("wrong-provider").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    assert_eq!(
        T3ChatProvider::from_manual_capture_at(
            wrong_scope,
            "session=abc",
            server.url("/"),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("wrong provider scope")
        .kind(),
        ErrorKind::Api
    );
}

#[test]
fn jsonl_bounds_and_adversarial_shapes_fail_closed() {
    let many_lines = "{}\n".repeat(257);
    let long_line = format!("{{\"padding\":\"{}\"}}", "x".repeat(512 * 1024));
    let many_nodes = format!(
        "{{\"usageFourHourPercentage\":1,\"nodes\":[{}]}}",
        vec!["0"; 33_000].join(",")
    );
    let mut deep = "{\"usageFourHourPercentage\":1}".to_owned();
    for _ in 0..40 {
        deep = format!("[{deep}]");
    }
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let cases: Vec<&[u8]> = vec![
        many_lines.as_bytes(),
        long_line.as_bytes(),
        many_nodes.as_bytes(),
        deep.as_bytes(),
        &[0xff, 0xfe],
        oversized.as_slice(),
    ];
    for body in cases {
        assert_eq!(
            parse_json_lines(scope("a"), timestamp(NOW_SECONDS), body)
                .expect_err("bounded parse failure")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[test]
fn malformed_customer_fields_and_secret_diagnostics_are_redacted() {
    for body in [
        br#"{"usageFourHourPercentage":"not-a-number"}"#.as_slice(),
        br#"{"usageFourHourPercentage":1,"subscription":{"currentPeriodEnd":"bad"}}"#.as_slice(),
        br#"{"unrelated":"missing-customer-data"}"#.as_slice(),
    ] {
        let error = parse_json_lines(scope("a"), timestamp(NOW_SECONDS), body)
            .expect_err("malformed customer data");
        assert_eq!(error.kind(), ErrorKind::Parse);
        assert!(!format!("{error:?}").contains("not-a-number"));
    }

    let endpoint = Url::parse("http://127.0.0.1:32123").expect("loopback origin");
    let raw = "curl https://evil.example -H 'Cookie: session=diagnostic-secret-canary'";
    let error = T3ChatProvider::from_manual_capture_at(
        scope("a"),
        raw,
        endpoint,
        EndpointClass::LoopbackDevelopment,
    )
    .expect_err("unsafe capture");
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("diagnostic-secret-canary"));
    assert!(!diagnostic.contains("evil.example"));
}
