use std::collections::BTreeMap;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::longcat::{LongCatProvider, LongCatRouteSet, parse_usage_responses};
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};
use tokio_util::sync::CancellationToken;

const ACCOUNT: &[u8] = include_bytes!("../../../fixtures/providers/longcat/account.json");
const SUMMARY: &[u8] =
    include_bytes!("../../../fixtures/providers/longcat/token_pack_summary.json");
const TOKEN_USAGE: &[u8] = include_bytes!("../../../fixtures/providers/longcat/token_usage.json");
const FUEL: &[u8] = include_bytes!("../../../fixtures/providers/longcat/pending_fuel.json");
const COOKIE_CANARY: &str = "longcat-cookie-canary";
const NOW_SECONDS: i64 = 1_782_000_000;
const USER_CURRENT_PATH: &str = "/api/v1/user-current";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn scope(account: &str) -> AccountScope {
    provider_scope(ProviderId::LongCat, account)
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

fn manual_provider(server: &FakeHttpServer, capture: &str) -> LongCatProvider {
    LongCatProvider::from_manual_capture_routes(
        scope("account-a"),
        capture,
        LongCatRouteSet::loopback(server.url("/")).expect("loopback routes"),
    )
    .expect("manual LongCat provider")
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
    let source = CookieSourceId::new(71);
    let order = CookieImportOrder::new([source]).expect("cookie order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn local_midnight_unix(year: i32, month: Month, day: u8) -> i64 {
    let wall = Date::from_calendar_date(year, month, day)
        .expect("fixture date")
        .with_time(Time::MIDNIGHT);
    let mut offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    for _ in 0..4 {
        let candidate = wall.assume_offset(offset);
        let observed = UtcOffset::local_offset_at(candidate).unwrap_or(offset);
        if observed == offset {
            return candidate.unix_timestamp();
        }
        offset = observed;
    }
    panic!("fixture local offset must converge");
}

#[test]
fn golden_active_token_pack_and_fuel_map_to_primary_and_secondary() {
    let sample = parse_usage_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        ProviderSource::ManualCookie,
        ACCOUNT,
        Some(SUMMARY),
        Some(TOKEN_USAGE),
        Some(FUEL),
    )
    .expect("captured responses parse");

    let primary = sample.primary().expect("token-pack quota");
    assert_percent(
        primary.used_percent().expect("primary percent").get(),
        2.425_152,
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("primary counts")
            .as_str(),
        "1212576/50000000"
    );
    assert!(primary.resets_at().is_none());

    let fuel = sample.secondary().expect("fuel quota");
    assert_percent(fuel.used_percent().expect("fuel percent").get(), 25.0);
    assert_eq!(
        fuel.reset_description().expect("fuel counts").as_str(),
        "Fuel pack: 750/1000"
    );
    assert_eq!(
        fuel.resets_at().expect("nearest expiry").unix_timestamp(),
        1_750_000_000
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("account name")
            .as_str(),
        "LongCat User"
    );
    assert_eq!(sample.provenance()[0].source(), "longcat");
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");
}

#[test]
fn inactive_zero_or_missing_lot_uses_canonical_legacy_aggregate() {
    for summary in [
        br#"{"code":0,"data":{}}"#.as_slice(),
        br#"{"code":0,"data":{"currentLot":null}}"#.as_slice(),
        br#"{"code":0,"data":{"currentLot":{"status":"ACTIVE","totalToken":0}}}"#.as_slice(),
        br#"{"code":0,"data":{"currentLot":{"status":"EXPIRED","totalToken":50000000}}}"#
            .as_slice(),
    ] {
        let sample = parse_usage_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            ProviderSource::BrowserSession,
            br#"{"code":200,"data":{"nickName":"Fallback User"}}"#,
            Some(summary),
            Some(TOKEN_USAGE),
            None,
        )
        .expect("legacy fallback");
        assert_percent(
            sample
                .primary()
                .expect("legacy quota")
                .used_percent()
                .expect("legacy percent")
                .get(),
            24.0,
        );
        assert_eq!(sample.provenance()[0].strategy(), "browser_session");
    }
}

#[test]
fn remaining_infers_used_and_fuel_without_balances_defaults_to_total() {
    let usage = br#"{"code":"0","data":{"usage":{"totalToken":"1000","availableToken":"400"}}}"#;
    let fuel = br#"{"code":0,"data":{"totalQuota":"500","list":[{"expireTime":"2026-04-15 00:00:00"},{"not":"a balance"}]}}"#;
    let sample = parse_usage_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        ProviderSource::ManualCookie,
        br#"{"code":0,"data":{"name":17}}"#,
        None,
        Some(usage),
        Some(fuel),
    )
    .expect("flexible scalar response");
    assert_percent(
        sample
            .primary()
            .expect("primary")
            .used_percent()
            .expect("percent")
            .get(),
        60.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("fuel")
            .used_percent()
            .expect("percent")
            .get(),
        0.0,
    );
    assert_eq!(
        sample
            .secondary()
            .expect("fuel")
            .resets_at()
            .expect("local expiry")
            .unix_timestamp(),
        local_midnight_unix(2026, Month::April, 15)
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("numeric name")
            .as_str(),
        "17"
    );

    let fuel_only = parse_usage_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        ProviderSource::ManualCookie,
        ACCOUNT,
        None,
        Some(br#"{"code":0,"data":{"usage":{"totalToken":0}}}"#),
        Some(FUEL),
    )
    .expect("zero main quota with fuel");
    assert!(fuel_only.primary().is_none());
    assert!(fuel_only.secondary().is_some());
}

#[test]
fn envelopes_required_shapes_and_json_bounds_fail_closed() {
    for (account, expected) in [
        (
            br#"{"code":401,"message":"private"}"#.as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            br#"{"code":"403","msg":"private"}"#.as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            br#"{"code":500,"message":"private"}"#.as_slice(),
            ErrorKind::Api,
        ),
        (br#"{"code":true,"data":{}}"#.as_slice(), ErrorKind::Api),
        (br"[]".as_slice(), ErrorKind::Parse),
        (br#"{"code":0,"data":[]}"#.as_slice(), ErrorKind::Parse),
    ] {
        let error = parse_usage_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            ProviderSource::ManualCookie,
            account,
            None,
            Some(TOKEN_USAGE),
            None,
        )
        .expect_err("invalid account envelope");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains("private"));
    }

    let missing_total = br#"{"code":0,"data":{"usage":{"usedToken":1}}}"#;
    assert_eq!(
        parse_usage_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            ProviderSource::ManualCookie,
            ACCOUNT,
            None,
            Some(missing_total),
            None,
        )
        .expect_err("missing canonical total")
        .kind(),
        ErrorKind::Parse
    );

    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    assert_eq!(
        parse_usage_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            ProviderSource::ManualCookie,
            &oversized,
            None,
            Some(TOKEN_USAGE),
            None,
        )
        .expect_err("oversized JSON")
        .kind(),
        ErrorKind::Parse
    );

    let mut deep = String::from(r#"{"code":0,"data":{"name":"x","nested":"#);
    deep.push_str(&"[".repeat(42));
    deep.push('0');
    deep.push_str(&"]".repeat(42));
    deep.push_str("}}");
    assert_eq!(
        parse_usage_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            ProviderSource::ManualCookie,
            deep.as_bytes(),
            None,
            Some(TOKEN_USAGE),
            None,
        )
        .expect_err("deep JSON")
        .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn active_fetch_sends_exact_fixed_sequence_headers_and_body() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, ACCOUNT.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, FUEL.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, &format!("session={COOKIE_CANARY}; uid=42"));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("active fetch");
    assert_eq!(provider.descriptor().id, ProviderId::LongCat);
    assert_percent(
        sample
            .primary()
            .expect("primary")
            .used_percent()
            .expect("percent")
            .get(),
        2.425_152,
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests
            .iter()
            .map(CapturedHttpRequest::target)
            .collect::<Vec<_>>(),
        [
            "/api/v1/user-current",
            "/api/pay/quota/metering/token-packs/summary",
            "/api/lc-platform/v1/pending-fuel-packages",
        ]
    );
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[1].method(), "POST");
    assert_eq!(requests[1].body(), b"{}");
    assert_eq!(requests[1].header("content-type"), Some("application/json"));
    for request in requests {
        assert_eq!(
            request.header("cookie"),
            Some("session=longcat-cookie-canary; uid=42")
        );
        assert_eq!(
            request.header("accept"),
            Some("application/json, text/plain, */*")
        );
        assert_eq!(request.header("origin"), Some("https://longcat.chat"));
        assert_eq!(
            request.header("referer"),
            Some("https://longcat.chat/platform/usage")
        );
        assert_eq!(request.header("accept-language"), Some("en-US,en;q=0.9"));
        assert_eq!(
            request.header("user-agent"),
            Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            )
        );
    }
}

#[tokio::test]
async fn summary_failures_fall_back_and_fuel_failures_never_erase_primary() {
    for (summary_response, fuel_response) in [
        (
            FakeHttpResponse::new(500, b"private summary".to_vec()),
            FakeHttpResponse::new(500, b"private fuel".to_vec()),
        ),
        (
            FakeHttpResponse::new(401, Vec::new()),
            FakeHttpResponse::new(401, Vec::new()),
        ),
        (
            FakeHttpResponse::new(200, b"not json".to_vec()),
            FakeHttpResponse::new(200, b"not json".to_vec()),
        ),
        (
            FakeHttpResponse::new(200, br#"{"code":403,"message":"private"}"#.to_vec()),
            FakeHttpResponse::new(200, br#"{"code":403,"message":"private"}"#.to_vec()),
        ),
        (
            FakeHttpResponse::new(307, Vec::new())
                .header("Location", "/api/pay/quota/metering/token-packs/summary"),
            FakeHttpResponse::new(204, Vec::new()),
        ),
    ] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, ACCOUNT.to_vec()),
            summary_response,
            FakeHttpResponse::new(200, TOKEN_USAGE.to_vec()),
            fuel_response,
        ])
        .await;
        let sample = manual_provider(&server, "session=valid")
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("legacy survives optional failures");
        assert_percent(
            sample
                .primary()
                .expect("legacy primary")
                .used_percent()
                .expect("percent")
                .get(),
            24.0,
        );
        assert!(sample.secondary().is_none());
        assert_eq!(
            server
                .requests()
                .iter()
                .map(CapturedHttpRequest::target)
                .collect::<Vec<_>>(),
            [
                "/api/v1/user-current",
                "/api/pay/quota/metering/token-packs/summary",
                "/api/lc-platform/v1/tokenUsage",
                "/api/lc-platform/v1/pending-fuel-packages",
            ]
        );
    }
}

#[tokio::test]
async fn same_origin_redirect_is_followed_but_redirect_loops_are_bounded() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", USER_CURRENT_PATH),
        FakeHttpResponse::new(200, ACCOUNT.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, FUEL.to_vec()),
    ])
    .await;
    manual_provider(&server, &format!("session={COOKIE_CANARY}"))
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("same-origin redirect");
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].target(), USER_CURRENT_PATH);
    assert_eq!(requests[1].target(), USER_CURRENT_PATH);
    assert_eq!(requests[1].header("cookie"), requests[0].header("cookie"));

    let redirects = (0..11)
        .map(|_| FakeHttpResponse::new(302, Vec::new()).header("Location", USER_CURRENT_PATH));
    let server = FakeHttpServer::start(redirects).await;
    assert_eq!(
        manual_provider(&server, "session=value")
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("redirect loop")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(server.requests().len(), 11);
}

#[tokio::test]
async fn required_statuses_redirects_and_framing_are_classified_without_bodies() {
    for (response, expected) in [
        (
            FakeHttpResponse::new(401, b"private".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, b"private".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(302, Vec::new()).header("Location", "https://evil.example/login"),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(429, b"private".to_vec()),
            ErrorKind::Api,
        ),
        (
            FakeHttpResponse::new(500, b"private".to_vec()),
            ErrorKind::Api,
        ),
        (FakeHttpResponse::new(201, ACCOUNT.to_vec()), ErrorKind::Api),
    ] {
        let server = FakeHttpServer::start([response]).await;
        let error = manual_provider(&server, "session=value")
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("required status");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains("private"));
        assert_eq!(server.requests().len(), 1);
    }

    let truncated = FakeHttpServer::start([FakeHttpResponse::truncated(
        200,
        ACCOUNT.len() + 10,
        ACCOUNT.to_vec(),
    )])
    .await;
    assert_eq!(
        manual_provider(&truncated, "session=value")
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("truncated body")
            .kind(),
        ErrorKind::Parse
    );

    let oversized =
        FakeHttpServer::start([FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1])]).await;
    assert_eq!(
        manual_provider(&oversized, "session=value")
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("oversized body")
            .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn browser_cookie_matching_preserves_path_scope_order_and_expiry() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, ACCOUNT.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, FUEL.to_vec()),
    ])
    .await;
    let host = server
        .url("/")
        .host_str()
        .expect("loopback host")
        .to_owned();
    let jar = cookie_jar(vec![
        cookie_record("root", "1", &host, "/", None),
        cookie_record("account", "2", &host, "/api/v1", None),
        cookie_record(
            "summary",
            "3",
            &host,
            "/api/pay/quota/metering/token-packs",
            None,
        ),
        cookie_record(
            "expired",
            "4",
            &host,
            "/",
            Some(now() - time::Duration::SECOND),
        ),
        cookie_record("future", "5", &host, "/", Some(now() + time::Duration::DAY)),
    ]);
    let routes = LongCatRouteSet::loopback(server.url("/")).expect("routes");
    let provider =
        LongCatProvider::from_browser_jars_routes(scope("account-a"), &[&jar], now(), routes)
            .expect("browser provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fetch");
    let requests = server.requests();
    assert_eq!(
        requests[0].header("cookie"),
        Some("account=2; future=5; root=1")
    );
    assert_eq!(
        requests[1].header("cookie"),
        Some("summary=3; future=5; root=1")
    );
    assert_eq!(requests[2].header("cookie"), Some("future=5; root=1"));
}

#[tokio::test]
async fn browser_profiles_rotate_only_after_required_credential_failure() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, ACCOUNT.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, FUEL.to_vec()),
    ])
    .await;
    let host = server
        .url("/")
        .host_str()
        .expect("loopback host")
        .to_owned();
    let first = cookie_jar(vec![cookie_record("session", "expired", &host, "/", None)]);
    let second = cookie_jar(vec![cookie_record("session", "valid", &host, "/", None)]);
    let provider = LongCatProvider::from_browser_jars_routes(
        scope("account-a"),
        &[&first, &second],
        now(),
        LongCatRouteSet::loopback(server.url("/")).expect("routes"),
    )
    .expect("browser sessions");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("second profile succeeds");
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].header("cookie"), Some("session=expired"));
    assert_eq!(requests[1].header("cookie"), Some("session=valid"));

    let server = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let host = server
        .url("/")
        .host_str()
        .expect("loopback host")
        .to_owned();
    let first = cookie_jar(vec![cookie_record("session", "one", &host, "/", None)]);
    let second = cookie_jar(vec![cookie_record("session", "two", &host, "/", None)]);
    let provider = LongCatProvider::from_browser_jars_routes(
        scope("account-a"),
        &[&first, &second],
        now(),
        LongCatRouteSet::loopback(server.url("/")).expect("routes"),
    )
    .expect("browser sessions");
    assert_eq!(
        provider
            .fetch_at(
                &context("account-a", ProviderSource::BrowserSession),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("server error stops rotation")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn legacy_auth_failure_rotates_the_whole_browser_profile() {
    let no_lot = br#"{"code":0,"data":{"currentLot":null}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, ACCOUNT.to_vec()),
        FakeHttpResponse::new(200, no_lot.to_vec()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(200, ACCOUNT.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, FUEL.to_vec()),
    ])
    .await;
    let host = server
        .url("/")
        .host_str()
        .expect("loopback host")
        .to_owned();
    let first = cookie_jar(vec![cookie_record("session", "expired", &host, "/", None)]);
    let second = cookie_jar(vec![cookie_record("session", "valid", &host, "/", None)]);
    let provider = LongCatProvider::from_browser_jars_routes(
        scope("account-a"),
        &[&first, &second],
        now(),
        LongCatRouteSet::loopback(server.url("/")).expect("routes"),
    )
    .expect("browser sessions");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("second profile after legacy auth failure");
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[0].header("cookie"), Some("session=expired"));
    assert_eq!(requests[2].header("cookie"), Some("session=expired"));
    assert_eq!(requests[3].header("cookie"), Some("session=valid"));
}

#[test]
fn empty_and_irrelevant_browser_jars_have_distinct_credential_errors() {
    let routes = || {
        LongCatRouteSet::loopback(url::Url::parse("http://127.0.0.1:7777/").expect("loopback URL"))
            .expect("routes")
    };
    let empty = cookie_jar(Vec::new());
    assert_eq!(
        LongCatProvider::from_browser_jars_routes(scope("account-a"), &[&empty], now(), routes(),)
            .expect_err("empty jar")
            .kind(),
        ErrorKind::MissingCredential
    );

    let irrelevant = cookie_jar(vec![cookie_record(
        "session",
        "value",
        "other.example",
        "/",
        None,
    )]);
    assert_eq!(
        LongCatProvider::from_browser_jars_routes(
            scope("account-a"),
            &[&irrelevant],
            now(),
            routes(),
        )
        .expect_err("no matching cookie")
        .kind(),
        ErrorKind::AuthenticationExpired
    );
}

#[tokio::test]
async fn cancellation_wins_a_stalled_required_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(&server, "session=value");
    let cancellation = CancellationToken::new();
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation.clone(),
    );
    let task =
        tokio::spawn(async move { provider.fetch_at(&context, timestamp(NOW_SECONDS)).await });
    server.wait_for_request_count(1).await;
    cancellation.cancel();
    assert_eq!(
        task.await
            .expect("fetch task")
            .expect_err("cancelled request")
            .kind(),
        ErrorKind::Network
    );

    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(&server, "session=value");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation,
    );
    assert_eq!(
        provider
            .fetch_at(&context, timestamp(NOW_SECONDS))
            .await
            .expect_err("pre-cancelled request")
            .kind(),
        ErrorKind::Network
    );
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn curl_is_host_bound_query_ignored_and_diagnostics_redacted() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, ACCOUNT.to_vec()),
        FakeHttpResponse::new(200, SUMMARY.to_vec()),
        FakeHttpResponse::new(200, FUEL.to_vec()),
    ])
    .await;
    let capture = format!(
        "curl 'https://longcat.chat/evil?secret=query' -H 'Cookie: session={COOKIE_CANARY}'"
    );
    let provider = manual_provider(&server, &capture);
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("copied cURL fetch");
    assert_eq!(server.requests()[0].target(), "/api/v1/user-current");

    let wrong = LongCatProvider::from_manual_capture_routes(
        scope("account-a"),
        "curl 'https://evil.example/api' -H 'Cookie: secret=must-not-leak'",
        LongCatRouteSet::loopback(server.url("/")).expect("routes"),
    )
    .expect_err("wrong host rejected");
    assert_eq!(wrong.kind(), ErrorKind::Parse);
    assert!(!format!("{provider:?} {wrong:?} {wrong}").contains(COOKIE_CANARY));
    assert!(!format!("{wrong:?} {wrong}").contains("must-not-leak"));
}

#[test]
fn environment_precedence_quotes_missing_and_wrong_scope_are_deterministic() {
    let server_url = url::Url::parse("http://127.0.0.1:7777/").expect("loopback URL");
    let routes = || LongCatRouteSet::loopback(server_url.clone()).expect("routes");
    let environment = BTreeMap::from([
        (
            "LONGCAT_MANUAL_COOKIE".to_owned(),
            "  'session=upper'  ".to_owned(),
        ),
        (
            "longcat_manual_cookie".to_owned(),
            "session=lower".to_owned(),
        ),
        ("LONGCAT_API_KEY".to_owned(), "ignored".to_owned()),
    ]);
    let provider =
        LongCatProvider::from_environment_routes(scope("account-a"), &environment, routes())
            .expect("environment parse")
            .expect("manual cookie");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);

    assert!(
        LongCatProvider::from_environment_routes(
            scope("account-a"),
            &BTreeMap::from([("LONGCAT_API_KEY".to_owned(), "ignored".to_owned())]),
            routes(),
        )
        .expect("API key is not a usage credential")
        .is_none()
    );
    assert_eq!(
        LongCatProvider::from_environment_routes(
            provider_scope(ProviderId::T3Chat, "account-a"),
            &environment,
            routes(),
        )
        .expect_err("wrong provider")
        .kind(),
        ErrorKind::Api
    );

    for capture in ["", "Cookie:", "session=ok\r\nx-evil: injected"] {
        let error =
            LongCatProvider::from_manual_capture_routes(scope("account-a"), capture, routes())
                .expect_err("invalid capture");
        assert!(matches!(
            error.kind(),
            ErrorKind::MissingCredential | ErrorKind::Parse
        ));
    }
}

#[tokio::test]
async fn account_scope_and_source_mismatch_fail_before_network() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, ACCOUNT.to_vec())]).await;
    let provider = manual_provider(&server, &format!("session={COOKIE_CANARY}"));
    for invalid in [
        context("account-b", ProviderSource::ManualCookie),
        context("account-a", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&invalid, timestamp(NOW_SECONDS))
                .await
                .expect_err("scope/source mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(server.requests().is_empty());
    let diagnostics = format!("{provider:?}");
    assert!(!diagnostics.contains("account-a"));
    assert!(!diagnostics.contains(COOKIE_CANARY));
    assert!(diagnostics.len() < 512);
}
