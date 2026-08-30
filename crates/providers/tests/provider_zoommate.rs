use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ExactDecimal, ProviderId, ProviderInstanceId, Timestamp,
};
use oab_providers::context::ProviderContext;
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::zoommate::{
    ZoomMateProvider, ZoomMateRouteSet, parse_zoommate_responses,
    parse_zoommate_responses_with_calendar_offset,
};
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use time::{OffsetDateTime, UtcOffset};
use tokio_util::sync::CancellationToken;

const STATUS: &[u8] = include_bytes!("../../../fixtures/providers/zoommate/status.json");
const HISTORY: &[u8] = include_bytes!("../../../fixtures/providers/zoommate/history.json");
const LOGIN: &[u8] = include_bytes!("../../../fixtures/providers/zoommate/login.json");
const NOW_SECONDS: i64 = 1_782_800_000;
const BEARER_CANARY: &str = "zoommate-bearer-canary";
const COOKIE_CANARY: &str = "zoommate-cookie-canary";

fn scope_for(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new("zoommate-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn scope(account: &str) -> AccountScope {
    scope_for(ProviderId::ZoomMate, account)
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn routes(primary: &FakeHttpServer, alternate: &FakeHttpServer) -> ZoomMateRouteSet {
    ZoomMateRouteSet::loopback(
        primary.url("/ignored?discarded=1"),
        alternate.url("/also-ignored#fragment"),
    )
    .expect("loopback routes")
}

fn capture(host: &str, token: &str, cookie: Option<&str>) -> String {
    let cookie = cookie.map_or_else(String::new, |cookie| format!(" -H 'Cookie: {cookie}'"));
    format!(
        "curl 'https://{host}/ai-computer/api/v1/credits/status' \
         -H 'Authorization: Bearer {token}'{cookie} \
         -H 'Origin: https://attacker.example' \
         -H 'Referer: https://attacker.example/path'"
    )
}

fn manual_provider(
    primary: &FakeHttpServer,
    alternate: &FakeHttpServer,
    capture: &str,
) -> ZoomMateProvider {
    ZoomMateProvider::from_manual_capture_routes(
        scope("account-a"),
        capture,
        routes(primary, alternate),
    )
    .expect("manual ZoomMate provider")
}

fn cookie_record(
    name: &str,
    value: &str,
    path: &str,
    expires_at: Option<OffsetDateTime>,
) -> CookieRecord {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain: "127.0.0.1",
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
    assert!((actual - expected).abs() < 1e-8, "{actual} != {expected}");
}

fn assert_common_headers(request: &CapturedHttpRequest) {
    assert_eq!(
        request.header("accept"),
        Some("application/json, text/plain, */*")
    );
    assert_eq!(request.header("accept-language"), Some("en-US,en;q=0.9"));
    assert_eq!(request.header("origin"), Some("https://zoommate.zoom.us"));
    assert_eq!(request.header("referer"), Some("https://zoommate.zoom.us"));
    assert_eq!(request.header("sec-fetch-dest"), Some("empty"));
    assert_eq!(request.header("sec-fetch-mode"), Some("cors"));
    assert_eq!(request.header("sec-fetch-site"), Some("same-site"));
}

fn history_page(first: usize, count: usize, total: usize, time: &str) -> Vec<u8> {
    let records = (first..first + count)
        .map(|index| {
            format!(
                r#"{{"session_id":"synthetic-{index}","title":"Synthetic {index}","cost":1,"time":"{time}","is_running":false,"is_deleted":false}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"data":{{"records":[{records}],"total":{total}}}}}"#).into_bytes()
}

fn login_with_exp(exp: i64) -> Vec<u8> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
    format!(r#"{{"success":true,"data":{{"nak":"{header}.{payload}.signature"}}}}"#).into_bytes()
}

#[test]
fn golden_status_and_history_normalize_credit_window_dashboard_and_typed_history() {
    let sample = parse_zoommate_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        STATUS,
        Some(HISTORY),
        ProviderSource::ManualCookie,
    )
    .expect("ZoomMate fixture");

    let primary = sample.primary().expect("credit window");
    assert_percent(
        primary.used_percent().expect("known usage").get(),
        942.0 / 35_000.0 * 100.0,
    );
    assert_eq!(
        primary.resets_at().expect("cycle end").unix_timestamp(),
        1_782_886_400
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("credit description")
            .as_str(),
        "Credits"
    );
    assert!(sample.secondary().is_none());
    let details = sample.detail_sections();
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].title(), Some("Credit history"));
    assert_eq!(details[0].rows()[0].label(), "Today");
    assert_eq!(details[0].rows()[0].value(), "8");
    assert_eq!(details[0].rows()[1].label(), "30d credits");
    assert_eq!(details[0].rows()[1].value(), "10");
    assert_eq!(details[0].rows()[2].label(), "Pace");
    assert!(details[0].rows()[2].value().contains("behind budget"));
    let chart = details[0].chart().expect("daily chart");
    assert_eq!(chart.unit(), Some("credits"));
    assert_eq!(chart.points().len(), 2);
    assert!(chart.points()[0].label() < chart.points()[1].label());
    assert_percent(chart.points()[0].value().get(), 2.0);
    assert_percent(chart.points()[1].value().get(), 8.0);

    let history = sample.cost_usage().expect("typed credit history");
    assert_eq!(history.unit().as_str(), "credits");
    assert_eq!(history.history_days(), 30);
    assert!(history.history_coverage_is_established());
    assert_eq!(
        history.history().amount(),
        Some(ExactDecimal::parse("10").expect("decimal"))
    );
    assert_eq!(
        history.session().amount(),
        Some(ExactDecimal::parse("8").expect("decimal"))
    );
    assert_eq!(history.daily().len(), 2);
    assert_eq!(sample.provenance()[0].source(), "zoommate");
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");
}

#[test]
fn fixed_non_utc_calendar_offset_controls_today_and_day_buckets() {
    let fetched_at = Timestamp::parse("2026-07-01T01:00:00Z").expect("fixture timestamp");
    let history = br#"{
      "data":{"records":[
        {"cost":3,"time":"2026-07-01T00:30:00Z","is_deleted":false},
        {"cost":2,"time":"2026-06-30T07:30:00Z","is_deleted":false}
      ],"total":2}
    }"#;
    let sample = parse_zoommate_responses_with_calendar_offset(
        scope("account-a"),
        fetched_at,
        STATUS,
        Some(history),
        ProviderSource::ManualCookie,
        UtcOffset::from_hms(-8, 0, 0).expect("Pacific fixture offset"),
    )
    .expect("fixed non-UTC normalization");
    let details = &sample.detail_sections()[0];
    assert_eq!(details.rows()[0].value(), "3");
    assert_eq!(details.rows()[1].value(), "5");
    let points = details.chart().expect("daily chart").points();
    assert_eq!(points[0].label(), "2026-06-29");
    assert_eq!(points[1].label(), "2026-06-30");
    assert_percent(points[0].value().get(), 2.0);
    assert_percent(points[1].value().get(), 3.0);
}

#[test]
fn unlimited_and_zero_budget_semantics_match_baseline() {
    for body in [
        br#"{"data":{"credit_status":{"budget_cap":35000,"used_credit":942,"cycle_end_date":1782886400000,"is_unlimited":true}}}"#.as_slice(),
        br#"{"data":{"credit_status":{"budget_cap":0,"used_credit":0,"cycle_end_date":1782886400000,"is_unlimited":false}}}"#.as_slice(),
    ] {
        let sample = parse_zoommate_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            body,
            None,
            ProviderSource::BrowserSession,
        )
        .expect("unmetered credit status");
        let primary = sample.primary().expect("credit window");
        assert_percent(primary.used_percent().expect("known").get(), 0.0);
        assert!(primary.resets_at().is_none());
        assert!(sample.cost_usage().is_none());
        assert!(sample.detail_sections().is_empty());
    }
}

#[test]
fn pacing_text_covers_on_track_ahead_and_invalid_cycle_branches() {
    let empty_history = br#"{"data":{"records":[],"total":0}}"#;
    for (used, expected) in [(50, "On track"), (80, "30% ahead of budget")] {
        let status = format!(
            r#"{{"data":{{"credit_status":{{"budget_cap":100,"used_credit":{used},"cycle_start_date":1782799940000,"cycle_end_date":1782800060000,"is_unlimited":false}}}}}}"#
        );
        let sample = parse_zoommate_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            status.as_bytes(),
            Some(empty_history),
            ProviderSource::ManualCookie,
        )
        .expect("paced status");
        assert_eq!(sample.detail_sections()[0].rows()[2].value(), expected);
    }

    let invalid_cycle = br#"{"data":{"credit_status":{"budget_cap":100,"used_credit":50,"cycle_start_date":1782800060000,"cycle_end_date":1782800060000,"is_unlimited":false}}}"#;
    let sample = parse_zoommate_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        invalid_cycle,
        Some(empty_history),
        ProviderSource::ManualCookie,
    )
    .expect("invalid cycle omits pace");
    assert_eq!(sample.detail_sections()[0].rows().len(), 2);
}

#[test]
fn parser_rejects_missing_shape_wrong_types_extremes_and_structural_bombs() {
    for body in [
        br"{}".as_slice(),
        br#"{"data":{}}"#.as_slice(),
        br#"{"data":{"credit_status":{"budget_cap":"35000"}}}"#.as_slice(),
        br#"{"data":{"credit_status":{"budget_cap":1000000000000001}}}"#.as_slice(),
        br#"{"data":{"credit_status":{"cycle_end_date":1.5}}}"#.as_slice(),
        br#"{"data":{"credit_status":{"is_unlimited":"false"}}}"#.as_slice(),
        br#"{"data":{"credit_status":{}},"status_code":"200"}"#.as_slice(),
        br#"{"data":{"credit_status":{}},"error_message":7}"#.as_slice(),
    ] {
        assert_eq!(
            parse_zoommate_responses(
                scope("account-a"),
                timestamp(NOW_SECONDS),
                body,
                None,
                ProviderSource::ManualCookie,
            )
            .expect_err("malformed status")
            .kind(),
            ErrorKind::Parse
        );
    }

    let deep = format!(
        r#"{{"data":{{"credit_status":{{"budget_cap":1,"x":{}0{}}}}}}}"#,
        "[".repeat(42),
        "]".repeat(42)
    );
    assert!(
        parse_zoommate_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            deep.as_bytes(),
            None,
            ProviderSource::ManualCookie,
        )
        .is_err()
    );

    let wide = format!(
        r#"{{"data":{{"credit_status":{{"budget_cap":1}}}},"x":[{}]}}"#,
        std::iter::repeat_n("0", 32_769)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(
        parse_zoommate_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            wide.as_bytes(),
            None,
            ProviderSource::ManualCookie,
        )
        .is_err()
    );
}

#[test]
fn malformed_history_is_strict_while_invalid_ledger_rows_are_skipped_during_aggregation() {
    let invalid_shapes = [
        br"{}".as_slice(),
        br#"{"data":{"records":{}}}"#.as_slice(),
        br#"{"data":{"records":[{"cost":"1"}]}}"#.as_slice(),
        br#"{"data":{"records":[]},"status_code":"200"}"#.as_slice(),
        br#"{"data":{"records":[]},"error_message":7}"#.as_slice(),
    ];
    for history in invalid_shapes {
        assert_eq!(
            parse_zoommate_responses(
                scope("account-a"),
                timestamp(NOW_SECONDS),
                STATUS,
                Some(history),
                ProviderSource::ManualCookie,
            )
            .expect_err("malformed fixture history")
            .kind(),
            ErrorKind::Parse
        );
    }

    let negative_total = parse_zoommate_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        STATUS,
        Some(br#"{"data":{"records":[],"total":-1}}"#),
        ProviderSource::ManualCookie,
    )
    .expect("signed total matches the baseline Int decoder");
    assert_eq!(
        negative_total
            .cost_usage()
            .expect("empty history")
            .history()
            .amount(),
        Some(ExactDecimal::parse("0").expect("decimal"))
    );

    let skipped = br#"{
      "data":{"records":[
        {"cost":-1,"time":"2026-06-30T01:00:00Z","is_deleted":false},
        {"cost":2,"time":"bad-time","is_deleted":false},
        {"cost":3,"time":"2026-06-30T02:00:00Z","is_deleted":true},
        {"cost":1.5,"time":"2026-06-30T03:00:00Z","is_running":true,"is_deleted":false},
        {"cost":100,"time":"2026-05-01T00:00:00Z","is_deleted":false}
      ],"total":5}
    }"#;
    let sample = parse_zoommate_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        STATUS,
        Some(skipped),
        ProviderSource::ManualCookie,
    )
    .expect("invalid ledger rows are ignored");
    assert_eq!(sample.detail_sections()[0].rows()[0].value(), "1.5");
    assert_eq!(sample.detail_sections()[0].rows()[1].value(), "1.5");
}

#[tokio::test]
async fn manual_fetch_sends_exact_status_and_history_requests_with_fixed_headers() {
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let capture = capture(
        "ai.zoom.us",
        BEARER_CANARY,
        Some(&format!("session={COOKIE_CANARY}")),
    );
    let provider = manual_provider(&primary, &alternate, &capture);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");
    assert!(sample.identity().email().is_none());

    let requests = primary.requests();
    assert_eq!(requests.len(), 2);
    let status = &requests[0];
    assert_eq!(status.method(), "GET");
    assert_eq!(status.target(), "/ai-computer/api/v1/credits/status");
    assert_eq!(
        status.header("authorization"),
        Some(format!("Bearer {BEARER_CANARY}").as_str())
    );
    assert_eq!(
        status.header("cookie"),
        Some(format!("session={COOKIE_CANARY}").as_str())
    );
    assert_common_headers(status);

    let history = &requests[1];
    assert!(
        history
            .target()
            .starts_with("/ai-computer/api/v1/credits/history?")
    );
    for query in [
        "app_id=demo_app",
        "limit=50",
        "page=0",
        "sort_by=time",
        "sort_order=desc",
        "start_time=",
        "end_time=",
    ] {
        assert!(history.target().contains(query), "missing {query}");
    }
    assert_eq!(
        history.header("authorization"),
        Some(format!("Bearer {BEARER_CANARY}").as_str())
    );
    assert_eq!(
        history.header("cookie"),
        Some(format!("session={COOKIE_CANARY}").as_str())
    );
    assert_common_headers(history);
    assert!(alternate.requests().is_empty());
}

#[tokio::test]
async fn manual_capture_is_exact_inert_and_forwards_only_the_named_header_allowlist() {
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let capture = format!(
        "curl 'https://ai.zoom.us/ai-computer/api/v1/credits/status' \
         -H 'Authorization: {BEARER_CANARY}' \
         -H 'Accept-Language: tr-TR,tr;q=0.9' \
         -H 'User-Agent: Synthetic Browser' \
         -H 'X-Evil: must-not-cross' \
         -H 'Origin: https://attacker.example' \
         -H 'Referer: https://attacker.example/path'"
    );
    manual_provider(&primary, &alternate, &capture)
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("allowlisted capture");
    let request = &primary.requests()[0];
    assert_eq!(request.header("accept-language"), Some("tr-TR,tr;q=0.9"));
    assert_eq!(request.header("user-agent"), Some("Synthetic Browser"));
    assert_eq!(request.header("x-evil"), None);
    assert_eq!(request.header("origin"), Some("https://zoommate.zoom.us"));
    assert_eq!(request.header("referer"), Some("https://zoommate.zoom.us"));
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {BEARER_CANARY}").as_str())
    );

    for malformed in [
        "",
        "Authorization: Bearer token-without-curl-url",
        "curl 'http://ai.zoom.us/ai-computer/api/v1/credits/status' -H 'Authorization: Bearer x'",
        "curl 'https://marketing.zoom.us/ai-computer/api/v1/credits/status' -H 'Authorization: Bearer x'",
        "curl 'https://zoom.us.attacker.test/ai-computer/api/v1/credits/status' -H 'Authorization: Bearer x'",
        "curl 'https://ai.zoom.us/ai-computer/api/v1/credits/history' -H 'Authorization: Bearer x'",
        "curl 'https://ai.zoom.us:444/ai-computer/api/v1/credits/status' -H 'Authorization: Bearer x'",
        "curl --location 'https://ai.zoom.us/ai-computer/api/v1/credits/status' -H 'Authorization: Bearer x'",
        "curl 'https://ai.zoom.us/ai-computer/api/v1/credits/status' -H 'Cookie: session=x'",
        "curl 'https://ai.zoom.us/ai-computer/api/v1/credits/status' --data '@/etc/passwd' -H 'Authorization: Bearer x'",
    ] {
        assert!(
            ZoomMateProvider::from_manual_capture_routes(
                scope("account-a"),
                malformed,
                routes(&primary, &alternate),
            )
            .is_err(),
            "capture should fail: {malformed}"
        );
    }
}

#[tokio::test]
async fn manual_host_preference_and_failover_never_leak_host_bound_cookies() {
    for (captured_host, first_is_primary) in [("ai.zoom.us", true), ("zoommate.zoom.us", false)] {
        let primary_responses = if first_is_primary {
            vec![
                FakeHttpResponse::new(503, Vec::new()),
                FakeHttpResponse::new(503, Vec::new()),
            ]
        } else {
            vec![
                FakeHttpResponse::new(200, STATUS.to_vec()),
                FakeHttpResponse::new(200, HISTORY.to_vec()),
            ]
        };
        let alternate_responses = if first_is_primary {
            vec![
                FakeHttpResponse::new(200, STATUS.to_vec()),
                FakeHttpResponse::new(200, HISTORY.to_vec()),
            ]
        } else {
            vec![
                FakeHttpResponse::new(503, Vec::new()),
                FakeHttpResponse::new(503, Vec::new()),
            ]
        };
        let primary = FakeHttpServer::start(primary_responses).await;
        let alternate = FakeHttpServer::start(alternate_responses).await;
        let capture = capture(
            captured_host,
            BEARER_CANARY,
            Some(&format!("session={COOKIE_CANARY}")),
        );
        manual_provider(&primary, &alternate, &capture)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("host failover");

        let captured_requests = if first_is_primary {
            primary.requests()
        } else {
            alternate.requests()
        };
        let fallback_requests = if first_is_primary {
            alternate.requests()
        } else {
            primary.requests()
        };
        let expected_cookie = format!("session={COOKIE_CANARY}");
        assert_eq!(captured_requests.len(), 2);
        assert!(
            captured_requests
                .iter()
                .all(|request| request.header("cookie") == Some(expected_cookie.as_str()))
        );
        assert_eq!(fallback_requests.len(), 2);
        assert!(
            fallback_requests
                .iter()
                .all(|request| request.header("cookie").is_none())
        );
        let expected_authorization = format!("Bearer {BEARER_CANARY}");
        assert!(fallback_requests.iter().all(|request| {
            request.header("authorization") == Some(expected_authorization.as_str())
        }));
    }
}

#[tokio::test]
async fn authentication_and_parse_failures_do_not_try_the_alternate_host() {
    for response in [
        FakeHttpResponse::new(401, vec![b'x'; 2 * 1024 * 1024 + 1]),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(200, br#"{"unexpected":true}"#.to_vec()),
        FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1]),
    ] {
        let primary = FakeHttpServer::start([response]).await;
        let alternate = FakeHttpServer::start([FakeHttpResponse::new(200, STATUS.to_vec())]).await;
        let provider = manual_provider(
            &primary,
            &alternate,
            &capture("ai.zoom.us", BEARER_CANARY, None),
        );
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("required status failure");
        assert!(matches!(
            error.kind(),
            ErrorKind::AuthenticationExpired | ErrorKind::Parse
        ));
        assert!(alternate.requests().is_empty());
    }
}

#[tokio::test]
async fn non_auth_statuses_and_redirects_fail_over_without_forwarding_captured_cookie() {
    for status in [302, 400, 408, 429, 500, 503] {
        let primary = FakeHttpServer::start([
            FakeHttpResponse::new(status, vec![b'x'; 2 * 1024 * 1024 + 1]),
            FakeHttpResponse::new(status, Vec::new()),
        ])
        .await;
        let alternate = FakeHttpServer::start([
            FakeHttpResponse::new(200, STATUS.to_vec()),
            FakeHttpResponse::new(200, HISTORY.to_vec()),
        ])
        .await;
        manual_provider(
            &primary,
            &alternate,
            &capture(
                "ai.zoom.us",
                BEARER_CANARY,
                Some(&format!("session={COOKIE_CANARY}")),
            ),
        )
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("alternate host succeeds");
        assert_eq!(primary.requests().len(), 2);
        assert_eq!(alternate.requests().len(), 2);
        assert!(
            alternate
                .requests()
                .iter()
                .all(|request| request.header("cookie").is_none())
        );
    }

    let primary = FakeHttpServer::start([
        FakeHttpResponse::truncated(200, 100, b"short".to_vec()),
        FakeHttpResponse::new(503, Vec::new()),
    ])
    .await;
    let alternate = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    manual_provider(
        &primary,
        &alternate,
        &capture("ai.zoom.us", BEARER_CANARY, None),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("truncated transport falls over");
    assert_eq!(primary.requests().len(), 2);
    assert_eq!(alternate.requests().len(), 2);
}

#[tokio::test]
async fn redirects_follow_only_within_the_original_origin() {
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("location", "/redirected-status"),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    manual_provider(
        &primary,
        &alternate,
        &capture(
            "ai.zoom.us",
            BEARER_CANARY,
            Some(&format!("session={COOKIE_CANARY}")),
        ),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("same-origin redirect");
    let requests = primary.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].target(), "/redirected-status");
    assert_eq!(
        requests[1].header("authorization"),
        Some(format!("Bearer {BEARER_CANARY}").as_str())
    );
    assert_eq!(
        requests[1].header("cookie"),
        Some(format!("session={COOKIE_CANARY}").as_str())
    );
    assert!(alternate.requests().is_empty());

    let alternate = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new())
            .header("location", alternate.url("/cross-origin-status").as_str()),
        FakeHttpResponse::new(503, Vec::new()),
    ])
    .await;
    manual_provider(
        &primary,
        &alternate,
        &capture(
            "ai.zoom.us",
            BEARER_CANARY,
            Some(&format!("session={COOKIE_CANARY}")),
        ),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("cross-origin redirect becomes host failover");
    assert_eq!(primary.requests().len(), 2);
    assert_eq!(alternate.requests().len(), 2);
    assert!(
        alternate
            .requests()
            .iter()
            .all(|request| request.target() != "/cross-origin-status")
    );
    assert!(
        alternate
            .requests()
            .iter()
            .all(|request| request.header("cookie").is_none())
    );
}

#[tokio::test]
async fn browser_session_mints_identity_and_reuses_an_in_date_bearer() {
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let jar = cookie_jar(vec![
        cookie_record("parent-session", COOKIE_CANARY, "/", None),
        cookie_record("wrong-path", "must-not-cross", "/unrelated", None),
        cookie_record(
            "expired",
            "must-not-cross",
            "/",
            Some(now() - time::Duration::seconds(1)),
        ),
    ]);
    let provider = ZoomMateProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&primary, &alternate),
    )
    .expect("browser provider");
    let browser_context = context("account-a", ProviderSource::BrowserSession);
    let first = provider
        .fetch_at(&browser_context, timestamp(NOW_SECONDS))
        .await
        .expect("first browser fetch");
    let second = provider
        .fetch_at(&browser_context, timestamp(NOW_SECONDS + 60))
        .await
        .expect("cached browser fetch");
    for sample in [&first, &second] {
        assert_eq!(
            sample.identity().email().expect("minted email").as_str(),
            "synthetic.user@example.com"
        );
        assert_eq!(
            sample
                .identity()
                .login_method()
                .expect("cookie method")
                .as_str(),
            "Cookie"
        );
        assert_eq!(sample.provenance()[0].strategy(), "browser_session");
    }

    let requests = primary.requests();
    assert_eq!(requests.len(), 5);
    assert!(
        requests[0]
            .target()
            .starts_with("/ai-computer/api/v1/login/?continue=")
    );
    assert!(requests[0].header("authorization").is_none());
    assert_eq!(
        requests[0].header("cookie"),
        Some(format!("parent-session={COOKIE_CANARY}").as_str())
    );
    assert!(
        !requests[0]
            .header("cookie")
            .expect("cookie")
            .contains("must-not-cross")
    );
    for request in &requests[1..] {
        assert_eq!(
            request.header("authorization"),
            Some("Bearer eyJhbGciOiJub25lIn0.eyJleHAiOjk5OTk5OTk5OTl9.signature")
        );
    }
}

#[tokio::test]
async fn browser_cookies_are_selected_independently_for_each_exact_endpoint() {
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let jar = cookie_jar(vec![
        cookie_record(
            "login-session",
            "login-only",
            "/ai-computer/api/v1/login/",
            None,
        ),
        cookie_record(
            "status-session",
            "status-only",
            "/ai-computer/api/v1/credits/status",
            None,
        ),
        cookie_record(
            "history-session",
            "history-only",
            "/ai-computer/api/v1/credits/history",
            None,
        ),
    ]);
    let provider = ZoomMateProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&primary, &alternate),
    )
    .expect("login-scoped browser credential");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("path-scoped browser fetch");

    let requests = primary.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].header("cookie"),
        Some("login-session=login-only")
    );
    assert_eq!(
        requests[1].header("cookie"),
        Some("status-session=status-only")
    );
    assert_eq!(
        requests[2].header("cookie"),
        Some("history-session=history-only")
    );
    assert!(alternate.requests().is_empty());
}

#[tokio::test]
async fn browser_mint_fails_over_only_for_non_auth_non_parse_failures() {
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([FakeHttpResponse::new(200, LOGIN.to_vec())]).await;
    let jar = cookie_jar(vec![cookie_record("session", COOKIE_CANARY, "/", None)]);
    let provider = ZoomMateProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&primary, &alternate),
    )
    .expect("browser provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("mint host failover");
    assert_eq!(primary.requests().len(), 3);
    assert!(
        primary.requests()[0]
            .target()
            .starts_with("/ai-computer/api/v1/login/")
    );
    assert_eq!(
        primary.requests()[1].target(),
        "/ai-computer/api/v1/credits/status"
    );
    assert_eq!(alternate.requests().len(), 1);
    assert!(
        alternate.requests()[0]
            .target()
            .starts_with("/ai-computer/api/v1/login/")
    );

    for (response, expected) in [
        (
            FakeHttpResponse::new(401, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(200, br#"{"success":true,"data":{}}"#.to_vec()),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(200, br#"{"success":true,"data":{"nak":"   "}}"#.to_vec()),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(
                200,
                br#"{"success":"true","data":{"nak":"token"}}"#.to_vec(),
            ),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(
                200,
                br#"{"success":true,"data":{"nak":"token","user_profile":"wrong"}}"#.to_vec(),
            ),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(
                200,
                br#"{"success":true,"data":{"nak":"token","user_profile":{"email":7}}}"#.to_vec(),
            ),
            ErrorKind::Parse,
        ),
    ] {
        let primary = FakeHttpServer::start([response]).await;
        let alternate = FakeHttpServer::start([FakeHttpResponse::new(200, LOGIN.to_vec())]).await;
        let provider = ZoomMateProvider::from_browser_jar_routes(
            scope("account-a"),
            &jar,
            now(),
            routes(&primary, &alternate),
        )
        .expect("browser provider");
        assert_eq!(
            provider
                .fetch_at(
                    &context("account-a", ProviderSource::BrowserSession),
                    timestamp(NOW_SECONDS),
                )
                .await
                .expect_err("terminal mint failure")
                .kind(),
            expected
        );
        assert!(alternate.requests().is_empty());
    }
}

#[tokio::test]
async fn ordered_browser_profiles_advance_only_after_an_auth_rejection() {
    let stale = cookie_jar(vec![cookie_record("session", "stale-profile", "/", None)]);
    let valid = cookie_jar(vec![cookie_record("session", "valid-profile", "/", None)]);
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let provider = ZoomMateProvider::from_browser_jars_routes(
        scope("account-a"),
        &[&stale, &valid],
        now(),
        routes(&primary, &alternate),
    )
    .expect("ordered browser profiles");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("second profile succeeds");
    let requests = primary.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].header("cookie"), Some("session=stale-profile"));
    assert_eq!(requests[1].header("cookie"), Some("session=valid-profile"));
    assert_eq!(requests[2].header("cookie"), Some("session=valid-profile"));
    assert_eq!(requests[3].header("cookie"), Some("session=valid-profile"));
    assert!(alternate.requests().is_empty());

    let primary = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        br#"{"success":true,"data":{}}"#.to_vec(),
    )])
    .await;
    let alternate = FakeHttpServer::start([FakeHttpResponse::new(200, LOGIN.to_vec())]).await;
    let provider = ZoomMateProvider::from_browser_jars_routes(
        scope("account-a"),
        &[&stale, &valid],
        now(),
        routes(&primary, &alternate),
    )
    .expect("ordered browser profiles");
    assert_eq!(
        provider
            .fetch_at(
                &context("account-a", ProviderSource::BrowserSession),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("parse failure is not hidden")
            .kind(),
        ErrorKind::Parse
    );
    assert_eq!(primary.requests().len(), 1);
    assert!(alternate.requests().is_empty());

    let references = std::iter::repeat_n(&valid, 65).collect::<Vec<_>>();
    assert_eq!(
        ZoomMateProvider::from_browser_jars_routes(
            scope("account-a"),
            &references,
            now(),
            routes(&primary, &alternate),
        )
        .expect_err("browser session bound")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn browser_cache_withholds_a_token_inside_the_sixty_second_refresh_skew() {
    let near_expiry = login_with_exp(NOW_SECONDS + 60);
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, near_expiry.clone()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
        FakeHttpResponse::new(200, near_expiry),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let jar = cookie_jar(vec![cookie_record("session", COOKIE_CANARY, "/", None)]);
    let provider = ZoomMateProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&primary, &alternate),
    )
    .expect("browser provider");
    let browser_context = context("account-a", ProviderSource::BrowserSession);
    provider
        .fetch_at(&browser_context, timestamp(NOW_SECONDS))
        .await
        .expect("first near-expiry fetch");
    provider
        .fetch_at(&browser_context, timestamp(NOW_SECONDS))
        .await
        .expect("near-expiry token is reminted");
    assert_eq!(
        primary
            .requests()
            .iter()
            .filter(|request| request.target().starts_with("/ai-computer/api/v1/login/"))
            .count(),
        2
    );
    assert!(alternate.requests().is_empty());
}

#[tokio::test]
async fn undatable_browser_tokens_are_reminted_and_auth_rejection_invalidates_the_cache() {
    let opaque_login = br#"{"success":true,"data":{"nak":"opaque-token"}}"#;
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, opaque_login.to_vec()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
        FakeHttpResponse::new(200, opaque_login.to_vec()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let jar = cookie_jar(vec![cookie_record("session", COOKIE_CANARY, "/", None)]);
    let provider = ZoomMateProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&primary, &alternate),
    )
    .expect("browser provider");
    let browser_context = context("account-a", ProviderSource::BrowserSession);
    provider
        .fetch_at(&browser_context, timestamp(NOW_SECONDS))
        .await
        .expect("opaque first fetch");
    provider
        .fetch_at(&browser_context, timestamp(NOW_SECONDS + 1))
        .await
        .expect("opaque second fetch");
    assert_eq!(
        primary
            .requests()
            .iter()
            .filter(|request| request.target().starts_with("/ai-computer/api/v1/login/"))
            .count(),
        2
    );

    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, LOGIN.to_vec()),
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let provider = ZoomMateProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&primary, &alternate),
    )
    .expect("browser provider");
    assert_eq!(
        provider
            .fetch_at(&browser_context, timestamp(NOW_SECONDS))
            .await
            .expect_err("rejected bearer")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    provider
        .fetch_at(&browser_context, timestamp(NOW_SECONDS + 1))
        .await
        .expect("reminted bearer");
    assert_eq!(
        primary
            .requests()
            .iter()
            .filter(|request| request.target().starts_with("/ai-computer/api/v1/login/"))
            .count(),
        2
    );
}

#[tokio::test]
async fn browser_missing_expired_and_unmatched_cookies_fail_before_network() {
    let primary = FakeHttpServer::start([]).await;
    let alternate = FakeHttpServer::start([]).await;
    for (jar, expected) in [
        (cookie_jar(Vec::new()), ErrorKind::MissingCredential),
        (
            cookie_jar(vec![cookie_record("wrong", "x", "/unrelated", None)]),
            ErrorKind::AuthenticationExpired,
        ),
        (
            cookie_jar(vec![cookie_record(
                "expired",
                "x",
                "/",
                Some(now() - time::Duration::seconds(1)),
            )]),
            ErrorKind::AuthenticationExpired,
        ),
    ] {
        assert_eq!(
            ZoomMateProvider::from_browser_jar_routes(
                scope("account-a"),
                &jar,
                now(),
                routes(&primary, &alternate),
            )
            .expect_err("invalid browser session")
            .kind(),
            expected
        );
    }
    assert!(primary.requests().is_empty());
    assert!(alternate.requests().is_empty());
}

#[tokio::test]
async fn history_paginates_until_total_and_stops_at_an_older_page_boundary() {
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, history_page(0, 50, 55, "2026-06-30T01:00:00Z")),
        FakeHttpResponse::new(200, history_page(50, 5, 55, "2026-06-29T01:00:00Z")),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let sample = manual_provider(
        &primary,
        &alternate,
        &capture("ai.zoom.us", BEARER_CANARY, None),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("paginated history");
    assert_eq!(primary.requests().len(), 3);
    assert!(primary.requests()[1].target().contains("page=0"));
    assert!(primary.requests()[2].target().contains("page=1"));
    assert_eq!(
        sample.cost_usage().expect("history").history().amount(),
        Some(ExactDecimal::parse("55").expect("decimal"))
    );

    let stale = history_page(0, 50, 1_000, "2026-05-01T00:00:00Z");
    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, stale),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let sample = manual_provider(
        &primary,
        &alternate,
        &capture("ai.zoom.us", BEARER_CANARY, None),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("stale boundary history");
    assert_eq!(primary.requests().len(), 2);
    assert_eq!(
        sample
            .cost_usage()
            .expect("empty bounded history")
            .history()
            .amount(),
        Some(ExactDecimal::parse("0").expect("decimal"))
    );

    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::new(200, br#"{"data":{"records":[],"total":1000}}"#.to_vec()),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let sample = manual_provider(
        &primary,
        &alternate,
        &capture("ai.zoom.us", BEARER_CANARY, None),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("empty page terminates pagination");
    assert_eq!(primary.requests().len(), 2);
    assert!(
        sample
            .cost_usage()
            .expect("empty history")
            .history_coverage_is_established()
    );
}

#[tokio::test]
async fn history_hard_page_bound_marks_the_common_snapshot_partial() {
    let mut responses = vec![FakeHttpResponse::new(200, STATUS.to_vec())];
    responses.extend((0..20).map(|page| {
        FakeHttpResponse::new(
            200,
            history_page(page * 50, 50, 1_001, "2026-06-30T01:00:00Z"),
        )
    }));
    let primary = FakeHttpServer::start(responses).await;
    let alternate = FakeHttpServer::start([]).await;
    let sample = manual_provider(
        &primary,
        &alternate,
        &capture("ai.zoom.us", BEARER_CANARY, None),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("bounded partial history");
    assert_eq!(primary.requests().len(), 21);
    let history = sample.cost_usage().expect("partial history");
    assert!(!history.history_coverage_is_established());
    assert_eq!(history.history_label(), Some("Last 30 days (partial)"));
    assert_eq!(
        history.history().amount(),
        Some(ExactDecimal::parse("1000").expect("decimal"))
    );
}

#[tokio::test]
async fn history_failures_are_nonfatal_but_cancellation_is_not_swallowed() {
    for response in [
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, br#"{"unexpected":true}"#.to_vec()),
        FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1]),
    ] {
        let primary =
            FakeHttpServer::start([FakeHttpResponse::new(200, STATUS.to_vec()), response]).await;
        let alternate = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
        let sample = manual_provider(
            &primary,
            &alternate,
            &capture("ai.zoom.us", BEARER_CANARY, None),
        )
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("valid status survives optional history failure");
        assert!(sample.cost_usage().is_none());
        assert!(sample.detail_sections().is_empty());
    }

    let primary = FakeHttpServer::start([
        FakeHttpResponse::new(200, STATUS.to_vec()),
        FakeHttpResponse::stall(),
    ])
    .await;
    let alternate = FakeHttpServer::start([]).await;
    let provider = manual_provider(
        &primary,
        &alternate,
        &capture("ai.zoom.us", BEARER_CANARY, None),
    );
    let cancellation = CancellationToken::new();
    let cancel_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            cancellation.cancel();
        })
    };
    let cancelled_context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation,
    );
    let error = provider
        .fetch_at_with_timeout(
            &cancelled_context,
            timestamp(NOW_SECONDS),
            Duration::from_secs(2),
        )
        .await
        .expect_err("history cancellation wins");
    cancel_task.await.expect("cancel task");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(alternate.requests().is_empty());
}

#[tokio::test]
async fn total_deadline_bounds_stalled_required_requests() {
    let primary = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let alternate = FakeHttpServer::start([]).await;
    let provider = manual_provider(
        &primary,
        &alternate,
        &capture("ai.zoom.us", BEARER_CANARY, None),
    );
    let started = Instant::now();
    let error = provider
        .fetch_at_with_timeout(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
            Duration::from_millis(30),
        )
        .await
        .expect_err("deadline");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(primary.requests().len(), 1);
    assert!(alternate.requests().is_empty());
}

#[tokio::test]
async fn scope_source_provider_and_debug_redaction_are_isolated() {
    let primary = FakeHttpServer::start([]).await;
    let alternate = FakeHttpServer::start([]).await;
    let provider = manual_provider(
        &primary,
        &alternate,
        &capture(
            "ai.zoom.us",
            BEARER_CANARY,
            Some(&format!("session={COOKIE_CANARY}")),
        ),
    );
    assert_eq!(provider.source(), ProviderSource::ManualCookie);
    let debug = format!("{provider:?}");
    assert!(!debug.contains(BEARER_CANARY));
    assert!(!debug.contains(COOKIE_CANARY));
    assert!(debug.contains("<redacted>"));

    for invalid in [
        context("account-b", ProviderSource::ManualCookie),
        context("account-a", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&invalid, timestamp(NOW_SECONDS))
                .await
                .expect_err("context mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(
        ZoomMateProvider::from_manual_capture_routes(
            scope_for(ProviderId::Perplexity, "account-a"),
            &capture("ai.zoom.us", BEARER_CANARY, None),
            routes(&primary, &alternate),
        )
        .is_err()
    );

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation,
    );
    assert_eq!(
        provider
            .fetch_at(&cancelled, timestamp(NOW_SECONDS))
            .await
            .expect_err("pre-cancelled")
            .kind(),
        ErrorKind::Network
    );
    assert!(primary.requests().is_empty());
    assert!(alternate.requests().is_empty());
}

#[test]
fn provider_trait_and_descriptor_contract_are_wired() {
    assert!(
        oab_providers::registry::descriptor_for(ProviderId::ZoomMate)
            .sources()
            .contains(ProviderSource::ManualCookie)
    );
    assert!(
        oab_providers::registry::descriptor_for(ProviderId::ZoomMate)
            .sources()
            .contains(ProviderSource::BrowserSession)
    );
}
