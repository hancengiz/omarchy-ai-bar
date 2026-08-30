use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId, CookieUrlPolicy,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::providers::mimo::{
    MiMoLocalProvider, MiMoProvider, parse_combined_snapshot, parse_local_usage,
    web_failure_allows_local_fallback,
};
use oab_providers::registry::descriptor_for;
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use serde_json::json;
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const BALANCE: &[u8] = include_bytes!("../../../fixtures/providers/mimo/balance.json");
const TOKEN_DETAIL: &[u8] = include_bytes!("../../../fixtures/providers/mimo/token_detail.json");
const TOKEN_USAGE: &[u8] = include_bytes!("../../../fixtures/providers/mimo/token_usage.json");
const LOCAL_USAGE: &[u8] = include_bytes!("../../../fixtures/providers/mimo/local_usage.json");
const COOKIE_CANARY: &str = "fixture-mimo-service-token-canary";
const USER_CANARY: &str = "fixture-mimo-user-canary";
const NOW_SECONDS: i64 = 1_783_555_200;

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Mimo,
        ProviderInstanceId::new("mimo-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
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

fn manual_provider(server: &FakeHttpServer, raw: &str) -> MiMoProvider {
    MiMoProvider::from_manual_capture_at(
        scope("account-a"),
        raw,
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual MiMo provider")
}

fn cookie_record(
    name: &str,
    value: &str,
    domain: &str,
    domain_kind: CookieDomainKind,
    path: &str,
    expires_at: Option<OffsetDateTime>,
) -> CookieRecord {
    CookieRecord::new(CookieRecordSpec {
        name,
        value,
        domain,
        domain_kind,
        path,
        secure: false,
        expires_at,
    })
    .expect("cookie record")
}

fn cookie_jar(records: Vec<CookieRecord>) -> CookieJar {
    let source = CookieSourceId::new(18);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn union_payload() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "code": 0,
        "message": "",
        "data": {
            "balance": "25.51",
            "currency": "USD",
            "cashBalance": "20.00",
            "giftBalance": "5.51",
            "planCode": "standard",
            "currentPeriodEnd": "2026-05-04 23:59:59",
            "expired": false,
            "monthUsage": {
                "percent": 0.0505,
                "items": [{
                    "name": "month_total_token",
                    "used": 10_100_158,
                    "limit": 200_000_000,
                    "percent": 0.0505
                }]
            }
        }
    }))
    .expect("union payload")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 0.000_001,
        "{actual} != {expected}"
    );
}

#[test]
fn golden_payloads_map_balance_quota_reset_identity_and_optional_components() {
    let sample = parse_combined_snapshot(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        BALANCE,
        Some(TOKEN_DETAIL),
        Some(TOKEN_USAGE),
    )
    .expect("MiMo fixtures");

    let balance = sample.balance().expect("native balance");
    assert_eq!(balance.amount().to_string(), "25.51");
    assert_eq!(balance.currency().as_str(), "USD");
    let primary = sample.primary().expect("token-plan quota");
    assert_percent(primary.used_percent().expect("known percent").get(), 5.05);
    assert_eq!(
        primary.duration().expect("monthly sentinel").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        primary.resets_at().expect("period end").unix_timestamp(),
        1_777_939_199
    );
    assert_eq!(
        primary.reset_description().expect("credit counts").as_str(),
        "10,100,158 / 200,000,000 Credits"
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Standard"
    );
    let details = sample.detail_sections().first().expect("credit details");
    assert_eq!(details.title(), Some("Credits"));
    assert_eq!(details.rows()[0].label(), "Balance");
    assert_eq!(
        details.rows()[0].value(),
        "$25.51 (Paid: $20.00 / Granted: $5.51)"
    );
    assert_eq!(sample.provenance()[0].source(), "mimo");
    assert_eq!(sample.provenance()[0].strategy(), "web");
}

#[test]
fn malformed_optional_payloads_and_balance_components_do_not_erase_authoritative_balance() {
    let malformed_components = br#"{
      "code":0,
      "data":{"balance":"25.51","currency":"USD","cashBalance":"unknown","giftBalance":""}
    }"#;
    let sample = parse_combined_snapshot(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        malformed_components,
        Some(b"{not-json}"),
        Some(br#"{"code":0,"data":{"monthUsage":{"percent":"bad","items":[]}}}"#),
    )
    .expect("optional failures are absent");
    assert_eq!(
        sample.balance().expect("balance").amount().to_string(),
        "25.51"
    );
    assert!(sample.primary().is_none());
    assert!(sample.identity().login_method().is_none());
    assert_eq!(sample.detail_sections()[0].rows()[0].value(), "$25.51");

    let oversized_plan = serde_json::to_vec(&json!({
        "code": 0,
        "data": {
            "planCode": "x".repeat(300),
            "currentPeriodEnd": "2026-05-04 23:59:59",
            "expired": false
        }
    }))
    .expect("oversized optional plan");
    let sample = parse_combined_snapshot(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        br#"{"code":0,"data":{"balance":"2.551e1","currency":"USD"}}"#,
        Some(&oversized_plan),
        Some(TOKEN_USAGE),
    )
    .expect("optional identity bound cannot erase required balance");
    assert_eq!(
        sample.balance().expect("balance").amount().to_string(),
        "25.51"
    );
    assert!(sample.identity().login_method().is_none());
    assert!(sample.primary().is_some());

    for body in [b"{not-json}".as_slice(), br#"{"code":0,"data":null}"#] {
        assert_eq!(
            parse_combined_snapshot(scope("account-a"), timestamp(NOW_SECONDS), body, None, None,)
                .expect_err("required balance must fail")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[test]
fn payload_auth_codes_and_missing_reset_semantics_match_baseline() {
    for (code, expected) in [
        (401, ErrorKind::AuthenticationExpired),
        (403, ErrorKind::AuthenticationExpired),
    ] {
        let body = format!(r#"{{"code":{code},"message":"private canary","data":null}}"#);
        let error = parse_combined_snapshot(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            body.as_bytes(),
            None,
            None,
        )
        .expect_err("payload auth code");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains("private canary"));
    }

    let sample = parse_combined_snapshot(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        BALANCE,
        Some(br#"{"code":0,"data":{"planCode":"standard","expired":false}}"#),
        Some(TOKEN_USAGE),
    )
    .expect("missing optional period end");
    let primary = sample.primary().expect("quota remains available");
    assert!(primary.resets_at().is_none());
    assert!(primary.duration().is_none());
}

#[tokio::test]
async fn manual_capture_sends_three_exact_fixed_requests_with_only_known_cookies() {
    let payload = union_payload();
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, payload.clone()),
        FakeHttpResponse::new(200, payload.clone()),
        FakeHttpResponse::new(200, payload),
    ])
    .await;
    let raw = format!(
        "curl 'https://platform.xiaomimimo.com/api/v1/balance?ignored=1' -H 'Cookie: userId=old; ignored=secret; api-platform_serviceToken={COOKIE_CANARY}; api-platform_ph=ph-token; userId={USER_CANARY}'"
    );
    let provider = manual_provider(&server, &raw);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert_eq!(provider.descriptor().id, ProviderId::Mimo);
    assert_percent(
        sample
            .primary()
            .expect("quota")
            .used_percent()
            .expect("known")
            .get(),
        5.05,
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    let mut paths = requests
        .iter()
        .map(CapturedHttpRequest::target)
        .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "/api/v1/balance",
            "/api/v1/tokenPlan/detail",
            "/api/v1/tokenPlan/usage"
        ]
    );
    for request in &requests {
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request.header("cookie"),
            Some(format!(
                "api-platform_ph=ph-token; api-platform_serviceToken={COOKIE_CANARY}; userId={USER_CANARY}"
            ).as_str())
        );
        assert_eq!(
            request.header("accept"),
            Some("application/json, text/plain, */*")
        );
        assert_eq!(request.header("accept-language"), Some("en-US,en;q=0.9"));
        assert_eq!(request.header("x-timezone"), Some("UTC+01:00"));
        assert_eq!(
            request.header("origin"),
            Some("https://platform.xiaomimimo.com")
        );
        assert_eq!(
            request.header("referer"),
            Some("https://platform.xiaomimimo.com/#/console/balance")
        );
        assert_eq!(
            request.header("user-agent"),
            Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            )
        );
        assert_eq!(request.body(), b"");
    }
}

#[tokio::test]
async fn exact_status_mapping_short_circuits_error_bodies() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let cases = [
        (
            FakeHttpResponse::new(302, oversized.clone()).header("Location", "/login"),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(401, oversized.clone()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::truncated(403, 100, b"short".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(201, oversized.clone()),
            ErrorKind::Network,
        ),
        (FakeHttpResponse::new(204, Vec::new()), ErrorKind::Network),
        (
            FakeHttpResponse::truncated(429, 100, b"short".to_vec()),
            ErrorKind::Network,
        ),
        (FakeHttpResponse::new(500, oversized), ErrorKind::Network),
    ];
    for (response, expected) in cases {
        let server = FakeHttpServer::start([response]).await;
        let error = manual_provider(
            &server,
            &format!("userId={USER_CANARY}; api-platform_serviceToken={COOKIE_CANARY}"),
        )
        .fetch_balance_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("status must fail");
        assert_eq!(error.kind(), expected);
    }
}

#[tokio::test]
async fn optional_parse_failure_never_erases_required_balance() {
    let payload = serde_json::to_vec(&json!({
        "code": 0,
        "data": {
            "balance": "25.51",
            "currency": "USD",
            "expired": "invalid",
            "monthUsage": {"percent": "invalid", "items": []}
        }
    }))
    .expect("mixed payload");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, payload.clone()),
        FakeHttpResponse::new(200, payload.clone()),
        FakeHttpResponse::new(200, payload),
    ])
    .await;
    let sample = manual_provider(
        &server,
        &format!("userId={USER_CANARY}; api-platform_serviceToken={COOKIE_CANARY}"),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("required balance survives");
    assert_eq!(
        sample.balance().expect("balance").amount().to_string(),
        "25.51"
    );
    assert!(sample.primary().is_none());
}

#[tokio::test]
async fn optional_http_and_framing_failures_never_erase_required_balance() {
    let server = RoutedMiMoServer::start(RoutedMode::OptionalFailures).await;
    let provider = MiMoProvider::from_manual_capture_at(
        scope("account-a"),
        &format!("userId={USER_CANARY}; api-platform_serviceToken={COOKIE_CANARY}"),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("routed MiMo provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("required balance survives optional transport failures");
    assert_eq!(
        sample.balance().expect("balance").amount().to_string(),
        "25.51"
    );
    assert!(sample.primary().is_none());
}

#[tokio::test]
async fn required_failure_cancels_already_started_optional_requests_promptly() {
    let server = RoutedMiMoServer::start(RoutedMode::RequiredFailure).await;
    let provider = MiMoProvider::from_manual_capture_at(
        scope("account-a"),
        &format!("userId={USER_CANARY}; api-platform_serviceToken={COOKIE_CANARY}"),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("routed MiMo provider");
    let started = Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        provider.fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        ),
    )
    .await
    .expect("required failure cancels optional futures")
    .expect_err("required status must fail");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn browser_cookie_selection_is_host_path_expiry_and_name_scoped() {
    let payload = union_payload();
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, payload.clone()),
        FakeHttpResponse::new(200, payload.clone()),
        FakeHttpResponse::new(200, payload),
    ])
    .await;
    let target = MiMoProvider::browser_target(&server.url("/"), CookieUrlPolicy::LoopbackHttp)
        .expect("browser target");
    let jar = cookie_jar(vec![
        cookie_record(
            "userId",
            "root-user",
            "127.0.0.1",
            CookieDomainKind::HostOnly,
            "/",
            Some(now() + time::Duration::days(5)),
        ),
        cookie_record(
            "userId",
            USER_CANARY,
            "127.0.0.1",
            CookieDomainKind::HostOnly,
            "/api",
            Some(now() + time::Duration::days(1)),
        ),
        cookie_record(
            "api-platform_serviceToken",
            "expired-token",
            "127.0.0.1",
            CookieDomainKind::HostOnly,
            "/api",
            Some(now() - time::Duration::seconds(1)),
        ),
        cookie_record(
            "api-platform_serviceToken",
            COOKIE_CANARY,
            "127.0.0.1",
            CookieDomainKind::HostOnly,
            "/api",
            None,
        ),
        cookie_record(
            "ignored",
            "not-forwarded",
            "127.0.0.1",
            CookieDomainKind::HostOnly,
            "/api",
            None,
        ),
    ]);
    let provider = MiMoProvider::from_browser_jar_at(
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
    for request in server.requests() {
        assert_eq!(
            request.header("cookie"),
            Some(
                format!("api-platform_serviceToken={COOKIE_CANARY}; userId={USER_CANARY}").as_str()
            )
        );
    }
}

#[tokio::test]
async fn scope_source_cancellation_and_diagnostics_are_isolated() {
    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(
        &server,
        &format!("userId={USER_CANARY}; api-platform_serviceToken={COOKIE_CANARY}"),
    );
    for wrong in [
        context("account-b", ProviderSource::ManualCookie),
        context("account-a", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_balance_at(&wrong, timestamp(NOW_SECONDS))
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
    let future = provider.fetch_balance_at(&cancelled, timestamp(NOW_SECONDS));
    tokio::pin!(future);
    tokio::select! {
        result = &mut future => panic!("stalled request completed early: {result:?}"),
        () = async {
            server.wait_for_request_count(1).await;
            token.cancel();
        } => {}
        () = tokio::time::sleep(Duration::from_secs(1)) => panic!("request did not start"),
    }
    let error = tokio::time::timeout(Duration::from_secs(1), future)
        .await
        .expect("cancellation prompt")
        .expect_err("cancelled request");
    assert_eq!(error.kind(), ErrorKind::Network);

    let debug = format!("{provider:?} {error:?} {error}");
    for canary in [
        COOKIE_CANARY,
        USER_CANARY,
        "account-a",
        server.origin().as_str(),
    ] {
        assert!(
            !debug.contains(canary),
            "diagnostic leaked {canary}: {debug}"
        );
    }
}

#[test]
fn local_fixture_maps_summary_without_fabricating_quota_or_balance() {
    let sample = parse_local_usage(
        scope("account-a"),
        timestamp(1_780_500_000),
        LOCAL_USAGE,
        None,
    )
    .expect("local fixture");
    assert!(sample.primary().is_none());
    assert!(sample.balance().is_none());
    assert!(sample.detail_sections().is_empty());
    assert_eq!(
        sample.identity().login_method().expect("summary").as_str(),
        "Local · 2.2k today · 110.0k week · 22.8M total · 1296 sessions"
    );
    assert_eq!(
        sample
            .fetched_at()
            .as_offset_date_time()
            .unix_timestamp_nanos(),
        1_780_463_043_123_456_000
    );
    assert_eq!(sample.provenance()[0].strategy(), "local");
}

#[test]
fn local_staleness_coercion_saturation_and_fallback_timestamp_match_baseline() {
    let body = serde_json::to_vec(&json!({
        "updated_at": "invalid",
        "sessions_scanned": "42",
        "windows": {
            "today": {"input": -3, "output": "bad"},
            "week": {"input": 0, "output": 0},
            "all_time": {"input": i64::MAX, "output": i64::MAX, "cache_read": 1.9}
        }
    }))
    .expect("local payload");
    let modified = timestamp(1_780_286_400);
    let sample = parse_local_usage(
        scope("account-a"),
        timestamp(1_783_555_200),
        &body,
        Some(modified),
    )
    .expect("coerced local payload");
    assert_eq!(sample.fetched_at(), modified);
    assert_eq!(
        sample.identity().login_method().expect("summary").as_str(),
        "Local · 9223372036854.8M total · 42 sessions · stale 37d"
    );

    let future = br#"{"updated_at":"2026-07-07T10:01:00Z","sessions_scanned":0,"windows":{"today":{},"week":{},"all_time":{}}}"#;
    let fresh = parse_local_usage(
        scope("account-a"),
        Timestamp::parse("2026-07-07T10:00:00Z").expect("now"),
        future,
        None,
    )
    .expect("future cache time");
    assert_eq!(
        fresh.identity().login_method().expect("summary").as_str(),
        "Local · 0 sessions"
    );
}

#[tokio::test]
async fn local_provider_uses_injected_absolute_cache_and_rejects_unsafe_files() {
    let directory = tempdir().expect("temporary directory");
    let cache = directory.path().join("mimo-local-usage.json");
    fs::write(&cache, LOCAL_USAGE).expect("write local fixture");
    let environment = BTreeMap::from([
        (
            "HOME".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
        (
            "MIMO_LOCAL_USAGE_PATH".to_owned(),
            cache.to_string_lossy().into_owned(),
        ),
    ]);
    let provider = MiMoLocalProvider::resolve(scope("account-a"), &environment)
        .expect("local provider settings");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::LocalData),
            timestamp(1_783_571_200),
        )
        .expect("local fetch");
    assert!(sample.identity().login_method().is_some());

    let link = directory.path().join("linked.json");
    symlink(&cache, &link).expect("create symlink");
    let linked = MiMoLocalProvider::new(scope("account-a"), &link).expect("path shape");
    assert_eq!(
        linked
            .fetch_at(
                &context("account-a", ProviderSource::LocalData),
                timestamp(NOW_SECONDS),
            )
            .expect_err("symlink must fail")
            .kind(),
        ErrorKind::Parse
    );

    let xdg_root = directory.path().join("xdg-data");
    let xdg_cache = xdg_root.join("omarchy-ai-bar/mimo-local-usage.json");
    fs::create_dir_all(xdg_cache.parent().expect("XDG cache parent"))
        .expect("create XDG cache parent");
    fs::write(&xdg_cache, LOCAL_USAGE).expect("write XDG cache");
    let xdg_provider = MiMoLocalProvider::resolve(
        scope("account-a"),
        &BTreeMap::from([(
            "XDG_DATA_HOME".to_owned(),
            xdg_root.to_string_lossy().into_owned(),
        )]),
    )
    .expect("XDG local provider settings");
    xdg_provider
        .fetch_at(
            &context("account-a", ProviderSource::LocalData),
            timestamp(1_783_571_200),
        )
        .expect("XDG default cache path");

    let home_root = directory.path().join("home");
    let home_cache = home_root.join(".local/share/omarchy-ai-bar/mimo-local-usage.json");
    fs::create_dir_all(home_cache.parent().expect("home cache parent"))
        .expect("create home cache parent");
    fs::write(&home_cache, LOCAL_USAGE).expect("write home cache");
    let home_provider = MiMoLocalProvider::resolve(
        scope("account-a"),
        &BTreeMap::from([("HOME".to_owned(), home_root.to_string_lossy().into_owned())]),
    )
    .expect("home local provider settings");
    home_provider
        .fetch_at(
            &context("account-a", ProviderSource::LocalData),
            timestamp(1_783_571_200),
        )
        .expect("home default cache path");
}

#[test]
fn fallback_policy_descriptor_and_constructor_errors_are_exact_and_redacted() {
    assert!(web_failure_allows_local_fallback(
        ErrorKind::MissingCredential
    ));
    assert!(web_failure_allows_local_fallback(
        ErrorKind::AuthenticationExpired
    ));
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Network,
        ErrorKind::Parse,
        ErrorKind::Api,
    ] {
        assert!(!web_failure_allows_local_fallback(kind));
    }
    assert_eq!(
        descriptor_for(ProviderId::Mimo)
            .sources()
            .iter()
            .collect::<Vec<_>>(),
        vec![
            ProviderSource::ManualCookie,
            ProviderSource::BrowserSession,
            ProviderSource::LocalData,
        ]
    );

    let canary = "constructor-secret-canary";
    let error = MiMoProvider::new_manual(
        scope("account-a"),
        &format!("curl 'https://evil.example/api/v1/balance' -H 'Cookie: userId=u; api-platform_serviceToken={canary}'"),
    )
    .expect_err("wrong captured host");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?} {error}").contains(canary));

    let missing = MiMoProvider::new_manual(scope("account-a"), "userId=only")
        .expect_err("both required cookies");
    assert_eq!(missing.kind(), ErrorKind::MissingCredential);
}

#[derive(Clone, Copy)]
enum RoutedMode {
    OptionalFailures,
    RequiredFailure,
}

struct RoutedMiMoServer {
    origin: String,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

impl RoutedMiMoServer {
    async fn start(mode: RoutedMode) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("routed fixture binds loopback");
        let address = listener.local_addr().expect("routed fixture address");
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let optional_started = Arc::new(Notify::new());
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = task_cancellation.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let connection_cancellation = task_cancellation.clone();
                let connection_optional_started = Arc::clone(&optional_started);
                tokio::spawn(async move {
                    serve_routed_connection(
                        stream,
                        mode,
                        connection_optional_started,
                        connection_cancellation,
                    )
                    .await;
                });
            }
        });
        Self {
            origin: format!("http://{address}"),
            cancellation,
            task,
        }
    }

    fn url(&self, path: &str) -> url::Url {
        url::Url::parse(&self.origin)
            .expect("routed origin URL")
            .join(path)
            .expect("routed fixture path")
    }
}

impl Drop for RoutedMiMoServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.task.abort();
    }
}

async fn serve_routed_connection(
    mut stream: TcpStream,
    mode: RoutedMode,
    optional_started: Arc<Notify>,
    cancellation: CancellationToken,
) {
    let Some(target) = read_request_target(&mut stream).await else {
        return;
    };
    match (mode, target.as_str()) {
        (RoutedMode::OptionalFailures, "/api/v1/balance") => {
            write_fixture_response(&mut stream, 200, BALANCE, None).await;
        }
        (RoutedMode::OptionalFailures, "/api/v1/tokenPlan/detail") => {
            write_fixture_response(&mut stream, 500, b"private optional body", None).await;
        }
        (RoutedMode::OptionalFailures, "/api/v1/tokenPlan/usage") => {
            write_fixture_response(&mut stream, 200, b"{", Some(100)).await;
        }
        (RoutedMode::RequiredFailure, "/api/v1/balance") => {
            let _ =
                tokio::time::timeout(Duration::from_millis(500), optional_started.notified()).await;
            write_fixture_response(&mut stream, 500, b"", None).await;
        }
        (RoutedMode::RequiredFailure, _) => {
            optional_started.notify_one();
            cancellation.cancelled().await;
        }
        (_, _) => write_fixture_response(&mut stream, 404, b"", None).await,
    }
}

async fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while bytes.len() <= 64 * 1024 {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let head_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&bytes[..head_end]).ok()?;
    head.lines()
        .next()?
        .split_ascii_whitespace()
        .nth(1)
        .map(str::to_owned)
}

async fn write_fixture_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    declared_length: Option<usize>,
) {
    let length = declared_length.unwrap_or(body.len());
    let head = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_ok() {
        let _ = stream.write_all(body).await;
        let _ = stream.shutdown().await;
    }
}
