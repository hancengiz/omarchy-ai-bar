use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::providers::perplexity::{PerplexityProvider, parse_credits_response};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const CREDITS: &[u8] = include_bytes!("../../../fixtures/providers/perplexity/credits.json");
const NOW_SECONDS: i64 = 1_782_000_000;
const TOKEN_CANARY: &str = "perplexity-token-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn scope(account: &str) -> AccountScope {
    provider_scope(ProviderId::Perplexity, account)
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
    let source = CookieSourceId::new(31);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn manual_provider(server: &FakeHttpServer, capture: &str) -> PerplexityProvider {
    PerplexityProvider::from_manual_capture_at(
        scope("account-a"),
        capture,
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual Perplexity provider")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

#[test]
fn golden_response_maps_waterfall_windows_plan_and_resets() {
    let sample = parse_credits_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        CREDITS,
        ProviderSource::ManualCookie,
    )
    .expect("credits parse");
    let recurring = sample.primary().expect("recurring window");
    assert_percent(recurring.used_percent().expect("percent").get(), 100.0);
    assert_eq!(recurring.duration(), None);
    assert_eq!(
        recurring.resets_at().expect("renewal").unix_timestamp(),
        1_782_864_000
    );
    assert_eq!(
        recurring.reset_description().expect("description").as_str(),
        "1500/1500 credits"
    );

    let bonus = sample.secondary().expect("bonus window");
    assert_percent(bonus.used_percent().expect("percent").get(), 0.0);
    assert_eq!(
        bonus.reset_description().expect("description").as_str(),
        "0/300 bonus · exp. Jun 30"
    );
    let purchased = sample.tertiary().expect("purchased window");
    assert_percent(purchased.used_percent().expect("percent").get(), 10.0);
    assert_eq!(
        purchased.reset_description().expect("description").as_str(),
        "200/2000 credits"
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Pro"
    );
}

#[test]
fn absent_recurring_falls_through_and_zero_account_keeps_exhausted_primary() {
    let fallback = br#"{
      "balance_cents":100,"renewal_date_ts":1782864000,
      "current_period_purchased_cents":50,
      "credit_grants":[{"type":"promotional","amount_cents":25,"expires_at_ts":null}],
      "total_usage_cents":10
    }"#;
    let sample = parse_credits_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        fallback,
        ProviderSource::BrowserSession,
    )
    .expect("fallback credits");
    assert!(sample.primary().is_none());
    assert_percent(
        sample
            .secondary()
            .expect("bonus")
            .used_percent()
            .expect("percent")
            .get(),
        0.0,
    );
    assert_percent(
        sample
            .tertiary()
            .expect("purchased")
            .used_percent()
            .expect("percent")
            .get(),
        20.0,
    );

    let zero = br#"{
      "balance_cents":0,"renewal_date_ts":1782864000,
      "current_period_purchased_cents":0,"credit_grants":[],"total_usage_cents":0
    }"#;
    let sample = parse_credits_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        zero,
        ProviderSource::ManualCookie,
    )
    .expect("zero account");
    assert_percent(
        sample
            .primary()
            .expect("exhausted primary")
            .used_percent()
            .expect("percent")
            .get(),
        100.0,
    );
    assert!(sample.identity().login_method().is_none());
}

#[tokio::test]
async fn bare_token_retries_supported_cookie_names_and_sends_exact_request() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, b"expired".to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, TOKEN_CANARY);
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("second supported cookie name succeeds");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].header("cookie"),
        Some("__Secure-authjs.session-token=perplexity-token-canary")
    );
    assert_eq!(
        requests[1].header("cookie"),
        Some("authjs.session-token=perplexity-token-canary")
    );
    for request in requests {
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request.target(),
            "/rest/billing/credits?version=2.18&source=default"
        );
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("origin"), Some("https://www.perplexity.ai"));
        assert_eq!(
            request.header("referer"),
            Some("https://www.perplexity.ai/account/usage")
        );
        assert!(request.header("user-agent").is_some());
        assert_eq!(request.body(), b"");
    }
}

#[tokio::test]
async fn full_cookie_and_curl_use_only_the_highest_priority_session_cookie() {
    for capture in [
        format!(
            "other=must-not-cross; next-auth.session-token=low; __Secure-authjs.session-token={TOKEN_CANARY}"
        ),
        format!(
            "curl 'https://www.perplexity.ai/evil?x=1' -H 'Cookie: other=must-not-cross; __Secure-next-auth.session-token={TOKEN_CANARY}'"
        ),
    ] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
        manual_provider(&server, &capture)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("manual session");
        let cookie = server.requests()[0]
            .header("cookie")
            .expect("session cookie")
            .to_owned();
        assert!(cookie.contains(TOKEN_CANARY));
        assert!(!cookie.contains("must-not-cross"));
        assert!(!cookie.contains("next-auth.session-token=low"));
    }
}

#[tokio::test]
async fn browser_reassembles_host_scoped_chunks_without_forwarding_other_cookies() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CREDITS.to_vec())]).await;
    let host = server
        .url("/")
        .host_str()
        .expect("loopback host")
        .to_owned();
    let jar = cookie_jar(vec![
        cookie_record(
            "__Secure-authjs.session-token.1",
            "canary",
            &host,
            "/rest/",
            None,
        ),
        cookie_record(
            "__Secure-authjs.session-token.0",
            "perplexity-token-",
            &host,
            "/rest/",
            None,
        ),
        cookie_record("other", "must-not-cross", &host, "/rest/", None),
    ]);
    let provider = PerplexityProvider::from_browser_jar_at(
        scope("account-a"),
        &jar,
        now(),
        &server.url("/"),
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
        Some("__Secure-authjs.session-token=perplexity-token-canary")
    );
}

#[tokio::test]
async fn missing_expired_unmatched_and_incomplete_chunks_fail_before_network() {
    let server = FakeHttpServer::start([]).await;
    let host = server
        .url("/")
        .host_str()
        .expect("loopback host")
        .to_owned();
    for (jar, expected) in [
        (cookie_jar(Vec::new()), ErrorKind::MissingCredential),
        (
            cookie_jar(vec![cookie_record("other", "x", &host, "/rest/", None)]),
            ErrorKind::AuthenticationExpired,
        ),
        (
            cookie_jar(vec![cookie_record(
                "__Secure-authjs.session-token",
                "expired",
                &host,
                "/rest/",
                Some(now() - time::Duration::seconds(1)),
            )]),
            ErrorKind::AuthenticationExpired,
        ),
        (
            cookie_jar(vec![cookie_record(
                "__Secure-authjs.session-token.1",
                "orphan",
                &host,
                "/rest/",
                None,
            )]),
            ErrorKind::AuthenticationExpired,
        ),
    ] {
        let error = PerplexityProvider::from_browser_jar_at(
            scope("a"),
            &jar,
            now(),
            &server.url("/"),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("invalid browser session");
        assert_eq!(error.kind(), expected);
    }
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn scope_source_capture_and_status_fail_closed() {
    let server = FakeHttpServer::start([]).await;
    let provider = manual_provider(&server, TOKEN_CANARY);
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
    assert_eq!(provider.descriptor().id, ProviderId::Perplexity);

    let error = PerplexityProvider::from_manual_capture_at(
        scope("a"),
        "curl 'https://www.perplexity.ai.evil.invalid/' -b 'next-auth.session-token=secret-canary'",
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect_err("suffix host rejected");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?} {error}").contains("secret-canary"));

    let error = PerplexityProvider::from_manual_capture_at(
        provider_scope(ProviderId::Abacus, "a"),
        TOKEN_CANARY,
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect_err("wrong provider scope");
    assert_eq!(error.kind(), ErrorKind::Api);
}

#[tokio::test]
async fn exact_status_redirect_oversize_and_cancellation_are_stable() {
    for (response, expected) in [
        (
            FakeHttpResponse::new(403, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(429, Vec::new()),
            ErrorKind::RateLimited,
        ),
        (FakeHttpResponse::new(201, CREDITS.to_vec()), ErrorKind::Api),
        (
            FakeHttpResponse::new(500, Vec::new()),
            ErrorKind::ProviderUnavailable,
        ),
        (
            FakeHttpResponse::new(302, Vec::new()).header("Location", "https://evil.invalid/"),
            ErrorKind::Parse,
        ),
    ] {
        let server = FakeHttpServer::start([response]).await;
        let error = manual_provider(&server, &format!("next-auth.session-token={TOKEN_CANARY}"))
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("status must fail");
        assert_eq!(error.kind(), expected);
    }

    let oversized =
        FakeHttpServer::start([FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1])]).await;
    assert_eq!(
        manual_provider(
            &oversized,
            &format!("next-auth.session-token={TOKEN_CANARY}"),
        )
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("oversize must fail")
        .kind(),
        ErrorKind::Parse
    );

    let cancelled = FakeHttpServer::start([]).await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation,
    );
    assert_eq!(
        manual_provider(
            &cancelled,
            &format!("next-auth.session-token={TOKEN_CANARY}"),
        )
        .fetch_at(&context, timestamp(NOW_SECONDS))
        .await
        .expect_err("cancelled")
        .kind(),
        ErrorKind::Network
    );
}

#[test]
fn parser_rejects_missing_extreme_deep_wide_and_wrong_scope_inputs() {
    for body in [
        br"{}".as_slice(),
        br#"{"balance_cents":1e100,"renewal_date_ts":1,"current_period_purchased_cents":0,"credit_grants":[],"total_usage_cents":0}"#.as_slice(),
    ] {
        assert_eq!(
            parse_credits_response(
                scope("a"),
                timestamp(NOW_SECONDS),
                body,
                ProviderSource::ManualCookie,
            )
            .expect_err("invalid response")
            .kind(),
            ErrorKind::Parse
        );
    }
    let deep = format!("{}0{}", "[".repeat(50), "]".repeat(50));
    let body = format!(
        r#"{{"balance_cents":0,"renewal_date_ts":1,"current_period_purchased_cents":0,"credit_grants":[],"total_usage_cents":0,"deep":{deep}}}"#
    );
    assert_eq!(
        parse_credits_response(
            scope("a"),
            timestamp(NOW_SECONDS),
            body.as_bytes(),
            ProviderSource::ManualCookie,
        )
        .expect_err("deep response")
        .kind(),
        ErrorKind::Parse
    );
    let wide = format!(
        r#"{{"balance_cents":0,"renewal_date_ts":1,"current_period_purchased_cents":0,"credit_grants":[],"total_usage_cents":0,"wide":[{}]}}"#,
        vec!["0"; 32_768].join(",")
    );
    assert_eq!(
        parse_credits_response(
            scope("a"),
            timestamp(NOW_SECONDS),
            wide.as_bytes(),
            ProviderSource::ManualCookie,
        )
        .expect_err("wide response")
        .kind(),
        ErrorKind::Parse
    );
    assert_eq!(
        parse_credits_response(
            scope("a"),
            timestamp(NOW_SECONDS),
            &vec![b' '; 2 * 1024 * 1024 + 1],
            ProviderSource::ManualCookie,
        )
        .expect_err("oversized response")
        .kind(),
        ErrorKind::Parse
    );
    assert_eq!(
        parse_credits_response(
            provider_scope(ProviderId::Abacus, "a"),
            timestamp(NOW_SECONDS),
            CREDITS,
            ProviderSource::ManualCookie,
        )
        .expect_err("wrong scope")
        .kind(),
        ErrorKind::Api
    );
}
