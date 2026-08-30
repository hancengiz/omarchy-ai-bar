use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::providers::sakana::{
    SakanaProvider, parse_billing_html, parse_pay_as_you_go_html,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const BILLING: &[u8] = include_bytes!("../../../fixtures/providers/sakana/billing.html");
const PAYG: &[u8] = include_bytes!("../../../fixtures/providers/sakana/pay_as_you_go.html");
const COOKIE_CANARY: &str = "sakana-cookie-canary";
const NOW_SECONDS: i64 = 1_782_222_000;

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Sakana,
        ProviderInstanceId::new("sakana-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn manual_provider(server: &FakeHttpServer, capture: &str) -> SakanaProvider {
    SakanaProvider::from_manual_capture_at(
        scope("account-a"),
        capture,
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("Sakana provider")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "{actual} != {expected}"
    );
}

#[test]
fn golden_pages_map_utc_windows_plan_and_payg_details() {
    let payg = parse_pay_as_you_go_html(PAYG)
        .expect("PAYG parse")
        .expect("PAYG fields");
    assert_eq!(payg.credit_balance().to_string(), "12.34");
    assert_eq!(
        payg.period_usage_total().map(|value| value.to_string()),
        Some("5.67".to_owned())
    );
    assert_eq!(payg.period_label(), Some("Jun 02, 2026 - Jul 01, 2026"));

    let sample = parse_billing_html(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        BILLING,
        Some(payg),
    )
    .expect("billing parse");
    let primary = sample.primary().expect("five-hour window");
    assert_percent(
        primary.used_percent().expect("five-hour percent").get(),
        92.0,
    );
    assert_eq!(
        primary.duration().expect("five-hour duration").seconds(),
        18_000
    );
    assert_eq!(
        primary
            .resets_at()
            .expect("five-hour reset")
            .unix_timestamp(),
        1_782_226_380
    );
    let secondary = sample.secondary().expect("weekly window");
    assert_percent(
        secondary.used_percent().expect("weekly percent").get(),
        32.0,
    );
    assert_eq!(
        secondary.duration().expect("weekly duration").seconds(),
        604_800
    );
    assert_eq!(
        secondary
            .resets_at()
            .expect("weekly reset")
            .unix_timestamp(),
        1_782_691_200
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Standard $20/mo"
    );
    let section = sample.detail_sections().first().expect("PAYG details");
    assert_eq!(section.title(), Some("Extra usage"));
    assert_eq!(section.rows()[0].label(), "Balance");
    assert_eq!(section.rows()[0].value(), "$12.34");
    assert_eq!(section.rows()[1].value(), "$5.67");
    assert_eq!(
        section.rows()[1].secondary_value(),
        Some("Jun 02, 2026 - Jul 01, 2026")
    );
}

#[test]
fn missing_or_invalid_optional_markup_never_invents_payg_data() {
    assert!(
        parse_pay_as_you_go_html(BILLING)
            .expect("non-PAYG page")
            .is_none()
    );
    let missing_total = String::from_utf8(PAYG.to_vec())
        .expect("fixture UTF-8")
        .replace(
            r#"<span class="text-muted-foreground text-sm">Total<!-- -->: <!-- -->$5.67</span>"#,
            "",
        );
    let parsed = parse_pay_as_you_go_html(missing_total.as_bytes())
        .expect("partial PAYG")
        .expect("balance remains available");
    assert_eq!(parsed.credit_balance().to_string(), "12.34");
    assert!(parsed.period_usage_total().is_none());
}

#[tokio::test]
async fn manual_cookie_fetch_sends_the_exact_fixed_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, BILLING.to_vec())]).await;
    let provider = manual_provider(&server, &format!("session={COOKIE_CANARY}; theme=dark"));
    let sample = provider
        .fetch_required_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("required fetch");
    assert_eq!(provider.descriptor().id, ProviderId::Sakana);
    assert_percent(
        sample
            .primary()
            .expect("five-hour")
            .used_percent()
            .expect("percent")
            .get(),
        92.0,
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/billing");
    assert_eq!(
        requests[0].header("cookie"),
        Some("session=sakana-cookie-canary; theme=dark")
    );
    assert_eq!(
        requests[0].header("accept"),
        Some("text/html,application/xhtml+xml")
    );
    assert_eq!(
        requests[0].header("accept-language"),
        Some("en-US,en;q=0.9")
    );
    assert_eq!(requests[0].body(), b"");
}

#[tokio::test]
async fn copied_curl_url_is_host_bound_and_its_query_is_ignored() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, BILLING.to_vec())]).await;
    let capture = format!(
        "curl 'https://console.sakana.ai/billing?tab=evil' -H 'Cookie: session={COOKIE_CANARY}'"
    );
    let provider = manual_provider(&server, &capture);
    provider
        .fetch_required_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("cURL fetch");
    assert_eq!(server.requests()[0].target(), "/billing");

    let wrong_host = SakanaProvider::from_manual_capture_at(
        scope("account-a"),
        "curl 'https://evil.example/billing' -H 'Cookie: session=secret-canary'",
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect_err("wrong capture host must fail");
    assert_eq!(wrong_host.kind(), ErrorKind::Parse);
    assert!(!format!("{wrong_host:?} {wrong_host}").contains("secret-canary"));
}

#[tokio::test]
async fn optional_payg_is_requested_concurrently_and_merged_when_fast() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BILLING.to_vec()),
        FakeHttpResponse::new(200, PAYG.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, &format!("session={COOKIE_CANARY}"));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("enriched fetch");
    assert_eq!(sample.detail_sections().len(), 1);
    let mut targets = server
        .requests()
        .iter()
        .map(|request| request.target().to_owned())
        .collect::<Vec<_>>();
    targets.sort();
    assert_eq!(targets, ["/billing", "/billing?tab=payAsYouGo"]);
}

#[tokio::test]
async fn optional_failure_is_ignored_but_required_failure_is_not() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BILLING.to_vec()),
        FakeHttpResponse::new(500, b"private optional body".to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "session=ok");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("required data survives optional failure");
    assert!(sample.detail_sections().is_empty());

    for (status, expected) in [
        (401, ErrorKind::AuthenticationExpired),
        (403, ErrorKind::AuthenticationExpired),
        (429, ErrorKind::RateLimited),
        (201, ErrorKind::Api),
        (500, ErrorKind::ProviderUnavailable),
    ] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(status, Vec::new())]).await;
        let provider = manual_provider(&server, "session=expired");
        let error = provider
            .fetch_required_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("status must fail");
        assert_eq!(error.kind(), expected);
    }
}

#[tokio::test]
async fn redirects_truncation_oversize_and_cancellation_are_bounded() {
    let redirect = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", "https://evil.example/login")
    ])
    .await;
    let error = manual_provider(&redirect, "session=expired")
        .fetch_required_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("redirect must fail");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert_eq!(redirect.requests().len(), 1);

    let truncated = FakeHttpServer::start([FakeHttpResponse::truncated(
        200,
        BILLING.len() + 10,
        BILLING.to_vec(),
    )])
    .await;
    let error = manual_provider(&truncated, "session=value")
        .fetch_required_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("truncated response must fail");
    assert_eq!(error.kind(), ErrorKind::Parse);

    let oversized_body = vec![b'x'; 2 * 1024 * 1024 + 1];
    let oversized = FakeHttpServer::start([FakeHttpResponse::new(200, oversized_body)]).await;
    let error = manual_provider(&oversized, "session=value")
        .fetch_required_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("oversized response must fail");
    assert_eq!(error.kind(), ErrorKind::Parse);

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(&stalled, "session=value");
    let cancellation = CancellationToken::new();
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation.clone(),
    );
    let task = tokio::spawn(async move {
        provider
            .fetch_required_at(&context, timestamp(NOW_SECONDS))
            .await
    });
    stalled.wait_for_request_count(1).await;
    cancellation.cancel();
    let error = task
        .await
        .expect("fetch task")
        .expect_err("cancellation must win");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[test]
fn parser_rejects_window_bleed_invalid_percent_and_html_bounds() {
    let billing = String::from_utf8(BILLING.to_vec()).expect("fixture UTF-8");
    let missing_primary = billing.replace(
        r#"<p class="text-muted-foreground text-sm">92% used</p>"#,
        "",
    );
    let error = parse_billing_html(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        missing_primary.as_bytes(),
        None,
    )
    .expect_err("weekly percent must not bleed into five-hour");
    assert_eq!(error.kind(), ErrorKind::Parse);

    for percent in ["101", "NaN", "-1"] {
        let malformed = billing.replace("92% used", &format!("{percent}% used"));
        let error = parse_billing_html(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            malformed.as_bytes(),
            None,
        )
        .expect_err("invalid percent");
        assert_eq!(error.kind(), ErrorKind::Parse);
    }
    assert_eq!(
        parse_billing_html(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            b"<main>Billing</main>",
            None,
        )
        .expect_err("missing windows")
        .kind(),
        ErrorKind::Parse
    );
    assert_eq!(
        parse_billing_html(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            &vec![b'x'; 2 * 1024 * 1024 + 1],
            None,
        )
        .expect_err("oversized HTML")
        .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn scope_source_and_diagnostics_are_isolated_and_redacted() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, BILLING.to_vec())]).await;
    let provider = manual_provider(&server, &format!("session={COOKIE_CANARY}"));
    let wrong_source = provider
        .fetch_required_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("wrong source");
    assert_eq!(wrong_source.kind(), ErrorKind::Api);
    let wrong_account = provider
        .fetch_required_at(
            &context("account-b", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("wrong account");
    assert_eq!(wrong_account.kind(), ErrorKind::Api);
    assert!(server.requests().is_empty());

    let diagnostics = format!("{provider:?} {wrong_source:?} {wrong_source}");
    assert!(!diagnostics.contains(COOKIE_CANARY));
    assert!(!diagnostics.contains("account-a"));
    assert!(diagnostics.len() < 512);
}

#[test]
fn missing_unsafe_and_wrong_provider_inputs_fail_before_network() {
    for capture in ["", "Cookie:", "session=ok\r\nx-evil: injected"] {
        let error =
            SakanaProvider::new_manual(scope("account-a"), capture).expect_err("invalid capture");
        assert!(matches!(
            error.kind(),
            ErrorKind::MissingCredential | ErrorKind::Parse
        ));
    }
    let wrong_scope = AccountScope::new(
        ProviderId::T3Chat,
        ProviderInstanceId::new("wrong-provider").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    assert_eq!(
        SakanaProvider::new_manual(wrong_scope, "session=value")
            .expect_err("wrong provider")
            .kind(),
        ErrorKind::Api
    );
}
