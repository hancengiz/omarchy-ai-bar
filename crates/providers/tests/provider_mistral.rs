use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ExactDecimal, ProviderId, ProviderInstanceId, Timestamp,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::mistral::{MistralProvider, MistralRouteSet, parse_billing_response};
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const BILLING: &[u8] = include_bytes!("../../../fixtures/providers/mistral/billing.json");
const VIBE: &[u8] = include_bytes!("../../../fixtures/providers/mistral/vibe.json");
const CREDITS: &[u8] = include_bytes!("../../../fixtures/providers/mistral/credits.json");
const FETCHED_AT: i64 = 1_763_985_600;
const SESSION_CANARY: &str = "mistral-session-canary";
const CSRF_CANARY: &str = "mistral-csrf-canary";
const ADMIN_CANARY: &str = "mistral-admin-only-canary";
const CSRF_COOKIE: &str = "csrftoken";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope_for(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new("mistral-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn scope(account: &str) -> AccountScope {
    scope_for(ProviderId::Mistral, account)
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn localhost_origin(server: &FakeHttpServer) -> Url {
    let mut origin = server.url("/");
    origin
        .set_host(Some("localhost"))
        .expect("localhost loopback host");
    origin
}

fn routes(admin: &FakeHttpServer, console: &FakeHttpServer) -> MistralRouteSet {
    MistralRouteSet::loopback(admin.url("/"), localhost_origin(console))
        .expect("loopback Mistral routes")
}

fn manual_cookie() -> String {
    format!(
        "ory_session_fixture={SESSION_CANARY}; csrftoken={CSRF_CANARY}; admin_secret={ADMIN_CANARY}"
    )
}

fn manual_provider(admin: &FakeHttpServer, console: &FakeHttpServer) -> MistralProvider {
    MistralProvider::from_manual_capture_routes(
        scope("account-a"),
        &manual_cookie(),
        routes(admin, console),
    )
    .expect("manual Mistral provider")
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

fn cookie_jar(source_id: u16, records: Vec<CookieRecord>) -> CookieJar {
    let source = CookieSourceId::new(source_id);
    let order = CookieImportOrder::new([source]).expect("cookie order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn assert_admin_usage_request(request: &CapturedHttpRequest, session: &str) {
    assert_eq!(request.method(), "GET");
    assert_eq!(request.target(), "/api/billing/v2/usage?month=11&year=2025");
    assert_eq!(request.header("accept"), Some("*/*"));
    assert_eq!(request.header("origin"), Some("https://admin.mistral.ai"));
    assert_eq!(
        request.header("referer"),
        Some("https://admin.mistral.ai/organization/usage")
    );
    assert_eq!(request.header("x-csrftoken"), Some(CSRF_CANARY));
    assert!(
        request
            .header("cookie")
            .is_some_and(|cookie| cookie.contains(session))
    );
}

#[test]
fn billing_fixture_projects_exact_month_cost_tokens_models_and_coverage() {
    let sample = parse_billing_response(
        scope("account-a"),
        timestamp(FETCHED_AT),
        BILLING,
        ProviderSource::ManualCookie,
    )
    .expect("billing fixture");

    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.cost().is_none());
    assert!(sample.balance().is_none());
    assert!(sample.extra_windows().is_empty());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("login method")
            .as_str(),
        "API spend: €0.4454 this month"
    );
    assert_eq!(sample.provenance()[0].source(), "mistral");
    assert_eq!(sample.provenance()[0].strategy(), "web");

    let usage = sample.cost_usage().expect("cost history");
    assert_eq!(usage.unit().as_str(), "EUR");
    assert_eq!(usage.history_days(), 24);
    assert!(usage.history_coverage_is_established());
    assert_eq!(usage.history_label(), Some("This month"));
    assert_eq!(usage.metered_amount(), Some(decimal("0.44536431")));
    assert_eq!(usage.history().amount(), Some(decimal("0.44536431")));
    assert_eq!(usage.history().total_tokens(), Some(15_368));
    assert_eq!(usage.history().token_mix().input_tokens(), Some(11_241));
    assert_eq!(usage.history().token_mix().output_tokens(), Some(4_097));
    assert_eq!(usage.history().token_mix().cache_read_tokens(), Some(30));
    assert_eq!(usage.session().amount(), Some(decimal("0.00064291")));
    assert_eq!(usage.session().total_tokens(), Some(2_612));
    assert_eq!(usage.updated_at().unix_timestamp(), 1_763_942_400);

    assert_eq!(
        usage
            .daily()
            .iter()
            .map(oab_domain::CostUsageDailyBucket::day)
            .collect::<Vec<_>>(),
        ["2025-11-14", "2025-11-15", "2025-11-24"]
    );
    assert_eq!(
        usage.daily()[0].metrics().amount(),
        Some(decimal("0.0247214"))
    );
    assert_eq!(usage.daily()[1].metrics().amount(), Some(decimal("0.42")));
    assert_eq!(usage.daily()[1].metrics().total_tokens(), Some(0));
    assert_eq!(
        usage.daily()[2].metrics().amount(),
        Some(decimal("0.00064291"))
    );
    assert_eq!(
        usage.daily()[0]
            .models()
            .iter()
            .map(oab_domain::CostUsageModelBreakdown::name)
            .collect::<Vec<_>>(),
        ["Mistral Small", "mistral-large-latest"]
    );
}

#[tokio::test]
async fn full_fetch_matches_request_goldens_and_keeps_console_cookie_minimal() {
    let admin = FakeHttpServer::start([
        FakeHttpResponse::new(200, BILLING.to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let console = FakeHttpServer::start([FakeHttpResponse::new(200, VIBE.to_vec())]).await;
    let provider = manual_provider(&admin, &console);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(FETCHED_AT),
        )
        .await
        .expect("full Mistral fetch");

    assert_eq!(provider.descriptor().id, ProviderId::Mistral);
    assert_eq!(provider.source(), ProviderSource::ManualCookie);
    let window = sample.extra_windows()[0].window();
    assert_eq!(
        sample.extra_windows()[0].id().as_str(),
        "mistral-monthly-plan"
    );
    assert_eq!(sample.extra_windows()[0].title().as_str(), "Monthly Plan");
    assert!((window.used_percent().expect("known").get() - 37.0).abs() < f64::EPSILON);
    assert_eq!(
        window.resets_at().map(Timestamp::unix_timestamp),
        Some(1_764_547_200)
    );
    let balance = sample.balance().expect("credit balance");
    assert_eq!(balance.amount(), decimal("13.25"));
    assert_eq!(balance.currency().as_str(), "USD");

    let admin_requests = admin.requests();
    assert_eq!(admin_requests.len(), 2);
    assert_admin_usage_request(&admin_requests[0], SESSION_CANARY);
    assert_eq!(admin_requests[1].target(), "/api/billing/credits");
    assert_eq!(admin_requests[1].header("accept"), Some("*/*"));
    assert_eq!(
        admin_requests[1].header("origin"),
        Some("https://admin.mistral.ai")
    );
    assert_eq!(
        admin_requests[1].header("referer"),
        Some("https://admin.mistral.ai/organization/billing")
    );
    assert_eq!(admin_requests[1].header("x-csrftoken"), Some(CSRF_CANARY));
    assert!(
        admin_requests[1]
            .header("cookie")
            .is_some_and(|cookie| cookie.contains(ADMIN_CANARY))
    );

    let console_requests = console.requests();
    assert_eq!(console_requests.len(), 1);
    assert_eq!(console_requests[0].method(), "GET");
    assert_eq!(
        console_requests[0].target(),
        "/api-ui/trpc/billing.vibeUsage?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%2C%22meta%22%3A%7B%22values%22%3A%5B%22undefined%22%5D%2C%22v%22%3A1%7D%7D%7D"
    );
    assert_eq!(console_requests[0].header("accept"), Some("*/*"));
    assert_eq!(console_requests[0].header("x-csrftoken"), Some(CSRF_CANARY));
    let cookie = console_requests[0]
        .header("cookie")
        .expect("console cookie");
    assert_eq!(
        cookie,
        format!("csrftoken={CSRF_CANARY}; ory_session_fixture={SESSION_CANARY}")
    );
    assert!(!cookie.contains(ADMIN_CANARY));
}

#[tokio::test]
async fn optional_endpoint_status_and_parse_failures_preserve_required_usage() {
    let malformed_credits = [
        br"{}".as_slice(),
        br#"{"wallet_amount":"15","currency":"USD"}"#.as_slice(),
        br#"{"wallet_amount":1e100,"currency":"USD"}"#.as_slice(),
    ];
    for credits in malformed_credits {
        let admin = FakeHttpServer::start([
            FakeHttpResponse::new(200, BILLING.to_vec()),
            FakeHttpResponse::new(200, credits.to_vec()),
        ])
        .await;
        let console = FakeHttpServer::start([FakeHttpResponse::new(
            200,
            br#"[{"result":{"data":{"json":{"usage_percentage":101}}}}]"#.to_vec(),
        )])
        .await;
        let sample = manual_provider(&admin, &console)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(FETCHED_AT),
            )
            .await
            .expect("optional parse failures are best effort");
        assert!(sample.balance().is_none());
        assert!(sample.extra_windows().is_empty());
        assert_eq!(
            sample
                .cost_usage()
                .expect("required usage")
                .history()
                .amount(),
            Some(decimal("0.44536431"))
        );
    }

    for status in [401, 403, 429, 500] {
        let admin = FakeHttpServer::start([
            FakeHttpResponse::new(200, BILLING.to_vec()),
            FakeHttpResponse::new(status, b"credit-body-canary".to_vec()),
        ])
        .await;
        let console =
            FakeHttpServer::start([FakeHttpResponse::new(status, b"vibe-body-canary".to_vec())])
                .await;
        let sample = manual_provider(&admin, &console)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(FETCHED_AT),
            )
            .await
            .expect("optional status failures are best effort");
        assert!(sample.balance().is_none());
        assert!(sample.extra_windows().is_empty());
    }
}

#[tokio::test]
async fn missing_csrf_skips_vibe_but_still_fetches_credits() {
    let admin = FakeHttpServer::start([
        FakeHttpResponse::new(200, BILLING.to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let console = FakeHttpServer::start([]).await;
    let provider = MistralProvider::from_manual_capture_routes(
        scope("account-a"),
        &format!("ory_session_fixture={SESSION_CANARY}"),
        routes(&admin, &console),
    )
    .expect("session without CSRF");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(FETCHED_AT),
        )
        .await
        .expect("credits without vibe");
    assert!(sample.extra_windows().is_empty());
    assert_eq!(
        sample.balance().expect("balance").amount(),
        decimal("13.25")
    );
    assert!(console.requests().is_empty());
    assert!(
        admin
            .requests()
            .iter()
            .all(|request| request.header("x-csrftoken").is_none())
    );
}

#[tokio::test]
async fn browser_profiles_rotate_only_after_required_auth_failure() {
    let admin = FakeHttpServer::start([
        FakeHttpResponse::new(401, b"first-profile-body-canary".to_vec()),
        FakeHttpResponse::new(200, BILLING.to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
    ])
    .await;
    let console = FakeHttpServer::start([FakeHttpResponse::new(200, VIBE.to_vec())]).await;
    let now = OffsetDateTime::from_unix_timestamp(FETCHED_AT).expect("fixture now");
    let first = cookie_jar(
        41,
        vec![
            cookie_record(
                "ory_session_first",
                "first-session",
                "127.0.0.1",
                "/api/",
                None,
            ),
            cookie_record(CSRF_COOKIE, CSRF_CANARY, "127.0.0.1", "/api/", None),
        ],
    );
    let second = cookie_jar(
        42,
        vec![
            cookie_record(
                "ory_session_second",
                "second-session",
                "127.0.0.1",
                "/api/",
                None,
            ),
            cookie_record(CSRF_COOKIE, CSRF_CANARY, "127.0.0.1", "/api/", None),
            cookie_record(
                "ory_session_second",
                "second-session",
                "localhost",
                "/api-ui/",
                None,
            ),
            cookie_record(CSRF_COOKIE, CSRF_CANARY, "localhost", "/api-ui/", None),
            cookie_record(
                "console_secret",
                "must-not-forward",
                "localhost",
                "/api-ui/",
                None,
            ),
        ],
    );
    let provider = MistralProvider::from_browser_jars_routes(
        scope("account-a"),
        &[&first, &second],
        now,
        routes(&admin, &console),
    )
    .expect("ordered browser sessions");
    assert_eq!(provider.source(), ProviderSource::BrowserSession);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(FETCHED_AT),
        )
        .await
        .expect("second browser session succeeds");
    assert_eq!(sample.extra_windows().len(), 1);

    let requests = admin.requests();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0]
            .header("cookie")
            .is_some_and(|value| value.contains("first-session"))
    );
    assert!(
        requests[1]
            .header("cookie")
            .is_some_and(|value| value.contains("second-session"))
    );
    assert!(
        requests[2]
            .header("cookie")
            .is_some_and(|value| value.contains("second-session"))
    );
    let console_cookie = console.requests()[0]
        .header("cookie")
        .expect("console cookie")
        .to_owned();
    assert!(console_cookie.contains("second-session"));
    assert!(!console_cookie.contains("console_secret"));
}

#[tokio::test]
async fn browser_non_auth_failure_does_not_advance_to_later_profile() {
    let admin = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let console = FakeHttpServer::start([]).await;
    let now = OffsetDateTime::from_unix_timestamp(FETCHED_AT).expect("fixture now");
    let first = cookie_jar(
        43,
        vec![cookie_record(
            "ory_session_first",
            "first-session",
            "127.0.0.1",
            "/api/",
            None,
        )],
    );
    let second = cookie_jar(
        44,
        vec![cookie_record(
            "ory_session_second",
            "second-session",
            "127.0.0.1",
            "/api/",
            None,
        )],
    );
    let provider = MistralProvider::from_browser_jars_routes(
        scope("account-a"),
        &[&first, &second],
        now,
        routes(&admin, &console),
    )
    .expect("browser sessions");
    assert_eq!(
        provider
            .fetch_at(
                &context("account-a", ProviderSource::BrowserSession),
                timestamp(FETCHED_AT),
            )
            .await
            .expect_err("required server failure")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(admin.requests().len(), 1);
    assert!(
        admin.requests()[0]
            .header("cookie")
            .is_some_and(|value| value.contains("first-session"))
    );
}

#[tokio::test]
async fn required_status_redirect_truncation_and_malformed_json_are_stable() {
    let cases = [
        (
            FakeHttpResponse::new(401, b"auth-body-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, b"permission-body-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (FakeHttpResponse::new(201, BILLING.to_vec()), ErrorKind::Api),
        (
            FakeHttpResponse::new(429, b"rate-body-canary".to_vec()),
            ErrorKind::Api,
        ),
        (
            FakeHttpResponse::new(503, b"server-body-canary".to_vec()),
            ErrorKind::Api,
        ),
        (
            FakeHttpResponse::new(302, Vec::new()).header("Location", "/login"),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::truncated(200, BILLING.len() + 7, BILLING.to_vec()),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(200, br#"{"completion":42}"#.to_vec()),
            ErrorKind::Parse,
        ),
    ];
    for (response, expected) in cases {
        let admin = FakeHttpServer::start([response]).await;
        let console = FakeHttpServer::start([]).await;
        let error = manual_provider(&admin, &console)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(FETCHED_AT),
            )
            .await
            .expect_err("required failure");
        assert_eq!(error.kind(), expected);
        let diagnostic = format!("{error:?} {error}");
        for canary in [
            "auth-body-canary",
            "permission-body-canary",
            "rate-body-canary",
            "server-body-canary",
            SESSION_CANARY,
            CSRF_CANARY,
        ] {
            assert!(!diagnostic.contains(canary));
        }
    }
}

#[tokio::test]
async fn required_and_optional_cancellation_propagate_as_network() {
    let admin = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let console = FakeHttpServer::start([]).await;
    let provider = manual_provider(&admin, &console);
    let ctx = context("account-a", ProviderSource::ManualCookie);
    let cancellation = ctx.cancellation().clone();
    let fetch = tokio::spawn(async move { provider.fetch_at(&ctx, timestamp(FETCHED_AT)).await });
    admin.wait_for_request_count(1).await;
    cancellation.cancel();
    assert_eq!(
        fetch
            .await
            .expect("fetch task")
            .expect_err("required cancellation")
            .kind(),
        ErrorKind::Network
    );

    let admin = FakeHttpServer::start([FakeHttpResponse::new(200, BILLING.to_vec())]).await;
    let console = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(&admin, &console);
    let ctx = context("account-a", ProviderSource::ManualCookie);
    let cancellation = ctx.cancellation().clone();
    let fetch = tokio::spawn(async move { provider.fetch_at(&ctx, timestamp(FETCHED_AT)).await });
    console.wait_for_request_count(1).await;
    cancellation.cancel();
    assert_eq!(
        fetch
            .await
            .expect("fetch task")
            .expect_err("optional cancellation")
            .kind(),
        ErrorKind::Network
    );
    assert_eq!(admin.requests().len(), 1);
}

#[test]
fn manual_capture_requires_exact_nonempty_session_cookie_and_redacts_failures() {
    let admin_origin = Url::parse("http://127.0.0.1:32101").expect("admin origin");
    let console_origin = Url::parse("http://localhost:32102").expect("console origin");
    let routes =
        || MistralRouteSet::loopback(admin_origin.clone(), console_origin.clone()).expect("routes");
    for raw in [
        "csrftoken=only-csrf",
        "Ory_session_wrong_case=value",
        "ory_session_fixture=",
    ] {
        let error = MistralProvider::from_manual_capture_routes(scope("account-a"), raw, routes())
            .expect_err("missing authenticated session");
        assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    }

    let provider = MistralProvider::from_manual_capture_routes(
        scope("account-a"),
        "curl 'https://admin.mistral.ai/api/billing/v2/usage?month=1&year=2000' -b 'ory_session_fixture=valid'",
        routes(),
    )
    .expect("exact captured host");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);

    let error = MistralProvider::from_manual_capture_routes(
        scope("account-a"),
        "curl 'https://admin.mistral.ai.evil.invalid/' -b 'ory_session_fixture=secret-canary'",
        routes(),
    )
    .expect_err("suffix host rejected");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?} {error}").contains("secret-canary"));
    assert!(
        MistralRouteSet::loopback(
            Url::parse("https://example.com").expect("public origin"),
            console_origin,
        )
        .is_err()
    );
}

#[test]
fn browser_cookie_selection_enforces_host_path_expiry_case_and_value() {
    let admin_origin = Url::parse("http://127.0.0.1:32111").expect("admin origin");
    let console_origin = Url::parse("http://localhost:32112").expect("console origin");
    let routes =
        || MistralRouteSet::loopback(admin_origin.clone(), console_origin.clone()).expect("routes");
    let now = OffsetDateTime::from_unix_timestamp(FETCHED_AT).expect("fixture now");
    let empty = cookie_jar(50, Vec::new());
    assert_eq!(
        MistralProvider::from_browser_jars_routes(scope("a"), &[&empty], now, routes())
            .expect_err("empty jar")
            .kind(),
        ErrorKind::MissingCredential
    );

    let expired = cookie_jar(
        51,
        vec![cookie_record(
            "ory_session_expired",
            "expired",
            "127.0.0.1",
            "/api/",
            now.checked_sub(time::Duration::SECOND),
        )],
    );
    let wrong_path = cookie_jar(
        52,
        vec![cookie_record(
            "ory_session_path",
            "wrong-path",
            "127.0.0.1",
            "/other/",
            None,
        )],
    );
    let wrong_case = cookie_jar(
        53,
        vec![cookie_record(
            "Ory_session_case",
            "wrong-case",
            "127.0.0.1",
            "/api/",
            None,
        )],
    );
    let empty_value = cookie_jar(
        54,
        vec![cookie_record(
            "ory_session_empty",
            "",
            "127.0.0.1",
            "/api/",
            None,
        )],
    );
    for jar in [&expired, &wrong_path, &wrong_case, &empty_value] {
        assert_eq!(
            MistralProvider::from_browser_jars_routes(scope("a"), &[jar], now, routes())
                .expect_err("inactive browser session")
                .kind(),
            ErrorKind::AuthenticationExpired
        );
    }
}

#[tokio::test]
async fn scope_and_source_isolation_precede_network() {
    let admin = FakeHttpServer::start([]).await;
    let console = FakeHttpServer::start([]).await;
    let provider = manual_provider(&admin, &console);
    for mismatched in [
        context("account-b", ProviderSource::ManualCookie),
        context("account-a", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&mismatched, timestamp(FETCHED_AT))
                .await
                .expect_err("scope/source mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(admin.requests().is_empty());
    assert!(console.requests().is_empty());

    let error = MistralProvider::from_manual_capture_routes(
        scope_for(ProviderId::Manus, "account-a"),
        &manual_cookie(),
        routes(&admin, &console),
    )
    .expect_err("wrong provider scope");
    assert_eq!(error.kind(), ErrorKind::Api);
}

#[test]
fn price_precedence_value_paid_currency_fallback_and_cost_only_categories_match_baseline() {
    let body = br#"{
        "completion": {"models": {"model::suffix": {
            "input": [{
                "billing_metric":"in", "billing_group":"g",
                "billing_display_name":"  Display Model  ",
                "timestamp":"2025-11-24T00:00:00Z", "value":999, "value_paid":2
            }]
        }}},
        "ocr": {"models": {"ocr::suffix": {
            "input": [{
                "billing_metric":"ocr", "billing_group":"g",
                "timestamp":"2025-11-24T00:00:00Z", "value":3
            }]
        }}},
        "start_date":"2025-11-01T00:00:00Z",
        "end_date":"2025-11-30T00:00:00Z",
        "currency":" ", "currency_symbol":" ",
        "prices":[
            {"billing_metric":"in","billing_group":"g","price":"5"},
            {"billing_metric":"in","billing_group":"g","price":"2"},
            {"billing_metric":"ocr","billing_group":"g","price":"10"}
        ]
    }"#;
    let sample = parse_billing_response(
        scope("a"),
        timestamp(FETCHED_AT),
        body,
        ProviderSource::ManualCookie,
    )
    .expect("aggregation variants");
    assert_eq!(
        sample.identity().login_method().expect("login").as_str(),
        "API spend: ¤34.0000 this month"
    );
    let usage = sample.cost_usage().expect("cost usage");
    assert_eq!(usage.unit().as_str(), "XXX");
    assert_eq!(usage.history().amount(), Some(decimal("34")));
    assert_eq!(usage.history().total_tokens(), Some(2));
    assert_eq!(usage.daily()[0].metrics().total_tokens(), Some(2));
    assert_eq!(
        usage.daily()[0]
            .models()
            .iter()
            .map(oab_domain::CostUsageModelBreakdown::name)
            .collect::<Vec<_>>(),
        ["Display Model", "ocr"]
    );
}

#[test]
fn missing_metadata_uses_observed_coverage_and_empty_data_stays_unknown() {
    let mut fixture: serde_json::Value = serde_json::from_slice(BILLING).expect("fixture JSON");
    fixture
        .as_object_mut()
        .expect("object")
        .remove("start_date");
    fixture.as_object_mut().expect("object").remove("end_date");
    let body = serde_json::to_vec(&fixture).expect("fixture body");
    let sample = parse_billing_response(
        scope("a"),
        timestamp(FETCHED_AT),
        &body,
        ProviderSource::ManualCookie,
    )
    .expect("observed coverage");
    let usage = sample.cost_usage().expect("cost usage");
    assert_eq!(usage.history_days(), 11);
    assert!(usage.history_coverage_is_established());
    assert_eq!(usage.history_label(), None);
    assert_eq!(usage.history().amount(), Some(decimal("0.44536431")));

    let sample = parse_billing_response(
        scope("a"),
        timestamp(FETCHED_AT),
        br"{}",
        ProviderSource::ManualCookie,
    )
    .expect("empty billing response");
    let usage = sample.cost_usage().expect("unknown history");
    assert_eq!(usage.history_days(), 1);
    assert!(!usage.history_coverage_is_established());
    assert_eq!(usage.history().amount(), None);
    assert_eq!(usage.history().total_tokens(), None);
    assert_eq!(usage.session().amount(), None);
    assert_eq!(
        sample.identity().login_method().expect("login").as_str(),
        "API spend: ¤0.0000 this month"
    );
}

#[test]
fn unplaced_missing_or_negative_rows_fail_closed_without_losing_required_snapshot() {
    for (timestamp_field, value) in [
        (r#""timestamp":"not-a-date!","#, 1),
        ("", 1),
        (r#""timestamp":"2025-11-24T00:00:00Z","#, -1),
    ] {
        let body = format!(
            r#"{{
                "completion":{{"models":{{"model":{{"input":[{{
                    "billing_metric":"in","billing_group":"g",{timestamp_field}"value":{value}
                }}]}}}}}},
                "start_date":"2025-11-01T00:00:00Z",
                "end_date":"2025-11-30T00:00:00Z",
                "currency":"USD",
                "prices":[{{"billing_metric":"in","billing_group":"g","price":"1"}}]
            }}"#
        );
        let sample = parse_billing_response(
            scope("a"),
            timestamp(FETCHED_AT),
            body.as_bytes(),
            ProviderSource::ManualCookie,
        )
        .expect("required aggregate remains usable");
        let usage = sample.cost_usage().expect("cost usage");
        assert_eq!(usage.history().amount(), None);
        assert_eq!(usage.history().total_tokens(), None);
        assert_eq!(usage.session().amount(), None);
        if value < 0 {
            assert_eq!(
                sample.identity().login_method().expect("login").as_str(),
                "API spend: USD0.0000 this month"
            );
        }
    }
}

#[test]
fn bounded_json_and_semantic_limits_reject_adversarial_payloads() {
    let mut deep = "0".to_owned();
    for _ in 0..41 {
        deep = format!("[{deep}]");
    }
    let long_model = "m".repeat(161);
    let oversized_name = format!(r#"{{"completion":{{"models":{{"{long_model}":{{}}}}}}}}"#);
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        br#"{"completion":42}"#.to_vec(),
        br#"{"prices":[{"price":3}]}"#.to_vec(),
        br#"{"currency":"USDD"}"#.to_vec(),
        deep.into_bytes(),
        oversized_name.into_bytes(),
    ];
    for body in cases {
        let error = parse_billing_response(
            scope("a"),
            timestamp(FETCHED_AT),
            &body,
            ProviderSource::ManualCookie,
        )
        .expect_err("bounded parse rejection");
        assert_eq!(error.kind(), ErrorKind::Parse);
    }

    let wrong_provider = parse_billing_response(
        scope_for(ProviderId::Manus, "a"),
        timestamp(FETCHED_AT),
        BILLING,
        ProviderSource::ManualCookie,
    )
    .expect_err("wrong provider scope");
    assert_eq!(wrong_provider.kind(), ErrorKind::Api);
    let wrong_source = parse_billing_response(
        scope("a"),
        timestamp(FETCHED_AT),
        BILLING,
        ProviderSource::ApiKey,
    )
    .expect_err("wrong source");
    assert_eq!(wrong_source.kind(), ErrorKind::Api);
}
