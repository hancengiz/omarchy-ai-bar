use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::abacus::{AbacusProvider, AbacusRouteSet, parse_usage_responses};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const COMPUTE: &[u8] = include_bytes!("../../../fixtures/providers/abacus/compute_points.json");
const BILLING: &[u8] = include_bytes!("../../../fixtures/providers/abacus/billing_info.json");
const COOKIE_CANARY: &str = "abacus-cookie-canary";
const NOW_SECONDS: i64 = 1_780_272_000;

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Abacus,
        ProviderInstanceId::new("abacus-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn routes(compute: &FakeHttpServer, billing: &FakeHttpServer) -> AbacusRouteSet {
    AbacusRouteSet::loopback(compute.url("/ignored"), billing.url("/ignored?bad=true"))
        .expect("loopback routes")
}

fn manual_provider(
    compute: &FakeHttpServer,
    billing: &FakeHttpServer,
    capture: &str,
) -> AbacusProvider {
    AbacusProvider::from_manual_capture_routes(
        scope("account-a"),
        capture,
        routes(compute, billing),
    )
    .expect("manual provider")
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
    let source = CookieSourceId::new(21);
    let order = CookieImportOrder::new([source]).expect("cookie source order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

#[test]
fn golden_responses_map_credits_cycle_and_plan() {
    let sample = parse_usage_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        COMPUTE,
        Some(BILLING),
        ProviderSource::ManualCookie,
    )
    .expect("Abacus fixture");
    let primary = sample.primary().expect("credit window");
    assert_percent(primary.used_percent().expect("percent").get(), 70.0);
    assert_eq!(
        primary.duration().expect("billing duration").seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        primary.resets_at().expect("billing reset").unix_timestamp(),
        1_782_864_000
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("credit description")
            .as_str(),
        "525 / 750 credits"
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Pro"
    );
    assert_eq!(sample.fetched_at().unix_timestamp(), NOW_SECONDS);
}

#[tokio::test]
async fn manual_fetch_sends_both_exact_requests_concurrently() {
    let compute = FakeHttpServer::start([FakeHttpResponse::new(200, COMPUTE.to_vec())]).await;
    let billing = FakeHttpServer::start([FakeHttpResponse::new(200, BILLING.to_vec())]).await;
    let provider = manual_provider(
        &compute,
        &billing,
        &format!("sessionid={COOKIE_CANARY}; theme=dark"),
    );
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert_eq!(provider.descriptor().id, ProviderId::Abacus);
    assert_percent(
        sample
            .primary()
            .expect("window")
            .used_percent()
            .expect("percent")
            .get(),
        70.0,
    );

    let compute_requests = compute.requests();
    assert_eq!(compute_requests.len(), 1);
    assert_eq!(compute_requests[0].method(), "GET");
    assert_eq!(
        compute_requests[0].target(),
        "/api/_getOrganizationComputePoints"
    );
    assert_eq!(
        compute_requests[0].header("accept"),
        Some("application/json")
    );
    assert_eq!(
        compute_requests[0].header("content-type"),
        Some("application/json")
    );
    assert_eq!(
        compute_requests[0].header("cookie"),
        Some("sessionid=abacus-cookie-canary; theme=dark")
    );
    assert!(compute_requests[0].body().is_empty());

    let billing_requests = billing.requests();
    assert_eq!(billing_requests.len(), 1);
    assert_eq!(billing_requests[0].method(), "POST");
    assert_eq!(billing_requests[0].target(), "/api/_getBillingInfo");
    assert_eq!(
        billing_requests[0].header("accept"),
        Some("application/json")
    );
    assert_eq!(
        billing_requests[0].header("content-type"),
        Some("application/json")
    );
    assert_eq!(billing_requests[0].body(), b"{}");
}

#[tokio::test]
async fn copied_curl_is_host_bound_and_query_is_ignored() {
    let compute = FakeHttpServer::start([FakeHttpResponse::new(200, COMPUTE.to_vec())]).await;
    let billing = FakeHttpServer::start([]).await;
    let capture = format!(
        "curl 'https://apps.abacus.ai/chatllm/admin/compute-points-usage?evil=true' -H 'Cookie: sessionid={COOKIE_CANARY}'"
    );
    let provider = manual_provider(&compute, &billing, &capture);
    provider
        .fetch_required_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("captured fetch");
    assert_eq!(
        compute.requests()[0].target(),
        "/api/_getOrganizationComputePoints"
    );

    let error = AbacusProvider::from_manual_capture_routes(
        scope("account-a"),
        "curl 'https://evil.example/api' -H 'Cookie: sessionid=private-canary'",
        routes(&compute, &billing),
    )
    .expect_err("wrong host must fail");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?} {error}").contains("private-canary"));
}

#[tokio::test]
async fn browser_cookie_selection_is_target_specific() {
    let compute = FakeHttpServer::start([FakeHttpResponse::new(200, COMPUTE.to_vec())]).await;
    let billing = FakeHttpServer::start([FakeHttpResponse::new(200, BILLING.to_vec())]).await;
    let jar = cookie_jar(vec![
        cookie_record("sessionid", COOKIE_CANARY, "/api", None),
        cookie_record(
            "compute_marker",
            "compute-only",
            "/api/_getOrganizationComputePoints",
            None,
        ),
        cookie_record(
            "billing_marker",
            "billing-only",
            "/api/_getBillingInfo",
            None,
        ),
    ]);
    let provider = AbacusProvider::from_browser_jar_routes(
        scope("account-a"),
        &jar,
        now(),
        routes(&compute, &billing),
    )
    .expect("browser provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fetch");

    let compute_requests = compute.requests();
    let compute_cookie = compute_requests[0]
        .header("cookie")
        .expect("compute cookie");
    assert!(compute_cookie.contains("sessionid=abacus-cookie-canary"));
    assert!(compute_cookie.contains("compute_marker=compute-only"));
    assert!(!compute_cookie.contains("billing-only"));
    let billing_requests = billing.requests();
    let billing_cookie = billing_requests[0]
        .header("cookie")
        .expect("billing cookie");
    assert!(billing_cookie.contains("sessionid=abacus-cookie-canary"));
    assert!(billing_cookie.contains("billing_marker=billing-only"));
    assert!(!billing_cookie.contains("compute-only"));
}

#[tokio::test]
async fn browser_missing_expired_and_anonymous_jars_fail_before_network() {
    let compute = FakeHttpServer::start([]).await;
    let billing = FakeHttpServer::start([]).await;
    for (jar, expected) in [
        (cookie_jar(Vec::new()), ErrorKind::MissingCredential),
        (
            cookie_jar(vec![cookie_record(
                "sessionid",
                "expired-canary",
                "/",
                Some(now() - time::Duration::seconds(1)),
            )]),
            ErrorKind::AuthenticationExpired,
        ),
        (
            cookie_jar(vec![cookie_record(
                "csrftoken",
                "anonymous-canary",
                "/",
                None,
            )]),
            ErrorKind::AuthenticationExpired,
        ),
    ] {
        let error = AbacusProvider::from_browser_jar_routes(
            scope("account-a"),
            &jar,
            now(),
            routes(&compute, &billing),
        )
        .expect_err("unusable jar");
        assert_eq!(error.kind(), expected);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("expired-canary"));
        assert!(!diagnostic.contains("anonymous-canary"));
    }
    assert!(compute.requests().is_empty());
    assert!(billing.requests().is_empty());
}

#[tokio::test]
async fn optional_billing_failure_never_erases_required_credits() {
    for response in [
        FakeHttpResponse::new(500, b"private optional response".to_vec()),
        FakeHttpResponse::new(200, b"not json".to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
    ] {
        let compute = FakeHttpServer::start([FakeHttpResponse::new(200, COMPUTE.to_vec())]).await;
        let billing = FakeHttpServer::start([response]).await;
        let provider = manual_provider(&compute, &billing, "sessionid=valid");
        let sample = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("required credits survive");
        assert_percent(
            sample
                .primary()
                .expect("window")
                .used_percent()
                .expect("percent")
                .get(),
            70.0,
        );
        assert!(sample.identity().login_method().is_none());
    }
}

#[tokio::test]
async fn required_status_redirect_truncation_and_cancellation_are_stable() {
    for (response, expected) in [
        (
            FakeHttpResponse::new(401, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(429, Vec::new()),
            ErrorKind::RateLimited,
        ),
        (
            FakeHttpResponse::new(500, Vec::new()),
            ErrorKind::ProviderUnavailable,
        ),
        (
            FakeHttpResponse::new(302, Vec::new()).header("location", "https://evil.example"),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::truncated(200, COMPUTE.len() + 20, COMPUTE.to_vec()),
            ErrorKind::Parse,
        ),
    ] {
        let compute = FakeHttpServer::start([response]).await;
        let billing = FakeHttpServer::start([]).await;
        let provider = manual_provider(&compute, &billing, "sessionid=status-test");
        let error = provider
            .fetch_required_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("required failure");
        assert_eq!(error.kind(), expected);
    }

    let compute = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let billing = FakeHttpServer::start([]).await;
    let provider = manual_provider(&compute, &billing, "sessionid=cancel-test");
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
    compute.wait_for_request_count(1).await;
    cancellation.cancel();
    let error = task
        .await
        .expect("fetch task")
        .expect_err("cancellation fails");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[test]
fn parser_rejects_auth_missing_oversize_deep_and_extreme_inputs() {
    let auth = br#"{"success":false,"error":"Session expired: private-canary"}"#;
    let error = parse_usage_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        auth,
        None,
        ProviderSource::ManualCookie,
    )
    .expect_err("auth envelope");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert!(!format!("{error:?} {error}").contains("private-canary"));

    for body in [
        br#"{"success":true,"result":{"totalComputePoints":1}}"#.to_vec(),
        br#"{"success":true,"result":{"totalComputePoints":1e100,"computePointsLeft":0}}"#.to_vec(),
        vec![b'x'; 2 * 1024 * 1024 + 1],
    ] {
        let error = parse_usage_responses(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            &body,
            None,
            ProviderSource::ManualCookie,
        )
        .expect_err("invalid required payload");
        assert_eq!(error.kind(), ErrorKind::Parse);
    }

    let nested = format!("{}0{}", "[".repeat(40), "]".repeat(40));
    let deep = format!(
        r#"{{"success":true,"result":{{"totalComputePoints":1,"computePointsLeft":0,"deep":{nested} }} }}"#
    );
    let error = parse_usage_responses(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        deep.as_bytes(),
        None,
        ProviderSource::ManualCookie,
    )
    .expect_err("deep JSON");
    assert_eq!(error.kind(), ErrorKind::Parse);
}

#[test]
fn scope_source_and_diagnostics_are_isolated() {
    let wrong_scope = AccountScope::new(
        ProviderId::Sakana,
        ProviderInstanceId::new("wrong-provider").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    for (scope, source) in [
        (wrong_scope, ProviderSource::ManualCookie),
        (scope("account-a"), ProviderSource::ApiKey),
    ] {
        let error = parse_usage_responses(
            scope,
            timestamp(NOW_SECONDS),
            COMPUTE,
            Some(BILLING),
            source,
        )
        .expect_err("scope/source mismatch");
        assert_eq!(error.kind(), ErrorKind::Api);
    }
}
