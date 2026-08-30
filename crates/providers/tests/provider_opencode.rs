use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::cookie::{
    CookieDomainKind, CookieImport, CookieImportOrder, CookieJar, CookieRecord, CookieRecordSpec,
    CookieSourceId, CookieUrlPolicy,
};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::providers::opencode::{OpenCodeProvider, parse_billing, parse_subscription};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use rust_decimal::Decimal;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const SUBSCRIPTION: &[u8] = include_bytes!("../../../fixtures/providers/opencode/subscription.txt");
const BILLING: &[u8] =
    include_bytes!("../../../fixtures/providers/opencode/billing-pay-as-you-go.txt");
const WORKSPACES_ID: &str = "def39973159c7f0483d8793a822b8dbb10d067e12c65455fcb4608459ba0234f";
const SUBSCRIPTION_ID: &str = "7abeebee372f304e050aaaf92be863f4a86490e382f8c79db68fd94040d691b4";
const BILLING_ID: &str = "c83b78a614689c38ebee981f9b39a8b377716db85c1fd7dbab604adc02d3313d";
const COOKIE_CANARY: &str = "fixture-opencode-cookie-canary";
const NOW_SECONDS: i64 = 1_778_000_000;

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::OpenCode,
        ProviderInstanceId::new("opencode-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn manual_provider(
    server: &FakeHttpServer,
    raw: &str,
    workspace: Option<&str>,
) -> OpenCodeProvider {
    OpenCodeProvider::from_manual_capture_at(
        scope("account-a"),
        raw,
        workspace,
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual OpenCode provider")
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
    let source = CookieSourceId::new(7);
    let order = CookieImportOrder::new([source]).expect("cookie import order");
    let import = CookieImport::new(source, records).expect("cookie import");
    CookieJar::from_imports(&order, [import]).expect("cookie jar")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "{actual} != {expected}"
    );
}

#[test]
fn golden_subscription_maps_rolling_weekly_resets_and_renewal() {
    let sample = parse_subscription(scope("a"), timestamp(NOW_SECONDS), SUBSCRIPTION)
        .expect("subscription fixture");
    let rolling = sample.primary().expect("rolling window");
    let weekly = sample.secondary().expect("weekly window");
    assert_percent(rolling.used_percent().expect("rolling percent").get(), 17.0);
    assert_percent(weekly.used_percent().expect("weekly percent").get(), 75.0);
    assert_eq!(
        rolling.duration().expect("rolling duration").seconds(),
        5 * 60 * 60
    );
    assert_eq!(
        weekly.duration().expect("weekly duration").seconds(),
        7 * 24 * 60 * 60
    );
    assert_eq!(
        rolling.resets_at().expect("rolling reset").unix_timestamp(),
        NOW_SECONDS + 5_944
    );
    assert_eq!(
        weekly.resets_at().expect("weekly reset").unix_timestamp(),
        NOW_SECONDS + 278_201
    );
    assert_eq!(
        sample
            .subscription_renews_at()
            .expect("renewal")
            .unix_timestamp(),
        1_790_683_200
    );
    assert!(
        sample.identity().login_method().is_none(),
        "baseline has no plan label"
    );
}

#[test]
fn json_window_aliases_ratios_candidates_and_child_renewal_match_baseline() {
    let direct = br#"{
      "renewAt":"2026-09-01T00:00:00Z",
      "data":{"renew_at":"2026-09-02T00:00:00Z","usage":{
        "rolling_window":{"used":1,"limit":4,"resetAt":1778000900},
        "weekly_usage":{"utilization":0.5,"resetsInSeconds":"7200"}
      }}
    }"#;
    let sample = parse_subscription(scope("a"), timestamp(NOW_SECONDS), direct).expect("aliases");
    assert_percent(
        sample
            .primary()
            .expect("rolling")
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
        50.0,
    );
    assert_eq!(
        sample
            .primary()
            .expect("rolling")
            .resets_at()
            .expect("reset")
            .unix_timestamp(),
        NOW_SECONDS + 900
    );
    assert_eq!(
        sample
            .subscription_renews_at()
            .expect("child renewal")
            .unix_timestamp(),
        1_788_307_200
    );

    let candidates = br#"{"limits":{"fiveHour":{"percent":33,"resetInSec":300},"week":{"percentUsed":66,"resetInSec":6000}}}"#;
    let sample =
        parse_subscription(scope("a"), timestamp(NOW_SECONDS), candidates).expect("candidates");
    assert_percent(
        sample
            .primary()
            .expect("rolling candidate")
            .used_percent()
            .expect("known")
            .get(),
        33.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly candidate")
            .used_percent()
            .expect("known")
            .get(),
        66.0,
    );
}

#[test]
fn candidate_windows_prefer_higher_usage_when_reset_times_tie() {
    let candidates = br#"{"windows":{
      "a_short_high":{"percent":80,"resetInSec":300},
      "b_short_low":{"percent":20,"resetInSec":300},
      "c_long_high":{"percent":90,"resetInSec":6000},
      "d_long_low":{"percent":40,"resetInSec":6000}
    }}"#;
    let sample =
        parse_subscription(scope("a"), timestamp(NOW_SECONDS), candidates).expect("candidates");
    assert_percent(
        sample
            .primary()
            .expect("rolling candidate")
            .used_percent()
            .expect("known")
            .get(),
        80.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly candidate")
            .used_percent()
            .expect("known")
            .get(),
        90.0,
    );
}

#[test]
fn malformed_optional_renewal_does_not_erase_valid_usage_windows() {
    let payload = br#"{
      "renewAt":"not-a-date",
      "rollingUsage":{"usagePercent":17,"resetInSec":600},
      "weeklyUsage":{"usagePercent":75,"resetInSec":7200}
    }"#;
    let sample =
        parse_subscription(scope("a"), timestamp(NOW_SECONDS), payload).expect("valid windows");
    assert_percent(
        sample
            .primary()
            .expect("rolling")
            .used_percent()
            .expect("known")
            .get(),
        17.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        75.0,
    );
    assert!(sample.subscription_renews_at().is_none());

    let payload = br#";0;($R=>$R[0]={
      renewAt:"not-a-date",
      rollingUsage:$R[1]={usagePercent:17,resetInSec:600},
      weeklyUsage:$R[2]={usagePercent:75,resetInSec:7200}
    })($R)"#;
    let sample =
        parse_subscription(scope("a"), timestamp(NOW_SECONDS), payload).expect("valid windows");
    assert_percent(
        sample
            .primary()
            .expect("rolling")
            .used_percent()
            .expect("known")
            .get(),
        17.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        75.0,
    );
    assert!(sample.subscription_renews_at().is_none());
}

#[test]
fn payload_windows_without_resets_fail_closed() {
    let payload = br";0;($R=>$R[0]={
      rollingUsage:$R[1]={usagePercent:17},
      weeklyUsage:$R[2]={usagePercent:75}
    })($R)";
    let error = parse_subscription(scope("a"), timestamp(NOW_SECONDS), payload)
        .expect_err("missing reset fields");
    assert_eq!(error.kind(), ErrorKind::Parse);
}

#[test]
fn golden_payg_maps_exact_spend_limit_balance_and_no_plan() {
    let sample = parse_billing(scope("a"), timestamp(NOW_SECONDS), BILLING)
        .expect("billing fixture")
        .expect("PAYG sample");
    assert_percent(
        sample
            .primary()
            .expect("monthly limit")
            .used_percent()
            .expect("known")
            .get(),
        75.0,
    );
    let cost = sample.cost().expect("cost");
    assert_eq!(cost.used().amount().get(), Decimal::new(15, 0));
    assert_eq!(cost.limit().get(), Decimal::new(20, 0));
    assert_eq!(
        cost.balance().expect("cost balance").get(),
        Decimal::new(125, 1)
    );
    assert_eq!(cost.period(), Some("Monthly"));
    assert_eq!(
        sample.balance().expect("native balance").amount().get(),
        Decimal::new(125, 1)
    );
    assert!(sample.identity().login_method().is_none());
}

#[test]
fn payg_without_limit_has_cost_but_no_synthetic_primary_and_subscription_is_not_payg() {
    let no_limit = br#"{"customerID":"cus","monthlyUsage":250000000,"balance":null,"monthlyLimit":null,"subscription":null}"#;
    let sample = parse_billing(scope("a"), timestamp(NOW_SECONDS), no_limit)
        .expect("billing parse")
        .expect("PAYG sample");
    assert!(sample.primary().is_none());
    assert_eq!(
        sample.cost().expect("cost").used().amount().get(),
        Decimal::new(25, 1)
    );
    assert_eq!(sample.cost().expect("cost").limit().get(), Decimal::ZERO);
    assert!(sample.balance().is_none());

    let payload_no_limit = br#";0;($R=>$R[0]={customerID:"cus",monthlyUsage:250000000,monthlyLimit:null,balance:null,subscription:null})($R)"#;
    let payload_sample = parse_billing(scope("a"), timestamp(NOW_SECONDS), payload_no_limit)
        .expect("payload billing parse")
        .expect("payload PAYG sample");
    assert!(payload_sample.primary().is_none());
    assert_eq!(
        payload_sample
            .cost()
            .expect("payload cost")
            .used()
            .amount()
            .get(),
        Decimal::new(25, 1)
    );

    let subscription =
        br#"{"customerID":"cus","monthlyUsage":100000000,"subscription":{"id":"sub"}}"#;
    assert!(
        parse_billing(scope("a"), timestamp(NOW_SECONDS), subscription)
            .expect("parse")
            .is_none()
    );
}

#[test]
fn malformed_optional_payg_money_does_not_erase_authoritative_spend() {
    let json = br#"{
      "customerID":"cus",
      "monthlyUsage":250000000,
      "monthlyLimit":"not-a-number",
      "balance":{"invalid":true},
      "subscription":null
    }"#;
    let sample = parse_billing(scope("a"), timestamp(NOW_SECONDS), json)
        .expect("billing parse")
        .expect("PAYG sample");
    assert!(sample.primary().is_none());
    assert!(sample.balance().is_none());
    assert_eq!(
        sample.cost().expect("cost").used().amount().get(),
        Decimal::new(25, 1)
    );
    assert_eq!(sample.cost().expect("cost").limit().get(), Decimal::ZERO);

    let payload = br#";0;($R=>$R[0]={
      customerID:"cus",
      monthlyUsage:250000000,
      monthlyLimit:notANumber,
      balance:"not-a-number",
      subscription:null
    })($R)"#;
    let sample = parse_billing(scope("a"), timestamp(NOW_SECONDS), payload)
        .expect("payload billing parse")
        .expect("payload PAYG sample");
    assert!(sample.primary().is_none());
    assert!(sample.balance().is_none());
    assert_eq!(
        sample.cost().expect("cost").used().amount().get(),
        Decimal::new(25, 1)
    );
    assert_eq!(sample.cost().expect("cost").limit().get(), Decimal::ZERO);
}

#[tokio::test]
async fn manual_override_sends_exact_get_headers_query_referer_and_filtered_cookie() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let provider = manual_provider(
        &server,
        &format!("provider=google; auth={COOKIE_CANARY}; __Host-auth=host-cookie; ignored=secret"),
        Some("https://opencode.ai/workspace/wrk_TEST123/billing"),
    );
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("manual fetch");
    assert_eq!(provider.descriptor().id, ProviderId::OpenCode);
    assert_percent(
        sample
            .primary()
            .expect("rolling")
            .used_percent()
            .expect("known")
            .get(),
        17.0,
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method(), "GET");
    let url = Url::parse(&format!("http://fixture{}", request.target())).expect("request URL");
    assert_eq!(url.path(), "/_server");
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        vec![
            ("id".into(), SUBSCRIPTION_ID.into()),
            ("args".into(), r#"["wrk_TEST123"]"#.into())
        ]
    );
    assert_eq!(
        request.header("cookie"),
        Some("auth=fixture-opencode-cookie-canary; __Host-auth=host-cookie")
    );
    assert_eq!(request.header("x-server-id"), Some(SUBSCRIPTION_ID));
    assert!(
        request
            .header("x-server-instance")
            .is_some_and(|value| value.starts_with("server-fn:00000000-0000-4000-8000-"))
    );
    assert_eq!(request.header("origin"), Some("https://opencode.ai"));
    assert_eq!(
        request.header("referer"),
        Some("https://opencode.ai/workspace/wrk_TEST123/billing")
    );
    assert_eq!(
        request.header("accept"),
        Some("text/javascript, application/json;q=0.9, */*;q=0.8")
    );
    assert_eq!(
        request.header("user-agent"),
        Some(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
        )
    );
    assert_eq!(request.header("content-type"), None);
    assert_eq!(request.body(), b"");
}

#[tokio::test]
async fn workspace_and_subscription_gets_use_bounded_post_fallbacks_with_exact_bodies() {
    let subscription_json = br#"{"rollingUsage":{"usagePercent":22,"resetInSec":300},"weeklyUsage":{"usagePercent":44,"resetInSec":3600}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, br#"{"ok":true}"#.to_vec()),
        FakeHttpResponse::new(
            200,
            br#";0;($R=>$R[0]={id:"wrk_DISCOVER123"})($R)"#.to_vec(),
        ),
        FakeHttpResponse::new(200, br#"{"ok":true}"#.to_vec()),
        FakeHttpResponse::new(200, subscription_json.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "auth=test", Some("not-a-workspace"));
    let result = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await;
    assert!(
        result.is_ok(),
        "fallback failed; requests={:?}",
        server.requests()
    );
    let sample = result.expect("fallback fetch");
    assert_percent(
        sample
            .primary()
            .expect("rolling")
            .used_percent()
            .expect("known")
            .get(),
        22.0,
    );

    let requests = server.requests();
    assert_eq!(
        requests
            .iter()
            .map(oab_test_support::http::CapturedHttpRequest::method)
            .collect::<Vec<_>>(),
        ["GET", "POST", "GET", "POST"]
    );
    assert_eq!(
        requests
            .iter()
            .map(|request| request.header("x-server-id").expect("server id"))
            .collect::<Vec<_>>(),
        [
            WORKSPACES_ID,
            WORKSPACES_ID,
            SUBSCRIPTION_ID,
            SUBSCRIPTION_ID
        ]
    );
    assert_eq!(requests[1].body(), b"[]");
    assert_eq!(requests[1].header("content-type"), Some("application/json"));
    assert_eq!(requests[3].body(), br#"["wrk_DISCOVER123"]"#);
    assert_eq!(requests[3].target(), "/_server");
}

#[tokio::test]
async fn json_workspace_discovery_ignores_embedded_workspace_decoys() {
    let workspaces = br#"{
      "description":"migrated from wrk_DECOY",
      "id":"wrk_REAL123"
    }"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, workspaces.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "auth=test", None);
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("workspace discovery");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    let subscription_url =
        Url::parse(&format!("http://fixture{}", requests[1].target())).expect("request URL");
    assert_eq!(
        subscription_url.query_pairs().collect::<Vec<_>>(),
        vec![
            ("id".into(), SUBSCRIPTION_ID.into()),
            ("args".into(), r#"["wrk_REAL123"]"#.into())
        ]
    );
}

#[tokio::test]
async fn incomplete_payload_windows_use_subscription_post_fallback() {
    let incomplete = br";0;($R=>$R[0]={
      rollingUsage:$R[1]={usagePercent:17},
      weeklyUsage:$R[2]={usagePercent:75}
    })($R)";
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, incomplete.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "auth=test", Some("wrk_TEST123"));
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("subscription POST fallback");

    let requests = server.requests();
    assert_eq!(
        requests
            .iter()
            .map(oab_test_support::http::CapturedHttpRequest::method)
            .collect::<Vec<_>>(),
        ["GET", "POST"]
    );
    assert_eq!(requests[1].body(), br#"["wrk_TEST123"]"#);
}

#[tokio::test]
async fn explicit_null_skips_subscription_post_and_maps_payg_billing_get() {
    let null = br#";0x51;((self.$R=self.$R||{})["server-fn:test"]=[],null)"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, null.to_vec()),
        FakeHttpResponse::new(200, BILLING.to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "auth=test", Some("wrk_TEST123"));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("PAYG fallback");
    assert_eq!(
        sample.cost().expect("cost").used().amount().get(),
        Decimal::new(15, 0)
    );
    let requests = server.requests();
    assert_eq!(
        requests
            .iter()
            .map(oab_test_support::http::CapturedHttpRequest::method)
            .collect::<Vec<_>>(),
        ["GET", "GET"]
    );
    assert_eq!(requests[0].header("x-server-id"), Some(SUBSCRIPTION_ID));
    assert_eq!(requests[1].header("x-server-id"), Some(BILLING_ID));
    assert_eq!(
        requests[1].header("referer"),
        Some("https://opencode.ai/workspace/wrk_TEST123")
    );
}

#[tokio::test]
async fn subscription_error_is_preserved_when_billing_is_invalid_or_has_subscription() {
    let subscription_billing =
        br#"{"customerID":"cus","monthlyUsage":100000000,"subscription":{"id":"sub"}}"#;
    for billing in [
        subscription_billing.as_slice(),
        br#"{"unrelated":true}"#.as_slice(),
    ] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, br#"{"ok":true}"#.to_vec()),
            FakeHttpResponse::new(500, b"subscription-error-canary".to_vec()),
            FakeHttpResponse::new(200, billing.to_vec()),
        ])
        .await;
        let provider = manual_provider(&server, "auth=test", Some("wrk_TEST123"));
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("subscription failure");
        assert_eq!(error.kind(), ErrorKind::Api);
        assert!(!format!("{error:?} {error}").contains("subscription-error-canary"));
        assert_eq!(server.requests().len(), 3);
    }
}

#[tokio::test]
async fn browser_jar_is_target_time_and_auth_name_scoped_without_cross_host_leakage() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let target = OpenCodeProvider::browser_target(server.url("/"), CookieUrlPolicy::LoopbackHttp)
        .expect("browser target");
    let host = target.url().host_str().expect("target host");
    let jar = cookie_jar(vec![
        cookie_record(
            "auth",
            "wrong-host",
            "localhost",
            CookieDomainKind::HostOnly,
            "/",
            None,
        ),
        cookie_record(
            "auth",
            "wrong-path",
            host,
            CookieDomainKind::HostOnly,
            "/other",
            None,
        ),
        cookie_record(
            "auth",
            "expired",
            host,
            CookieDomainKind::HostOnly,
            "/",
            Some(now() - time::Duration::SECOND),
        ),
        cookie_record(
            "provider",
            "must-not-forward",
            host,
            CookieDomainKind::HostOnly,
            "/",
            None,
        ),
        cookie_record(
            "__Host-auth",
            COOKIE_CANARY,
            host,
            CookieDomainKind::HostOnly,
            "/",
            Some(now() + time::Duration::HOUR),
        ),
    ]);
    let provider = OpenCodeProvider::from_browser_jar_at(
        scope("account-a"),
        &jar,
        &target,
        now(),
        Some("wrk_TEST123"),
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
        Some("__Host-auth=fixture-opencode-cookie-canary")
    );
}

#[test]
fn browser_missing_and_non_applicable_auth_are_distinct_and_never_probe() {
    let target = OpenCodeProvider::browser_target(
        Url::parse("http://127.0.0.1:32123").expect("loopback origin"),
        CookieUrlPolicy::LoopbackHttp,
    )
    .expect("browser target");
    let empty = cookie_jar(Vec::new());
    assert_eq!(
        OpenCodeProvider::from_browser_jar_at(
            scope("a"),
            &empty,
            &target,
            now(),
            Some("wrk_TEST"),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("empty jar")
        .kind(),
        ErrorKind::MissingCredential
    );

    let host = target.url().host_str().expect("target host");
    let unrelated = cookie_jar(vec![cookie_record(
        "provider",
        "google",
        host,
        CookieDomainKind::HostOnly,
        "/",
        None,
    )]);
    assert_eq!(
        OpenCodeProvider::from_browser_jar_at(
            scope("a"),
            &unrelated,
            &target,
            now(),
            Some("wrk_TEST"),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("no applicable auth")
        .kind(),
        ErrorKind::AuthenticationExpired
    );
}

#[test]
fn constructors_reject_unsafe_hosts_missing_auth_and_wrong_provider_scope() {
    let endpoint = Url::parse("http://127.0.0.1:32123").expect("loopback origin");
    for raw in [
        "provider=google",
        "curl https://evil.example -H 'Cookie: auth=secret-canary'",
        "curl http://opencode.ai -H 'Cookie: auth=secret-canary'",
    ] {
        let error = OpenCodeProvider::from_manual_capture_at(
            scope("a"),
            raw,
            Some("wrk_TEST"),
            endpoint.clone(),
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("unsafe or missing credential");
        assert!(matches!(
            error.kind(),
            ErrorKind::MissingCredential | ErrorKind::Parse
        ));
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
    }

    let wrong_scope = AccountScope::new(
        ProviderId::OpenAi,
        ProviderInstanceId::new("wrong").expect("instance"),
        AccountKey::new("account").expect("account"),
    );
    assert_eq!(
        OpenCodeProvider::from_manual_capture_at(
            wrong_scope,
            "auth=test",
            None,
            endpoint,
            EndpointClass::LoopbackDevelopment,
        )
        .expect_err("wrong provider")
        .kind(),
        ErrorKind::Api
    );

    let unbound = Url::parse("https://example.com").expect("public origin");
    assert_eq!(
        OpenCodeProvider::from_manual_capture_at(
            scope("a"),
            "auth=test",
            None,
            unbound,
            EndpointClass::PublicHttps,
        )
        .expect_err("public seam is fixed to opencode.ai")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn source_and_account_scope_mismatches_fail_before_network() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let provider = manual_provider(&server, "auth=test", Some("wrk_TEST"));
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
}

#[tokio::test]
async fn auth_rate_challenge_and_server_statuses_have_stable_taxonomy() {
    let cases = [
        (
            FakeHttpResponse::new(401, b"auth-body-canary".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, b"challenge-body-canary".to_vec())
                .header("x-vercel-mitigated", "challenge"),
            ErrorKind::PermissionDenied,
        ),
        (
            FakeHttpResponse::new(200, b"challenge-page-canary".to_vec())
                .header("x-vercel-mitigated", "challenge"),
            ErrorKind::PermissionDenied,
        ),
        (
            FakeHttpResponse::new(429, b"rate-body-canary".to_vec()),
            ErrorKind::RateLimited,
        ),
    ];
    for (response, expected) in cases {
        let server = FakeHttpServer::start([response]).await;
        let provider = manual_provider(&server, "auth=test", Some("wrk_TEST"));
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("status failure");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?} {error}").contains("body-canary"));
        assert_eq!(server.requests().len(), 1);
    }

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(500, b"server-body-canary".to_vec()),
        FakeHttpResponse::new(500, b"billing-body-canary".to_vec()),
    ])
    .await;
    let provider = manual_provider(&server, "auth=test", Some("wrk_TEST"));
    assert_eq!(
        provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS)
            )
            .await
            .expect_err("server failure")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        server.requests().len(),
        2,
        "API-shaped subscription errors attempt billing once"
    );
}

#[tokio::test]
async fn terminal_statuses_and_challenges_take_precedence_over_untrusted_bodies() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let cases = [
        (
            FakeHttpResponse::new(401, oversized.clone()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::truncated(403, 100, b"short".to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(200, oversized).header("x-vercel-mitigated", "challenge"),
            ErrorKind::PermissionDenied,
        ),
        (
            FakeHttpResponse::truncated(429, 100, b"short".to_vec()),
            ErrorKind::RateLimited,
        ),
    ];
    for (response, expected) in cases {
        let server = FakeHttpServer::start([response]).await;
        let provider = manual_provider(&server, "auth=test", Some("wrk_TEST"));
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("terminal response");
        assert_eq!(error.kind(), expected);
        assert_eq!(
            server.requests().len(),
            1,
            "terminal errors do not fall back"
        );
    }
}

#[tokio::test]
async fn only_exact_http_200_is_accepted_as_a_server_function_success() {
    for status in [201, 204] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(status, SUBSCRIPTION.to_vec()),
            FakeHttpResponse::new(200, br#"{"unrelated":true}"#.to_vec()),
        ])
        .await;
        let provider = manual_provider(&server, "auth=test", Some("wrk_TEST"));
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("non-200 server response");
        assert_eq!(error.kind(), ErrorKind::Api);
        assert_eq!(
            server.requests().len(),
            2,
            "subscription API errors attempt the baseline billing fallback once"
        );
    }
}

#[tokio::test]
async fn workspace_count_bound_fails_without_post_or_subscription_requests() {
    let body = format!(
        "[{}]",
        (0..65)
            .map(|index| format!(r#""wrk_{index}""#))
            .collect::<Vec<_>>()
            .join(",")
    );
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.into_bytes())]).await;
    let provider = manual_provider(&server, "auth=test", None);
    assert_eq!(
        provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("workspace cap")
            .kind(),
        ErrorKind::Parse
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn redirects_truncation_oversize_and_cancellation_are_bounded() {
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("location", "/redirected"),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::truncated(200, 100, b"short".to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, oversized),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    let provider = manual_provider(&server, "auth=test", Some("wrk_TEST"));
    for _ in 0..3 {
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("bounded response failure");
        assert!(matches!(error.kind(), ErrorKind::Api | ErrorKind::Parse));
    }
    assert_eq!(
        server.requests().len(),
        6,
        "redirect was not followed; API errors alone use billing fallback"
    );

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(&stalled, "auth=test", Some("wrk_TEST"));
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
        result = tokio::time::timeout(Duration::from_millis(200), stalled.wait_for_request_count(1)) => result.expect("request reached server"),
    }
    cancellation.cancel();
    assert_eq!(
        fetch.await.expect_err("cancelled fetch").kind(),
        ErrorKind::Network
    );
}

#[test]
fn response_bounds_and_adversarial_payloads_fail_closed_and_redacted() {
    let many_nodes = format!(
        "{{\"rollingUsage\":{{\"usagePercent\":1}},\"nodes\":[{}]}}",
        vec!["0"; 33_000].join(",")
    );
    let mut deep = r#"{"rollingUsage":{"usagePercent":1}}"#.to_owned();
    for _ in 0..70 {
        deep = format!("[{deep}]");
    }
    let long_field = format!(
        r#"{{"rollingUsage":{{"usagePercent":1,"x":"{}"}},"weeklyUsage":{{"usagePercent":2}}}}"#,
        "x".repeat(9_000)
    );
    let too_many_workspaces = format!(
        "[{}]",
        (0..65)
            .map(|index| format!(r#""wrk_{index}""#))
            .collect::<Vec<_>>()
            .join(",")
    );
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let cases: Vec<&[u8]> = vec![
        many_nodes.as_bytes(),
        deep.as_bytes(),
        long_field.as_bytes(),
        &[0xff, 0xfe],
        oversized.as_slice(),
    ];
    for body in cases {
        let error = parse_subscription(scope("a"), timestamp(NOW_SECONDS), body)
            .expect_err("bounded parse failure");
        assert_eq!(error.kind(), ErrorKind::Parse);
        assert!(!format!("{error:?} {error}").contains("usagePercent"));
    }
    assert_eq!(
        parse_subscription(
            scope("a"),
            timestamp(NOW_SECONDS),
            too_many_workspaces.as_bytes()
        )
        .expect_err("not subscription")
        .kind(),
        ErrorKind::Parse
    );

    for malformed in [
        br#"{"rollingUsage":{"usagePercent":"NaN"},"weeklyUsage":{"usagePercent":1}}"#.as_slice(),
        br#"{"rollingUsage":{"used":1,"limit":0},"weeklyUsage":{"usagePercent":1}}"#.as_slice(),
        br#"{"customerID":"cus","monthlyUsage":"overflow-canary","subscription":null}"#.as_slice(),
    ] {
        let error = if malformed.windows(10).any(|window| window == b"customerID") {
            parse_billing(scope("a"), timestamp(NOW_SECONDS), malformed).expect_err("bad billing")
        } else {
            parse_subscription(scope("a"), timestamp(NOW_SECONDS), malformed)
                .expect_err("bad subscription")
        };
        assert_eq!(error.kind(), ErrorKind::Parse);
        assert!(!format!("{error:?} {error}").contains("overflow-canary"));
    }
}
