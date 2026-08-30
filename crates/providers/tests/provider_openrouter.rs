use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, CostProvenance, DetailChartKind, ErrorKind, ExactDecimal, ProviderId,
    ProviderInstanceId, Timestamp,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::openrouter::{OpenRouterProvider, OpenRouterSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const CREDITS: &[u8] = include_bytes!("../../../fixtures/providers/openrouter/credits.json");
const KEY: &[u8] = include_bytes!("../../../fixtures/providers/openrouter/key.json");
const ACTIVITY: &[u8] = include_bytes!("../../../fixtures/providers/openrouter/activity.json");
const ACTIVITY_BYOK: &[u8] =
    include_bytes!("../../../fixtures/providers/openrouter/activity_byok.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/openrouter/malformed.json");
const STANDARD_KEY: &str = "fixture-openrouter-standard-key-canary";
const MANAGEMENT_KEY: &str = "fixture-openrouter-management-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::OpenRouter,
        ProviderInstanceId::new("openrouter-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(timeout: Duration) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        timeout,
        5 * 1024 * 1024,
        3,
        RetryPolicy::none(),
    )
    .expect("fixture config")
}

fn context(account: &str) -> ProviderContext {
    ProviderContext::new(
        scope(account),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    )
}

fn provider(
    server: &FakeHttpServer,
    account: &str,
    management: bool,
    optional_timeout: Duration,
) -> OpenRouterProvider {
    let account_scope = scope(account);
    let standard = ApiKeyCredential::new(STANDARD_KEY).expect("standard credential");
    let credits_client = FixedApiClient::new_bearer(
        account_scope.clone(),
        server.url("/api/v1/"),
        EndpointClass::LoopbackDevelopment,
        standard.clone(),
        config(Duration::from_millis(250)),
    )
    .expect("credits client");
    let key_client = FixedApiClient::new_bearer(
        account_scope.clone(),
        server.url("/api/v1/"),
        EndpointClass::LoopbackDevelopment,
        standard,
        config(optional_timeout),
    )
    .expect("key client");
    let activity_client = management.then(|| {
        FixedApiClient::new_bearer(
            account_scope,
            server.url("/api/v1/"),
            EndpointClass::LoopbackDevelopment,
            ApiKeyCredential::new(MANAGEMENT_KEY).expect("management credential"),
            config(optional_timeout),
        )
        .expect("activity client")
    });
    OpenRouterProvider::from_clients(
        credits_client,
        key_client,
        activity_client,
        "Omarchy AI Bar QA".to_owned(),
        Some("https://omarchy.example".to_owned()),
    )
    .expect("OpenRouter provider")
}

fn detail_value<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a str {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .map(oab_domain::DetailRow::value)
        .expect("detail row")
}

fn detail_secondary<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> Option<&'a str> {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .and_then(oab_domain::DetailRow::secondary_value)
}

#[test]
fn settings_trim_secrets_normalize_bare_https_and_fail_closed() {
    let environment = BTreeMap::from([
        (
            "OPENROUTER_API_KEY".to_owned(),
            format!(" '{STANDARD_KEY}' "),
        ),
        (
            "OPENROUTER_MANAGEMENT_API_KEY".to_owned(),
            format!(" \"{MANAGEMENT_KEY}\" "),
        ),
        (
            "OPENROUTER_API_URL".to_owned(),
            " localhost:8443/gateway/v1/// ".to_owned(),
        ),
        (
            "OPENROUTER_HTTP_REFERER".to_owned(),
            " 'https://omarchy.example' ".to_owned(),
        ),
        (
            "OPENROUTER_X_TITLE".to_owned(),
            " Omarchy AI Bar QA ".to_owned(),
        ),
    ]);
    let settings = OpenRouterSettings::resolve(&environment).expect("settings");
    assert_eq!(
        settings.api_base().as_str(),
        "https://localhost:8443/gateway/v1/"
    );
    assert_eq!(settings.client_title(), "Omarchy AI Bar QA");
    assert_eq!(settings.http_referer(), Some("https://omarchy.example"));
    assert!(settings.has_management_credential());
    let debug = format!("{settings:?}");
    assert!(!debug.contains(STANDARD_KEY));
    assert!(!debug.contains(MANAGEMENT_KEY));

    assert_eq!(
        OpenRouterSettings::resolve(&BTreeMap::new())
            .expect_err("missing standard key")
            .kind(),
        ErrorKind::MissingCredential
    );
    for endpoint in [
        "http://router.example/api/v1",
        "https://user:pass@router.example/api/v1",
        "https://router.example%2f.attacker.test/api/v1",
        "https://bad host/api/v1",
        "https://router.example/api/v1?token=secret",
        "https://router.example/api/v1#fragment",
    ] {
        let environment = BTreeMap::from([
            ("OPENROUTER_API_KEY".to_owned(), STANDARD_KEY.to_owned()),
            ("OPENROUTER_API_URL".to_owned(), endpoint.to_owned()),
        ]);
        assert_eq!(
            OpenRouterSettings::resolve(&environment)
                .expect_err("unsafe endpoint")
                .kind(),
            ErrorKind::Api
        );
    }

    let ipv6 = BTreeMap::from([
        ("OPENROUTER_API_KEY".to_owned(), STANDARD_KEY.to_owned()),
        (
            "OPENROUTER_API_URL".to_owned(),
            "https://[::1]:8443/v1".to_owned(),
        ),
    ]);
    assert_eq!(
        OpenRouterSettings::resolve(&ipv6)
            .expect("IPv6 endpoint")
            .api_base()
            .as_str(),
        "https://[::1]:8443/v1/"
    );
}

#[tokio::test]
async fn credits_and_key_fixture_match_snapshot_and_request_golden() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, KEY.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", false, Duration::from_millis(250));
    let sample = provider
        .fetch_at(&context("account-a"), timestamp(1_787_079_600))
        .await
        .expect("OpenRouter fixture");

    assert_eq!(provider.descriptor().id, ProviderId::OpenRouter);
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("balance identity")
            .as_str(),
        "Balance: $60.00"
    );
    let used_percent = sample
        .primary()
        .expect("key quota")
        .used_percent()
        .expect("percentage")
        .get();
    assert!((used_percent - 25.0).abs() < f64::EPSILON);
    assert!(sample.primary().expect("key quota").duration().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.tertiary().is_none());
    assert!(sample.balance().is_none());
    assert!(sample.cost().is_none());
    assert!(sample.cost_usage().is_none());
    assert_eq!(detail_value(&sample, "Remaining"), "$60.00");
    assert_eq!(detail_value(&sample, "Used"), "$40.00");
    assert_eq!(detail_value(&sample, "Total added"), "$100.00");
    assert_eq!(detail_value(&sample, "API key limit"), "$20.00");
    assert_eq!(
        detail_secondary(&sample, "API key limit"),
        Some("Spending cap, not balance")
    );
    assert_eq!(detail_value(&sample, "API key remaining"), "$15.00");
    assert_eq!(detail_value(&sample, "API key used"), "$5.00");
    assert_eq!(detail_value(&sample, "Reset window"), "monthly");
    assert_eq!(detail_value(&sample, "Today"), "$1.00");
    assert_eq!(detail_value(&sample, "This week"), "$2.00");
    assert_eq!(detail_value(&sample, "This month"), "$4.00");
    assert_eq!(detail_value(&sample, "Rate limit"), "120 requests / 10s");
    assert_eq!(
        detail_secondary(&sample, "Last 30 days"),
        Some("Management API key not configured")
    );
    let key_section = sample
        .detail_sections()
        .iter()
        .find(|section| section.title() == Some("API key"))
        .expect("key section");
    let chart = key_section.chart().expect("key spend chart");
    assert_eq!(chart.kind(), DetailChartKind::Bars);
    assert_eq!(chart.title(), Some("Key spend"));
    assert_eq!(chart.unit(), Some("USD"));
    assert_eq!(
        chart
            .points()
            .iter()
            .map(|point| (point.label(), point.value().get()))
            .collect::<Vec<_>>(),
        [("Today", 1.0), ("This week", 2.0), ("This month", 4.0)]
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/api/v1/credits");
    assert_eq!(requests[1].target(), "/api/v1/key");
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-openrouter-standard-key-canary")
            && request.header("accept") == Some("application/json")
    }));
    assert_eq!(requests[0].header("x-title"), Some("Omarchy AI Bar QA"));
    assert_eq!(
        requests[0].header("http-referer"),
        Some("https://omarchy.example")
    );
    assert_eq!(requests[1].header("x-title"), None);
    assert_eq!(requests[1].header("http-referer"), None);
    assert!(
        requests
            .iter()
            .all(|request| request.header("content-type").is_none())
    );
}

#[tokio::test]
async fn activity_is_deduplicated_aggregated_and_management_scoped() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, KEY.to_vec()),
        FakeHttpResponse::new(200, ACTIVITY.to_vec()),
        FakeHttpResponse::new(200, ACTIVITY.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a", true, Duration::from_millis(250))
        .fetch_at(&context("account-a"), timestamp(1_787_079_600))
        .await
        .expect("Activity fixture");
    assert_eq!(sample.detail_sections().len(), 2);
    assert!(
        sample
            .detail_sections()
            .iter()
            .all(|section| section.title() != Some("Spend history"))
    );
    let usage = sample.cost_usage().expect("cost usage");
    assert_eq!(usage.history_days(), 30);
    assert!(usage.history_coverage_is_established());
    assert_eq!(usage.history_label(), Some("Last 30 days (UTC)"));
    assert_eq!(usage.provenance(), CostProvenance::VendorMetered);
    assert_eq!(usage.history().total_tokens(), Some(555));
    assert_eq!(usage.history().request_count(), Some(7));
    assert_eq!(usage.history().amount(), Some(decimal("39.79")));
    assert_eq!(usage.metered_amount(), None);
    assert_eq!(
        usage.updated_at(),
        Timestamp::parse("2026-08-17T12:00:00Z").expect("window end")
    );
    assert_eq!(usage.daily().len(), 2);
    let august_17 = usage
        .daily()
        .iter()
        .find(|day| day.day() == "2026-08-17")
        .expect("August 17");
    assert_eq!(august_17.metrics().token_mix().input_tokens(), Some(102));
    assert_eq!(august_17.metrics().token_mix().output_tokens(), Some(53));
    assert_eq!(august_17.metrics().token_mix().reasoning_tokens(), Some(11));
    assert_eq!(august_17.metrics().total_tokens(), Some(155));
    assert_eq!(august_17.metrics().request_count(), Some(3));
    assert_eq!(august_17.metrics().amount(), Some(decimal("12.35")));
    assert_eq!(
        august_17.models_used().collect::<Vec<_>>(),
        ["openai/gpt-5.6", "x-ai/grok-4"]
    );
    assert_eq!(august_17.models().len(), 2);
    assert_eq!(august_17.models()[0].name(), "openai/gpt-5.6");
    assert_eq!(
        august_17.models()[0].metrics().amount(),
        Some(decimal("12.345"))
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    let activity = requests
        .iter()
        .filter(|request| request.target().starts_with("/api/v1/activity"))
        .collect::<Vec<_>>();
    assert_eq!(activity.len(), 2);
    assert!(activity.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-openrouter-management-key-canary")
            && request.header("x-title").is_none()
            && request.header("http-referer").is_none()
    }));
    assert!(
        activity
            .iter()
            .any(|request| request.target() == "/api/v1/activity")
    );
    assert!(
        activity
            .iter()
            .any(|request| { request.target() == "/api/v1/activity?date=2026-08-17" })
    );
}

#[tokio::test]
async fn byok_activity_reports_mixed_and_estimated_cost_provenance() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, KEY.to_vec()),
        FakeHttpResponse::new(200, ACTIVITY_BYOK.to_vec()),
        FakeHttpResponse::new(200, ACTIVITY_BYOK.to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, KEY.to_vec()),
        FakeHttpResponse::new(
            200,
            br#"{"data":[{"date":"2026-08-17","model_permaslug":"openai/gpt-5.6","endpoint_id":"endpoint-a","prompt_tokens":10,"completion_tokens":5,"reasoning_tokens":2,"requests":1,"usage":0,"byok_usage_inference":0.75}]}"#.to_vec(),
        ),
        FakeHttpResponse::new(
            200,
            br#"{"data":[{"date":"2026-08-17","model_permaslug":"openai/gpt-5.6","endpoint_id":"endpoint-a","prompt_tokens":10,"completion_tokens":5,"reasoning_tokens":2,"requests":1,"usage":0,"byok_usage_inference":0.75}]}"#.to_vec(),
        ),
    ])
    .await;
    let provider = provider(&server, "account-a", true, Duration::from_millis(250));
    let mixed = provider
        .fetch_at(&context("account-a"), timestamp(1_787_079_600))
        .await
        .expect("mixed Activity")
        .cost_usage()
        .expect("mixed cost")
        .clone();
    assert_eq!(mixed.provenance(), CostProvenance::Mixed);
    assert_eq!(mixed.history().amount(), Some(decimal("2")));
    assert_eq!(mixed.metered_amount(), Some(decimal("1.25")));
    assert_eq!(mixed.history().total_tokens(), Some(150));
    assert_eq!(mixed.history().coverage().estimated(), 2);

    let estimated = provider
        .fetch_at(&context("account-a"), timestamp(1_787_079_600))
        .await
        .expect("estimated Activity");
    let estimated = estimated.cost_usage().expect("estimated cost");
    assert_eq!(estimated.provenance(), CostProvenance::ListPriceEstimate);
    assert_eq!(estimated.history().amount(), Some(decimal("0.75")));
    assert_eq!(estimated.metered_amount(), None);
    assert_eq!(estimated.history().coverage().estimated(), 1);
}

#[tokio::test]
async fn key_quota_precedence_and_boundary_values_match_baseline() {
    let key_bodies: [&[u8]; 7] = [
        br#"{"data":{"limit":30,"limit_remaining":-5}}"#,
        br#"{"data":{"limit":30}}"#,
        br#"{"data":{}}"#,
        br#"{"data":{"limit":0,"usage":0}}"#,
        br#"{"data":{"limit":30,"limit_reset":"daily","usage":27,"usage_daily":6,"usage_weekly":12,"usage_monthly":18}}"#,
        br#"{"data":{"limit":30,"limit_reset":"weekly","usage":27,"usage_daily":6,"usage_weekly":12,"usage_monthly":18}}"#,
        br#"{"data":{"limit":30,"limit_reset":"monthly","usage":27,"usage_daily":6,"usage_weekly":12,"usage_monthly":18}}"#,
    ];
    let mut responses = Vec::new();
    for body in key_bodies {
        responses.push(FakeHttpResponse::new(200, CREDITS.to_vec()));
        responses.push(FakeHttpResponse::new(200, body.to_vec()));
    }
    let server = FakeHttpServer::start(responses).await;
    let provider = provider(&server, "account-a", false, Duration::from_millis(250));
    let expected = [
        (Some(100.0), Some("$0.00"), "$30.00"),
        (None, None, "$30.00"),
        (None, None, "No limit configured"),
        (None, None, "No limit configured"),
        (Some(20.0), Some("$24.00"), "$30.00"),
        (Some(40.0), Some("$18.00"), "$30.00"),
        (Some(60.0), Some("$12.00"), "$30.00"),
    ];
    for (percent, remaining, limit) in expected {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(1_787_079_600))
            .await
            .expect("quota vector");
        let actual = sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get);
        match (actual, percent) {
            (Some(actual), Some(expected)) => {
                assert!((actual - expected).abs() < f64::EPSILON);
            }
            (None, None) => {}
            values => panic!("unexpected quota percentage: {values:?}"),
        }
        assert_eq!(
            sample
                .detail_sections()
                .iter()
                .flat_map(oab_domain::DetailSection::rows)
                .find(|row| row.label() == "API key remaining")
                .map(oab_domain::DetailRow::value),
            remaining
        );
        assert_eq!(detail_value(&sample, "API key limit"), limit);
    }
}

#[tokio::test]
async fn optional_status_parse_and_timeout_failures_preserve_credits() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, br#"{"data":{"limit":"twenty"}}"#.to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::stall(),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::truncated(200, 100, br#"{"data":{}"#.to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, br"{}".to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", false, Duration::from_millis(50));
    for expected in [
        "Request returned HTTP 403",
        "Response was invalid",
        "Request timed out",
        "Request failed",
        "Response was unavailable",
    ] {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(1_787_079_600))
            .await
            .expect("credits survive optional failure");
        assert_eq!(detail_value(&sample, "Remaining"), "$60.00");
        assert_eq!(
            detail_value(&sample, "API key limit"),
            "Unavailable right now"
        );
        assert_eq!(detail_secondary(&sample, "API key limit"), Some(expected));
    }
}

#[tokio::test]
async fn activity_permission_and_validation_failures_are_observable_degradations() {
    let conflict = br#"{"data":[
      {"date":"2026-08-17","model":"openai/gpt-5.6","endpoint_id":"same","prompt_tokens":1,"completion_tokens":1,"reasoning_tokens":0,"requests":1,"usage":1},
      {"date":"2026-08-17","model":"openai/gpt-5.6","endpoint_id":"same","prompt_tokens":2,"completion_tokens":1,"reasoning_tokens":0,"requests":1,"usage":1}
    ]}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, KEY.to_vec()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(200, br#"{"data":[]}"#.to_vec()),
        FakeHttpResponse::new(200, CREDITS.to_vec()),
        FakeHttpResponse::new(200, KEY.to_vec()),
        FakeHttpResponse::new(200, conflict.to_vec()),
        FakeHttpResponse::new(200, br#"{"data":[]}"#.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", true, Duration::from_millis(250));
    for expected in ["Management API key required", "Response was invalid"] {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(1_787_079_600))
            .await
            .expect("credits survive Activity failure");
        assert!(sample.cost_usage().is_none());
        assert_eq!(detail_value(&sample, "Remaining"), "$60.00");
        assert_eq!(detail_secondary(&sample, "Last 30 days"), Some(expected));
    }
}

#[tokio::test]
async fn required_credits_status_and_schema_failures_remain_authoritative() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, b"fixture-secret-response-canary".to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", false, Duration::from_millis(250));
    assert_eq!(
        provider
            .fetch_at(&context("account-a"), timestamp(1_787_079_600))
            .await
            .expect_err("credits status")
            .kind(),
        ErrorKind::Api
    );
    let error = provider
        .fetch_at(&context("account-a"), timestamp(1_787_079_600))
        .await
        .expect_err("credits parse");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!error.to_string().contains("fixture-secret-response-canary"));
    assert!(!error.to_string().contains("secret-fixture-canary"));
}

#[test]
fn clients_are_rejected_across_provider_and_account_boundaries() {
    let wrong_scope = AccountScope::new(
        ProviderId::OpenAi,
        ProviderInstanceId::new("openai-primary").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    let base = url::Url::parse("https://openrouter.ai/api/v1/").expect("URL");
    let wrong = FixedApiClient::new_bearer(
        wrong_scope,
        base.clone(),
        EndpointClass::PublicHttps,
        ApiKeyCredential::new(STANDARD_KEY).expect("credential"),
        config(Duration::from_millis(250)),
    )
    .expect("client");
    let right = FixedApiClient::new_bearer(
        scope("account-a"),
        base,
        EndpointClass::PublicHttps,
        ApiKeyCredential::new(STANDARD_KEY).expect("credential"),
        config(Duration::from_millis(250)),
    )
    .expect("client");
    let error =
        OpenRouterProvider::from_clients(wrong, right, None, "Omarchy AI Bar".to_owned(), None)
            .err()
            .expect("scope mismatch");
    assert_eq!(error.kind(), ErrorKind::Api);
}
