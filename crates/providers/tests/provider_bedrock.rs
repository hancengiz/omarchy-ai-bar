use std::collections::BTreeMap;
use std::path::PathBuf;

use oab_domain::{
    AccountKey, AccountScope, CostProvenance, ErrorKind, ExactDecimal, ProviderId,
    ProviderInstanceId, Timestamp,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::bedrock::{
    BedrockAuthMode, BedrockCredentialBundle, BedrockProvider, BedrockSettings,
    cloudwatch_url_for_region,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::{Value, json};
use time::UtcOffset;
use tokio_util::sync::CancellationToken;

const MONTHLY_PAGE_1: &[u8] =
    include_bytes!("../../../fixtures/providers/bedrock/monthly_page_1.json");
const MONTHLY_PAGE_2: &[u8] =
    include_bytes!("../../../fixtures/providers/bedrock/monthly_page_2.json");
const DAILY: &[u8] = include_bytes!("../../../fixtures/providers/bedrock/daily.json");
const CLOUDWATCH_PAGE_1: &[u8] =
    include_bytes!("../../../fixtures/providers/bedrock/cloudwatch_page_1.json");
const CLOUDWATCH_PAGE_2: &[u8] =
    include_bytes!("../../../fixtures/providers/bedrock/cloudwatch_page_2.json");
const DATA_UNAVAILABLE: &[u8] =
    include_bytes!("../../../fixtures/providers/bedrock/data_unavailable.json");
const EMPTY_COST: &[u8] = include_bytes!("../../../fixtures/providers/bedrock/empty_cost.json");
const ACCESS_KEY: &str = "AKIA_BEDROCK_FIXTURE";
const SECRET_KEY: &str = "bedrock-secret-fixture-canary";

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Bedrock,
        ProviderInstanceId::new("bedrock-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str) -> ProviderContext {
    ProviderContext::new(
        scope(account),
        ProviderSource::CloudCredentials,
        CancellationToken::new(),
    )
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn static_environment(server: &FakeHttpServer, cloudwatch: bool) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        ("AWS_ACCESS_KEY_ID".to_owned(), ACCESS_KEY.to_owned()),
        ("AWS_SECRET_ACCESS_KEY".to_owned(), SECRET_KEY.to_owned()),
        ("AWS_REGION".to_owned(), "us-west-2".to_owned()),
        (
            "OMARCHY_AI_BAR_BEDROCK_BUDGET".to_owned(),
            "100.00".to_owned(),
        ),
        ("OMARCHY_AI_BAR_BEDROCK_API_URL".to_owned(), server.origin()),
    ]);
    if cloudwatch {
        environment.insert(
            "OMARCHY_AI_BAR_BEDROCK_CLOUDWATCH_API_URL".to_owned(),
            server.origin(),
        );
    }
    environment
}

fn provider(server: &FakeHttpServer, account: &str, cloudwatch: bool) -> BedrockProvider {
    let settings =
        BedrockSettings::resolve(&static_environment(server, cloudwatch)).expect("settings");
    BedrockProvider::with_local_offset(
        scope(account),
        settings,
        UtcOffset::from_hms(3, 0, 0).expect("UTC+3"),
    )
    .expect("provider")
}

fn one_month_page(amount: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "ResultsByTime": [{
            "TimePeriod": {"Start": "2026-08-01", "End": "2026-08-31"},
            "Groups": [{
                "Keys": ["Amazon Bedrock"],
                "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}}
            }]
        }]
    }))
    .expect("fixture JSON")
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

#[test]
fn settings_clean_infer_auth_and_reject_unsafe_endpoints() {
    let keys = BTreeMap::from([
        ("AWS_ACCESS_KEY_ID".to_owned(), " 'AKIA' ".to_owned()),
        (
            "AWS_SECRET_ACCESS_KEY".to_owned(),
            " \"secret\" ".to_owned(),
        ),
        ("AWS_PROFILE".to_owned(), " work ".to_owned()),
        ("AWS_DEFAULT_REGION".to_owned(), " eu-west-1 ".to_owned()),
        (
            "OMARCHY_AI_BAR_BEDROCK_BUDGET".to_owned(),
            " 50.125 ".to_owned(),
        ),
    ]);
    let settings = BedrockSettings::resolve(&keys).expect("complete keys");
    assert_eq!(settings.auth_mode(), BedrockAuthMode::Keys);
    assert_eq!(settings.configured_region(), Some("eu-west-1"));
    assert_eq!(settings.budget(), "50.125".parse().ok());
    let debug = format!("{settings:?}");
    assert!(!debug.contains("AKIA"));
    assert!(!debug.contains("secret"));

    let incomplete_with_profile = BTreeMap::from([
        ("AWS_ACCESS_KEY_ID".to_owned(), "incomplete".to_owned()),
        ("AWS_PROFILE".to_owned(), "work".to_owned()),
        (
            "OMARCHY_AI_BAR_AWS_CLI_PATH".to_owned(),
            aws_fixture_path().to_string_lossy().into_owned(),
        ),
    ]);
    assert_eq!(
        BedrockSettings::resolve(&incomplete_with_profile)
            .expect("profile inference")
            .auth_mode(),
        BedrockAuthMode::Profile
    );

    for endpoint in [
        "http://billing.example",
        "https://user:pass@billing.example",
        "https://billing.example/?token=secret",
        "https://billing.example/#fragment",
        "not-an-absolute-url",
    ] {
        let mut environment = keys.clone();
        environment.insert(
            "OMARCHY_AI_BAR_BEDROCK_API_URL".to_owned(),
            endpoint.to_owned(),
        );
        assert_eq!(
            BedrockSettings::resolve(&environment)
                .expect_err("unsafe endpoint")
                .kind(),
            ErrorKind::Api
        );
    }

    let mut invalid_budget = keys;
    invalid_budget.insert("OMARCHY_AI_BAR_BEDROCK_BUDGET".to_owned(), "-2".to_owned());
    assert_eq!(
        BedrockSettings::resolve(&invalid_budget)
            .expect("invalid budget is absent")
            .budget(),
        None
    );
}

#[tokio::test]
async fn full_fixture_matches_billing_activity_history_and_wire_contract() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, MONTHLY_PAGE_1.to_vec()),
        FakeHttpResponse::new(200, MONTHLY_PAGE_2.to_vec()),
        FakeHttpResponse::new(200, CLOUDWATCH_PAGE_1.to_vec()),
        FakeHttpResponse::new(200, CLOUDWATCH_PAGE_2.to_vec()),
        FakeHttpResponse::new(200, DAILY.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", true);
    let fetched_at = timestamp("2026-08-30T12:00:00Z");
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Bedrock fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Bedrock);
    assert_full_sample(&sample);
    assert_full_wire(&server, fetched_at);
}

fn assert_full_sample(sample: &oab_domain::UsageSample) {
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get),
        Some(20.0)
    );
    assert_eq!(
        sample.primary().and_then(oab_domain::RateWindow::resets_at),
        Some(timestamp("2026-08-31T21:00:00Z"))
    );
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::reset_description)
            .map(oab_domain::BoundedText::as_str),
        Some("Monthly budget")
    );
    let cost = sample.cost().expect("monthly cost");
    assert_eq!(cost.used().amount(), decimal("20"));
    assert_eq!(cost.limit(), decimal("100"));
    assert_eq!(cost.period(), Some("Monthly"));
    assert_eq!(cost.provenance(), CostProvenance::VendorMetered);
    assert_eq!(cost.resets_at(), Some(timestamp("2026-08-31T21:00:00Z")));

    let login = sample
        .identity()
        .login_method()
        .map(oab_domain::BoundedText::as_str)
        .expect("login summary");
    assert_eq!(
        login,
        "Spend: $20.00 - Budget: $100.00 - Claude 14d: 4.5K tokens - Requests: 15"
    );
    assert_eq!(detail_value(sample, "Input tokens"), "3504");
    assert_eq!(detail_value(sample, "Output tokens"), "1000");
    assert_eq!(detail_value(sample, "Region"), "us-west-2");

    let history = sample.cost_usage().expect("30-day history");
    assert_eq!(history.history_days(), 30);
    assert!(history.history_coverage_is_established());
    assert_eq!(history.history_label(), Some("Last 30 days (UTC)"));
    assert_eq!(history.provenance(), CostProvenance::VendorMetered);
    assert_eq!(history.history().amount(), Some(decimal("7.5")));
    assert_eq!(history.session().amount(), Some(decimal("4")));
    assert_eq!(
        history
            .daily()
            .iter()
            .map(oab_domain::CostUsageDailyBucket::day)
            .collect::<Vec<_>>(),
        ["2026-08-28", "2026-08-29"]
    );
    assert_eq!(history.daily()[0].models().len(), 1);
    assert_eq!(history.daily()[0].models()[0].name(), "Amazon Bedrock");
    assert_eq!(
        history.daily()[0].models()[0].metrics().amount(),
        Some(decimal("3.5"))
    );
}

fn assert_full_wire(server: &FakeHttpServer, fetched_at: Timestamp) {
    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|request| request.method() == "POST"));
    assert_eq!(
        requests
            .iter()
            .map(|request| request.header("x-amz-target"))
            .collect::<Vec<_>>(),
        [
            Some("AWSInsightsIndexService.GetCostAndUsage"),
            Some("AWSInsightsIndexService.GetCostAndUsage"),
            Some("GraniteServiceVersion20100801.GetMetricData"),
            Some("GraniteServiceVersion20100801.GetMetricData"),
            Some("AWSInsightsIndexService.GetCostAndUsage"),
        ]
    );
    assert_eq!(
        requests[0].header("content-type"),
        Some("application/x-amz-json-1.1")
    );
    assert_eq!(
        requests[2].header("content-type"),
        Some("application/x-amz-json-1.0")
    );
    assert!(
        requests[0]
            .header("authorization")
            .is_some_and(|value| value.contains("/us-east-1/ce/aws4_request"))
    );
    assert!(
        requests[2]
            .header("authorization")
            .is_some_and(|value| value.contains("/us-west-2/monitoring/aws4_request"))
    );

    let monthly: Value = serde_json::from_slice(requests[0].body()).expect("monthly request");
    assert_eq!(monthly["TimePeriod"]["Start"], "2026-08-01");
    assert_eq!(monthly["TimePeriod"]["End"], "2026-08-31");
    assert_eq!(monthly["Granularity"], "MONTHLY");
    let monthly_page_2: Value =
        serde_json::from_slice(requests[1].body()).expect("monthly page 2 request");
    assert_eq!(monthly_page_2["NextPageToken"], "month-page-2");

    let cloudwatch: Value = serde_json::from_slice(requests[2].body()).expect("CloudWatch request");
    assert_eq!(cloudwatch["EndTime"], fetched_at.unix_timestamp());
    assert_eq!(
        cloudwatch["StartTime"],
        fetched_at.unix_timestamp() - 14 * 24 * 60 * 60
    );
    let queries = cloudwatch["MetricDataQueries"]
        .as_array()
        .expect("metric queries");
    assert_eq!(queries.len(), 3);
    assert!(queries.iter().all(|query| {
        query["Expression"]
            .as_str()
            .is_some_and(|value| value.starts_with("SUM(SEARCH(") && value.contains("86400"))
    }));
    let cloudwatch_page_2: Value =
        serde_json::from_slice(requests[3].body()).expect("CloudWatch page 2 request");
    assert_eq!(cloudwatch_page_2["NextToken"], "cloud-page-2");

    let daily: Value = serde_json::from_slice(requests[4].body()).expect("daily request");
    assert_eq!(daily["TimePeriod"]["Start"], "2026-08-01");
    assert_eq!(daily["TimePeriod"]["End"], "2026-08-31");
    assert_eq!(daily["Granularity"], "DAILY");
}

#[tokio::test]
async fn history_has_an_independent_context_checked_refresh_path() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, DAILY.to_vec())]).await;
    let provider = provider(&server, "history-account", false);
    let fetched_at = timestamp("2026-08-30T12:00:00Z");
    let history = provider
        .fetch_cost_history_at(&context("history-account"), fetched_at)
        .await
        .expect("independent history");
    assert_eq!(history.history().amount(), Some(decimal("7.5")));
    assert_eq!(server.requests().len(), 1);
    let body: Value =
        serde_json::from_slice(server.requests()[0].body()).expect("history request body");
    assert_eq!(body["Granularity"], "DAILY");

    let wrong_context = ProviderContext::new(
        scope("history-account"),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    );
    assert_eq!(
        provider
            .fetch_cost_history_at(&wrong_context, fetched_at)
            .await
            .expect_err("wrong source")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn data_unavailable_is_zero_but_other_bad_requests_are_api_errors() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(400, DATA_UNAVAILABLE.to_vec()),
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
    ])
    .await;
    let sample = provider(&server, "data-unavailable", false)
        .fetch_at(
            &context("data-unavailable"),
            timestamp("2026-08-30T12:00:00Z"),
        )
        .await
        .expect("data unavailable is zero");
    assert_eq!(sample.cost().expect("cost").used().amount(), decimal("0"));
    assert_eq!(
        sample
            .cost_usage()
            .expect("empty established history")
            .history()
            .amount(),
        Some(decimal("0"))
    );

    let unrelated = FakeHttpServer::start([FakeHttpResponse::new(
        400,
        br#"{"__type":"ValidationException","message":"secret fixture body"}"#.to_vec(),
    )])
    .await;
    let error = provider(&unrelated, "bad-request", false)
        .fetch_at(&context("bad-request"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect_err("unrelated 400");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(!format!("{error:?}").contains("secret fixture body"));
}

#[tokio::test]
async fn optional_cloudwatch_and_history_failures_preserve_monthly_spend() {
    let cloudwatch_denied = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page("12.50")),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(200, DAILY.to_vec()),
    ])
    .await;
    let sample = provider(&cloudwatch_denied, "cloudwatch-denied", true)
        .fetch_at(
            &context("cloudwatch-denied"),
            timestamp("2026-08-30T12:00:00Z"),
        )
        .await
        .expect("CloudWatch is best effort");
    assert_eq!(
        sample.cost().expect("cost").used().amount(),
        decimal("12.5")
    );
    assert!(sample.cost_usage().is_some());
    assert!(
        sample
            .detail_sections()
            .iter()
            .all(|section| section.title() != Some("Claude activity (14 days)"))
    );

    let malformed_history = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page("9.25")),
        FakeHttpResponse::new(200, b"not-json".to_vec()),
    ])
    .await;
    let sample = provider(&malformed_history, "history-malformed", false)
        .fetch_at(
            &context("history-malformed"),
            timestamp("2026-08-30T12:00:00Z"),
        )
        .await
        .expect("history is best effort");
    assert_eq!(
        sample.cost().expect("cost").used().amount(),
        decimal("9.25")
    );
    assert!(sample.cost_usage().is_none());
}

#[tokio::test]
async fn pagination_repetition_and_oversized_tokens_fail_closed() {
    let repeated = br#"{
        "NextPageToken":"repeat",
        "ResultsByTime":[]
    }"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, repeated.to_vec()),
        FakeHttpResponse::new(200, repeated.to_vec()),
    ])
    .await;
    let error = provider(&server, "repeat", false)
        .fetch_at(&context("repeat"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect_err("repeated pagination token");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert_eq!(server.requests().len(), 2);

    let oversized = serde_json::to_vec(&json!({
        "NextPageToken": "x".repeat(4097),
        "ResultsByTime": []
    }))
    .expect("oversized token fixture");
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, oversized)]).await;
    let error = provider(&server, "oversized", false)
        .fetch_at(&context("oversized"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect_err("oversized pagination token");
    assert_eq!(error.kind(), ErrorKind::Parse);
}

#[tokio::test]
async fn atomic_one_shot_bundle_wins_without_field_mixing() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
    ])
    .await;
    let environment = BTreeMap::from([
        (
            "AWS_ACCESS_KEY_ID".to_owned(),
            "AKIA_ENVIRONMENT".to_owned(),
        ),
        (
            "AWS_SECRET_ACCESS_KEY".to_owned(),
            "environment-secret".to_owned(),
        ),
        ("AWS_PROFILE".to_owned(), "ambient-profile".to_owned()),
        ("OMARCHY_AI_BAR_BEDROCK_API_URL".to_owned(), server.origin()),
    ]);
    let one_shot =
        BedrockCredentialBundle::new("AKIA_ONESHOT", "one-shot-secret", Some("one-shot-session"))
            .expect("one-shot bundle");
    let secret_service =
        BedrockCredentialBundle::new("AKIA_SECRET_SERVICE", "service-secret", None::<String>)
            .expect("Secret Service bundle");
    let settings =
        BedrockSettings::resolve_with_bundles(&environment, Some(one_shot), Some(secret_service))
            .expect("atomic resolution");
    let provider = BedrockProvider::with_local_offset(scope("atomic"), settings, UtcOffset::UTC)
        .expect("provider");
    provider
        .fetch_at(&context("atomic"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("one-shot request");
    let authorization = server.requests()[0]
        .header("authorization")
        .expect("authorization")
        .to_owned();
    assert!(authorization.contains("Credential=AKIA_ONESHOT/"));
    assert!(!authorization.contains("AKIA_ENVIRONMENT"));
    assert!(!authorization.contains("AKIA_SECRET_SERVICE"));
    assert!(
        server.requests()[0]
            .header("x-amz-security-token")
            .is_some()
    );
}

#[tokio::test]
async fn profile_mode_refreshes_via_shell_free_cli_and_removes_aws_profile() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page("3.25")),
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
    ])
    .await;
    let environment = profile_environment(&server, false);
    let settings = BedrockSettings::resolve(&environment).expect("profile settings");
    assert_eq!(settings.auth_mode(), BedrockAuthMode::Profile);
    let provider = BedrockProvider::with_local_offset(scope("profile"), settings, UtcOffset::UTC)
        .expect("profile provider");
    let sample = provider
        .fetch_at(&context("profile"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("profile fetch");
    assert_eq!(detail_value(&sample, "Region"), "ap-southeast-2");
    assert_eq!(
        sample.cost().expect("cost").used().amount(),
        decimal("3.25")
    );
    assert!(
        server.requests()[0]
            .header("authorization")
            .is_some_and(|value| value.contains("Credential=AKIA_PROFILE_FIXTURE/"))
    );

    let expired_server = FakeHttpServer::start([]).await;
    let expired_settings =
        BedrockSettings::resolve(&profile_environment(&expired_server, true)).expect("settings");
    let expired_provider = BedrockProvider::with_local_offset(
        scope("profile-expired"),
        expired_settings,
        UtcOffset::UTC,
    )
    .expect("provider");
    let error = expired_provider
        .fetch_at(
            &context("profile-expired"),
            timestamp("2026-08-30T12:00:00Z"),
        )
        .await
        .expect_err("expired SSO session");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert!(expired_server.requests().is_empty());
}

#[tokio::test]
async fn cloudwatch_saturates_large_totals_and_rejects_incomplete_results_softly() {
    let saturated = serde_json::to_vec(&json!({
        "MetricDataResults": [
            {"Id":"inputTokens", "StatusCode":"Complete", "Values":["9223372036854775808"]}
        ]
    }))
    .expect("fixture JSON");
    // Replace the string with a JSON number while retaining exact decimal text.
    let saturated = String::from_utf8(saturated)
        .expect("UTF-8")
        .replace("\"9223372036854775808\"", "9223372036854775808")
        .into_bytes();
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page("1")),
        FakeHttpResponse::new(200, saturated),
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
    ])
    .await;
    let sample = provider(&server, "saturating", true)
        .fetch_at(&context("saturating"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("saturated CloudWatch result");
    assert_eq!(detail_value(&sample, "Input tokens"), i64::MAX.to_string());

    let incomplete = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page("2")),
        FakeHttpResponse::new(200, br#"{"Messages":[{"Code":"MaxQueryLimit"}]}"#.to_vec()),
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
    ])
    .await;
    let sample = provider(&incomplete, "incomplete", true)
        .fetch_at(&context("incomplete"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("incomplete activity is optional");
    assert_eq!(sample.cost().expect("cost").used().amount(), decimal("2"));
    assert!(
        sample
            .detail_sections()
            .iter()
            .all(|section| section.title() != Some("Claude activity (14 days)"))
    );
}

#[tokio::test]
async fn extreme_spend_and_tiny_budget_saturate_without_decimal_division_panic() {
    const MAX_DECIMAL: &str = "79228162514264337593543950335";
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page(MAX_DECIMAL)),
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
    ])
    .await;
    let mut environment = static_environment(&server, false);
    environment.insert(
        "OMARCHY_AI_BAR_BEDROCK_BUDGET".to_owned(),
        "0.0000000000000000000000000001".to_owned(),
    );
    let settings = BedrockSettings::resolve(&environment).expect("extreme settings");
    let provider = BedrockProvider::with_local_offset(scope("extreme"), settings, UtcOffset::UTC)
        .expect("provider");
    let sample = provider
        .fetch_at(&context("extreme"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("extreme values remain bounded");

    assert_eq!(
        sample.cost().expect("cost").used().amount(),
        decimal(MAX_DECIMAL)
    );
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get),
        Some(100.0)
    );
}

#[tokio::test]
async fn monthly_cost_keeps_signed_adjustments_while_history_ignores_nonpositive_rows() {
    let daily = serde_json::to_vec(&json!({
        "ResultsByTime": [{
            "TimePeriod": {"Start": "2026-08-29", "End": "2026-08-30"},
            "Groups": [
                {
                    "Keys": ["Amazon Bedrock"],
                    "Metrics": {"UnblendedCost": {"Amount": "5.00", "Unit": "USD"}}
                },
                {
                    "Keys": ["Amazon Bedrock"],
                    "Metrics": {"UnblendedCost": {"Amount": "-2.00", "Unit": "USD"}}
                },
                {
                    "Keys": ["Amazon Bedrock"],
                    "Metrics": {"UnblendedCost": {"Amount": "0", "Unit": "USD"}}
                }
            ]
        }]
    }))
    .expect("daily fixture");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page("-1.50")),
        FakeHttpResponse::new(200, daily),
    ])
    .await;
    let sample = provider(&server, "adjustments", false)
        .fetch_at(&context("adjustments"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("signed monthly adjustment");

    assert_eq!(
        sample.cost().expect("cost").used().amount(),
        decimal("-1.5")
    );
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get),
        Some(0.0)
    );
    let history = sample.cost_usage().expect("history");
    assert_eq!(history.history().amount(), Some(decimal("5")));
    assert_eq!(history.session().amount(), Some(decimal("5")));
    assert_eq!(
        history.daily()[0].models()[0].metrics().amount(),
        Some(decimal("5"))
    );
}

#[tokio::test]
async fn request_count_uses_the_same_compact_formatter_as_tokens() {
    let activity = serde_json::to_vec(&json!({
        "MetricDataResults": [
            {"Id":"inputTokens", "StatusCode":"Complete", "Values":[]},
            {"Id":"outputTokens", "StatusCode":"Complete", "Values":[]},
            {"Id":"requests", "StatusCode":"Complete", "Values":[1500]}
        ]
    }))
    .expect("activity fixture");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, one_month_page("1")),
        FakeHttpResponse::new(200, activity),
        FakeHttpResponse::new(200, EMPTY_COST.to_vec()),
    ])
    .await;
    let sample = provider(&server, "compact-requests", true)
        .fetch_at(
            &context("compact-requests"),
            timestamp("2026-08-30T12:00:00Z"),
        )
        .await
        .expect("compact request count");

    assert!(
        sample
            .identity()
            .login_method()
            .is_some_and(|value| value.as_str().contains("Requests: 1.5K"))
    );
}

#[test]
fn cloudwatch_partition_endpoints_are_exact_and_invalid_regions_fail_closed() {
    let cases = [
        ("us-east-1", "monitoring.us-east-1.amazonaws.com"),
        ("us-gov-west-1", "monitoring.us-gov-west-1.amazonaws.com"),
        ("cn-north-1", "monitoring.cn-north-1.amazonaws.com.cn"),
        ("eusc-de-east-1", "monitoring.eusc-de-east-1.amazonaws.eu"),
        ("us-iso-east-1", "monitoring.us-iso-east-1.c2s.ic.gov"),
        ("us-isob-east-1", "monitoring.us-isob-east-1.sc2s.sgov.gov"),
        ("eu-isoe-west-1", "monitoring.eu-isoe-west-1.cloud.adc-e.uk"),
        (
            "us-isof-south-1",
            "monitoring.us-isof-south-1.csp.hci.ic.gov",
        ),
    ];
    for (region, host) in cases {
        assert_eq!(
            cloudwatch_url_for_region(region)
                .expect("valid region")
                .host_str(),
            Some(host)
        );
    }
    for region in ["", "US-EAST-1", "us_east_1", "us-east", "us-east-one"] {
        assert_eq!(
            cloudwatch_url_for_region(region)
                .expect_err("invalid region")
                .kind(),
            ErrorKind::Parse
        );
    }
}

fn aws_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/providers/bedrock/aws-cli-fixture.sh")
}

fn profile_environment(server: &FakeHttpServer, expired: bool) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        (
            "OMARCHY_AI_BAR_BEDROCK_AUTH_MODE".to_owned(),
            "profile".to_owned(),
        ),
        ("AWS_PROFILE".to_owned(), "work".to_owned()),
        (
            "AWS_ACCESS_KEY_ID".to_owned(),
            "AKIA_SOURCE_FIXTURE".to_owned(),
        ),
        (
            "AWS_SECRET_ACCESS_KEY".to_owned(),
            "source-secret-fixture".to_owned(),
        ),
        (
            "AWS_SESSION_TOKEN".to_owned(),
            "source-session-fixture".to_owned(),
        ),
        (
            "OMARCHY_AI_BAR_AWS_CLI_PATH".to_owned(),
            aws_fixture_path().to_string_lossy().into_owned(),
        ),
        ("OMARCHY_AI_BAR_BEDROCK_API_URL".to_owned(), server.origin()),
    ]);
    if expired {
        environment.insert("AWS_TEST_EXPIRED".to_owned(), "1".to_owned());
    }
    environment
}
