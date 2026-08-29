use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, DetailChartKind, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy,
    PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::zai::{ZaiProvider, ZaiRegion, ZaiSettings, ZaiUsageScope};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use time::UtcOffset;
use tokio_util::sync::CancellationToken;
use url::Url;

const QUOTA: &[u8] = include_bytes!("../../../fixtures/providers/zai/quota.json");
const CREDIT: &[u8] = include_bytes!("../../../fixtures/providers/zai/credit.json");
const BALANCE: &[u8] = include_bytes!("../../../fixtures/providers/zai/balance.json");
const HOURLY: &[u8] = include_bytes!("../../../fixtures/providers/zai/hourly.json");
const DAILY: &[u8] = include_bytes!("../../../fixtures/providers/zai/daily.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/zai/malformed.json");
const EMPTY_MODEL: &[u8] =
    br#"{"success":true,"code":200,"data":{"x_time":[],"modelDataList":[]}}"#;
const KEY_CANARY: &str = "fixture-zai-key-canary";
const ORGANIZATION_CANARY: &str = "fixture-zai-organization";
const PROJECT_CANARY: &str = "fixture-zai-project";

fn timestamp(raw: &str) -> Timestamp {
    Timestamp::parse(raw).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Zai,
        ProviderInstanceId::new("zai-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(retry: RetryPolicy) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        2 * 1024 * 1024,
        3,
        retry,
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

fn client(
    server: &FakeHttpServer,
    path: &str,
    account: &str,
    retry: RetryPolicy,
) -> FixedApiClient {
    FixedApiClient::new_bearer(
        scope(account),
        server.url(path),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client")
}

fn provider(
    server: &FakeHttpServer,
    account: &str,
    retry: RetryPolicy,
    region: ZaiRegion,
    usage_scope: ZaiUsageScope,
    local_offset: UtcOffset,
    with_balance: bool,
) -> ZaiProvider {
    let quota = client(server, "/custom/quota?keep=1&type=9", account, retry);
    let model = client(server, "/custom/model?discard=1", account, retry);
    let balance = with_balance.then(|| client(server, "/custom/balance", account, retry));
    ZaiProvider::from_clients(quota, model, balance, region, usage_scope, local_offset)
        .expect("z.ai provider")
}

fn personal_provider(server: &FakeHttpServer, account: &str, retry: RetryPolicy) -> ZaiProvider {
    provider(
        server,
        account,
        retry,
        ZaiRegion::Global,
        ZaiUsageScope::Personal,
        UtcOffset::UTC,
        false,
    )
}

fn detail_row<'a>(
    sample: &'a oab_domain::UsageSample,
    section: &str,
    label: &str,
) -> &'a oab_domain::DetailRow {
    sample
        .detail_sections()
        .iter()
        .find(|candidate| candidate.title() == Some(section))
        .expect("detail section")
        .rows()
        .iter()
        .find(|row| row.label() == label)
        .expect("detail row")
}

fn query(target: &str) -> BTreeMap<String, String> {
    Url::parse(&format!("http://fixture{target}"))
        .expect("captured target is a URL")
        .query_pairs()
        .into_owned()
        .collect()
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < f64::EPSILON);
}

fn unique_temp_directory(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fixture clock")
        .as_nanos();
    for ordinal in 0..100_u8 {
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-{label}-{}-{nonce}-{ordinal}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("could not create fixture directory: {error}"),
        }
    }
    panic!("could not allocate a unique fixture directory")
}

#[test]
fn settings_preserve_regional_credentials_routes_team_context_and_redaction() {
    let global = BTreeMap::from([("BIGMODEL_API_KEY".to_owned(), "china-only-key".to_owned())]);
    assert_eq!(
        ZaiSettings::resolve(&global)
            .expect_err("CN aliases cannot reach the global service")
            .kind(),
        ErrorKind::MissingCredential
    );

    let china = BTreeMap::from([
        ("Z_AI_REGION".to_owned(), " 'bigmodel-cn' ".to_owned()),
        (
            "BIGMODEL_API_KEY".to_owned(),
            " 'china-fallback-key' ".to_owned(),
        ),
    ]);
    let china = ZaiSettings::resolve(&china).expect("CN alias credential");
    assert_eq!(china.region(), ZaiRegion::BigModelCn);
    assert_eq!(
        china.quota_url().as_str(),
        "https://open.bigmodel.cn/api/monitor/usage/quota/limit"
    );
    assert_eq!(
        china.model_usage_url().as_str(),
        "https://open.bigmodel.cn/api/monitor/usage/model-usage"
    );
    assert_eq!(
        china.balance_url().expect("CN balance").as_str(),
        "https://www.bigmodel.cn/api/biz/account/query-customer-account-report"
    );

    let environment = BTreeMap::from([
        ("Z_AI_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        ("BIGMODEL_API_KEY".to_owned(), "not-selected".to_owned()),
        ("Z_AI_REGION".to_owned(), "bigmodel-cn".to_owned()),
        ("Z_AI_USAGE_SCOPE".to_owned(), "team".to_owned()),
        (
            "Z_AI_BIGMODEL_ORGANIZATION".to_owned(),
            format!(" {ORGANIZATION_CANARY} "),
        ),
        (
            "Z_AI_BIGMODEL_PROJECT".to_owned(),
            format!(" '{PROJECT_CANARY}' "),
        ),
        (
            "Z_AI_API_HOST".to_owned(),
            "proxy.example.test:8443/custom-model".to_owned(),
        ),
        (
            "Z_AI_QUOTA_URL".to_owned(),
            "proxy.example.test:8443/custom-quota?keep=1".to_owned(),
        ),
        (
            "Z_AI_BALANCE_URL".to_owned(),
            "balance.example.test:9443/custom-balance".to_owned(),
        ),
    ]);
    let settings = ZaiSettings::resolve(&environment).expect("team settings");
    assert_eq!(settings.region(), ZaiRegion::BigModelCn);
    assert!(matches!(
        settings.usage_scope(),
        ZaiUsageScope::Team { organization, project }
            if organization == ORGANIZATION_CANARY && project == PROJECT_CANARY
    ));
    assert_eq!(
        settings.quota_url().as_str(),
        "https://proxy.example.test:8443/custom-quota?keep=1"
    );
    assert_eq!(
        settings.model_usage_url().as_str(),
        "https://proxy.example.test:8443/custom-model"
    );
    assert_eq!(
        settings.balance_url().expect("override").as_str(),
        "https://balance.example.test:9443/custom-balance"
    );
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("china-fallback-key"));
}

#[test]
fn settings_fail_closed_for_scope_region_and_endpoint_mismatches() {
    for (name, value) in [
        ("Z_AI_REGION", "mars"),
        ("Z_AI_USAGE_SCOPE", "organization"),
        ("Z_AI_API_HOST", "http://proxy.example.test"),
        ("Z_AI_QUOTA_URL", "not a host / or url"),
        ("Z_AI_BALANCE_URL", "http://balance.example.test"),
    ] {
        let environment = BTreeMap::from([
            ("Z_AI_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            (name.to_owned(), value.to_owned()),
        ]);
        assert_eq!(
            ZaiSettings::resolve(&environment)
                .expect_err("invalid setting")
                .kind(),
            ErrorKind::Api,
            "{name}={value}"
        );
    }

    for environment in [
        BTreeMap::from([
            ("Z_AI_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("Z_AI_USAGE_SCOPE".to_owned(), "team".to_owned()),
            (
                "Z_AI_BIGMODEL_ORGANIZATION".to_owned(),
                ORGANIZATION_CANARY.to_owned(),
            ),
        ]),
        BTreeMap::from([
            ("Z_AI_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("Z_AI_USAGE_SCOPE".to_owned(), "team".to_owned()),
            (
                "Z_AI_BIGMODEL_PROJECT".to_owned(),
                PROJECT_CANARY.to_owned(),
            ),
        ]),
        BTreeMap::from([
            ("Z_AI_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("Z_AI_REGION".to_owned(), "global".to_owned()),
            (
                "Z_AI_API_HOST".to_owned(),
                "https://open.bigmodel.cn".to_owned(),
            ),
        ]),
        BTreeMap::from([
            ("Z_AI_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("Z_AI_REGION".to_owned(), "bigmodel-cn".to_owned()),
            (
                "Z_AI_QUOTA_URL".to_owned(),
                "https://api.z.ai/custom".to_owned(),
            ),
        ]),
    ] {
        assert_eq!(
            ZaiSettings::resolve(&environment)
                .expect_err("invalid bound settings")
                .kind(),
            ErrorKind::Api
        );
    }

    let proxy = BTreeMap::from([
        ("Z_AI_API_KEY".to_owned(), KEY_CANARY.to_owned()),
        (
            "Z_AI_API_HOST".to_owned(),
            "custom-proxy.example.test".to_owned(),
        ),
    ]);
    let proxy = ZaiSettings::resolve(&proxy).expect("arbitrary HTTPS proxy");
    assert_eq!(
        proxy.quota_url().as_str(),
        "https://custom-proxy.example.test/api/monitor/usage/quota/limit"
    );
    assert_eq!(
        proxy.model_usage_url().as_str(),
        "https://custom-proxy.example.test/api/monitor/usage/model-usage"
    );
}

#[test]
fn cn_credential_file_uses_the_first_nonempty_physical_line_only() {
    let root = unique_temp_directory("zai-credential");
    let credential_dir = root.join(".coding-relay");
    std::fs::create_dir_all(&credential_dir).expect("credential fixture directory");
    std::fs::write(
        credential_dir.join("glm-api-key"),
        "\nfixture-file-key\nignored-key\n",
    )
    .expect("credential fixture");
    let environment = BTreeMap::from([
        ("Z_AI_REGION".to_owned(), "bigmodel-cn".to_owned()),
        ("HOME".to_owned(), root.display().to_string()),
    ]);
    let settings = ZaiSettings::resolve(&environment).expect("file credential fallback");
    assert!(!format!("{settings:?}").contains("fixture-file-key"));

    let global = BTreeMap::from([("HOME".to_owned(), root.display().to_string())]);
    assert_eq!(
        ZaiSettings::resolve(&global)
            .expect_err("CN credential file is region-bound")
            .kind(),
        ErrorKind::MissingCredential
    );
    std::fs::remove_dir_all(root).expect("credential fixture cleanup");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end quota golden keeps its related contract assertions together"
)]
async fn personal_quota_normalizes_short_long_and_mcp_lanes_and_cli_schema() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, b"model-response-canary".to_vec()),
    ])
    .await;
    let provider = personal_provider(&server, "account-a", RetryPolicy::none());
    let fetched_at = timestamp("2026-08-31T06:00:00Z");
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("quota fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Zai);
    let primary = sample.primary().expect("short session quota");
    assert_percent(primary.used_percent().expect("percent").get(), 20.0);
    assert_eq!(primary.duration().expect("duration").seconds(), 5 * 60 * 60);
    assert_eq!(primary.resets_at(), Some(timestamp("2026-08-31T11:00:00Z")));
    assert_eq!(
        primary.reset_description().expect("description").as_str(),
        "5-hour"
    );

    let secondary = sample.secondary().expect("long token quota");
    assert_percent(secondary.used_percent().expect("percent").get(), 30.0);
    assert_eq!(
        secondary.duration().expect("duration").seconds(),
        30 * 86_400
    );
    assert_eq!(
        secondary.reset_description().expect("description").as_str(),
        "30 days window"
    );
    assert!(sample.tertiary().is_none());

    assert_eq!(sample.extra_windows().len(), 1);
    let mcp = &sample.extra_windows()[0];
    assert_eq!(mcp.id().as_str(), "zai-mcp");
    assert_eq!(mcp.title().as_str(), "MCP");
    assert_percent(
        mcp.window().used_percent().expect("MCP percent").get(),
        50.0,
    );
    assert_eq!(
        mcp.window().duration().expect("monthly marker").seconds(),
        30 * 86_400
    );
    assert_eq!(
        mcp.window()
            .reset_description()
            .expect("description")
            .as_str(),
        "MCP"
    );

    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "GLM Coding Pro"
    );
    let token = detail_row(&sample, "Quota details", "Token quota");
    assert_eq!(token.value(), "30% used");
    assert_eq!(
        token.secondary_value(),
        Some("10000 limit · 8000 remaining")
    );
    let session = detail_row(&sample, "Quota details", "Session token quota");
    assert_eq!(session.value(), "20% used");
    assert_eq!(
        session.secondary_value(),
        Some("1000 limit · 800 remaining")
    );
    assert_eq!(
        detail_row(&sample, "Quota details", "MCP quota").value(),
        "50% used"
    );
    assert_eq!(
        detail_row(&sample, "Quota details", "glm-4.5").value(),
        "180"
    );
    assert_eq!(
        detail_row(&sample, "Quota details", "glm-4.5-air").value(),
        "70"
    );
    assert_eq!(sample.detail_sections().len(), 1);

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].target(), "/custom/quota?keep=1&type=9");
    assert!(requests.iter().all(|request| {
        request.method() == "GET"
            && request.header("authorization") == Some("Bearer fixture-zai-key-canary")
            && request.header("accept") == Some("application/json")
            && request.header("bigmodel-organization").is_none()
            && request.header("bigmodel-project").is_none()
    }));

    let ready = ProviderSnapshot::ready(sample, Freshness::Fresh, RefreshPhase::Idle, None)
        .expect("ready snapshot");
    let envelope = SnapshotEnvelopeV1::new(fetched_at, vec![ready]).expect("CLI envelope");
    let projected = envelope.project(
        PrivacyPolicy::ShowPersonalInfo,
        PrivacySurface::Cli,
        &PrivacyKey::from_bytes([7_u8; 32]),
    );
    let json = serde_json::to_value(projected).expect("CLI JSON");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["extra_windows"][0]["id"],
        "zai-mcp"
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end CN golden keeps routing, balance, and chart assertions together"
)]
async fn cn_team_routes_headers_balance_and_local_model_ranges() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, HOURLY.to_vec()),
        FakeHttpResponse::new(200, DAILY.to_vec()),
    ])
    .await;
    let provider = provider(
        &server,
        "account-a",
        RetryPolicy::none(),
        ZaiRegion::BigModelCn,
        ZaiUsageScope::Team {
            organization: ORGANIZATION_CANARY.to_owned(),
            project: PROJECT_CANARY.to_owned(),
        },
        UtcOffset::from_hms(3, 0, 0).expect("UTC+3"),
        true,
    );
    let sample = provider
        .fetch_at(&context("account-a"), timestamp("2026-08-30T12:34:56Z"))
        .await
        .expect("CN team fixture");

    let balance = detail_row(&sample, "Quota details", "Account balance");
    assert_eq!(balance.value(), "¥12.35");
    assert_eq!(
        balance.secondary_value(),
        Some("recharged ¥20.00 · granted ¥3.50 · spent ¥11.66")
    );

    let hourly = sample
        .detail_sections()
        .iter()
        .find(|section| section.title() == Some("Hourly tokens"))
        .expect("hourly section");
    assert_eq!(hourly.rows()[0].label(), "GLM-4");
    assert_eq!(hourly.rows()[0].value(), "300");
    assert_eq!(hourly.rows()[1].label(), "Alpha");
    assert_eq!(hourly.rows()[1].value(), "100");
    assert_eq!(hourly.rows()[2].label(), "Unknown");
    assert_eq!(hourly.rows()[2].value(), "10");
    let chart = hourly.chart().expect("hourly chart");
    assert_eq!(chart.kind(), DetailChartKind::Bars);
    assert_eq!(chart.title(), Some("Hourly tokens"));
    assert_eq!(chart.unit(), Some("tokens"));
    assert_eq!(
        chart
            .points()
            .iter()
            .map(|point| (point.label(), point.value().get()))
            .collect::<Vec<_>>(),
        [("09:00", 160.0), ("11:00", 250.0)]
    );

    let daily = sample
        .detail_sections()
        .iter()
        .find(|section| section.title() == Some("Daily tokens"))
        .expect("daily section");
    assert_eq!(daily.rows()[0].label(), "GLM-5");
    assert_eq!(daily.rows()[0].value(), "3000");
    assert_eq!(daily.rows()[1].label(), "Alpha");
    assert_eq!(daily.rows()[1].value(), "1000");
    assert_eq!(daily.rows()[2].label(), "Beta");
    assert_eq!(daily.rows()[2].value(), "750");
    assert_eq!(
        daily
            .chart()
            .expect("daily chart")
            .points()
            .iter()
            .map(|point| (point.label(), point.value().get()))
            .collect::<Vec<_>>(),
        [
            ("2026-08-28", 1500.0),
            ("2026-08-29", 2250.0),
            ("2026-08-30", 1000.0),
        ]
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].target(), "/custom/quota?keep=1&type=2");
    assert_eq!(requests[1].target(), "/custom/balance");
    assert!(requests[1].header("bigmodel-organization").is_none());
    assert!(requests[1].header("bigmodel-project").is_none());
    for request in [&requests[0], &requests[2], &requests[3]] {
        assert_eq!(
            request.header("bigmodel-organization"),
            Some(ORGANIZATION_CANARY)
        );
        assert_eq!(request.header("bigmodel-project"), Some(PROJECT_CANARY));
    }
    for request in [&requests[2], &requests[3]] {
        assert_eq!(
            Url::parse(&format!("http://fixture{}", request.target()))
                .expect("model URL")
                .path(),
            "/custom/model"
        );
        assert!(!query(request.target()).contains_key("discard"));
        assert_eq!(
            query(request.target()).get("type").map(String::as_str),
            Some("3")
        );
    }
    let hourly_query = query(requests[2].target());
    assert_eq!(
        hourly_query.get("startTime").map(String::as_str),
        Some("2026-08-29 00:00:00")
    );
    assert_eq!(
        hourly_query.get("endTime").map(String::as_str),
        Some("2026-08-30 15:59:59")
    );
    let daily_query = query(requests[3].target());
    assert_eq!(
        daily_query.get("startTime").map(String::as_str),
        Some("2026-07-31 00:00:00")
    );
    assert_eq!(
        daily_query.get("endTime").map(String::as_str),
        Some("2026-08-30 15:59:59")
    );
}

#[tokio::test]
async fn credit_rate_uses_injected_utc_clock_at_peak_and_weekend_boundaries() {
    let cases = [
        ("2026-08-31T05:59:01Z", "Off-peak", "peak in 1m"),
        ("2026-08-31T06:00:00Z", "Peak", "off-peak in 4h"),
        ("2026-08-31T09:30:01Z", "Peak", "off-peak in 30m"),
        ("2026-08-31T10:00:00Z", "Off-peak", "peak in 20h"),
        ("2026-08-29T12:00:00Z", "Off-peak", "peak in 1d 18h"),
    ];
    let responses = cases.iter().flat_map(|_| {
        [
            FakeHttpResponse::new(200, CREDIT.to_vec()),
            FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
            FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
        ]
    });
    let server = FakeHttpServer::start(responses).await;
    let provider = personal_provider(&server, "account-a", RetryPolicy::none());

    for (at, value, secondary) in cases {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(at))
            .await
            .expect("credit fixture");
        assert_percent(
            sample
                .primary()
                .expect("session credit")
                .used_percent()
                .expect("percent")
                .get(),
            30.0,
        );
        assert_percent(
            sample
                .secondary()
                .expect("long credit")
                .used_percent()
                .expect("percent")
                .get(),
            62.0,
        );
        assert!(sample.extra_windows().is_empty());
        assert_eq!(
            sample
                .primary()
                .expect("session credit")
                .reset_description()
                .expect("description")
                .as_str(),
            "5-hour"
        );
        assert_eq!(
            sample
                .secondary()
                .expect("30-day credit")
                .reset_description()
                .expect("description")
                .as_str(),
            "30 days window"
        );
        assert_eq!(
            detail_row(&sample, "Quota details", "Credit quota").value(),
            "62% used"
        );
        assert_eq!(
            detail_row(&sample, "Quota details", "Session credit quota").value(),
            "30% used"
        );
        let rate = detail_row(&sample, "Quota details", "Quota rate");
        assert_eq!(rate.value(), value);
        assert_eq!(rate.secondary_value(), Some(secondary));
    }
}

#[tokio::test]
async fn optional_balance_and_each_model_feed_fail_independently() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(503, b"balance-canary".to_vec()),
        FakeHttpResponse::new(200, b"hourly-canary".to_vec()),
        FakeHttpResponse::new(401, b"daily-canary".to_vec()),
    ])
    .await;
    let provider = provider(
        &server,
        "account-a",
        RetryPolicy::none(),
        ZaiRegion::BigModelCn,
        ZaiUsageScope::Personal,
        UtcOffset::UTC,
        true,
    );
    let sample = provider
        .fetch_at(&context("account-a"), timestamp("2026-08-30T12:34:56Z"))
        .await
        .expect("authoritative quota survives optional failures");

    assert_percent(
        sample
            .primary()
            .expect("quota")
            .used_percent()
            .expect("percent")
            .get(),
        20.0,
    );
    assert_eq!(sample.detail_sections().len(), 1);
    assert!(
        sample.detail_sections()[0]
            .rows()
            .iter()
            .all(|row| row.label() != "Account balance")
    );
    assert_eq!(server.requests().len(), 4);
}

#[tokio::test]
async fn optional_services_require_exact_http_200() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(201, BALANCE.to_vec()),
        FakeHttpResponse::new(201, HOURLY.to_vec()),
        FakeHttpResponse::new(201, DAILY.to_vec()),
    ])
    .await;
    let provider = provider(
        &server,
        "account-a",
        RetryPolicy::none(),
        ZaiRegion::BigModelCn,
        ZaiUsageScope::Personal,
        UtcOffset::UTC,
        true,
    );
    let sample = provider
        .fetch_at(&context("account-a"), timestamp("2026-08-30T12:34:56Z"))
        .await
        .expect("quota remains usable");

    assert_eq!(sample.detail_sections().len(), 1);
    assert!(
        sample.detail_sections()[0]
            .rows()
            .iter()
            .all(|row| row.label() != "Account balance")
    );
}

#[tokio::test]
async fn balance_uses_non_null_fallback_and_filters_secondary_amounts() {
    let balance = br#"{
      "success":true,
      "code":200,
      "data":{
        "availableBalance":null,
        "balance":" 8 ",
        "rechargeAmount":" -2 ",
        "giveAmount":false,
        "totalSpendAmount":true
      }
    }"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, balance.to_vec()),
        FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
        FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
    ])
    .await;
    let provider = provider(
        &server,
        "account-a",
        RetryPolicy::none(),
        ZaiRegion::BigModelCn,
        ZaiUsageScope::Personal,
        UtcOffset::UTC,
        true,
    );
    let sample = provider
        .fetch_at(&context("account-a"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("balance fallback");
    let balance = detail_row(&sample, "Quota details", "Account balance");
    assert_eq!(balance.value(), "¥8.00");
    assert_eq!(
        balance.secondary_value(),
        Some("recharged ¥-2.00 · spent ¥1.00")
    );
}

#[tokio::test]
async fn malformed_quota_envelopes_and_entries_fail_closed_without_response_leaks() {
    let rejected = br#"{
      "success":false,
      "code":401,
      "msg":"provider-message-canary",
      "data":{"limits":[]}
    }"#;
    let malformed_unknown = br#"{
      "success":true,
      "code":200,
      "data":{"limits":[{"type":"FUTURE_LIMIT","unit":5,"number":1}]}
    }"#;
    let fractional_optional = br#"{
      "success":true,
      "code":200,
      "data":{"limits":[{
        "type":"TOKENS_LIMIT","unit":3,"number":5,"percentage":20,"remaining":1.5
      }]}
    }"#;
    let invalid_details = br#"{
      "success":true,
      "code":200,
      "data":{"limits":[{
        "type":"TIME_LIMIT","unit":5,"number":1,"percentage":20,"usageDetails":{}
      }]}
    }"#;
    let cases: [(&[u8], ErrorKind); 7] = [
        (rejected, ErrorKind::Api),
        (MALFORMED, ErrorKind::Parse),
        (br"[]", ErrorKind::Api),
        (
            br#"{"success":true,"code":200,"data":{}}"#,
            ErrorKind::Parse,
        ),
        (malformed_unknown, ErrorKind::Parse),
        (fractional_optional, ErrorKind::Parse),
        (invalid_details, ErrorKind::Parse),
    ];
    let server = FakeHttpServer::start(
        cases
            .iter()
            .map(|(body, _)| FakeHttpResponse::new(200, body.to_vec())),
    )
    .await;
    let provider = personal_provider(&server, "account-a", RetryPolicy::none());

    for (_, expected) in cases {
        let error = provider
            .fetch_at(&context("account-a"), timestamp("2026-08-30T12:00:00Z"))
            .await
            .expect_err("malformed quota");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains("provider-message-canary"));
        assert!(!debug.contains("response-canary"));
        assert!(!debug.contains(KEY_CANARY));
    }
}

#[tokio::test]
async fn every_completed_non_200_quota_status_is_an_api_failure_but_timeout_is_network() {
    let statuses = [201, 401, 403, 408, 429, 500, 503];
    let server = FakeHttpServer::start(
        statuses
            .into_iter()
            .map(|status| FakeHttpResponse::new(status, b"status-canary".to_vec())),
    )
    .await;
    let provider = personal_provider(&server, "account-a", RetryPolicy::none());
    for _ in statuses {
        let error = provider
            .fetch_at(&context("account-a"), timestamp("2026-08-30T12:00:00Z"))
            .await
            .expect_err("quota HTTP status");
        assert_eq!(error.kind(), ErrorKind::Api);
        assert!(!format!("{error:?}").contains("status-canary"));
    }

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let error = personal_provider(&stalled, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect_err("real transport timeout");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[tokio::test]
async fn transient_quota_retries_once_then_optional_feeds_continue() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
        FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
    ])
    .await;
    let retry = RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1));
    personal_provider(&server, "account-a", retry)
        .fetch_at(&context("account-a"), timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("retried quota fixture");
    assert_eq!(server.requests().len(), 4);
}

#[tokio::test]
async fn last_good_and_account_boundaries_remain_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, QUOTA.to_vec()),
        FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
        FakeHttpResponse::new(200, EMPTY_MODEL.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = personal_provider(&server, "account-a", RetryPolicy::none());
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp("2026-08-30T12:00:00Z"))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider
            .fetch_at(&provider_context, timestamp("2026-08-30T12:00:01Z"))
            .await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let before = server.requests().len();
    assert_eq!(
        provider
            .fetch_at(&context("account-b"), timestamp("2026-08-30T12:00:02Z"),)
            .await
            .expect_err("cross-account context")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), before);
}
