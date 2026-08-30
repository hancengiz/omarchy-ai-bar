use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, CostProvenance, ErrorKind, ExactDecimal, Freshness, PrivacyKey,
    PrivacyPolicy, PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::clawrouter::{ClawRouterProvider, ClawRouterSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const BUDGETED: &[u8] = include_bytes!("../../../fixtures/providers/clawrouter/budgeted.json");
const UNMETERED: &[u8] = include_bytes!("../../../fixtures/providers/clawrouter/unmetered.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/clawrouter/malformed.json");
const KEY_CANARY: &str = "fixture-clawrouter-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::ClawRouter,
        ProviderInstanceId::new("clawrouter-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(response_limit: usize, request_timeout: Duration) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        request_timeout,
        response_limit,
        3,
        RetryPolicy::none(),
    )
    .expect("fixture transport")
}

fn context(account: &str) -> ProviderContext {
    ProviderContext::new(
        scope(account),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    )
}

fn provider(server: &FakeHttpServer, base_path: &str, account: &str) -> ClawRouterProvider {
    provider_with_config(
        server,
        base_path,
        account,
        config(5 * 1024 * 1024, Duration::from_millis(250)),
    )
}

fn provider_with_config(
    server: &FakeHttpServer,
    base_path: &str,
    account: &str,
    config: TransportConfig,
) -> ClawRouterProvider {
    let endpoint = ConfiguredEndpoint::parse(
        server.url(base_path).as_str(),
        ConfiguredHttpPolicy::LoopbackHttp,
    )
    .expect("fixture endpoint");
    let client = FixedApiClient::new_bearer(
        scope(account),
        endpoint.url().clone(),
        endpoint.class(),
        ApiKeyCredential::new(KEY_CANARY).expect("fixture key"),
        config,
    )
    .expect("fixture client");
    ClawRouterProvider::from_client(client, endpoint).expect("ClawRouter provider")
}

fn row<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a oab_domain::DetailRow {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .expect("detail row")
}

fn budgeted_value() -> Value {
    serde_json::from_slice(BUDGETED).expect("budgeted fixture JSON")
}

#[test]
fn settings_apply_default_and_bare_https_endpoint_rules_and_redact() {
    let defaults = BTreeMap::from([("CLAWROUTER_API_KEY".to_owned(), format!(" '{KEY_CANARY}' "))]);
    let settings = ClawRouterSettings::resolve(&defaults).expect("default settings");
    assert_eq!(
        settings.endpoint().as_str(),
        "https://clawrouter.openclaw.ai/"
    );

    let environment = BTreeMap::from([
        ("CLAWROUTER_API_KEY".to_owned(), format!(" '{KEY_CANARY}' ")),
        (
            "CLAWROUTER_BASE_URL".to_owned(),
            " 'router.example.test:8443/gateway/v1/' ".to_owned(),
        ),
    ]);
    let settings = ClawRouterSettings::resolve(&environment).expect("bare HTTPS settings");
    assert_eq!(
        settings.endpoint().as_str(),
        "https://router.example.test:8443/gateway/v1/"
    );
    let debug = format!("{settings:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains("router.example.test"));

    assert_eq!(
        ClawRouterSettings::resolve(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    let oversized = BTreeMap::from([("CLAWROUTER_API_KEY".to_owned(), "x".repeat(16 * 1024 + 1))]);
    assert_eq!(
        ClawRouterSettings::resolve(&oversized)
            .expect_err("oversized key")
            .kind(),
        ErrorKind::MissingCredential
    );

    for endpoint in [
        "http://router.example.test",
        "ftp://router.example.test",
        "https://user:pass@router.example.test",
        "https://router.example.test/path?key=canary",
        "https://router.example.test/path#fragment",
        "https:\\router.example.test",
        "https://",
    ] {
        let environment = BTreeMap::from([
            ("CLAWROUTER_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("CLAWROUTER_BASE_URL".to_owned(), endpoint.to_owned()),
        ]);
        assert_eq!(
            ClawRouterSettings::resolve(&environment)
                .expect_err("unsafe endpoint")
                .kind(),
            ErrorKind::Api,
            "endpoint: {endpoint}"
        );
    }
}

#[tokio::test]
async fn budgeted_fixture_matches_request_snapshot_details_chart_and_cli_contract() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, BUDGETED.to_vec())]).await;
    let provider = provider(&server, "/gateway/v1/", "account-a");
    let fetched_at = timestamp(1_785_686_400);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("budgeted fixture");

    assert_eq!(provider.descriptor().id, ProviderId::ClawRouter);
    let primary = sample.primary().expect("monthly budget lane");
    assert!((primary.used_percent().expect("percent").get() - 0.024).abs() < f64::EPSILON);
    let reset = Timestamp::parse("2026-08-01T00:00:00Z").expect("reset");
    assert_eq!(primary.resets_at(), Some(reset));
    assert!(sample.secondary().is_none());
    assert!(sample.tertiary().is_none());

    let cost = sample.cost().expect("budget cost");
    assert_eq!(cost.used().amount(), decimal("0.006"));
    assert_eq!(cost.limit(), decimal("25"));
    assert_eq!(cost.period(), Some("This month"));
    assert_eq!(cost.resets_at(), Some(reset));
    assert_eq!(cost.provenance(), CostProvenance::VendorMetered);
    assert_eq!(sample.fetched_at(), fetched_at);
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("organization")
            .as_str(),
        "2 routed providers"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("login method")
            .as_str(),
        "Managed monthly budget"
    );
    assert_eq!(row(&sample, "Requests").value(), "6");
    assert_eq!(
        row(&sample, "Requests").secondary_value(),
        Some("5 succeeded · 1 failed")
    );
    assert_eq!(row(&sample, "Tokens").value(), "54191");
    assert_eq!(
        row(&sample, "Tokens").secondary_value(),
        Some("50000 input · 4191 output")
    );
    assert_eq!(row(&sample, "Actual cost").value(), "$0.006000");
    assert_eq!(row(&sample, "Budget ledger").value(), "durable_object");
    assert_eq!(row(&sample, "Monthly budget").value(), "$0.006000 / $25.00");
    assert_eq!(
        row(&sample, "Monthly budget").secondary_value(),
        Some("$24.994000 remaining")
    );

    let routed = &sample.detail_sections()[1];
    assert_eq!(routed.title(), Some("Routed providers"));
    assert_eq!(
        routed
            .rows()
            .iter()
            .map(oab_domain::DetailRow::label)
            .collect::<Vec<_>>(),
        ["openai", "anthropic"]
    );
    assert_eq!(routed.rows()[0].value(), "4 requests");
    assert_eq!(
        routed.rows()[0].secondary_value(),
        Some("$0.004000 · 42000 tokens")
    );
    let chart = routed.chart().expect("provider chart");
    assert_eq!(chart.title(), Some("Provider cost"));
    assert_eq!(chart.unit(), Some("USD"));
    assert_eq!(chart.points()[0].label(), "openai");
    assert!((chart.points()[0].value().get() - 0.004).abs() < f64::EPSILON);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/gateway/v1/usage");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-clawrouter-key-canary")
    );
    assert_eq!(requests[0].header("accept"), Some("application/json"));

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
        json["snapshots"][0]["last_known_good"]["detail_sections"][1]["rows"][0]["label"],
        "openai"
    );
}

#[tokio::test]
async fn unmetered_fixture_keeps_actual_spend_and_data_driven_provider_order() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, UNMETERED.to_vec())]).await;
    let sample = provider(&server, "/", "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("unmetered fixture");

    assert!(sample.primary().is_none());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("login method")
            .as_str(),
        "Unmetered"
    );
    let cost = sample.cost().expect("actual spend");
    assert_eq!(cost.used().amount(), decimal("1.25"));
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.resets_at(), None);
    assert_eq!(row(&sample, "Actual cost").value(), "$1.250000");
    assert!(
        sample.detail_sections()[0]
            .rows()
            .iter()
            .all(|row| row.label() != "Monthly budget")
    );
    assert_eq!(
        sample.detail_sections()[1]
            .rows()
            .iter()
            .map(oab_domain::DetailRow::label)
            .collect::<Vec<_>>(),
        ["replicate", "tavily"]
    );

    let mut zero = serde_json::from_slice::<Value>(UNMETERED).expect("fixture JSON");
    zero["usage"]["summary"]["actualCostMicros"] = json!(0);
    let zero_server = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        serde_json::to_vec(&zero).unwrap(),
    )])
    .await;
    let zero_sample = provider(&zero_server, "/v1", "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("zero spend fixture");
    assert!(zero_sample.cost().is_none());
    assert_eq!(row(&zero_sample, "Actual cost").value(), "$0.000000");
}

#[tokio::test]
async fn utc_month_reset_handles_suffix_rollover_absence_and_invalid_months() {
    let mut november = budgeted_value();
    november["budget"]["windowKey"] = json!("tenant/policy/2026-11");
    let mut december = budgeted_value();
    december["budget"]["windowKey"] = json!("2026-12");
    let mut zero_month = budgeted_value();
    zero_month["budget"]["windowKey"] = json!("prefix-2026-00");
    let mut malformed = budgeted_value();
    malformed["budget"]["windowKey"] = json!("2026/11");
    let mut non_string = budgeted_value();
    non_string["budget"]["windowKey"] = json!(202_611);
    let mut invalid = budgeted_value();
    invalid["budget"]["windowKey"] = json!("tenant/2026-13");
    let mut leading_zero_year = budgeted_value();
    leading_zero_year["budget"]["windowKey"] = json!("tenant/0099-01");
    let mut maximum_year_rollover = budgeted_value();
    maximum_year_rollover["budget"]["windowKey"] = json!("tenant/9999-12");

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, serde_json::to_vec(&november).unwrap()),
        FakeHttpResponse::new(200, serde_json::to_vec(&december).unwrap()),
        FakeHttpResponse::new(200, serde_json::to_vec(&zero_month).unwrap()),
        FakeHttpResponse::new(200, serde_json::to_vec(&malformed).unwrap()),
        FakeHttpResponse::new(200, serde_json::to_vec(&non_string).unwrap()),
        FakeHttpResponse::new(200, serde_json::to_vec(&invalid).unwrap()),
        FakeHttpResponse::new(200, serde_json::to_vec(&leading_zero_year).unwrap()),
        FakeHttpResponse::new(200, serde_json::to_vec(&maximum_year_rollover).unwrap()),
    ])
    .await;
    let provider = provider(&server, "/v1", "account-a");
    let expected = [
        Some("2026-12-01T00:00:00Z"),
        Some("2027-01-01T00:00:00Z"),
        Some("2026-01-01T00:00:00Z"),
        None,
        None,
    ];
    for expected in expected {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect("month fixture");
        assert_eq!(
            sample.primary().expect("primary").resets_at(),
            expected.map(|value| Timestamp::parse(value).expect("expected reset"))
        );
    }
    for reason in [
        "invalid month",
        "leading-zero year",
        "maximum-year rollover",
    ] {
        assert_eq!(
            provider
                .fetch_at(&context("account-a"), timestamp(1))
                .await
                .expect_err(reason)
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn provider_breakdown_caps_rows_and_collapses_chart_tail() {
    let providers = (0..121)
        .map(|index| {
            json!({
                "provider": format!("provider-{index:03}"),
                "requestCount": index,
                "successCount": index,
                "errorCount": 0,
                "totalTokens": index * 10,
                "actualCostMicros": 1
            })
        })
        .collect::<Vec<_>>();
    let body = json!({
        "budget": {
            "configured": false,
            "ledger": "unmetered",
            "windowKey": null,
            "limitMicros": null,
            "spentMicros": null,
            "remainingMicros": null
        },
        "usage": {
            "summary": {
                "requestCount": 7260,
                "successCount": 7260,
                "errorCount": 0,
                "inputTokens": 0,
                "outputTokens": 0,
                "totalTokens": 0,
                "actualCostMicros": 121
            },
            "providers": providers
        }
    });
    let server = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        serde_json::to_vec(&body).expect("fixture body"),
    )])
    .await;
    let sample = provider(&server, "/", "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("large provider fixture");
    assert_eq!(
        sample.identity().organization().expect("count").as_str(),
        "121 routed providers"
    );
    let routed = &sample.detail_sections()[1];
    assert_eq!(routed.rows().len(), 20);
    assert_eq!(routed.rows()[0].label(), "provider-120");
    assert_eq!(routed.rows()[19].label(), "provider-101");
    let chart = routed.chart().expect("chart");
    assert_eq!(chart.points().len(), 120);
    assert_eq!(chart.points()[118].label(), "provider-002");
    assert_eq!(chart.points()[119].label(), "Other");
    assert!((chart.points()[119].value().get() - 0.000_002).abs() < f64::EPSILON);
}

#[tokio::test]
async fn schema_and_integer_coercions_fail_closed_without_response_leaks() {
    let mut cases = vec![
        MALFORMED.to_vec(),
        br"[]".to_vec(),
        br"not-json-response-canary".to_vec(),
    ];
    for (path, value) in [
        (vec!["budget", "configured"], json!("true")),
        (vec!["budget", "ledger"], json!(7)),
        (vec!["usage", "providers"], json!({})),
        (vec!["usage", "summary", "requestCount"], json!("6")),
        (vec!["usage", "summary", "actualCostMicros"], json!(1.5)),
        (
            vec!["usage", "summary", "totalTokens"],
            json!(9_007_199_254_740_992_i64),
        ),
        (vec!["usage", "providers", "0", "provider"], json!(7)),
        (vec!["usage", "providers", "0", "requestCount"], json!("2")),
    ] {
        let mut body = budgeted_value();
        let mut cursor = &mut body;
        for component in &path[..path.len() - 1] {
            cursor = if let Ok(index) = component.parse::<usize>() {
                &mut cursor[index]
            } else {
                &mut cursor[*component]
            };
        }
        cursor[path[path.len() - 1]] = value;
        cases.push(serde_json::to_vec(&body).expect("schema case"));
    }

    let responses = cases
        .iter()
        .cloned()
        .map(|body| FakeHttpResponse::new(200, body));
    let server = FakeHttpServer::start(responses).await;
    let provider = provider(&server, "/", "account-a");
    for _ in cases {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("schema failure");
        assert_eq!(error.kind(), ErrorKind::Parse);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("response-canary"));
    }
}

#[tokio::test]
async fn http_status_transport_and_cached_failure_classes_are_stable() {
    for (status, expected) in [
        (401, ErrorKind::AuthenticationExpired),
        (403, ErrorKind::AuthenticationExpired),
        (429, ErrorKind::RateLimited),
        (500, ErrorKind::ProviderUnavailable),
        (503, ErrorKind::ProviderUnavailable),
        (400, ErrorKind::Api),
    ] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(
            status,
            b"provider-status-response-canary".to_vec(),
        )])
        .await;
        let error = provider(&server, "/", "account-a")
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("HTTP status");
        assert_eq!(error.kind(), expected, "status: {status}");
        assert!(!format!("{error:?}").contains("response-canary"));
    }

    let truncated = FakeHttpServer::start([FakeHttpResponse::truncated(
        200,
        BUDGETED.len() + 10,
        BUDGETED.to_vec(),
    )])
    .await;
    assert_eq!(
        provider(&truncated, "/", "account-a")
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("truncated response")
            .kind(),
        ErrorKind::Parse
    );

    let oversized = FakeHttpServer::start([FakeHttpResponse::new(200, BUDGETED.to_vec())]).await;
    assert_eq!(
        provider_with_config(
            &oversized,
            "/",
            "account-a",
            config(64, Duration::from_millis(250)),
        )
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect_err("oversized response")
        .kind(),
        ErrorKind::Parse
    );

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    assert_eq!(
        provider_with_config(
            &stalled,
            "/",
            "account-a",
            config(5 * 1024 * 1024, Duration::from_millis(25)),
        )
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect_err("transport timeout")
        .kind(),
        ErrorKind::Network
    );

    let cache_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BUDGETED.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let cache_provider = provider(&cache_server, "/", "account-a");
    let provider_context = context("account-a");
    let last_good = cache_provider
        .fetch_at(&provider_context, timestamp(1))
        .await
        .expect("last good");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        cache_provider
            .fetch_at(&provider_context, timestamp(2))
            .await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));
}

#[tokio::test]
async fn account_scope_client_binding_and_redirects_isolate_the_policy_key() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, BUDGETED.to_vec())]).await;
    let scoped_provider = provider(&server, "/", "account-a");
    assert_eq!(
        scoped_provider
            .fetch_at(&context("account-b"), timestamp(1))
            .await
            .expect_err("cross-account context")
            .kind(),
        ErrorKind::Api
    );
    assert!(server.requests().is_empty());

    let wrong_scope = AccountScope::new(
        ProviderId::OpenRouter,
        ProviderInstanceId::new("wrong-provider").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    let endpoint =
        ConfiguredEndpoint::parse(server.url("/").as_str(), ConfiguredHttpPolicy::LoopbackHttp)
            .expect("endpoint");
    let wrong_client = FixedApiClient::new_bearer(
        wrong_scope,
        endpoint.url().clone(),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("key"),
        config(5 * 1024 * 1024, Duration::from_millis(250)),
    )
    .expect("wrong client");
    assert_eq!(
        ClawRouterProvider::from_client(wrong_client, endpoint)
            .err()
            .expect("wrong provider")
            .kind(),
        ErrorKind::Api
    );

    let target = FakeHttpServer::start([FakeHttpResponse::new(200, BUDGETED.to_vec())]).await;
    let source =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let error = provider(&source, "/v1", "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(target.requests().is_empty());
    assert_eq!(source.requests().len(), 1);
    assert_eq!(
        source.requests()[0].header("authorization"),
        Some("Bearer fixture-clawrouter-key-canary")
    );
}
