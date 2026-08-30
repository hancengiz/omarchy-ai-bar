use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, DataConfidence, DetailChartKind, ErrorKind, Freshness, PrivacyKey,
    PrivacyPolicy, PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::poe::PoeProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const BALANCE: &[u8] = include_bytes!("../../../fixtures/providers/poe/balance.json");
const HISTORY: &[u8] = include_bytes!("../../../fixtures/providers/poe/history.json");
const HISTORY_ALIASES: &[u8] =
    include_bytes!("../../../fixtures/providers/poe/history_aliases.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/poe/malformed.json");
const KEY_CANARY: &str = "fixture-poe-key-canary";
const BODY_CANARY: &str = "fixture-poe-response-secret-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Poe,
        ProviderInstanceId::new("poe-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(timeout: Duration, max_response_bytes: usize) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        timeout,
        max_response_bytes,
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

fn provider(server: &FakeHttpServer, account: &str) -> PoeProvider {
    provider_with_limits(server, account, Duration::from_millis(250), 5 * 1024 * 1024)
}

fn provider_with_limits(
    server: &FakeHttpServer,
    account: &str,
    timeout: Duration,
    max_response_bytes: usize,
) -> PoeProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(timeout, max_response_bytes),
    )
    .expect("fixed API client");
    PoeProvider::from_client(client).expect("Poe provider")
}

fn row<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a oab_domain::DetailRow {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .expect("detail row")
}

fn history_body(rows: Value, next_cursor: Value, has_more: Option<bool>) -> Vec<u8> {
    let mut root = serde_json::Map::from_iter([
        ("data".to_owned(), rows),
        ("next_cursor".to_owned(), next_cursor),
    ]);
    if let Some(has_more) = has_more {
        root.insert("has_more".to_owned(), Value::Bool(has_more));
    }
    serde_json::to_vec(&root).expect("history JSON")
}

#[test]
fn credential_resolution_trims_quotes_redacts_and_rejects_wrong_provider() {
    let environment = BTreeMap::from([("POE_API_KEY".to_owned(), format!("  '{KEY_CANARY}'  "))]);
    let credential = PoeProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));
    assert_eq!(
        PoeProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing credential")
            .kind(),
        ErrorKind::MissingCredential
    );
    assert_eq!(
        PoeProvider::resolve_credential(&BTreeMap::from([(
            "POE_API_KEY".to_owned(),
            " \" \" ".to_owned(),
        )]))
        .expect_err("empty quoted credential")
        .kind(),
        ErrorKind::MissingCredential
    );

    let wrong_scope = AccountScope::new(
        ProviderId::OpenRouter,
        ProviderInstanceId::new("openrouter-primary").expect("instance"),
        AccountKey::new("account-a").expect("account"),
    );
    let wrong = FixedApiClient::new_bearer(
        wrong_scope,
        url::Url::parse("https://api.poe.com/").expect("URL"),
        EndpointClass::PublicHttps,
        ApiKeyCredential::new(KEY_CANARY).expect("credential"),
        config(Duration::from_millis(250), 5 * 1024 * 1024),
    )
    .expect("client");
    assert_eq!(
        PoeProvider::from_client(wrong)
            .err()
            .expect("provider mismatch")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn golden_balance_and_history_match_snapshot_and_request_contract() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, HISTORY.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let sample = provider
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("Poe fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Poe);
    assert_eq!(sample.confidence(), DataConfidence::Unknown);
    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.tertiary().is_none());
    assert!(sample.balance().is_none());
    assert!(sample.cost().is_none());
    assert!(sample.cost_usage().is_none());
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("balance identity")
            .as_str(),
        "Balance: 2,500 points"
    );
    let section = &sample.detail_sections()[0];
    assert_eq!(section.title(), Some("Points"));
    assert_eq!(row(&sample, "Current balance").value(), "2,500 points");
    assert_eq!(row(&sample, "Today").value(), "0 points");
    assert_eq!(row(&sample, "Today").secondary_value(), Some("0 requests"));
    assert_eq!(row(&sample, "Last 7 days").value(), "20.5 points");
    assert_eq!(
        row(&sample, "Last 7 days").secondary_value(),
        Some("2 requests · $0.05")
    );
    assert_eq!(row(&sample, "Last 30 days").value(), "20.5 points");
    assert_eq!(row(&sample, "Top model").value(), "gpt-5");
    assert_eq!(
        row(&sample, "Top model").secondary_value(),
        Some("12.5 points")
    );
    assert_eq!(
        row(&sample, "Usage mix").value(),
        "API: 12.5 points · Chat: 8 points"
    );
    assert_eq!(
        row(&sample, "Recent activity").value(),
        "08-03 16:00 · claude-sonnet-4"
    );
    assert_eq!(row(&sample, "08-02 16:00").value(), "gpt-5");
    let chart = section.chart().expect("daily chart");
    assert_eq!(chart.kind(), DetailChartKind::Bars);
    assert_eq!(chart.title(), Some("Daily points"));
    assert_eq!(chart.unit(), Some("points"));
    assert_eq!(
        chart
            .points()
            .iter()
            .map(|point| (point.label(), point.value().get()))
            .collect::<Vec<_>>(),
        [("2026-08-02", 12.5), ("2026-08-03", 8.0)]
    );
    assert_eq!(sample.provenance().len(), 1);
    assert_eq!(sample.provenance()[0].source(), "poe");
    assert_eq!(sample.provenance()[0].strategy(), "api");

    let ready = ProviderSnapshot::ready(sample, Freshness::Fresh, RefreshPhase::Idle, None)
        .expect("ready snapshot");
    let envelope =
        SnapshotEnvelopeV1::new(timestamp(1_785_816_000), vec![ready]).expect("CLI envelope");
    let projected = envelope.project(
        PrivacyPolicy::ShowPersonalInfo,
        PrivacySurface::Cli,
        &PrivacyKey::from_bytes([7_u8; 32]),
    );
    let json = serde_json::to_value(projected).expect("CLI JSON");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["detail_sections"][0]["rows"][0]["value"],
        "2,500 points"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/usage/current_balance");
    assert_eq!(requests[1].method(), "GET");
    assert_eq!(requests[1].target(), "/usage/points_history?limit=100");
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-poe-key-canary")
            && request.header("accept") == Some("application/json")
            && request.header("content-type").is_none()
            && request.body().is_empty()
    }));
}

#[tokio::test]
async fn canonically_equivalent_equal_totals_preserve_javascript_map_insertion_order() {
    let history = history_body(
        json!([
            {
                "creation_time": 1_785_812_400,
                "cost_points": 1,
                "bot_name": "é",
                "usage_type": "é-type"
            },
            {
                "creation_time": 1_785_812_400,
                "cost_points": 1,
                "bot_name": "e\u{301}",
                "usage_type": "e\u{301}-type"
            }
        ]),
        Value::Null,
        None,
    );
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, history),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("Unicode tie fixture");

    assert_eq!(row(&sample, "Top model").value(), "é");
    assert_eq!(
        row(&sample, "Usage mix").value(),
        "é-type: 1 points · e\u{301}-type: 1 points"
    );
}

#[tokio::test]
async fn aliases_clamps_and_javascript_rounding_match_the_pinned_plugin() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, br#"{"current_point_balance":"1500.5"}"#.to_vec()),
        FakeHttpResponse::new(200, HISTORY_ALIASES.to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("alias fixture");

    assert_eq!(
        sample.identity().login_method().expect("balance").as_str(),
        "Balance: 1,501 points"
    );
    assert_eq!(row(&sample, "Today").value(), "4.3 points");
    assert_eq!(
        row(&sample, "Today").secondary_value(),
        Some("2 requests · $0.01")
    );
    assert_eq!(row(&sample, "Top model").value(), "model-b");
    assert_eq!(
        row(&sample, "Usage mix").value(),
        "Chat: 4.3 points · API: 0 points"
    );
    assert_eq!(
        row(&sample, "Recent activity").value(),
        "08-04 03:00 · model-b"
    );
    assert!(
        (sample.detail_sections()[0].chart().expect("chart").points()[0]
            .value()
            .get()
            - 4.25)
            .abs()
            < f64::EPSILON
    );
}

#[tokio::test]
async fn pagination_encodes_cursors_honors_cutoff_and_accepts_date_forms() {
    let cutoff_seconds = 1_783_224_000_i64;
    let first = history_body(
        json!([
            {"query_id":"exact","creation_time":cutoff_seconds,"cost_points":1,"bot_name":"seconds"},
            {"query_id":"old","creation_time":cutoff_seconds * 1000 - 1,"cost_points":50},
            {"query_id":"date","creation_time":"2026-08-04","points":2,"bot_name":"date-only"},
            {"query_id":"invalid","creation_time":"not-a-date","points":100}
        ]),
        Value::String(" cursor/?&= ".to_owned()),
        None,
    );
    let second = serde_json::to_vec(&json!({
        "results": [{
            "query_id": "next / two",
            "created_at": "2026-08-04 03:30:00Z",
            "point_cost": "3",
            "bot_name": "space-iso"
        }],
        "has_more": true
    }))
    .expect("second page");
    let third = history_body(
        json!([{
            "query_id":"stale",
            "creation_time": cutoff_seconds * 1000 - 1,
            "cost_points": 100
        }]),
        Value::String("must-not-be-requested".to_owned()),
        None,
    );
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, first),
        FakeHttpResponse::new(200, second),
        FakeHttpResponse::new(200, third),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("pagination fixture");

    assert_eq!(row(&sample, "Last 30 days").value(), "6 points");
    assert_eq!(
        row(&sample, "Last 30 days").secondary_value(),
        Some("3 requests")
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].target(), "/usage/points_history?limit=100");
    assert_eq!(
        requests[2].target(),
        "/usage/points_history?limit=100&starting_after=cursor%2F%3F%26%3D"
    );
    assert_eq!(
        requests[3].target(),
        "/usage/points_history?limit=100&starting_after=next%20%2F%20two"
    );
}

#[tokio::test]
async fn later_page_failure_preserves_entries_already_accepted() {
    let first = history_body(
        json!([{
            "query_id":"p1",
            "creation_time":1_785_812_400,
            "cost_points":5,
            "bot_name":"partial"
        }]),
        Value::String("page-two".to_owned()),
        None,
    );
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, first),
        FakeHttpResponse::new(500, BODY_CANARY.as_bytes().to_vec()),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("partial history");

    assert_eq!(row(&sample, "Today").value(), "5 points");
    assert_eq!(row(&sample, "Top model").value(), "partial");
    assert_eq!(server.requests().len(), 3);
}

#[tokio::test]
async fn every_first_page_history_failure_preserves_the_required_balance() {
    let oversized = vec![b'x'; 1_025];
    let cases = [
        FakeHttpResponse::new(401, BODY_CANARY.as_bytes().to_vec()),
        FakeHttpResponse::new(500, BODY_CANARY.as_bytes().to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::truncated(200, 100, br#"{"data":[]}"#.to_vec()),
        FakeHttpResponse::new(200, oversized),
        FakeHttpResponse::stall(),
    ];

    for failure in cases {
        let server =
            FakeHttpServer::start([FakeHttpResponse::new(200, BALANCE.to_vec()), failure]).await;
        let sample = provider_with_limits(&server, "account-a", Duration::from_millis(40), 1_024)
            .fetch_at(&context("account-a"), timestamp(1_785_816_000))
            .await
            .expect("balance survives optional history");

        assert_eq!(sample.detail_sections()[0].rows().len(), 1);
        assert_eq!(row(&sample, "Current balance").value(), "2,500 points");
        assert!(sample.detail_sections()[0].chart().is_none());
    }
}

#[tokio::test]
async fn balance_status_schema_and_number_failures_are_authoritative_and_redacted() {
    for (status, expected) in [
        (401, ErrorKind::AuthenticationExpired),
        (403, ErrorKind::AuthenticationExpired),
        (418, ErrorKind::Api),
        (429, ErrorKind::Api),
        (500, ErrorKind::Api),
    ] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(
            status,
            format!("{BODY_CANARY}-{KEY_CANARY}").into_bytes(),
        )])
        .await;
        let error = provider(&server, "account-a")
            .fetch_at(&context("account-a"), timestamp(1_785_816_000))
            .await
            .expect_err("required balance status");
        assert_eq!(error.kind(), expected);
        assert!(!error.to_string().contains(BODY_CANARY));
        assert!(!error.to_string().contains(KEY_CANARY));
    }

    for body in [
        MALFORMED.to_vec(),
        br"[]".to_vec(),
        br#"{"current_point_balance":true}"#.to_vec(),
        br#"{"current_point_balance":"NaN"}"#.to_vec(),
    ] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(200, body)]).await;
        assert_eq!(
            provider(&server, "account-a")
                .fetch_at(&context("account-a"), timestamp(1_785_816_000))
                .await
                .expect_err("required balance schema")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn failed_authoritative_refresh_retains_the_last_good_sample() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, br#"{"data":[]}"#.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1_785_816_000))
        .await
        .expect("last good");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider
            .fetch_at(&provider_context, timestamp(1_785_816_001))
            .await,
    );

    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));
}

#[tokio::test]
async fn absent_and_empty_string_balances_follow_javascript_optional_number_semantics() {
    let empty_history = br#"{"data":[],"next_cursor":null}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, br"{}".to_vec()),
        FakeHttpResponse::new(200, empty_history.to_vec()),
        FakeHttpResponse::new(200, br#"{"current_point_balance":""}"#.to_vec()),
        FakeHttpResponse::new(200, empty_history.to_vec()),
        FakeHttpResponse::new(200, br#"{"current_point_balance":1e-300}"#.to_vec()),
        FakeHttpResponse::new(200, empty_history.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");

    let absent = provider
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("absent balance");
    assert!(absent.identity().login_method().is_none());
    assert!(absent.detail_sections()[0].rows().is_empty());

    let empty = provider
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("empty string is JavaScript zero");
    assert_eq!(
        empty
            .identity()
            .login_method()
            .expect("zero balance")
            .as_str(),
        "Balance: 0 points"
    );

    let tiny = provider
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("tiny finite balance rounds to zero");
    assert_eq!(row(&tiny, "Current balance").value(), "0 points");
}

#[tokio::test]
async fn history_is_bounded_to_five_pages_and_overfull_pages_fail_closed() {
    let mut responses = vec![FakeHttpResponse::new(200, BALANCE.to_vec())];
    for page in 0..5 {
        responses.push(FakeHttpResponse::new(
            200,
            history_body(
                json!([{
                    "query_id": format!("row-{page}"),
                    "creation_time": 1_785_812_400,
                    "cost_points": 1,
                    "bot_name": "bounded"
                }]),
                Value::String(format!("page-{}", page + 1)),
                None,
            ),
        ));
    }
    let server = FakeHttpServer::start(responses).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("five bounded pages");
    assert_eq!(row(&sample, "Today").value(), "5 points");
    assert_eq!(server.requests().len(), 6);

    let rows = (0..101)
        .map(|index| {
            json!({
                "query_id": format!("over-{index}"),
                "creation_time": 1_785_812_400,
                "cost_points": 1
            })
        })
        .collect::<Vec<_>>();
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, history_body(Value::Array(rows), Value::Null, None)),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("overfull optional page is ignored");
    assert_eq!(sample.detail_sections()[0].rows().len(), 1);
    assert!(sample.detail_sections()[0].chart().is_none());
}

#[tokio::test]
async fn account_source_origin_and_output_bounds_fail_closed_without_credential_leakage() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, BALANCE.to_vec())]).await;
    let scoped_provider = provider(&server, "account-a");
    assert_eq!(
        scoped_provider
            .fetch_at(&context("account-b"), timestamp(1_785_816_000))
            .await
            .expect_err("account mismatch")
            .kind(),
        ErrorKind::Api
    );
    let wrong_source = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ConfigurableEndpoint,
        CancellationToken::new(),
    );
    assert_eq!(
        scoped_provider
            .fetch_at(&wrong_source, timestamp(1_785_816_000))
            .await
            .expect_err("source mismatch")
            .kind(),
        ErrorKind::Api
    );
    assert!(server.requests().is_empty());

    let sink = FakeHttpServer::start([]).await;
    let redirect = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", sink.url("/steal").as_str())
    ])
    .await;
    let error = provider(&redirect, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(sink.requests().is_empty());
    assert_eq!(redirect.requests().len(), 1);
    assert_eq!(
        redirect.requests()[0].header("authorization"),
        Some("Bearer fixture-poe-key-canary")
    );

    let oversized_model = "m".repeat(121);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(
            200,
            history_body(
                json!([{
                    "creation_time":1_785_812_400,
                    "cost_points":1,
                    "bot_name":oversized_model
                }]),
                Value::Null,
                None,
            ),
        ),
    ])
    .await;
    let error = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect_err("bounded output text");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!error.to_string().contains(KEY_CANARY));
}

#[tokio::test]
async fn millisecond_cutoff_pre_epoch_clipping_and_large_number_formatting_are_explicit() {
    let cutoff_millis = 1_783_224_000_000_i64;
    let history = history_body(
        json!([
            {"query_id":"included","creation_time":cutoff_millis,"cost_points":1},
            {"query_id":"excluded","creation_time":cutoff_millis - 1,"cost_points":100},
            {"query_id":"pre-epoch","creation_time":-0.0005,"cost_points":100}
        ]),
        Value::Null,
        None,
    );
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, br#"{"current_point_balance":1.2e21}"#.to_vec()),
        FakeHttpResponse::new(200, history),
    ])
    .await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1_785_816_000))
        .await
        .expect("boundary fixture");

    assert_eq!(row(&sample, "Current balance").value(), "1.2e+21 points");
    assert_eq!(row(&sample, "Last 30 days").value(), "1 points");
    assert_eq!(
        row(&sample, "Last 30 days").secondary_value(),
        Some("1 requests")
    );

    for (raw, expected) in [("1e21", "1e+21 points"), ("-1e21", "-1e+21 points")] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(
                200,
                format!(r#"{{"current_point_balance":{raw}}}"#).into_bytes(),
            ),
            FakeHttpResponse::new(200, br#"{"data":[]}"#.to_vec()),
        ])
        .await;
        let sample = provider(&server, "account-a")
            .fetch_at(&context("account-a"), timestamp(1_785_816_000))
            .await
            .expect("exact scientific threshold");
        assert_eq!(row(&sample, "Current balance").value(), expected);
    }
}

#[tokio::test]
async fn textual_pre_epoch_floor_and_numeric_timeclip_truncation_remain_distinct() {
    let textual = history_body(
        json!([
            {
                "query_id":"floored-out",
                "creation_time":"1969-12-31T23:59:59.123999Z",
                "cost_points":100,
                "bot_name":"excluded"
            },
            {
                "query_id":"floored-in",
                "creation_time":"1969-12-31T23:59:59.124001Z",
                "cost_points":1,
                "bot_name":"included"
            }
        ]),
        Value::Null,
        None,
    );
    let numeric = history_body(
        json!([{
            "query_id":"timeclip",
            "creation_time":-0.0005,
            "cost_points":2,
            "bot_name":"numeric"
        }]),
        Value::Null,
        None,
    );
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, textual),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, numeric),
    ])
    .await;
    let provider = provider(&server, "account-a");

    let textual_cutoff =
        Timestamp::parse("1970-01-30T23:59:59.124Z").expect("millisecond textual cutoff");
    let textual = provider
        .fetch_at(&context("account-a"), textual_cutoff)
        .await
        .expect("textual pre-epoch fixture");
    assert_eq!(row(&textual, "Last 30 days").value(), "1 points");
    assert_eq!(
        row(&textual, "Recent activity").value(),
        "12-31 23:59 · included"
    );

    let numeric_cutoff =
        Timestamp::parse("1970-01-31T00:00:00Z").expect("millisecond numeric cutoff");
    let numeric = provider
        .fetch_at(&context("account-a"), numeric_cutoff)
        .await
        .expect("numeric pre-epoch fixture");
    assert_eq!(row(&numeric, "Last 30 days").value(), "2 points");
    assert_eq!(
        row(&numeric, "Recent activity").value(),
        "01-01 00:00 · numeric"
    );
}
