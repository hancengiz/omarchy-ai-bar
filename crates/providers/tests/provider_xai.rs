use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, DataConfidence, ErrorKind, ExactDecimal, Freshness, PrivacyKey,
    PrivacyPolicy, PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::xai::{XaiCredential, XaiProvider};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const BALANCE: &[u8] = include_bytes!("../../../fixtures/providers/xai/balance.json");
const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/xai/usage.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/xai/malformed.json");
const EMPTY_USAGE: &[u8] = br#"{"timeSeries":[],"limitReached":false}"#;
const KEY_CANARY: &str = "fixture-xai-management-key-canary";
const TEAM_CANARY: &str = "fixture-xai-team-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Xai,
        ProviderInstanceId::new("xai-primary").expect("provider instance"),
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

fn provider(
    server: &FakeHttpServer,
    account: &str,
    team_id: &str,
    retry: RetryPolicy,
) -> XaiProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/v1/billing/teams/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    XaiProvider::from_client(client, team_id.to_owned()).expect("xAI provider")
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
fn credential_resolution_trims_quotes_validates_team_and_redacts_both_values() {
    let environment = BTreeMap::from([
        (
            "XAI_MANAGEMENT_API_KEY".to_owned(),
            format!(" '{KEY_CANARY}' "),
        ),
        ("XAI_TEAM_ID".to_owned(), format!(" \"{TEAM_CANARY}\" ")),
    ]);
    let credential = XaiCredential::resolve(&environment).expect("credential");
    let debug = format!("{credential:?}");
    assert!(!debug.contains(KEY_CANARY));
    assert!(!debug.contains(TEAM_CANARY));

    for environment in [
        BTreeMap::new(),
        BTreeMap::from([("XAI_MANAGEMENT_API_KEY".to_owned(), KEY_CANARY.to_owned())]),
        BTreeMap::from([
            ("XAI_MANAGEMENT_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("XAI_TEAM_ID".to_owned(), "team/other".to_owned()),
        ]),
        BTreeMap::from([
            ("XAI_MANAGEMENT_API_KEY".to_owned(), KEY_CANARY.to_owned()),
            ("XAI_TEAM_ID".to_owned(), "..".to_owned()),
        ]),
    ] {
        assert_eq!(
            XaiCredential::resolve(&environment)
                .expect_err("missing or invalid credential")
                .kind(),
            ErrorKind::MissingCredential
        );
    }
}

#[tokio::test]
async fn balance_and_history_match_request_golden_and_project_complete_spend() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", "team-1234", RetryPolicy::none());
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("xAI fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Xai);
    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert_eq!(sample.confidence(), DataConfidence::Exact);
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("login method")
            .as_str(),
        "Management API"
    );
    let cost = sample.cost().expect("prepaid balance");
    assert_eq!(cost.used().amount(), decimal("10"));
    assert_eq!(cost.used().unit().as_str(), "USD");
    assert_eq!(cost.limit(), decimal("0"));
    assert_eq!(cost.period(), Some("Prepaid credits"));
    assert_eq!(detail_value(&sample, "Prepaid balance"), "$10.00");
    assert_eq!(detail_value(&sample, "Last 30 days"), "$1.76");

    let details = &sample.detail_sections()[0];
    assert_eq!(details.title(), Some("Billing summary"));
    let chart = details.chart().expect("successful history chart");
    assert_eq!(chart.title(), Some("Daily spend"));
    assert_eq!(chart.unit(), Some("USD"));
    assert_eq!(
        chart
            .points()
            .iter()
            .map(oab_domain::DetailChartPoint::label)
            .collect::<Vec<_>>(),
        ["2027-01-13", "2027-01-14", "2027-01-15"]
    );
    assert!((chart.points()[0].value().get() - 1.259_737_25).abs() < f64::EPSILON);

    let usage = sample.cost_usage().expect("daily spend mapping");
    assert_eq!(usage.history_days(), 30);
    assert!(usage.history_coverage_is_established());
    assert_eq!(usage.history_label(), None);
    assert_eq!(usage.metered_amount(), Some(decimal("1.75973725")));
    assert_eq!(usage.history().amount(), Some(decimal("1.75973725")));
    assert_eq!(usage.session().amount(), Some(decimal("0")));
    assert_eq!(usage.daily().len(), 3);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(
        requests[0].target(),
        "/v1/billing/teams/team-1234/prepaid/balance"
    );
    assert_eq!(requests[1].method(), "POST");
    assert_eq!(requests[1].target(), "/v1/billing/teams/team-1234/usage");
    assert!(requests.iter().all(|request| {
        request.header("authorization") == Some("Bearer fixture-xai-management-key-canary")
            && request.header("accept") == Some("application/json")
    }));
    assert_eq!(requests[1].header("content-type"), Some("application/json"));
    let body: serde_json::Value =
        serde_json::from_slice(requests[1].body()).expect("JSON request body");
    let analytics = &body["analyticsRequest"];
    assert_eq!(analytics["timeRange"]["startTime"], "2026-12-17 00:00:00");
    assert_eq!(analytics["timeRange"]["endTime"], "2027-01-15 08:00:00");
    assert_eq!(analytics["timeRange"]["timezone"], "Etc/GMT");
    assert_eq!(analytics["timeUnit"], "TIME_UNIT_DAY");
    assert_eq!(analytics["values"][0]["name"], "usd");
    assert_eq!(analytics["values"][0]["aggregation"], "AGGREGATION_SUM");

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
        json["snapshots"][0]["last_known_good"]["cost"]["period"],
        "Prepaid credits"
    );
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["cost_usage"]["history_days"],
        30
    );
}

#[tokio::test]
async fn ledger_signs_partial_history_and_successful_empty_history_remain_exact() {
    let partial = String::from_utf8(USAGE.to_vec())
        .expect("fixture UTF-8")
        .replace("\"limitReached\": false", "\"limitReached\": true");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, br#"{"total":{"val":"2500"}}"#.to_vec()),
        FakeHttpResponse::new(200, EMPTY_USAGE.to_vec()),
        FakeHttpResponse::new(200, br#"{"total":{"val":"0"}}"#.to_vec()),
        FakeHttpResponse::new(200, EMPTY_USAGE.to_vec()),
        FakeHttpResponse::new(200, br#"{"total":{"val":"-333"}}"#.to_vec()),
        FakeHttpResponse::new(200, EMPTY_USAGE.to_vec()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, partial.into_bytes()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, EMPTY_USAGE.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", "team-1234", RetryPolicy::none());

    for (expected, display) in [("-25", "$-25.00"), ("0", "$0.00"), ("3.33", "$3.33")] {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect("ledger fixture");
        assert_eq!(
            sample.cost().expect("balance").used().amount(),
            decimal(expected)
        );
        assert_eq!(detail_value(&sample, "Prepaid balance"), display);
    }
    let partial = provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("partial history");
    assert_eq!(partial.confidence(), DataConfidence::Estimated);
    assert_eq!(detail_value(&partial, "Last 30 days (partial)"), "$1.76");
    let usage = partial.cost_usage().expect("partial spend");
    assert!(!usage.history_coverage_is_established());
    assert_eq!(usage.history_label(), Some("Last 30 days (partial)"));

    let empty = provider
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("successful empty history");
    assert_eq!(empty.confidence(), DataConfidence::Exact);
    assert!(
        empty.detail_sections()[0]
            .chart()
            .expect("confirmed empty chart")
            .points()
            .is_empty()
    );
    let usage = empty.cost_usage().expect("confirmed zero spend");
    assert_eq!(usage.metered_amount(), Some(decimal("0")));
    assert!(usage.daily().is_empty());
}

#[tokio::test]
async fn non_auth_history_failures_preserve_balance_but_history_auth_is_fatal() {
    let malformed_histories: [&[u8]; 4] = [
        br"{}",
        br#"{"timeSeries":null}"#,
        br#"{"timeSeries":[{}]}"#,
        br#"{"timeSeries":[{"dataPoints":[{"timestamp":"2027-01-15T00:00:00Z"}]}]}"#,
    ];
    let mut responses = vec![
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(429, Vec::new()),
    ];
    for body in malformed_histories {
        responses.push(FakeHttpResponse::new(200, BALANCE.to_vec()));
        responses.push(FakeHttpResponse::new(200, body.to_vec()));
    }
    responses.extend([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(403, Vec::new()),
    ]);
    let server = FakeHttpServer::start(responses).await;
    let provider = provider(&server, "account-a", "team-1234", RetryPolicy::none());

    for _ in 0..6 {
        let sample = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect("best-effort history");
        assert_eq!(
            sample.cost().expect("balance").used().amount(),
            decimal("10")
        );
        assert!(sample.cost_usage().is_none());
        assert!(sample.detail_sections()[0].chart().is_none());
        assert_eq!(detail_value(&sample, "Last 30 days"), "$0.00");
    }
    for _ in 0..2 {
        assert_eq!(
            provider
                .fetch_at(&context("account-a"), timestamp(1_800_000_000))
                .await
                .expect_err("history auth failure")
                .kind(),
            ErrorKind::AuthenticationExpired
        );
    }
}

#[tokio::test]
async fn balance_status_parse_last_good_and_account_boundaries_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(404, Vec::new()),
        FakeHttpResponse::new(408, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"fixture-error-canary".to_vec()),
        FakeHttpResponse::truncated(200, BALANCE.len() + 10, BALANCE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", "team-1234", RetryPolicy::none());
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::AuthenticationExpired,
        ErrorKind::Api,
        ErrorKind::Api,
        ErrorKind::RateLimited,
        ErrorKind::Api,
        ErrorKind::Api,
        ErrorKind::Parse,
        ErrorKind::Parse,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1_800_000_000))
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains(KEY_CANARY));
        assert!(!debug.contains("fixture-error-canary"));
        assert!(!debug.contains("response-canary"));
    }

    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1_800_000_000))
        .await
        .expect("initial fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider
            .fetch_at(&provider_context, timestamp(1_800_000_001))
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
            .fetch_at(&context("account-b"), timestamp(1_800_000_002))
            .await
            .expect_err("cross-account context")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), before);
}

#[tokio::test]
async fn completed_http_timeout_is_api_but_real_transport_timeout_stays_network() {
    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let error = provider(&server, "account-a", "team-1234", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("transport timeout");
    assert_eq!(error.kind(), ErrorKind::Network);
}

#[tokio::test]
async fn team_id_is_one_encoded_segment_and_redirects_cannot_leak_management_key() {
    let encoded = FakeHttpServer::start([
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, EMPTY_USAGE.to_vec()),
    ])
    .await;
    provider(&encoded, "account-a", "team ?#%", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("encoded team fixture");
    assert_eq!(
        encoded.requests()[0].target(),
        "/v1/billing/teams/team%20%3F%23%25/prepaid/balance"
    );

    let target = FakeHttpServer::start([FakeHttpResponse::new(200, BALANCE.to_vec())]).await;
    let source =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let error = provider(&source, "account-a", "team-1234", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect_err("cross-origin redirect");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(target.requests().is_empty());
}

#[tokio::test]
async fn transient_balance_failure_retries_once() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, BALANCE.to_vec()),
        FakeHttpResponse::new(200, USAGE.to_vec()),
    ])
    .await;
    provider(
        &server,
        "account-a",
        "team-1234",
        RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1)),
    )
    .fetch_at(&context("account-a"), timestamp(1_800_000_000))
    .await
    .expect("retried fixture");
    assert_eq!(server.requests().len(), 3);
}
