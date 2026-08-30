use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, CostProvenance, ErrorKind, ExactDecimal, Freshness, PrivacyKey,
    PrivacyPolicy, PrivacySurface, ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase,
    SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::synthetic::SyntheticProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const KNOWN: &[u8] = include_bytes!("../../../fixtures/providers/synthetic/known.json");
const GENERIC: &[u8] = include_bytes!("../../../fixtures/providers/synthetic/generic.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/synthetic/malformed.json");
const KEY_CANARY: &str = "fixture-synthetic-key-canary";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("fixture decimal")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Synthetic,
        ProviderInstanceId::new("synthetic-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config(retry: RetryPolicy) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        5 * 1024 * 1024,
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

fn provider(server: &FakeHttpServer, account: &str, retry: RetryPolicy) -> SyntheticProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        config(retry),
    )
    .expect("fixed API client");
    SyntheticProvider::from_client(client).expect("Synthetic provider")
}

fn percent(window: Option<&oab_domain::RateWindow>) -> f64 {
    window
        .expect("quota window")
        .used_percent()
        .expect("known percent")
        .get()
}

#[test]
fn credential_resolution_trims_quotes_and_redacts_the_selected_value() {
    let environment = BTreeMap::from([(
        "SYNTHETIC_API_KEY".to_owned(),
        format!("  '{KEY_CANARY}'  "),
    )]);
    let credential = SyntheticProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(KEY_CANARY));
    assert_eq!(
        SyntheticProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
    assert_eq!(
        SyntheticProvider::resolve_credential(&BTreeMap::from([(
            "SYNTHETIC_API_KEY".to_owned(),
            " \" \" ".to_owned(),
        )]))
        .expect_err("empty quoted key")
        .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn known_fixture_preserves_three_lanes_regeneration_cost_and_request_contract() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, KNOWN.to_vec())]).await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    let fetched_at = timestamp(1_800_000_000);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Synthetic fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Synthetic);
    assert!((percent(sample.primary()) - 20.0).abs() < f64::EPSILON);
    assert_eq!(
        sample.primary().expect("rolling").resets_at(),
        Some(Timestamp::parse("2026-04-17T03:44:11Z").expect("rolling reset"))
    );
    assert!(
        (sample
            .primary()
            .expect("rolling")
            .next_regen_percent()
            .expect("rolling regeneration")
            .get()
            - 5.0)
            .abs()
            < f64::EPSILON
    );
    let secondary_percent = percent(sample.secondary());
    assert!(
        (secondary_percent - 1.941_152_777_777_773_5).abs() < 1e-12,
        "secondary percent was {secondary_percent:?}"
    );
    assert_eq!(
        sample.secondary().expect("weekly").resets_at(),
        Some(Timestamp::parse("2026-04-17T05:19:30Z").expect("weekly reset"))
    );
    assert!((percent(sample.tertiary()) - 0.8).abs() < f64::EPSILON);
    assert_eq!(
        sample.tertiary().expect("search").resets_at(),
        Some(Timestamp::parse("2026-04-17T04:30:01.494Z").expect("search reset"))
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("plan identity")
            .as_str(),
        "Starter"
    );

    let cost = sample.cost().expect("weekly credits");
    assert_eq!(cost.used().amount(), decimal("0.7000000000000028"));
    assert_eq!(cost.limit(), decimal("36"));
    assert_eq!(cost.used().unit().as_str(), "USD");
    assert_eq!(cost.period(), Some("Weekly"));
    assert_eq!(
        cost.resets_at(),
        Some(Timestamp::parse("2026-04-17T05:19:30Z").expect("cost reset"))
    );
    assert_eq!(cost.next_regen_amount(), Some(decimal("0.72")));
    assert_eq!(cost.updated_at(), fetched_at);
    assert_eq!(cost.provenance(), CostProvenance::VendorMetered);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/v2/quotas");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-synthetic-key-canary")
    );
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(requests[0].header("content-type"), None);
    assert!(requests[0].body().is_empty());

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
        json["snapshots"][0]["last_known_good"]["primary"]["next_regen_percent"],
        5.0
    );
    assert_eq!(
        json["snapshots"][0]["last_known_good"]["cost"]["period"],
        "Weekly"
    );
}

#[tokio::test]
async fn missing_rolling_lane_keeps_weekly_and_search_in_their_positional_slots() {
    let payload = br#"{
      "weeklyTokenLimit": {
        "nextRegenAt": "2026-04-17T05:19:30.000Z",
        "percentRemaining": 98.0,
        "maxCredits": "$36.00",
        "remainingCredits": "$35.30",
        "nextRegenCredits": "$0.72"
      },
      "search": {"hourly": {"limit": 250, "requests": 2}}
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, payload.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("sparse known lanes");

    assert!(sample.primary().is_none());
    assert!((percent(sample.secondary()) - 2.0).abs() < f64::EPSILON);
    assert!((percent(sample.tertiary()) - 0.8).abs() < f64::EPSILON);
    assert_eq!(
        sample.cost().expect("weekly cost").used().amount(),
        decimal("0.7000000000000028")
    );
}

#[tokio::test]
async fn generic_fixture_uses_sorted_recursion_aliases_dates_descriptions_and_late_cost() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, GENERIC.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1_800_000_000))
        .await
        .expect("generic fixture");

    assert!((percent(sample.primary()) - 30.0).abs() < f64::EPSILON);
    let primary = sample.primary().expect("first sorted quota");
    assert_eq!(
        primary.duration().expect("two hours").seconds(),
        2 * 60 * 60
    );
    assert_eq!(
        primary
            .reset_description()
            .expect("duration description")
            .as_str(),
        "2 hours window"
    );

    assert!((percent(sample.secondary()) - 75.0).abs() < f64::EPSILON);
    let secondary = sample.secondary().expect("second sorted quota");
    assert_eq!(secondary.duration().expect("one hour").seconds(), 60 * 60);
    assert_eq!(
        secondary.resets_at(),
        Some(Timestamp::parse("2025-01-01T00:00:00Z").expect("Unix-second reset"))
    );
    assert!(secondary.reset_description().is_none());

    assert!((percent(sample.tertiary()) - 50.0).abs() < f64::EPSILON);
    let tertiary = sample.tertiary().expect("third sorted quota");
    assert_eq!(
        tertiary.duration().expect("half day").seconds(),
        12 * 60 * 60
    );
    assert_eq!(
        tertiary
            .reset_description()
            .expect("half-day description")
            .as_str(),
        "12 hours window"
    );
    assert!(
        (tertiary.next_regen_percent().expect("regeneration").get() - 3.0).abs() < f64::EPSILON
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("data plan")
            .as_str(),
        "Team"
    );
    let cost = sample.cost().expect("cost from fourth parsed quota");
    assert_eq!(cost.limit(), decimal("1000.5"));
    assert!(cost.used().amount().to_string().starts_with("200.1"));
}

#[tokio::test]
async fn root_arrays_pack_generic_lanes_and_leave_identity_empty() {
    let payload = br#"[
      {"percentUsed":"0.25"},
      {"limit":"0x10","used":"0b100"},
      {"percentRemaining":50}
    ]"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, payload.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("root array");

    assert!((percent(sample.primary()) - 25.0).abs() < f64::EPSILON);
    assert!((percent(sample.secondary()) - 25.0).abs() < f64::EPSILON);
    assert!((percent(sample.tertiary()) - 50.0).abs() < f64::EPSILON);
    assert!(sample.identity().login_method().is_none());
    assert!(sample.cost().is_none());
}

#[tokio::test]
async fn inferred_limit_overflow_uses_the_plugin_host_percentage_fallback() {
    let payload = br#"{"quotas":[{"used":1e308,"remaining":1e308}]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, payload.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("overflowing inferred limit");
    assert!((percent(sample.primary()) - 100.0).abs() < f64::EPSILON);
}

#[tokio::test]
async fn generic_windows_beyond_the_three_emitted_slots_do_not_undergo_window_validation() {
    let payload = br#"{"quotas":[
      {"percentUsed":10},
      {"percentUsed":20},
      {"percentUsed":30},
      {"percentUsed":40,"windowMinutes":0,"maxCredits":10}
    ]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, payload.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("unemitted invalid fourth window");
    assert!((percent(sample.primary()) - 10.0).abs() < f64::EPSILON);
    assert!((percent(sample.secondary()) - 20.0).abs() < f64::EPSILON);
    assert!((percent(sample.tertiary()) - 30.0).abs() < f64::EPSILON);
    assert_eq!(
        sample.cost().expect("fourth quota cost").used().amount(),
        decimal("4")
    );
}

#[tokio::test]
async fn generic_candidate_and_known_slot_selection_match_plugin_short_circuiting() {
    let fixtures: [&[u8]; 2] = [
        br#"{
          "quotas":[{"limit":5}],
          "limits":[{"limit":10,"used":1}]
        }"#,
        br#"{
          "rollingFiveHourLimit":{"limit":5},
          "quotas":[{"limit":10,"used":1}]
        }"#,
    ];
    let server = FakeHttpServer::start(
        fixtures
            .into_iter()
            .map(|body| FakeHttpResponse::new(200, body.to_vec())),
    )
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for _ in fixtures {
        assert_eq!(
            provider
                .fetch_at(&context("account-a"), timestamp(1))
                .await
                .expect_err("short-circuited incomplete quota")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn invalid_window_text_is_ignored_but_emitted_nonpositive_or_unsafe_minutes_fail() {
    let fixtures: [(&[u8], bool); 4] = [
        (
            br#"{"quotas":[{"percentUsed":25,"window":"forever"}]}"#,
            true,
        ),
        (br#"{"quotas":[{"percentUsed":25,"window":"0h"}]}"#, false),
        (
            br#"{"quotas":[{"percentUsed":25,"windowMinutes":-2}]}"#,
            false,
        ),
        (
            br#"{"quotas":[{"percentUsed":25,"windowMinutes":9007199254740992}]}"#,
            false,
        ),
    ];
    let server = FakeHttpServer::start(
        fixtures
            .iter()
            .map(|(body, _)| FakeHttpResponse::new(200, body.to_vec())),
    )
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for (_, succeeds) in fixtures {
        let result = provider.fetch_at(&context("account-a"), timestamp(1)).await;
        if succeeds {
            assert!(
                result
                    .expect("ignored invalid description")
                    .primary()
                    .is_some()
            );
        } else {
            assert_eq!(
                result.expect_err("invalid emitted duration").kind(),
                ErrorKind::Parse
            );
        }
    }
}

#[tokio::test]
async fn cost_precedence_and_date_coercion_preserve_plugin_number_semantics() {
    let payloads: [&[u8]; 3] = [
        br#"{"quotas":[{
          "percentUsed":25,
          "maxCredits":"$ 1,000",
          "remainingCredits":"999",
          "usedCredits":"-5",
          "nextRegenCredits":"$ $",
          "resetAt":1735689600123
        }]}"#,
        br#"{"quotas":[{
          "percentUsed":25,
          "maxCredits":10,
          "remainingCredits":12,
          "resetAt":42,
          "reset_at":"1735689600.999"
        }]}"#,
        br#"{"quotas":[{"percentUsed":25,"maxCredits":20}]}"#,
    ];
    let server = FakeHttpServer::start(
        payloads
            .into_iter()
            .map(|body| FakeHttpResponse::new(200, body.to_vec())),
    )
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());

    let explicit = provider
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("explicit used credits");
    let cost = explicit.cost().expect("explicit cost");
    assert_eq!(cost.used().amount(), decimal("-5"));
    assert_eq!(cost.limit(), decimal("1000"));
    assert_eq!(cost.next_regen_amount(), Some(decimal("0")));
    assert_eq!(
        cost.resets_at(),
        Some(Timestamp::parse("2025-01-01T00:00:00.123Z").expect("millisecond reset"))
    );

    let remaining = provider
        .fetch_at(&context("account-a"), timestamp(2))
        .await
        .expect("remaining credits");
    let cost = remaining.cost().expect("remaining cost");
    assert_eq!(cost.used().amount(), decimal("0"));
    assert_eq!(
        cost.resets_at(),
        Some(Timestamp::parse("2025-01-01T00:00:00.999Z").expect("fractional second reset"))
    );

    let inferred = provider
        .fetch_at(&context("account-a"), timestamp(3))
        .await
        .expect("percent-derived credits");
    assert_eq!(
        inferred.cost().expect("inferred cost").used().amount(),
        decimal("5")
    );
}

#[tokio::test]
async fn javascript_iso_dates_accept_date_only_and_truncate_sub_millisecond_precision() {
    let payload = br#"{"quotas":[
      {"percentUsed":10,"resetAt":"2025-01-01"},
      {"percentUsed":20,"resetAt":"2025-01-01T00:00:00.123999Z"},
      {"percentUsed":30,"resetAt":"1969-12-31T23:59:59.123999Z"}
    ]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, payload.to_vec())]).await;
    let sample = provider(&server, "account-a", RetryPolicy::none())
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("JavaScript-compatible ISO dates");
    assert_eq!(
        sample.primary().expect("date-only lane").resets_at(),
        Some(Timestamp::parse("2025-01-01T00:00:00Z").expect("date-only reset"))
    );
    assert_eq!(
        sample.secondary().expect("fractional lane").resets_at(),
        Some(Timestamp::parse("2025-01-01T00:00:00.123Z").expect("truncated reset"))
    );
    assert_eq!(
        sample.tertiary().expect("pre-epoch lane").resets_at(),
        Some(Timestamp::parse("1969-12-31T23:59:59.123Z").expect("pre-epoch reset"))
    );
}

#[tokio::test]
async fn malformed_shapes_fail_closed_without_leaking_payload_or_secret_text() {
    let fixtures: [&[u8]; 8] = [
        MALFORMED,
        br"null",
        br#""response-canary""#,
        br"{}",
        br#"{"quotas":[]}"#,
        br#"{"quotas":[{"limit":10}]}"#,
        br#"{"quotas":[{"percentUsed":25,"resetAt":8640000000000001}]}"#,
        br#"{"quotas":[{"percentUsed":25,"tickPercent":-1e308}]}"#,
    ];
    let server = FakeHttpServer::start(
        fixtures
            .into_iter()
            .map(|body| FakeHttpResponse::new(200, body.to_vec())),
    )
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for _ in fixtures {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("malformed payload");
        assert_eq!(error.kind(), ErrorKind::Parse);
        let debug = format!("{error:?}");
        assert!(!debug.contains("response-canary"));
        assert!(!debug.contains(KEY_CANARY));
    }
}

#[tokio::test]
async fn exact_status_auth_mapping_no_retry_and_account_isolation_are_stable() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(201, KNOWN.to_vec()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(400, b"response-canary".to_vec()),
        FakeHttpResponse::new(200, KNOWN.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a", RetryPolicy::none());
    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::AuthenticationExpired,
        ErrorKind::Api,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Api,
    ] {
        let error = provider
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("scripted failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains("response-canary"));
        assert!(!debug.contains(KEY_CANARY));
    }
    assert_eq!(server.requests().len(), 6);

    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(2))
        .await
        .expect("valid fixture");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider.fetch_at(&provider_context, timestamp(3)).await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let before = server.requests().len();
    assert_eq!(
        provider
            .fetch_at(&context("account-b"), timestamp(4))
            .await
            .expect_err("cross-account context")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), before);
}

#[tokio::test]
async fn configured_retry_policy_is_honored_by_injected_clients() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, KNOWN.to_vec()),
    ])
    .await;
    provider(
        &server,
        "account-a",
        RetryPolicy::one(Duration::from_millis(1), Duration::from_secs(1)),
    )
    .fetch_at(&context("account-a"), timestamp(1))
    .await
    .expect("retried fixture");
    assert_eq!(server.requests().len(), 2);
}
