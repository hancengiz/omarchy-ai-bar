use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::cloud_signing::VolcengineCredentials;
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::providers::doubao::{
    DoubaoApiCredential, DoubaoCliSettings, DoubaoProvider, resolve_cloud_credentials,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{HttpTransport, TransportConfig};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const CODING: &[u8] = include_bytes!("../../../fixtures/providers/doubao/coding_plan.json");
const AGENT: &[u8] = include_bytes!("../../../fixtures/providers/doubao/agent_plan.json");
const ARKCLI: &[u8] = include_bytes!("../../../fixtures/providers/doubao/arkcli.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/doubao/malformed.json");
const ACCESS_KEY_CANARY: &str = "AKLT-fixture-doubao-access-key";
const SECRET_KEY_CANARY: &str = "fixture-doubao-secret-key";
const API_KEY_CANARY: &str = "fixture-doubao-api-key";

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope_for(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(format!("{}-primary", provider.as_str())).expect("instance"),
        AccountKey::new(account).expect("account"),
    )
}

fn scope(account: &str) -> AccountScope {
    scope_for(ProviderId::Doubao, account)
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
        2 * 1024 * 1024,
        0,
        RetryPolicy::none(),
    )
    .expect("fixture transport config")
}

fn transport(server: &FakeHttpServer) -> HttpTransport {
    let policy =
        EndpointPolicy::new([(server.origin().as_str(), EndpointClass::LoopbackDevelopment)])
            .expect("fixture endpoint policy");
    HttpTransport::new(policy, config()).expect("fixture transport")
}

fn cloud_provider(server: &FakeHttpServer, account: &str) -> DoubaoProvider {
    DoubaoProvider::from_cloud_transport(
        scope(account),
        VolcengineCredentials::new(ACCESS_KEY_CANARY, SECRET_KEY_CANARY, "cn-beijing")
            .expect("cloud credentials"),
        server.url("/"),
        transport(server),
    )
    .expect("cloud provider")
}

fn api_provider(server: &FakeHttpServer, account: &str) -> DoubaoProvider {
    DoubaoProvider::from_api_transport(
        scope(account),
        DoubaoApiCredential::new(API_KEY_CANARY).expect("API credential"),
        server.url("/api/coding/v3/chat/completions"),
        transport(server),
    )
    .expect("API provider")
}

fn percent(window: &oab_domain::RateWindow) -> f64 {
    window.used_percent().expect("known fixture usage").get()
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn extra_percent(sample: &oab_domain::UsageSample, id: &str) -> f64 {
    let window = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == id)
        .expect("named fixture window");
    percent(window.window())
}

#[test]
fn credential_resolution_preserves_precedence_atomicity_and_redaction() {
    let api_environment = BTreeMap::from([
        (
            "VOLCENGINE_API_KEY".to_owned(),
            format!("  '{API_KEY_CANARY}'  "),
        ),
        (
            "DOUBAO_API_KEY".to_owned(),
            "lower-precedence-key".to_owned(),
        ),
    ]);
    let api = DoubaoApiCredential::resolve(&api_environment).expect("API alias");
    assert!(!format!("{api:?}").contains(API_KEY_CANARY));

    let cloud_environment = BTreeMap::from([
        (
            "VOLCENGINE_ACCESS_KEY".to_owned(),
            format!(" '{ACCESS_KEY_CANARY}' "),
        ),
        (
            "VOLCENGINE_SECRET_KEY".to_owned(),
            format!(" \"{SECRET_KEY_CANARY}\" "),
        ),
    ]);
    let cloud = resolve_cloud_credentials(&cloud_environment).expect("AK/SK aliases");
    assert_eq!(cloud.region(), "cn-beijing");
    let debug = format!("{cloud:?}");
    assert!(!debug.contains(ACCESS_KEY_CANARY));
    assert!(!debug.contains(SECRET_KEY_CANARY));

    let incomplete = BTreeMap::from([(
        "VOLCENGINE_ACCESS_KEY_ID".to_owned(),
        ACCESS_KEY_CANARY.to_owned(),
    )]);
    assert_eq!(
        resolve_cloud_credentials(&incomplete)
            .expect_err("partial AK/SK is rejected")
            .kind(),
        ErrorKind::MissingCredential
    );
    for region in ["bad region", "CN-BEIJING", "cn_beijing", "cn.beijing"] {
        let bad_region = BTreeMap::from([
            (
                "VOLCENGINE_ACCESS_KEY_ID".to_owned(),
                ACCESS_KEY_CANARY.to_owned(),
            ),
            (
                "VOLCENGINE_SECRET_ACCESS_KEY".to_owned(),
                SECRET_KEY_CANARY.to_owned(),
            ),
            ("VOLCENGINE_REGION".to_owned(), region.to_owned()),
        ]);
        assert_eq!(
            resolve_cloud_credentials(&bad_region)
                .expect_err("invalid signer region")
                .kind(),
            ErrorKind::Api,
            "region {region:?} must be a configuration error"
        );
    }
}

#[tokio::test]
async fn signed_cloud_fetch_maps_coding_and_agent_windows_and_wire_contract() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CODING.to_vec()),
        FakeHttpResponse::new(200, AGENT.to_vec()),
    ])
    .await;
    let provider = cloud_provider(&server, "cloud-account");
    let sample = provider
        .fetch_at(
            &context("cloud-account", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect("signed plan usage");

    assert_eq!(sample.fetched_at(), timestamp(1_782_226_444));
    assert_percent(percent(sample.primary().expect("session")), 12.5);
    assert_eq!(
        sample
            .primary()
            .expect("session")
            .duration()
            .map(oab_domain::WindowDuration::seconds),
        Some(18_000)
    );
    assert_percent(percent(sample.secondary().expect("weekly")), 25.0);
    assert_percent(percent(sample.tertiary().expect("monthly")), 50.0);
    assert_percent(extra_percent(&sample, "doubao-agent-session"), 0.0);
    assert_percent(extra_percent(&sample, "doubao-agent-weekly"), 25.0);
    assert_percent(extra_percent(&sample, "doubao-agent-monthly"), 25.0);
    assert_eq!(sample.extra_windows().len(), 3);
    assert_eq!(
        sample
            .identity()
            .login_method()
            .map(oab_domain::BoundedText::as_str),
        Some("Running")
    );
    assert_eq!(sample.provenance()[0].strategy(), "cloud");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(
        requests[0].target(),
        "/?Action=GetCodingPlanUsage&Version=2024-01-01"
    );
    assert_eq!(
        requests[1].target(),
        "/?Action=GetAFPUsage&Version=2024-01-01"
    );
    for request in &requests {
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(
            request.header("content-type"),
            Some("application/x-www-form-urlencoded; charset=utf-8")
        );
        assert_eq!(request.body(), b"");
        assert!(
            request
                .header("authorization")
                .is_some_and(|value| value.contains("HMAC-SHA256 Credential=AKLT-fixture"))
        );
        assert!(request.header("x-date").is_some());
        assert!(request.header("x-content-sha256").is_some());
    }
    let debug = format!("{provider:?}");
    assert!(!debug.contains(ACCESS_KEY_CANARY));
    assert!(!debug.contains(SECRET_KEY_CANARY));
}

#[tokio::test]
async fn cloud_agent_probe_is_best_effort_only_after_authoritative_coding_usage() {
    for second in [
        FakeHttpResponse::new(403, b"secret-error-body".to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::truncated(200, 100, b"{}".to_vec()),
    ] {
        let server =
            FakeHttpServer::start([FakeHttpResponse::new(200, CODING.to_vec()), second]).await;
        let sample = cloud_provider(&server, "coding-only")
            .fetch_at(
                &context("coding-only", ProviderSource::CloudCredentials),
                timestamp(1_700_000_000),
            )
            .await
            .expect("coding usage survives optional AFP failure");
        assert_percent(percent(sample.primary().expect("coding session")), 12.5);
        assert!(sample.extra_windows().is_empty());
    }

    let reclaimed = br#"{"Result":{"Status":"Reclaimed","UpdateTimestamp":1785322689}}"#;
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, reclaimed.to_vec()),
        FakeHttpResponse::new(200, AGENT.to_vec()),
    ])
    .await;
    let sample = cloud_provider(&server, "agent-only")
        .fetch_at(
            &context("agent-only", ProviderSource::CloudCredentials),
            timestamp(1_700_000_000),
        )
        .await
        .expect("agent-only plan");
    assert!(sample.primary().is_none());
    assert_eq!(sample.extra_windows().len(), 3);
    assert!(sample.identity().login_method().is_none());

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, reclaimed.to_vec()),
        FakeHttpResponse::new(200, br#"{"Result":null}"#.to_vec()),
    ])
    .await;
    assert_eq!(
        cloud_provider(&server, "no-plan")
            .fetch_at(
                &context("no-plan", ProviderSource::CloudCredentials),
                timestamp(1_700_000_000),
            )
            .await
            .expect_err("malformed required fallback")
            .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn cloud_required_statuses_and_payload_bounds_fail_closed() {
    let denied = FakeHttpServer::start([FakeHttpResponse::new(
        403,
        b"credential-adjacent-denial".to_vec(),
    )])
    .await;
    assert_eq!(
        cloud_provider(&denied, "denied")
            .fetch_at(
                &context("denied", ProviderSource::CloudCredentials),
                timestamp(1),
            )
            .await
            .expect_err("coding denial")
            .kind(),
        ErrorKind::PermissionDenied
    );

    let unexpected_success =
        FakeHttpServer::start([FakeHttpResponse::new(201, CODING.to_vec())]).await;
    assert_eq!(
        cloud_provider(&unexpected_success, "unexpected-success")
            .fetch_at(
                &context("unexpected-success", ProviderSource::CloudCredentials),
                timestamp(1),
            )
            .await
            .expect_err("required usage accepts only HTTP 200")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(unexpected_success.requests().len(), 1);

    let quotas = (0..129)
        .map(|index| {
            serde_json::json!({
                "Level": format!("level-{index}"),
                "Percent": 1,
                "ResetTimestamp": 0
            })
        })
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&serde_json::json!({
        "Result": {"Status": "Running", "QuotaUsage": quotas}
    }))
    .expect("oversized quota fixture");
    let bounded = FakeHttpServer::start([FakeHttpResponse::new(200, body)]).await;
    assert_eq!(
        cloud_provider(&bounded, "bounded")
            .fetch_at(
                &context("bounded", ProviderSource::CloudCredentials),
                timestamp(1),
            )
            .await
            .expect_err("quota count bound")
            .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn api_probe_emits_exact_request_and_normalizes_headers_deterministically() {
    let fetched_at = timestamp(1_700_000_000);
    let server = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        br#"{"usage":{"total_tokens":1}}"#.to_vec(),
    )
    .header("X-RateLimit-Remaining-Requests", "75")
    .header("x-ratelimit-limit-requests", "100")
    .header("x-ratelimit-reset-requests", "1h30m")])
    .await;
    let provider = api_provider(&server, "api-account");
    let sample = provider
        .fetch_at(&context("api-account", ProviderSource::ApiKey), fetched_at)
        .await
        .expect("Ark rate-limit probe");

    let primary = sample.primary().expect("request window");
    assert_percent(percent(primary), 25.0);
    assert_eq!(
        primary
            .reset_description()
            .map(oab_domain::BoundedText::as_str),
        Some("25/100 requests")
    );
    assert_eq!(primary.resets_at(), Some(timestamp(1_700_005_400)));
    assert_eq!(sample.provenance()[0].strategy(), "api");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/api/coding/v3/chat/completions");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-doubao-api-key")
    );
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(requests[0].header("content-type"), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(requests[0].body()).expect("probe JSON");
    assert_eq!(body["model"], "doubao-seed-2.0-code");
    assert_eq!(body["max_tokens"], 1);
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "hi");
    assert!(!format!("{provider:?}").contains(API_KEY_CANARY));
}

#[tokio::test]
async fn api_probe_uses_ordered_model_fallback_without_crossing_sources() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(403, b"first-model-denied".to_vec()),
        FakeHttpResponse::new(404, b"second-model-missing".to_vec()),
        FakeHttpResponse::new(200, Vec::new())
            .header("x-ratelimit-remaining-requests", "9")
            .header("x-ratelimit-limit-requests", "10"),
    ])
    .await;
    let sample = api_provider(&server, "fallback")
        .fetch_at(
            &context("fallback", ProviderSource::ApiKey),
            timestamp(1_700_000_000),
        )
        .await
        .expect("third probe model");
    assert_percent(percent(sample.primary().expect("request window")), 10.0);
    let models = server
        .requests()
        .iter()
        .map(|request| {
            serde_json::from_slice::<serde_json::Value>(request.body())
                .expect("request JSON")["model"]
                .as_str()
                .expect("model")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        models,
        [
            "doubao-seed-2.0-code",
            "doubao-1.5-pro-32k",
            "doubao-lite-32k"
        ]
    );

    let exhausted = FakeHttpServer::start([
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
    ])
    .await;
    assert_eq!(
        api_provider(&exhausted, "all-denied")
            .fetch_at(&context("all-denied", ProviderSource::ApiKey), timestamp(1),)
            .await
            .expect_err("all models denied")
            .kind(),
        ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn api_zero_remaining_confirmation_distinguishes_exhaustion_from_bad_headers() {
    let repeated = FakeHttpServer::start([
        rate_response(200, Some(1000), Some(0)),
        rate_response(200, Some(1000), Some(0)),
    ])
    .await;
    let sample = api_provider(&repeated, "ambiguous")
        .fetch_at(&context("ambiguous", ProviderSource::ApiKey), timestamp(1))
        .await
        .expect("ambiguous confirmation");
    assert!(sample.primary().is_none());
    assert_eq!(repeated.requests().len(), 2);

    let exhausted = FakeHttpServer::start([
        rate_response(200, Some(1000), Some(0)),
        rate_response(429, Some(1000), None),
    ])
    .await;
    let sample = api_provider(&exhausted, "exhausted")
        .fetch_at(&context("exhausted", ProviderSource::ApiKey), timestamp(1))
        .await
        .expect("confirmed exhaustion");
    assert_percent(percent(sample.primary().expect("exhausted window")), 100.0);

    let headerless = FakeHttpServer::start([rate_response(429, None, None)]).await;
    let sample = api_provider(&headerless, "unknown-throttle")
        .fetch_at(
            &context("unknown-throttle", ProviderSource::ApiKey),
            timestamp(1),
        )
        .await
        .expect("valid key with unknown throttle");
    assert!(sample.primary().is_none());

    let failed_confirmation = FakeHttpServer::start([
        rate_response(200, Some(1000), Some(0)),
        FakeHttpResponse::new(500, b"hidden-confirmation-error".to_vec()),
    ])
    .await;
    let sample = api_provider(&failed_confirmation, "failed-confirmation")
        .fetch_at(
            &context("failed-confirmation", ProviderSource::ApiKey),
            timestamp(1),
        )
        .await
        .expect("initial exhausted state survives failed confirmation");
    assert_percent(percent(sample.primary().expect("initial state")), 100.0);
}

fn rate_response(status: u16, limit: Option<i64>, remaining: Option<i64>) -> FakeHttpResponse {
    let mut response = FakeHttpResponse::new(status, Vec::new());
    if let Some(limit) = limit {
        response = response.header("x-ratelimit-limit-requests", limit.to_string());
    }
    if let Some(remaining) = remaining {
        response = response.header("x-ratelimit-remaining-requests", remaining.to_string());
    }
    response
}

#[tokio::test]
async fn source_and_account_mismatches_fail_before_network_or_process_execution() {
    let api_server = FakeHttpServer::start([rate_response(200, Some(10), Some(9))]).await;
    let provider = api_provider(&api_server, "account-a");
    for bad_context in [
        context("account-a", ProviderSource::CloudCredentials),
        context("account-b", ProviderSource::ApiKey),
    ] {
        assert_eq!(
            provider
                .fetch_at(&bad_context, timestamp(1))
                .await
                .expect_err("isolated context")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(api_server.requests().is_empty());

    let cloud_server = FakeHttpServer::start([FakeHttpResponse::new(200, CODING.to_vec())]).await;
    let provider = cloud_provider(&cloud_server, "cloud-account-a");
    for bad_context in [
        context("cloud-account-a", ProviderSource::ApiKey),
        context("cloud-account-b", ProviderSource::CloudCredentials),
    ] {
        assert_eq!(
            provider
                .fetch_at(&bad_context, timestamp(1))
                .await
                .expect_err("isolated cloud context")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(cloud_server.requests().is_empty());

    let directory = TestDirectory::new("doubao-cli-scope-guard");
    let executable = directory.path().join("arkcli");
    let marker = directory.path().join("process-was-started");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n: > '{}'\nexit 0\n",
            shell_quote(marker.to_string_lossy().as_ref())
        ),
    );
    let settings =
        DoubaoCliSettings::new(executable, &BTreeMap::new()).expect("fixture CLI settings");
    let provider = DoubaoProvider::new_cli(scope("cli-account-a"), settings).expect("CLI provider");
    for bad_context in [
        context("cli-account-a", ProviderSource::ApiKey),
        context("cli-account-b", ProviderSource::Cli),
    ] {
        assert_eq!(
            provider
                .fetch_at(&bad_context, timestamp(1))
                .await
                .expect_err("isolated CLI context")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(!marker.exists(), "scope rejection must happen before spawn");

    assert_eq!(
        DoubaoProvider::new_api_key(
            scope_for(ProviderId::OpenAi, "wrong-provider"),
            DoubaoApiCredential::new(API_KEY_CANARY).expect("credential"),
        )
        .expect_err("provider scope mismatch")
        .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        DoubaoProvider::resolve(
            scope("unsupported-source"),
            ProviderSource::OAuth,
            &BTreeMap::new(),
        )
        .expect_err("unsupported source")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn arkcli_maps_personal_team_and_agent_windows_with_linux_path_discovery() {
    let directory = TestDirectory::new("doubao-arkcli-node");
    let arkcli = directory.path().join("arkcli");
    let node = directory.path().join("node");
    write_executable(&arkcli, "#!/usr/bin/env node\n");
    write_executable(
        &node,
        &format!(
            "#!/bin/sh\nif [ \"$2 $3 $4 $5\" != \"usage plan --format json\" ]; then exit 9; fi\nprintf '%s' '{}'\n",
            shell_quote(std::str::from_utf8(ARKCLI).expect("fixture UTF-8"))
        ),
    );
    let environment = BTreeMap::from([
        (
            "PATH".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
        (
            "HOME".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
        ("ARK_API_KEY".to_owned(), API_KEY_CANARY.to_owned()),
    ]);
    let settings = DoubaoCliSettings::resolve(&environment).expect("PATH discovery");
    assert_eq!(settings.executable(), arkcli);
    let debug = format!("{settings:?}");
    assert!(!debug.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!debug.contains(API_KEY_CANARY));

    let provider = DoubaoProvider::new_cli(scope("cli-account"), settings).expect("CLI provider");
    let sample = provider
        .fetch_at(
            &context("cli-account", ProviderSource::Cli),
            timestamp(1_700_000_000),
        )
        .await
        .expect("arkcli usage");
    assert_eq!(sample.fetched_at(), timestamp(1_784_191_293));
    assert_percent(percent(sample.primary().expect("coding session")), 7.48);
    assert_percent(percent(sample.secondary().expect("coding weekly")), 2.71);
    assert_percent(percent(sample.tertiary().expect("coding monthly")), 1.36);
    assert_eq!(sample.extra_windows().len(), 7);
    assert_percent(extra_percent(&sample, "doubao-agent-session"), 5.0);
    assert_percent(extra_percent(&sample, "doubao-coding-team-session"), 17.0);
    assert_percent(extra_percent(&sample, "doubao-agent-team-weekly"), 45.0);
    assert_eq!(
        sample
            .identity()
            .login_method()
            .map(oab_domain::BoundedText::as_str),
        Some("sso")
    );
    assert_eq!(sample.provenance()[0].strategy(), "cli");
}

#[tokio::test]
async fn arkcli_errors_are_bounded_classified_and_never_expose_stderr() {
    let cases = [
        (
            "printf '%s\\n' 'not logged in; run arkcli auth login' >&2\nexit 1",
            ErrorKind::AuthenticationExpired,
        ),
        ("printf '%s' 'not json'", ErrorKind::Parse),
        ("/usr/bin/head -c 300000 /dev/zero", ErrorKind::Parse),
        (
            "printf '%s\\n' 'fixture-sensitive-cli-failure' >&2\nexit 2",
            ErrorKind::Api,
        ),
    ];
    for (index, (command, expected)) in cases.into_iter().enumerate() {
        let directory = TestDirectory::new(&format!("doubao-cli-error-{index}"));
        let executable = directory.path().join("arkcli");
        write_executable(&executable, &format!("#!/bin/sh\n{command}\n"));
        let environment = BTreeMap::from([(
            "OMARCHY_AI_BAR_ARKCLI_PATH".to_owned(),
            executable.to_string_lossy().into_owned(),
        )]);
        let settings = DoubaoCliSettings::resolve(&environment).expect("explicit executable");
        let provider = DoubaoProvider::new_cli(scope(&format!("cli-error-{index}")), settings)
            .expect("CLI provider");
        let error = provider
            .fetch_at(
                &context(&format!("cli-error-{index}"), ProviderSource::Cli),
                timestamp(1),
            )
            .await
            .expect_err("CLI failure");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains("fixture-sensitive-cli-failure"));
        assert!(!debug.contains("not logged in"));
    }
}

#[tokio::test]
async fn arkcli_incomplete_or_unauthenticated_payloads_fail_closed() {
    for (index, (payload, expected)) in [
        (
            r#"{"viewer":{"auth_method":"none"},"items":[{"product":"coding-plan","periods":[{"label":"session","percent":5}]}]}"#,
            ErrorKind::AuthenticationExpired,
        ),
        (
            r#"{"items":[{"product":"coding-plan","periods":[{"label":"session","percent":5}]},{"product":"agent-plan-team","subscribed":true,"error":"no seat"}]}"#,
            ErrorKind::Parse,
        ),
        (r#"{"items":[]}"#, ErrorKind::Api),
    ]
    .into_iter()
    .enumerate()
    {
        let directory = TestDirectory::new(&format!("doubao-cli-payload-{index}"));
        let executable = directory.path().join("arkcli");
        write_executable(
            &executable,
            &format!("#!/bin/sh\nprintf '%s' '{}'\n", shell_quote(payload)),
        );
        let settings = DoubaoCliSettings::new(executable, &BTreeMap::new())
            .expect("fixture CLI settings");
        let account = format!("payload-{index}");
        let provider = DoubaoProvider::new_cli(scope(&account), settings).expect("CLI provider");
        assert_eq!(
            provider
                .fetch_at(&context(&account, ProviderSource::Cli), timestamp(1))
                .await
                .expect_err("invalid CLI payload")
                .kind(),
            expected
        );
    }
}

#[test]
fn cli_discovery_is_authoritative_bounded_and_linux_native() {
    let relative = BTreeMap::from([(
        "OMARCHY_AI_BAR_ARKCLI_PATH".to_owned(),
        "relative/arkcli".to_owned(),
    )]);
    assert_eq!(
        DoubaoCliSettings::resolve(&relative)
            .expect_err("relative override")
            .kind(),
        ErrorKind::Api
    );

    let directory = TestDirectory::new("doubao-cli-authoritative");
    let fallback = directory.path().join("arkcli");
    write_executable(&fallback, "#!/bin/sh\nexit 0\n");
    let environment = BTreeMap::from([
        (
            "OMARCHY_AI_BAR_ARKCLI_PATH".to_owned(),
            "/does/not/exist/arkcli".to_owned(),
        ),
        (
            "PATH".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
    ]);
    assert_eq!(
        DoubaoCliSettings::resolve(&environment)
            .expect_err("override does not fall through to PATH")
            .kind(),
        ErrorKind::Api
    );

    let unnamespaced = BTreeMap::from([
        (
            "ARKCLI_PATH".to_owned(),
            "/does/not/exist/arkcli".to_owned(),
        ),
        (
            "PATH".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
    ]);
    let resolved = DoubaoCliSettings::resolve(&unnamespaced)
        .expect("unnamespaced application override is ignored");
    assert_eq!(resolved.executable(), fallback);

    let missing = BTreeMap::from([(
        "PATH".to_owned(),
        directory
            .path()
            .join("empty")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert_eq!(
        DoubaoCliSettings::resolve(&missing)
            .expect_err("missing arkcli")
            .kind(),
        ErrorKind::MissingCredential
    );
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture clock")
            .as_nanos();
        for ordinal in 0..100_u8 {
            let path = std::env::temp_dir().join(format!(
                "omarchy-ai-bar-{label}-{}-{nonce}-{ordinal}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("could not create fixture directory: {error}"),
            }
        }
        panic!("could not allocate fixture directory")
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

fn write_executable(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write fixture executable");
    let mut permissions = std::fs::metadata(path)
        .expect("fixture metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).expect("fixture executable permissions");
}

fn shell_quote(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}
