use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::providers::amp::{
    AmpApiCredential, AmpCliSettings, AmpProvider, parse_display_text,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{HttpTransport, TransportConfig};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const CURRENT: &str = include_str!("../../../fixtures/providers/amp/current.txt");
const MONTHLY: &str = include_str!("../../../fixtures/providers/amp/monthly.txt");
const API_SUCCESS: &[u8] = include_bytes!("../../../fixtures/providers/amp/api_success.json");
const API_AUTH: &[u8] = include_bytes!("../../../fixtures/providers/amp/api_auth.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/amp/malformed.json");
const FAKE_AMP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/providers/amp/fake-amp"
);
const TOKEN_CANARY: &str = "sgamp-fixture-sensitive-token";

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("fixture timestamp")
}

fn scope_for(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(format!("{}-primary", provider.as_str())).expect("instance"),
        AccountKey::new(account).expect("account"),
    )
}

fn scope(account: &str) -> AccountScope {
    scope_for(ProviderId::Amp, account)
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
        512 * 1024,
        0,
        RetryPolicy::none(),
    )
    .expect("fixture transport config")
}

fn api_provider(server: &FakeHttpServer, account: &str) -> AmpProvider {
    let policy = EndpointPolicy::new([(server.origin(), EndpointClass::LoopbackDevelopment)])
        .expect("loopback policy");
    let transport = HttpTransport::new(policy, config()).expect("loopback transport");
    AmpProvider::from_api_transport(
        scope(account),
        AmpApiCredential::new(TOKEN_CANARY).expect("credential"),
        server.url("/api/internal?userDisplayBalanceInfo"),
        transport,
    )
    .expect("Amp provider")
}

fn percent(window: &oab_domain::RateWindow) -> f64 {
    window.used_percent().expect("known usage").get()
}

fn assert_percent(window: &oab_domain::RateWindow, expected: f64) {
    let actual = percent(window);
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "expected {expected}%, got {actual}%"
    );
}

fn detail<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> Option<&'a str> {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .map(oab_domain::DetailRow::value)
}

#[test]
fn parser_covers_ansi_identity_rolling_balance_and_credit_details() {
    let fetched_at = timestamp("2026-08-18T12:00:00Z");
    let sample = parse_display_text(
        scope("parser-current"),
        fetched_at,
        CURRENT,
        ProviderSource::Cli,
    )
    .expect("current display text");

    assert_percent(sample.primary().expect("free window"), 20.0);
    assert_eq!(
        sample
            .primary()
            .expect("free window")
            .duration()
            .map(oab_domain::WindowDuration::seconds),
        Some(72_000)
    );
    assert_eq!(
        sample.primary().expect("free window").resets_at(),
        Some(timestamp("2026-08-18T16:00:00Z"))
    );
    assert_eq!(
        sample
            .identity()
            .email()
            .map(oab_domain::BoundedText::as_str),
        Some("cli@example.test")
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .map(oab_domain::BoundedText::as_str),
        Some("fixture-team")
    );
    assert_eq!(detail(&sample, "Individual credits"), Some("$12.50"));
    assert_eq!(detail(&sample, "Workspace Alpha Team"), Some("$1,234.56"));
    assert_eq!(detail(&sample, "Workspace Beta"), Some("$7.00"));
    assert_eq!(sample.provenance()[0].strategy(), "cli");
}

#[test]
fn parser_covers_bold_subscription_months_and_new_york_daily_reset() {
    let fetched_at = timestamp("2026-08-03T22:00:00Z");
    let sample = parse_display_text(
        scope("parser-monthly"),
        fetched_at,
        MONTHLY,
        ProviderSource::ApiKey,
    )
    .expect("monthly display text");

    assert_percent(sample.primary().expect("other usage"), 27.0);
    assert_percent(sample.secondary().expect("orb usage"), 9.0);
    assert!(sample.subscription_renews_at().is_none());
    assert_eq!(
        sample.primary().expect("other usage").resets_at(),
        Some(timestamp("2026-09-03T22:00:00Z"))
    );
    assert_eq!(
        sample.secondary().expect("orb usage").resets_at(),
        Some(timestamp("2026-09-03T22:00:00Z"))
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .map(oab_domain::BoundedText::as_str),
        Some("Gigawatt")
    );
    let free = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == "amp-free")
        .expect("free lane");
    assert_percent(free.window(), 39.0);
    assert_eq!(
        free.window().resets_at(),
        Some(timestamp("2026-08-04T00:00:00Z"))
    );
    assert_eq!(
        free.window()
            .reset_description()
            .map(oab_domain::BoundedText::as_str),
        Some("resets daily")
    );
    assert_eq!(detail(&sample, "Workspace meow"), Some("$5.33"));

    let boundary = parse_display_text(
        scope("parser-boundary"),
        timestamp("2026-08-04T00:00:00Z"),
        "Amp Free: 61% remaining today (resets daily)",
        ProviderSource::Cli,
    )
    .expect("boundary display text");
    assert_eq!(
        boundary.primary().expect("free").resets_at(),
        Some(timestamp("2026-08-05T00:00:00Z"))
    );

    let winter = parse_display_text(
        scope("parser-winter"),
        timestamp("2026-01-16T00:59:59Z"),
        "Amp Free: 61% remaining today (resets daily)",
        ProviderSource::Cli,
    )
    .expect("winter display text");
    assert_eq!(
        winter.primary().expect("free").resets_at(),
        Some(timestamp("2026-01-16T01:00:00Z"))
    );
}

#[test]
fn parser_accepts_zero_renewals_and_clamps_subhour_rolling_durations() {
    let fetched_at = timestamp("2026-08-01T00:00:00Z");
    for unit in ["days", "months"] {
        let sample = parse_display_text(
            scope(&format!("zero-{unit}")),
            fetched_at,
            &format!(
                "Amp Gigawatt Subscription: 73% other usage and 91% orb usage remaining - resets upon renewal in 0 {unit}"
            ),
            ProviderSource::Cli,
        )
        .expect("zero renewal");
        assert_eq!(
            sample.primary().expect("other usage").resets_at(),
            Some(fetched_at)
        );
        assert_eq!(
            sample.secondary().expect("orb usage").resets_at(),
            Some(fetched_at)
        );
        assert_eq!(
            sample
                .primary()
                .expect("other usage")
                .reset_description()
                .map(oab_domain::BoundedText::as_str),
            Some(format!("renews in 0 {unit}").as_str())
        );
        assert!(sample.subscription_renews_at().is_none());
    }

    let rolling = parse_display_text(
        scope("zero-hour-rolling"),
        fetched_at,
        "Amp Free: $0/$0.1 remaining (replenishes +$1/hour)",
        ProviderSource::Cli,
    )
    .expect("sub-hour rolling quota");
    assert_percent(rolling.primary().expect("rolling free"), 100.0);
    assert_eq!(
        rolling
            .primary()
            .expect("rolling free")
            .duration()
            .map(oab_domain::WindowDuration::seconds),
        Some(60 * 60),
        "the pinned parser clamps a rounded zero-hour duration to one hour"
    );
    assert_eq!(
        rolling.primary().expect("rolling free").resets_at(),
        Some(timestamp("2026-08-01T00:06:00Z"))
    );
}

#[test]
fn parser_preserves_legacy_precedence_and_accepts_credit_only_accounts() {
    let sample = parse_display_text(
        scope("precedence"),
        timestamp("2026-08-01T00:00:00Z"),
        "Signed in as login@example.test\nAmp Free: $6/$10 remaining (replenishes +$0.5/hour)\nAmp Free: 61% remaining today (resets daily)",
        ProviderSource::Cli,
    )
    .expect("legacy precedence");
    assert_percent(sample.primary().expect("free"), 40.0);
    assert_eq!(
        sample.primary().expect("free").reset_description(),
        None,
        "the rolling form wins even when the daily form is present"
    );

    let credits = parse_display_text(
        scope("credits-only"),
        timestamp("2026-08-01T00:00:00Z"),
        "Signed in as paid@example.test\nIndividual credits: $25.64 remaining",
        ProviderSource::ApiKey,
    )
    .expect("credits-only display text");
    assert!(credits.primary().is_none());
    assert_eq!(detail(&credits, "Individual credits"), Some("$25.64"));
    assert_eq!(
        credits
            .identity()
            .login_method()
            .map(oab_domain::BoundedText::as_str),
        Some("Amp")
    );

    let legacy_subscription = parse_display_text(
        scope("legacy-subscription"),
        timestamp("2026-08-01T00:00:00Z"),
        "Subscription Megawatt: 97% other usage and 100% orb usage remaining - resets upon renewal in 29 days - https://ampcode.com/settings#subscription",
        ProviderSource::Cli,
    )
    .expect("legacy subscription syntax");
    assert_percent(legacy_subscription.primary().expect("other"), 3.0);
    assert_percent(legacy_subscription.secondary().expect("orb"), 0.0);
    assert_eq!(
        legacy_subscription.primary().expect("other").resets_at(),
        Some(timestamp("2026-08-30T00:00:00Z"))
    );

    let no_cadence = parse_display_text(
        scope("no-cadence"),
        timestamp("2026-08-01T00:00:00Z"),
        "Amp Free: $6/$10 remaining",
        ProviderSource::Cli,
    )
    .expect("legacy balance without replenishment");
    assert!(no_cadence.primary().expect("free").duration().is_none());
    assert!(no_cadence.primary().expect("free").resets_at().is_none());
}

#[test]
fn parser_fails_closed_on_signout_malformed_bounds_and_wrong_source() {
    for (text, expected) in [
        ("Please sign in to Amp.", ErrorKind::AuthenticationExpired),
        ("unrecognized usage format", ErrorKind::Parse),
        ("\u{1b}[31", ErrorKind::Parse),
    ] {
        assert_eq!(
            parse_display_text(
                scope("bad-parser"),
                timestamp("2026-08-01T00:00:00Z"),
                text,
                ProviderSource::Cli,
            )
            .expect_err("invalid display text")
            .kind(),
            expected
        );
    }

    let oversized = "x".repeat(256 * 1024 + 1);
    assert_eq!(
        parse_display_text(
            scope("oversized"),
            timestamp("2026-08-01T00:00:00Z"),
            &oversized,
            ProviderSource::Cli,
        )
        .expect_err("oversized display text")
        .kind(),
        ErrorKind::Parse
    );

    let workspaces = (0..24)
        .map(|index| format!("Workspace team-{index}: $1 remaining"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        parse_display_text(
            scope("workspace-bound"),
            timestamp("2026-08-01T00:00:00Z"),
            &workspaces,
            ProviderSource::Cli,
        )
        .expect_err("too many workspaces")
        .kind(),
        ErrorKind::Parse
    );
    assert_eq!(
        parse_display_text(
            scope("wrong-source"),
            timestamp("2026-08-01T00:00:00Z"),
            "Amp Free: 50% remaining",
            ProviderSource::BrowserSession,
        )
        .expect_err("browser boundary is separate")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn api_uses_exact_bearer_rpc_and_normalizes_current_display_text() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, API_SUCCESS.to_vec())]).await;
    let provider = api_provider(&server, "api-success");
    let sample = provider
        .fetch_at(
            &context("api-success", ProviderSource::ApiKey),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect("Amp API usage");

    assert_percent(sample.primary().expect("free"), 20.0);
    assert_eq!(sample.provenance()[0].strategy(), "api");
    assert_eq!(
        sample
            .identity()
            .email()
            .map(oab_domain::BoundedText::as_str),
        Some("api@example.test")
    );
    assert_eq!(detail(&sample, "Workspace Alpha Team"), Some("$1,234.56"));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/api/internal?userDisplayBalanceInfo");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer sgamp-fixture-sensitive-token")
    );
    assert_eq!(requests[0].header("cookie"), None);
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(requests[0].header("content-type"), Some("application/json"));
    let body: Value = serde_json::from_slice(requests[0].body()).expect("request JSON");
    assert_eq!(
        body,
        json!({"method": "userDisplayBalanceInfo", "params": {}})
    );
}

#[tokio::test]
async fn api_maps_http_body_auth_drift_and_malformed_payloads_without_leaks() {
    for (index, (response, expected)) in [
        (
            FakeHttpResponse::new(401, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(200, API_AUTH.to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(200, MALFORMED.to_vec()),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::new(
                200,
                br#"{"ok":false,"error":{"code":"other","message":"fixture-sensitive"}}"#.to_vec(),
            ),
            ErrorKind::Api,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let server = FakeHttpServer::start([response]).await;
        let account = format!("api-error-{index}");
        let provider = api_provider(&server, &account);
        let error = provider
            .fetch_at(
                &context(&account, ProviderSource::ApiKey),
                timestamp("2026-08-18T12:00:00Z"),
            )
            .await
            .expect_err("API error");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains("fixture-sensitive"));
        assert!(!debug.contains(TOKEN_CANARY));
    }
}

#[tokio::test]
async fn account_and_source_mismatches_are_rejected_before_api_or_cli_io() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, API_SUCCESS.to_vec())]).await;
    let provider = api_provider(&server, "bound-api");
    for bad in [
        context("different-account", ProviderSource::ApiKey),
        context("bound-api", ProviderSource::Cli),
    ] {
        assert_eq!(
            provider
                .fetch_at(&bad, timestamp("2026-08-18T12:00:00Z"))
                .await
                .expect_err("isolated API context")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(server.requests().is_empty());

    let directory = TestDirectory::new("amp-scope-cli");
    let executable = directory.path().join("amp");
    let marker = directory.path().join("started");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n: > '{}'\n",
            shell_quote(marker.to_string_lossy().as_ref())
        ),
    );
    let settings = AmpCliSettings::new(executable, &BTreeMap::new()).expect("CLI settings");
    let cli = AmpProvider::new_cli(scope("bound-cli"), settings).expect("CLI provider");
    assert_eq!(
        cli.fetch_at(
            &context("bound-cli", ProviderSource::ApiKey),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect_err("isolated CLI context")
        .kind(),
        ErrorKind::Api
    );
    assert!(!marker.exists());

    assert_eq!(
        AmpProvider::new_api(
            scope_for(ProviderId::OpenAi, "wrong-provider"),
            AmpApiCredential::new(TOKEN_CANARY).expect("credential"),
        )
        .expect_err("wrong provider")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn cli_runs_exact_usage_with_sanitized_environment_and_linux_fixture() {
    let environment = BTreeMap::from([
        ("HOME".to_owned(), "/tmp/amp-fixture-home".to_owned()),
        ("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned()),
        ("AMP_API_KEY".to_owned(), TOKEN_CANARY.to_owned()),
        ("OMARCHY_AI_BAR_AMP_PATH".to_owned(), FAKE_AMP.to_owned()),
    ]);
    let settings = AmpCliSettings::resolve(&environment).expect("fixture discovery");
    assert_eq!(settings.executable(), Path::new(FAKE_AMP));
    let debug = format!("{settings:?}");
    assert!(!debug.contains(FAKE_AMP));
    assert!(!debug.contains(TOKEN_CANARY));
    let provider = AmpProvider::new_cli(scope("cli-fixture"), settings).expect("CLI provider");
    let sample = provider
        .fetch_at(
            &context("cli-fixture", ProviderSource::Cli),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect("CLI usage");
    assert_percent(sample.primary().expect("free"), 20.0);
    assert_eq!(detail(&sample, "Workspace Alpha Team"), Some("$1,234.56"));
}

#[tokio::test]
async fn cli_forwards_valid_amp_customization_and_omits_blank_or_secret_values() {
    let directory = TestDirectory::new("amp-custom-environment");
    let executable = directory.path().join("amp");
    let amp_home = directory.path().join("relocated-home");
    let settings_file = directory.path().join("relocated-settings.json");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n[ \"${{AMP_URL:-}}\" = 'https://amp.example.test/base' ] || exit 21\n[ \"${{AMP_HOME:-}}\" = '{}' ] || exit 22\n[ \"${{AMP_SETTINGS_FILE:-}}\" = '{}' ] || exit 23\n[ -z \"${{AMP_API_KEY+x}}\" ] || exit 24\n[ -z \"${{AMP_STORAGE_BASE+x}}\" ] || exit 25\nprintf '%s' '{}'\n",
            shell_quote(amp_home.to_string_lossy().as_ref()),
            shell_quote(settings_file.to_string_lossy().as_ref()),
            shell_quote(CURRENT),
        ),
    );
    let environment = BTreeMap::from([
        (
            "AMP_URL".to_owned(),
            " 'https://amp.example.test/base' ".to_owned(),
        ),
        (
            "AMP_HOME".to_owned(),
            format!(" '{}' ", amp_home.to_string_lossy()),
        ),
        (
            "AMP_SETTINGS_FILE".to_owned(),
            format!(" '{}' ", settings_file.to_string_lossy()),
        ),
        ("AMP_API_KEY".to_owned(), TOKEN_CANARY.to_owned()),
        (
            "AMP_STORAGE_BASE".to_owned(),
            "/tmp/internal-amp-storage".to_owned(),
        ),
    ]);
    let provider = AmpProvider::new_cli(
        scope("custom-environment"),
        AmpCliSettings::new(executable, &environment).expect("custom CLI environment"),
    )
    .expect("CLI provider");
    let sample = provider
        .fetch_at(
            &context("custom-environment", ProviderSource::Cli),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect("customized CLI usage");
    assert_percent(sample.primary().expect("free"), 20.0);

    let executable = directory.path().join("amp-blank");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n[ -z \"${{AMP_URL+x}}\" ] || exit 31\n[ -z \"${{AMP_HOME+x}}\" ] || exit 32\n[ -z \"${{AMP_SETTINGS_FILE+x}}\" ] || exit 33\nprintf '%s' '{}'\n",
            shell_quote(CURRENT)
        ),
    );
    let blank_environment = BTreeMap::from([
        ("AMP_URL".to_owned(), "   ".to_owned()),
        ("AMP_HOME".to_owned(), " '' ".to_owned()),
        ("AMP_SETTINGS_FILE".to_owned(), " \"\" ".to_owned()),
    ]);
    let provider = AmpProvider::new_cli(
        scope("blank-custom-environment"),
        AmpCliSettings::new(executable, &blank_environment).expect("blank values are omitted"),
    )
    .expect("CLI provider");
    provider
        .fetch_at(
            &context("blank-custom-environment", ProviderSource::Cli),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect("blank custom values omitted");
}

#[test]
fn cli_rejects_unsafe_amp_customization_values() {
    let directory = TestDirectory::new("amp-unsafe-custom-environment");
    let executable = directory.path().join("amp");
    write_executable(&executable, "#!/bin/sh\nexit 0\n");

    let invalid_values = vec![
        ("AMP_URL", "http://amp.example.test".to_owned()),
        (
            "AMP_URL",
            "https://user:password@amp.example.test".to_owned(),
        ),
        (
            "AMP_URL",
            "https://amp.example.test/base?token=secret".to_owned(),
        ),
        ("AMP_URL", "https://amp.example.test\n".to_owned()),
        ("AMP_URL", "https://amp.\nexample.test".to_owned()),
        (
            "AMP_URL",
            format!("https://amp.example.test/{}", "x".repeat(4_096)),
        ),
        ("AMP_HOME", "/tmp/amp\0home".to_owned()),
        ("AMP_SETTINGS_FILE", "/tmp/amp\nsettings.json".to_owned()),
        ("AMP_SETTINGS_FILE", format!("/tmp/{}", "x".repeat(4_096))),
    ];
    for (name, value) in invalid_values {
        let environment = BTreeMap::from([(name.to_owned(), value)]);
        assert_eq!(
            AmpCliSettings::new(executable.clone(), &environment)
                .expect_err("unsafe Amp customization")
                .kind(),
            ErrorKind::Api,
            "{name} must fail closed"
        );
    }

    AmpCliSettings::new(
        executable,
        &BTreeMap::from([("AMP_URL".to_owned(), "http://[::1]:4317/custom".to_owned())]),
    )
    .expect("explicit loopback HTTP is safe for local Amp development");
}

#[tokio::test]
async fn cli_uses_successful_stderr_only_when_stdout_is_blank() {
    let directory = TestDirectory::new("amp-stderr-success");
    let executable = directory.path().join("amp");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\nprintf '  \\n'\nprintf '%s' '{}' >&2\n",
            shell_quote(MONTHLY)
        ),
    );
    let settings = AmpCliSettings::new(executable, &BTreeMap::new()).expect("CLI settings");
    let provider = AmpProvider::new_cli(scope("stderr-success"), settings).expect("CLI provider");
    let sample = provider
        .fetch_at(
            &context("stderr-success", ProviderSource::Cli),
            timestamp("2026-08-03T22:00:00Z"),
        )
        .await
        .expect("stderr usage");
    assert_percent(sample.primary().expect("subscription"), 27.0);
}

#[tokio::test]
async fn cli_timeout_cancellation_and_output_caps_are_bounded() {
    let cases = [
        ("sleep 5", ErrorKind::Network, true),
        ("/usr/bin/head -c 128 /dev/zero", ErrorKind::Parse, false),
        (
            "/usr/bin/head -c 128 /dev/zero >&2",
            ErrorKind::Parse,
            false,
        ),
    ];
    for (index, (command, expected, short_timeout)) in cases.into_iter().enumerate() {
        let directory = TestDirectory::new(&format!("amp-resource-{index}"));
        let executable = directory.path().join("amp");
        write_executable(&executable, &format!("#!/bin/sh\n{command}\n"));
        let timeout = if short_timeout {
            Duration::from_millis(50)
        } else {
            Duration::from_secs(1)
        };
        let settings = AmpCliSettings::new(executable, &BTreeMap::new())
            .expect("CLI settings")
            .with_test_limits(timeout, 64, 64)
            .expect("test limits");
        let account = format!("resource-{index}");
        let provider = AmpProvider::new_cli(scope(&account), settings).expect("CLI provider");
        assert_eq!(
            provider
                .fetch_at(
                    &context(&account, ProviderSource::Cli),
                    timestamp("2026-08-18T12:00:00Z"),
                )
                .await
                .expect_err("bounded CLI error")
                .kind(),
            expected
        );
    }

    let directory = TestDirectory::new("amp-cancelled");
    let executable = directory.path().join("amp");
    let marker = directory.path().join("started");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n: > '{}'\nsleep 5\n",
            shell_quote(marker.to_string_lossy().as_ref())
        ),
    );
    let provider = AmpProvider::new_cli(
        scope("cancelled"),
        AmpCliSettings::new(executable, &BTreeMap::new()).expect("CLI settings"),
    )
    .expect("CLI provider");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled_context =
        ProviderContext::new(scope("cancelled"), ProviderSource::Cli, cancellation);
    assert_eq!(
        provider
            .fetch_at(&cancelled_context, timestamp("2026-08-18T12:00:00Z"),)
            .await
            .expect_err("cancelled CLI")
            .kind(),
        ErrorKind::Network
    );
    assert!(!marker.exists(), "pre-cancellation must prevent spawn");
}

#[tokio::test]
async fn cli_nonzero_errors_are_safely_classified_and_redacted() {
    for (index, (command, expected)) in [
        (
            "printf '%s' 'not logged in; fixture-sensitive-auth' >&2; exit 1",
            ErrorKind::AuthenticationExpired,
        ),
        (
            "printf '%s' 'fixture-sensitive-generic' >&2; exit 2",
            ErrorKind::Api,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let directory = TestDirectory::new(&format!("amp-nonzero-{index}"));
        let executable = directory.path().join("amp");
        write_executable(&executable, &format!("#!/bin/sh\n{command}\n"));
        let account = format!("nonzero-{index}");
        let provider = AmpProvider::new_cli(
            scope(&account),
            AmpCliSettings::new(executable, &BTreeMap::new()).expect("CLI settings"),
        )
        .expect("CLI provider");
        let error = provider
            .fetch_at(
                &context(&account, ProviderSource::Cli),
                timestamp("2026-08-18T12:00:00Z"),
            )
            .await
            .expect_err("nonzero CLI");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?}").contains("fixture-sensitive"));
    }
}

#[test]
fn credentials_and_discovery_are_precedence_bounded_and_redacted() {
    let credential = AmpApiCredential::resolve(&BTreeMap::from([(
        "AMP_API_KEY".to_owned(),
        format!(" '{TOKEN_CANARY}' "),
    )]))
    .expect("quoted token");
    assert!(!format!("{credential:?}").contains(TOKEN_CANARY));

    let relative = BTreeMap::from([(
        "OMARCHY_AI_BAR_AMP_PATH".to_owned(),
        "relative/amp".to_owned(),
    )]);
    assert_eq!(
        AmpCliSettings::resolve(&relative)
            .expect_err("relative override")
            .kind(),
        ErrorKind::Api
    );

    let directory = TestDirectory::new("amp-authoritative");
    let fallback = directory.path().join("amp");
    write_executable(&fallback, "#!/bin/sh\nexit 0\n");
    let authoritative = BTreeMap::from([
        (
            "OMARCHY_AI_BAR_AMP_PATH".to_owned(),
            "/does/not/exist/amp".to_owned(),
        ),
        (
            "PATH".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
    ]);
    assert_eq!(
        AmpCliSettings::resolve(&authoritative)
            .expect_err("override does not fall through")
            .kind(),
        ErrorKind::Api
    );

    let discovered = AmpCliSettings::resolve(&BTreeMap::from([(
        "PATH".to_owned(),
        directory.path().to_string_lossy().into_owned(),
    )]))
    .expect("PATH discovery");
    assert_eq!(discovered.executable(), fallback);
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-amp-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fixture executable");
    let mut permissions = fs::metadata(path).expect("fixture metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("fixture permissions");
}

fn shell_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}
