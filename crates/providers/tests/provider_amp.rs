use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::browser_cookie::DisabledChromiumCookieDecryptor;
use oab_providers::browser_profile::{BrowserProfileDiscovery, BrowserProfileRoots};
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::providers::amp::{
    AmpApiCredential, AmpCliSettings, AmpProvider, AmpWebRouteSet, is_amp_login_redirect,
    parse_display_text, parse_html,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{HttpTransport, TransportConfig};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;

const CURRENT: &str = include_str!("../../../fixtures/providers/amp/current.txt");
const MONTHLY: &str = include_str!("../../../fixtures/providers/amp/monthly.txt");
const API_SUCCESS: &[u8] = include_bytes!("../../../fixtures/providers/amp/api_success.json");
const API_AUTH: &[u8] = include_bytes!("../../../fixtures/providers/amp/api_auth.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/amp/malformed.json");
const SETTINGS_HTML: &str = include_str!("../../../fixtures/providers/amp/settings.html");
const SETTINGS_PREFETCHED: &str =
    include_str!("../../../fixtures/providers/amp/settings-prefetched.html");
const SETTINGS_SIGNED_OUT: &str =
    include_str!("../../../fixtures/providers/amp/settings-signed-out.html");
const FAKE_AMP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/providers/amp/fake-amp"
);
const TOKEN_CANARY: &str = "sgamp-fixture-sensitive-token";
const SESSION_CANARY_A: &str = "amp-session-fixture-sensitive-a";
const SESSION_CANARY_B: &str = "amp-session-fixture-sensitive-b";
const SESSION_CANARY_C: &str = "amp-session-fixture-sensitive-c";
const ROOT_SESSION_CANARY: &str = "amp-root-session-must-not-win";

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

fn web_routes(server: &FakeHttpServer) -> AmpWebRouteSet {
    AmpWebRouteSet::loopback(server.url("/settings")).expect("loopback Amp routes")
}

fn manual_provider(server: &FakeHttpServer, account: &str, raw: &str) -> AmpProvider {
    AmpProvider::from_manual_capture_routes(scope(account), raw, web_routes(server))
        .expect("manual Amp provider")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixture browser time")
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
fn parser_subscription_suffix_matches_pinned_line_grammar() {
    let fetched_at = timestamp("2026-08-01T00:00:00Z");
    let prefix = "Subscription Megawatt: 97% other usage and 100% orb usage remaining";
    for (index, suffix) in [
        " - resets upon renewal in 1 month",
        "  -  resets  upon renewal in 2 days - https://ampcode.com/settings#subscription",
        " - resets upon renewal in 1 day - HTTP://localhost:3000/settings",
    ]
    .into_iter()
    .enumerate()
    {
        let sample = parse_display_text(
            scope(&format!("subscription-positive-{index}")),
            fetched_at,
            &format!("{prefix}{suffix}"),
            ProviderSource::Cli,
        )
        .expect("pinned subscription suffix");
        assert_percent(sample.primary().expect("subscription"), 3.0);
    }

    for (index, suffix) in [
        " resets upon renewal in 1 month",
        " arbitrary - resets upon renewal in 1 month",
        " - resets upon renewal in 1 monthly",
        " - resets upon renewal in 1 dayz",
        " - resets upon renewal in 1 month trailing",
        " - resets upon renewal in 1 month - ftp://ampcode.com/settings",
        " - resets upon renewal in 1 month - https://",
        " - resets upon renewal in 1 month -https://ampcode.com/settings",
        " - resets upon renewal in 1 month - https://ampcode.com/settings trailing",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            parse_display_text(
                scope(&format!("subscription-negative-{index}")),
                fetched_at,
                &format!("{prefix}{suffix}"),
                ProviderSource::Cli,
            )
            .expect_err("subscription grammar drift")
            .kind(),
            ErrorKind::Parse,
            "unexpectedly accepted suffix {suffix:?}"
        );
    }
}

#[test]
fn parser_free_metadata_is_exact_and_rounds_midpoints_away_from_zero() {
    let fetched_at = timestamp("2026-08-01T00:00:00Z");
    let rolling = parse_display_text(
        scope("rolling-midpoint"),
        fetched_at,
        "Amp Free: $5/$10 remaining (replenishes +$4/hour)",
        ProviderSource::Cli,
    )
    .expect("exact rolling metadata");
    assert_eq!(
        rolling
            .primary()
            .expect("rolling free")
            .duration()
            .map(oab_domain::WindowDuration::seconds),
        Some(3 * 60 * 60)
    );

    for (index, text) in [
        "Amp Free: $5/$10 remaining replenishes +$4/hour",
        "Amp Free: $5/$10 remaining (replenishes $4/hour)",
        "Amp Free: $5/$10 remaining (replenishes +$4/bananas)",
        "Amp Free: $5/$10 remaining guidance (replenishes +$4/hour)",
    ]
    .into_iter()
    .enumerate()
    {
        let sample = parse_display_text(
            scope(&format!("rolling-metadata-negative-{index}")),
            fetched_at,
            text,
            ProviderSource::Cli,
        )
        .expect("base rolling balance remains valid");
        let window = sample.primary().expect("free balance");
        assert!(
            window.duration().is_none(),
            "fabricated duration for {text:?}"
        );
        assert!(
            window.resets_at().is_none(),
            "fabricated reset for {text:?}"
        );
    }

    for (index, text) in [
        "Amp Free: 50% remaining resets daily",
        "Amp Free: 50% remaining today resets daily",
        "Amp Free: 50% remaining guidance (resets daily)",
        "Amp Free: 50% remaining (resets someday)",
    ]
    .into_iter()
    .enumerate()
    {
        let sample = parse_display_text(
            scope(&format!("daily-metadata-negative-{index}")),
            fetched_at,
            text,
            ProviderSource::Cli,
        )
        .expect("base daily balance remains valid");
        let window = sample.primary().expect("daily balance");
        assert!(
            window.resets_at().is_none(),
            "fabricated reset for {text:?}"
        );
        assert!(window.reset_description().is_none());
    }

    let html = "<script>window.data={freeTierUsage:{quota:10,used:5,hourlyReplenishment:1,windowHours:0.075}};</script>";
    let sample = parse_html(
        scope("html-window-midpoint"),
        fetched_at,
        html,
        ProviderSource::ManualCookie,
    )
    .expect("HTML midpoint window");
    assert_eq!(
        sample
            .primary()
            .expect("HTML free")
            .duration()
            .map(oab_domain::WindowDuration::seconds),
        Some(5 * 60)
    );
}

#[test]
fn parser_accepts_pinned_required_tabs_and_repeated_spaces() {
    let fetched_at = timestamp("2026-08-01T00:00:00Z");
    let account = parse_display_text(
        scope("whitespace-account"),
        fetched_at,
        "Signed in as\tspace@example.test\t\t(team)\nAmp Free:\t$5 / $10\tremaining (replenishes\t+$2 /\thour)\nIndividual credits:\t$5\tremaining\nWorkspace\tTeam:\t$7\tremaining",
        ProviderSource::Cli,
    )
    .expect("required tabs and repeated spaces");
    assert_percent(account.primary().expect("free"), 50.0);
    assert_eq!(
        account
            .primary()
            .expect("free")
            .duration()
            .map(oab_domain::WindowDuration::seconds),
        Some(5 * 60 * 60)
    );
    assert_eq!(
        account
            .identity()
            .email()
            .map(oab_domain::BoundedText::as_str),
        Some("space@example.test")
    );
    assert_eq!(detail(&account, "Individual credits"), Some("$5.00"));
    assert_eq!(detail(&account, "Workspace Team"), Some("$7.00"));

    let daily = parse_display_text(
        scope("whitespace-daily"),
        fetched_at,
        "Amp Free:\t50\t%\tremaining\ttoday\t(resets\t daily)",
        ProviderSource::Cli,
    )
    .expect("daily whitespace");
    assert_eq!(
        daily
            .primary()
            .expect("daily")
            .reset_description()
            .map(oab_domain::BoundedText::as_str),
        Some("resets daily")
    );

    for (index, text) in [
        "Subscription\tMegawatt:\t97\t%\tother\tusage\tand\t100\t%\torb\tusage\tremaining\t-\tresets\tupon\trenewal\tin\t2\tdays",
        "Amp\tGigawatt\t\tSubscription:\t97\t%\tother\tusage\tand\t100\t%\torb\tusage\tremaining\t-\tresets\tupon\trenewal\tin\t2\tdays\t-\thttps://ampcode.com/settings",
    ]
    .into_iter()
    .enumerate()
    {
        let subscription = parse_display_text(
            scope(&format!("whitespace-subscription-{index}")),
            fetched_at,
            text,
            ProviderSource::Cli,
        )
        .expect("subscription whitespace");
        assert_percent(subscription.primary().expect("other usage"), 3.0);
        assert_percent(subscription.secondary().expect("orb usage"), 0.0);
    }
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
        ("Amp Free: +$5/$10 remaining", ErrorKind::Parse),
        ("Amp Free: $5/+$10 remaining", ErrorKind::Parse),
        ("Amp Free: $5/$10remaining", ErrorKind::Parse),
        ("Amp Free: 50%remaining", ErrorKind::Parse),
        ("Individual credits: +$1 remaining", ErrorKind::Parse),
        ("Individual credits: $5remaining", ErrorKind::Parse),
        ("Workspace team: +$1 remaining", ErrorKind::Parse),
        ("Workspace team: $5remaining", ErrorKind::Parse),
        ("WorkspaceTeam: $5 remaining", ErrorKind::Parse),
        (
            "SubscriptionMegawatt: 97% other usage and 100% orb usage remaining - resets upon renewal in 2 days",
            ErrorKind::Parse,
        ),
        (
            "AmpMegawatt Subscription: 97% other usage and 100% orb usage remaining - resets upon renewal in 2 days",
            ErrorKind::Parse,
        ),
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

#[test]
fn html_parser_matches_pinned_svelte_shapes_and_fails_closed_on_bounds() {
    let fetched_at = timestamp("2026-08-18T12:00:00Z");
    let sample = parse_html(
        scope("html-direct"),
        fetched_at,
        SETTINGS_HTML,
        ProviderSource::ManualCookie,
    )
    .expect("direct Svelte usage object");
    assert_percent(sample.primary().expect("free usage"), 33.85);
    assert_eq!(
        sample
            .primary()
            .expect("free usage")
            .duration()
            .map(oab_domain::WindowDuration::seconds),
        Some(24 * 60 * 60)
    );
    assert!(sample.primary().expect("free usage").resets_at().is_some());
    assert_eq!(sample.provenance()[0].strategy(), "manual_cookie");

    let prefetched = parse_html(
        scope("html-prefetched"),
        fetched_at,
        SETTINGS_PREFETCHED,
        ProviderSource::BrowserSession,
    )
    .expect("prefetched usage key");
    assert_percent(prefetched.primary().expect("free usage"), 0.0);
    assert_eq!(prefetched.provenance()[0].strategy(), "browser_session");

    let nested = format!("{}value:0{}", "level:{".repeat(64), "}".repeat(64));
    let too_deep =
        format!("freeTierUsage:{{quota:1,used:0,hourlyReplenishment:1,noise:{{{nested}}}}}");
    let fields = (0..4_097)
        .map(|index| format!("field{index}:0"))
        .collect::<Vec<_>>()
        .join(",");
    let too_many_fields =
        format!("freeTierUsage:{{quota:1,used:0,hourlyReplenishment:1,noise:{{{fields}}}}}");
    for (html, expected) in [
        (
            SETTINGS_SIGNED_OUT.to_owned(),
            ErrorKind::AuthenticationExpired,
        ),
        (
            "<html><body>No usage here.</body></html>".to_owned(),
            ErrorKind::Parse,
        ),
        (too_deep, ErrorKind::Parse),
        (too_many_fields, ErrorKind::Parse),
        (
            format!(
                "freeTierUsage:{{noise:\"{}\",quota:1,used:0,hourlyReplenishment:1}}",
                "x".repeat(128 * 1024 + 1)
            ),
            ErrorKind::Parse,
        ),
        ("x".repeat(512 * 1024 + 1), ErrorKind::Parse),
    ] {
        assert_eq!(
            parse_html(
                scope("html-invalid"),
                fetched_at,
                &html,
                ProviderSource::ManualCookie,
            )
            .expect_err("invalid HTML")
            .kind(),
            expected
        );
    }
    assert_eq!(
        parse_html(
            scope("html-source"),
            fetched_at,
            SETTINGS_HTML,
            ProviderSource::ApiKey,
        )
        .expect_err("wrong HTML source")
        .kind(),
        ErrorKind::Api
    );
}

#[test]
fn login_redirect_detector_matches_amp_hosts_without_suffix_confusion() {
    for url in [
        "https://ampcode.com/auth/sign-in?returnTo=%2Fsettings",
        "http://ampcode.com/auth/sign-in?returnTo=%2Fsettings",
        "https://ampcode.com/auth/sso?redirect=%2Fsettings",
        "https://www.ampcode.com/login",
        "https://app.ampcode.com/signin",
        "https://auth.ampcode.com/?client_id=test",
    ] {
        assert!(
            is_amp_login_redirect(&Url::parse(url).expect("login fixture URL")),
            "{url}"
        );
    }
    for url in [
        "https://ampcode.com/settings",
        "https://ampcode.com/auth/sign-out",
        "https://ampcode.com.evil.test/auth/sign-in",
        "https://example.test/login",
    ] {
        assert!(
            !is_amp_login_redirect(&Url::parse(url).expect("non-login fixture URL")),
            "{url}"
        );
    }

    let routes = AmpWebRouteSet::production().expect("production web routes");
    for url in [
        "https://ampcode.com/settings",
        "https://www.ampcode.com/settings",
        "https://app.ampcode.com/path",
    ] {
        assert!(
            routes.allows_cookie_target(&Url::parse(url).expect("cookie route URL")),
            "{url}"
        );
    }
    for url in [
        "http://ampcode.com/settings",
        "https://ampcode.com.evil.test/settings",
        "https://auth.ampcode.com/",
        "https://app.ampcode.com/signin",
    ] {
        assert!(
            !routes.allows_cookie_target(&Url::parse(url).expect("rejected cookie route URL")),
            "{url}"
        );
    }
}

#[tokio::test]
async fn manual_web_capture_filters_to_session_and_sends_pinned_browser_headers() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        SETTINGS_HTML.as_bytes().to_vec(),
    )])
    .await;
    let provider = manual_provider(
        &server,
        "manual-web",
        &format!("unrelated=private; session={SESSION_CANARY_A}; other=private"),
    );
    let sample = provider
        .fetch_at(
            &context("manual-web", ProviderSource::ManualCookie),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect("manual web usage");
    assert_percent(sample.primary().expect("free usage"), 33.85);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/settings");
    assert_eq!(
        requests[0].header("cookie"),
        Some(format!("session={SESSION_CANARY_A}").as_str())
    );
    assert_eq!(
        requests[0].header("accept"),
        Some("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    );
    assert_eq!(requests[0].header("origin"), Some("https://ampcode.com"));
    assert_eq!(
        requests[0].header("referer"),
        Some("https://ampcode.com/settings")
    );
    assert!(requests[0].header("user-agent").is_some());
    for bad_context in [
        context("different-account", ProviderSource::ManualCookie),
        context("manual-web", ProviderSource::BrowserSession),
    ] {
        assert_eq!(
            provider
                .fetch_at(&bad_context, timestamp("2026-08-18T12:00:00Z"))
                .await
                .expect_err("source-bound manual provider")
                .kind(),
            ErrorKind::Api
        );
    }
    assert_eq!(
        server.requests().len(),
        1,
        "scope/source mismatches must fail before IO"
    );
    let provider_debug = format!("{provider:?}");
    assert!(!provider_debug.contains("manual-web"));
    assert!(!provider_debug.contains(SESSION_CANARY_A));

    for host in ["ampcode.com", "app.ampcode.com"] {
        AmpProvider::from_manual_capture_routes(
            scope("curl-capture"),
            &format!(
                "curl 'https://{host}/settings?view=usage' -H 'Cookie: session={SESSION_CANARY_A}'"
            ),
            web_routes(&server),
        )
        .expect("exact-host cURL capture");
    }
    for raw in [
        "other=value",
        "session=",
        "curl 'https://ampcode.com.evil.test/settings' -H 'Cookie: session=secret'",
        "Authorization: Bearer secret",
    ] {
        let error =
            AmpProvider::from_manual_capture_routes(scope("bad-capture"), raw, web_routes(&server))
                .expect_err("invalid manual capture");
        assert!(matches!(
            error.kind(),
            ErrorKind::MissingCredential | ErrorKind::Parse
        ));
        assert!(!format!("{error:?}").contains("secret"));
    }
}

#[tokio::test]
async fn web_redirects_follow_only_approved_same_origin_targets() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/settings/usage"),
        FakeHttpResponse::new(200, SETTINGS_HTML.as_bytes().to_vec()),
    ])
    .await;
    manual_provider(
        &server,
        "safe-redirect",
        &format!("session={SESSION_CANARY_A}"),
    )
    .fetch_at(
        &context("safe-redirect", ProviderSource::ManualCookie),
        timestamp("2026-08-18T12:00:00Z"),
    )
    .await
    .expect("same-origin redirect");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target(), "/settings");
    assert_eq!(requests[1].target(), "/settings/usage");
    assert_eq!(
        requests[1].header("cookie"),
        Some(format!("session={SESSION_CANARY_A}").as_str())
    );
    assert_eq!(
        requests[1].header("referer"),
        Some(server.url("/settings").as_str())
    );
}

#[tokio::test]
async fn web_redirect_count_is_bounded_without_dropping_cookie_policy() {
    let responses =
        (0..6).map(|_| FakeHttpResponse::new(302, Vec::new()).header("Location", "/settings"));
    let server = FakeHttpServer::start(responses).await;
    let error = manual_provider(
        &server,
        "redirect-bound",
        &format!("session={SESSION_CANARY_A}"),
    )
    .fetch_at(
        &context("redirect-bound", ProviderSource::ManualCookie),
        timestamp("2026-08-18T12:00:00Z"),
    )
    .await
    .expect_err("redirect limit");
    assert_eq!(error.kind(), ErrorKind::Parse);
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert!(requests.iter().all(|request| {
        request.header("cookie") == Some(format!("session={SESSION_CANARY_A}").as_str())
    }));
}

#[tokio::test]
async fn web_redirects_stop_before_login_downgrade_or_foreign_targets() {
    let login = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new())
            .header("Location", "/auth/sign-in?returnTo=%2Fsettings"),
        FakeHttpResponse::new(200, SETTINGS_HTML.as_bytes().to_vec()),
    ])
    .await;
    let error = manual_provider(
        &login,
        "login-redirect",
        &format!("session={SESSION_CANARY_A}"),
    )
    .fetch_at(
        &context("login-redirect", ProviderSource::ManualCookie),
        timestamp("2026-08-18T12:00:00Z"),
    )
    .await
    .expect_err("login redirect");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert_eq!(
        login.requests().len(),
        1,
        "the login target must not receive a cookie"
    );

    for (index, (location, expected)) in [
        ("http://ampcode.com/settings", ErrorKind::Parse),
        (
            "http://ampcode.com/auth/sign-in?returnTo=%2Fsettings",
            ErrorKind::AuthenticationExpired,
        ),
        ("https://ampcode.com.evil.test/settings", ErrorKind::Parse),
    ]
    .into_iter()
    .enumerate()
    {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(302, Vec::new()).header("Location", location),
            FakeHttpResponse::new(200, SETTINGS_HTML.as_bytes().to_vec()),
        ])
        .await;
        let account = format!("rejected-redirect-{index}");
        let error = manual_provider(&server, &account, &format!("session={SESSION_CANARY_A}"))
            .fetch_at(
                &context(&account, ProviderSource::ManualCookie),
                timestamp("2026-08-18T12:00:00Z"),
            )
            .await
            .expect_err("unsafe redirect rejected");
        assert_eq!(error.kind(), expected);
        assert_eq!(
            server.requests().len(),
            1,
            "redirect target must not receive a cookie"
        );
    }

    let foreign = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        SETTINGS_HTML.as_bytes().to_vec(),
    )])
    .await;
    let origin =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", foreign.url("/stolen").as_str())])
        .await;
    let error = manual_provider(
        &origin,
        "foreign-redirect",
        &format!("session={SESSION_CANARY_A}"),
    )
    .fetch_at(
        &context("foreign-redirect", ProviderSource::ManualCookie),
        timestamp("2026-08-18T12:00:00Z"),
    )
    .await
    .expect_err("foreign redirect rejected");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(foreign.requests().is_empty());
}

#[tokio::test]
async fn web_status_login_body_size_and_cancellation_are_bounded_and_redacted() {
    for (response, expected) in [
        (
            FakeHttpResponse::new(401, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(403, Vec::new()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(500, Vec::new()),
            ErrorKind::ProviderUnavailable,
        ),
        (
            FakeHttpResponse::new(200, SETTINGS_SIGNED_OUT.as_bytes().to_vec()),
            ErrorKind::AuthenticationExpired,
        ),
        (
            FakeHttpResponse::new(200, vec![b'x'; 512 * 1024 + 1]),
            ErrorKind::Parse,
        ),
    ] {
        let server = FakeHttpServer::start([response]).await;
        let provider =
            manual_provider(&server, "web-error", &format!("session={SESSION_CANARY_A}"));
        let error = provider
            .fetch_at(
                &context("web-error", ProviderSource::ManualCookie),
                timestamp("2026-08-18T12:00:00Z"),
            )
            .await
            .expect_err("bounded web error");
        assert_eq!(error.kind(), expected);
        let debug = format!("{error:?} {provider:?}");
        assert!(!debug.contains(SESSION_CANARY_A));
    }

    let no_fallback = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, SETTINGS_HTML.as_bytes().to_vec()),
    ])
    .await;
    let error = manual_provider(
        &no_fallback,
        "manual-no-fallback",
        &format!("session={SESSION_CANARY_A}"),
    )
    .fetch_at(
        &context("manual-no-fallback", ProviderSource::ManualCookie),
        timestamp("2026-08-18T12:00:00Z"),
    )
    .await
    .expect_err("manual source never rotates or falls back");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert_eq!(no_fallback.requests().len(), 1);

    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_provider(
        &server,
        "web-cancel",
        &format!("session={SESSION_CANARY_A}"),
    );
    let cancellation = CancellationToken::new();
    let cancelled_context = ProviderContext::new(
        scope("web-cancel"),
        ProviderSource::ManualCookie,
        cancellation.clone(),
    );
    let fetch = provider.fetch_at(&cancelled_context, timestamp("2026-08-18T12:00:00Z"));
    tokio::pin!(fetch);
    tokio::select! {
        () = server.wait_for_request_count(1) => cancellation.cancel(),
        result = &mut fetch => panic!("fetch completed before cancellation: {result:?}"),
    }
    assert_eq!(
        fetch.await.expect_err("cancelled web fetch").kind(),
        ErrorKind::Network
    );
}

#[tokio::test]
async fn ordered_chromium_and_firefox_sessions_rotate_without_profile_mixing() {
    let directory = TestDirectory::new("amp-browser-profiles");
    let home = directory.path().join("home");
    let config = directory.path().join("config");
    fs::create_dir_all(&home).expect("browser home");
    fs::create_dir_all(&config).expect("browser config");
    create_chromium_cookie_profile(
        &config,
        "Default",
        Some(SESSION_CANARY_A),
        ROOT_SESSION_CANARY,
    );
    create_chromium_cookie_profile(&config, "Profile 1", None, SESSION_CANARY_A);
    create_chromium_cookie_profile(
        &config,
        "Profile 2",
        Some(SESSION_CANARY_C),
        ROOT_SESSION_CANARY,
    );
    let firefox = create_firefox_cookie_profile(&home, SESSION_CANARY_B);
    let roots = BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("browser roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots);
    assert_eq!(discovery.discover().profiles().len(), 4);

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, SETTINGS_SIGNED_OUT.as_bytes().to_vec()),
        FakeHttpResponse::new(200, SETTINGS_HTML.as_bytes().to_vec()),
    ])
    .await;
    let provider = AmpProvider::from_browser_routes(
        scope("browser-rotation"),
        &discovery,
        &DisabledChromiumCookieDecryptor,
        now(),
        web_routes(&server),
    )
    .expect("browser Amp provider");
    drop(firefox);
    let sample = provider
        .fetch_at(
            &context("browser-rotation", ProviderSource::BrowserSession),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect("second profile succeeds");
    assert_percent(sample.primary().expect("free usage"), 33.85);
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].header("cookie"),
        Some(format!("session={SESSION_CANARY_A}").as_str())
    );
    assert_eq!(
        requests[1].header("cookie"),
        Some(format!("session={SESSION_CANARY_C}").as_str())
    );
    assert_eq!(
        requests[2].header("cookie"),
        Some(format!("session={SESSION_CANARY_B}").as_str())
    );
    assert!(requests.iter().all(|request| {
        !request.header("cookie").is_some_and(|cookie| {
            cookie.contains("unrelated") || cookie.contains(ROOT_SESSION_CANARY)
        })
    }));
    let debug = format!("{provider:?}");
    for canary in [
        SESSION_CANARY_A,
        SESSION_CANARY_B,
        SESSION_CANARY_C,
        ROOT_SESSION_CANARY,
    ] {
        assert!(!debug.contains(canary));
    }
}

#[tokio::test]
async fn chromium_root_store_is_a_fallback_only_when_network_has_no_session() {
    let directory = TestDirectory::new("amp-browser-root-fallback");
    let home = directory.path().join("home");
    let config = directory.path().join("config");
    fs::create_dir_all(&home).expect("browser home");
    fs::create_dir_all(&config).expect("browser config");
    create_chromium_cookie_profile(&config, "Default", None, SESSION_CANARY_B);
    let roots = BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("browser roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots);
    let server = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        SETTINGS_HTML.as_bytes().to_vec(),
    )])
    .await;
    let provider = AmpProvider::from_browser_routes(
        scope("browser-root-fallback"),
        &discovery,
        &DisabledChromiumCookieDecryptor,
        now(),
        web_routes(&server),
    )
    .expect("root fallback provider");
    provider
        .fetch_at(
            &context("browser-root-fallback", ProviderSource::BrowserSession),
            timestamp("2026-08-18T12:00:00Z"),
        )
        .await
        .expect("root fallback usage");
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header("cookie"),
        Some(format!("session={SESSION_CANARY_B}").as_str())
    );
}

#[tokio::test]
async fn browser_non_auth_failure_is_fail_fast_and_disabled_discovery_is_missing() {
    let directory = TestDirectory::new("amp-browser-fail-fast");
    let home = directory.path().join("home");
    let config = directory.path().join("config");
    fs::create_dir_all(&home).expect("browser home");
    fs::create_dir_all(&config).expect("browser config");
    create_chromium_cookie_profile(&config, "Default", Some(SESSION_CANARY_A), "root-a");
    create_chromium_cookie_profile(&config, "Profile 2", Some(SESSION_CANARY_C), "root-c");
    let roots = BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("browser roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, SETTINGS_HTML.as_bytes().to_vec()),
    ])
    .await;
    let error = AmpProvider::from_browser_routes(
        scope("browser-fail-fast"),
        &discovery,
        &DisabledChromiumCookieDecryptor,
        now(),
        web_routes(&server),
    )
    .expect("browser Amp provider")
    .fetch_at(
        &context("browser-fail-fast", ProviderSource::BrowserSession),
        timestamp("2026-08-18T12:00:00Z"),
    )
    .await
    .expect_err("non-auth failures do not rotate profiles");
    assert_eq!(error.kind(), ErrorKind::ProviderUnavailable);
    assert_eq!(server.requests().len(), 1);

    assert_eq!(
        AmpProvider::new_browser(
            scope("browser-disabled"),
            &BrowserProfileDiscovery::disabled(),
            &DisabledChromiumCookieDecryptor,
            now(),
        )
        .expect_err("disabled browser discovery")
        .kind(),
        ErrorKind::MissingCredential
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
async fn cli_forwards_valid_customization_and_api_key_but_omits_unrelated_secrets() {
    let directory = TestDirectory::new("amp-custom-environment");
    let executable = directory.path().join("amp");
    let amp_home = directory.path().join("relocated-home");
    let settings_file = directory.path().join("relocated-settings.json");
    write_executable(
        &executable,
        &format!(
            "#!/bin/sh\n[ \"${{AMP_URL:-}}\" = 'https://amp.example.test/base' ] || exit 21\n[ \"${{AMP_HOME:-}}\" = '{}' ] || exit 22\n[ \"${{AMP_SETTINGS_FILE:-}}\" = '{}' ] || exit 23\n[ \"${{AMP_API_KEY:-}}\" = '{}' ] || exit 24\n[ -z \"${{AMP_STORAGE_BASE+x}}\" ] || exit 25\n[ \"${{NODE_EXTRA_CA_CERTS:-}}\" = '/tmp/fixture-corporate-ca.pem' ] || exit 26\nprintf '%s' '{}'\n",
            shell_quote(amp_home.to_string_lossy().as_ref()),
            shell_quote(settings_file.to_string_lossy().as_ref()),
            shell_quote(TOKEN_CANARY),
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
            "NODE_EXTRA_CA_CERTS".to_owned(),
            "/tmp/fixture-corporate-ca.pem".to_owned(),
        ),
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
            "#!/bin/sh\n[ -z \"${{AMP_URL+x}}\" ] || exit 31\n[ -z \"${{AMP_HOME+x}}\" ] || exit 32\n[ -z \"${{AMP_SETTINGS_FILE+x}}\" ] || exit 33\n[ -z \"${{AMP_API_KEY+x}}\" ] || exit 34\nprintf '%s' '{}'\n",
            shell_quote(CURRENT)
        ),
    );
    let blank_environment = BTreeMap::from([
        ("AMP_URL".to_owned(), "   ".to_owned()),
        ("AMP_HOME".to_owned(), " '' ".to_owned()),
        ("AMP_SETTINGS_FILE".to_owned(), " \"\" ".to_owned()),
        ("AMP_API_KEY".to_owned(), " '' ".to_owned()),
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

    for token in ["line\nbreak".to_owned(), "x".repeat(16 * 1024 + 1)] {
        let environment = BTreeMap::from([("AMP_API_KEY".to_owned(), token)]);
        assert_eq!(
            AmpCliSettings::new(executable.clone(), &environment)
                .expect_err("unsafe Amp API token")
                .kind(),
            ErrorKind::MissingCredential
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

    for name in ["OMARCHY_AI_BAR_AMP_PATH", "AMP_CLI_PATH"] {
        let relative = BTreeMap::from([(name.to_owned(), "relative/amp".to_owned())]);
        assert_eq!(
            AmpCliSettings::resolve(&relative)
                .expect_err("relative override")
                .kind(),
            ErrorKind::Api,
            "{name} must use the executable boundary"
        );
    }

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

    let pinned = directory.path().join("amp-pinned");
    let app = directory.path().join("amp-app");
    write_executable(&pinned, "#!/bin/sh\nexit 0\n");
    write_executable(&app, "#!/bin/sh\nexit 0\n");
    let pinned_only = AmpCliSettings::resolve(&BTreeMap::from([(
        "AMP_CLI_PATH".to_owned(),
        pinned.to_string_lossy().into_owned(),
    )]))
    .expect("pinned override");
    assert_eq!(pinned_only.executable(), pinned);

    let both = BTreeMap::from([
        (
            "AMP_CLI_PATH".to_owned(),
            pinned.to_string_lossy().into_owned(),
        ),
        (
            "OMARCHY_AI_BAR_AMP_PATH".to_owned(),
            app.to_string_lossy().into_owned(),
        ),
    ]);
    assert_eq!(
        AmpCliSettings::resolve(&both)
            .expect("app override precedence")
            .executable(),
        app
    );

    let blank_app = BTreeMap::from([
        (
            "AMP_CLI_PATH".to_owned(),
            pinned.to_string_lossy().into_owned(),
        ),
        ("OMARCHY_AI_BAR_AMP_PATH".to_owned(), "  ''  ".to_owned()),
    ]);
    assert_eq!(
        AmpCliSettings::resolve(&blank_app)
            .expect("blank app override falls back to pinned override")
            .executable(),
        pinned
    );
}

fn create_chromium_cookie_profile(
    config: &Path,
    profile_name: &str,
    network_session: Option<&str>,
    root_session: &str,
) {
    let profile = config.join("chromium").join(profile_name);
    let network = profile.join("Network");
    fs::create_dir_all(&network).expect("Chromium Network profile");
    let root = Connection::open(profile.join("Cookies")).expect("Chromium root cookie database");
    create_chromium_cookie_schema(&root);
    root.execute(
        "INSERT INTO cookies VALUES ('.ampcode.com','session','/settings',13500000000000000,1,?,X'')",
        [root_session],
    )
    .expect("Chromium Amp session");
    root.execute(
        "INSERT INTO cookies VALUES ('ampcode.com.evil.test','session','/',0,1,'evil',X'')",
        [],
    )
    .expect("Chromium foreign decoy");

    let network =
        Connection::open(network.join("Cookies")).expect("Chromium Network cookie database");
    create_chromium_cookie_schema(&network);
    network
        .execute(
            "INSERT INTO cookies VALUES ('.ampcode.com','unrelated','/',0,1,'private',X'')",
            [],
        )
        .expect("Chromium Network unrelated cookie");
    if let Some(session) = network_session {
        network
            .execute(
                "INSERT INTO cookies VALUES ('.ampcode.com','session','/',0,1,?,X'')",
                [session],
            )
            .expect("Chromium Network Amp session");
    }
}

fn create_chromium_cookie_schema(connection: &Connection) {
    connection
        .execute_batch(
            "CREATE TABLE cookies (
               host_key TEXT NOT NULL,
               name TEXT NOT NULL,
               path TEXT NOT NULL,
               expires_utc INTEGER NOT NULL,
               is_secure INTEGER NOT NULL,
               value TEXT NOT NULL,
               encrypted_value BLOB NOT NULL DEFAULT X''
             );
             CREATE TABLE meta (key TEXT NOT NULL, value);
             INSERT INTO meta (key, value) VALUES ('version', 23);",
        )
        .expect("Chromium cookie schema");
}

fn create_firefox_cookie_profile(home: &Path, session: &str) -> Connection {
    let root = home.join(".mozilla/firefox");
    let profile = root.join("fixture.default");
    fs::create_dir_all(&profile).expect("Firefox profile");
    fs::write(
        root.join("profiles.ini"),
        "[Profile0]\nName=fixture\nIsRelative=1\nPath=fixture.default\nDefault=1\n",
    )
    .expect("Firefox profiles.ini");
    let connection = Connection::open(profile.join("cookies.sqlite")).expect("Firefox cookies");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             CREATE TABLE moz_cookies (
               host TEXT NOT NULL,
               name TEXT NOT NULL,
               path TEXT NOT NULL,
               expiry INTEGER NOT NULL,
               isSecure INTEGER NOT NULL,
               value TEXT NOT NULL
             );",
        )
        .expect("Firefox WAL schema");
    connection
        .execute(
            "INSERT INTO moz_cookies VALUES ('.ampcode.com','session','/',2000000000,1,?)",
            params![session],
        )
        .expect("Firefox Amp session");
    connection
        .execute(
            "INSERT INTO moz_cookies VALUES ('www.ampcode.com','unrelated','/',2000000000,1,'private')",
            [],
        )
        .expect("Firefox unrelated cookie");
    connection
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
