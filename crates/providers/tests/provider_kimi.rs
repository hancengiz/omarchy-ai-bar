use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, RateWindow, Timestamp,
    UsageSample,
};
use oab_providers::browser_cookie::DisabledChromiumCookieDecryptor;
use oab_providers::browser_profile::{
    BrowserProfileDiscovery, BrowserProfileRoots, FlatpakProfileDiscovery,
};
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::kimi::{
    KimiCliCredential, KimiCliIdentity, KimiDesktopCookieStore, KimiProvider, KimiRouteSet,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use rusqlite::{Connection, params};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const CODE_USAGE: &[u8] = include_bytes!("../../../fixtures/providers/kimi/code-usage.json");
const WEB_USAGE: &[u8] = include_bytes!("../../../fixtures/providers/kimi/web-usage.json");
const SUBSCRIPTION: &[u8] = include_bytes!("../../../fixtures/providers/kimi/subscription.json");
const NOW_SECONDS: i64 = 1_777_590_000;
const JWT: &str = concat!(
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
    "eyJkZXZpY2VfaWQiOiJkZXZpY2UtY2FuYXJ5Iiwic3NpZCI6InNlc3Npb24tY2FuYXJ5Iiwic3ViIjoidHJhZmZpYy1jYW5hcnkifQ.",
    "signature-canary"
);
const JWT_TWO: &str = concat!(
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
    "eyJkZXZpY2VfaWQiOiJkZXZpY2UtdHdvIiwic3NpZCI6InNlc3Npb24tdHdvIiwic3ViIjoidHJhZmZpYy10d28ifQ.",
    "signature-two"
);
const OPAQUE_TOKEN: &str = "opaque_token-1.2+/=";

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Kimi,
        ProviderInstanceId::new("kimi-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn timestamp() -> Timestamp {
    Timestamp::from_unix_timestamp(NOW_SECONDS).expect("fixture timestamp")
}

fn parsed_timestamp(raw: &str) -> Timestamp {
    Timestamp::parse(raw).expect("fixture timestamp")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn routes(code: &FakeHttpServer, web: &FakeHttpServer) -> KimiRouteSet {
    KimiRouteSet::loopback(&code.url("/"), &web.url("/")).expect("loopback Kimi routes")
}

fn code_provider(
    code: &FakeHttpServer,
    web: &FakeHttpServer,
    source: ProviderSource,
) -> KimiProvider {
    KimiProvider::from_code_token_routes(
        scope("account-a"),
        "api-key-canary",
        source,
        None,
        routes(code, web),
    )
    .expect("Code provider")
}

fn manual_provider(code: &FakeHttpServer, web: &FakeHttpServer, capture: &str) -> KimiProvider {
    KimiProvider::from_manual_routes(
        scope("account-a"),
        capture,
        ProviderSource::ManualCookie,
        routes(code, web),
    )
    .expect("manual provider")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-8, "{actual} != {expected}");
}

#[tokio::test]
async fn code_api_golden_maps_windows_headers_and_optional_membership() {
    let code = FakeHttpServer::start([FakeHttpResponse::new(200, CODE_USAGE.to_vec())]).await;
    let web = FakeHttpServer::start([FakeHttpResponse::new(200, SUBSCRIPTION.to_vec())]).await;
    let provider = code_provider(&code, &web, ProviderSource::ApiKey)
        .with_web_enrichment(JWT)
        .expect("web enrichment");
    let debug = format!("{provider:?}");
    assert!(!debug.contains("api-key-canary"));
    assert!(!debug.contains("signature-canary"));

    let sample = provider
        .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
        .await
        .expect("Kimi API sample");

    assert_code_api_windows(&sample);
    assert_code_api_requests(&code, &web);
}

fn assert_code_api_windows(sample: &UsageSample) {
    let primary = sample.primary().expect("weekly");
    let secondary = sample.secondary().expect("rate");

    assert_percent(
        primary.used_percent().expect("weekly percent").get(),
        375.0 / 2048.0 * 100.0,
    );
    assert_eq!(primary.duration().expect("7d").seconds(), 7 * 24 * 60 * 60);
    assert_eq!(
        primary.resets_at(),
        Some(parsed_timestamp("2026-09-05T12:00:00Z"))
    );
    assert_percent(secondary.used_percent().expect("rate percent").get(), 9.5);
    assert_eq!(secondary.duration().expect("5h").seconds(), 5 * 60 * 60);
    assert_eq!(
        secondary.resets_at(),
        Some(parsed_timestamp("2026-08-30T17:00:00Z"))
    );
    assert_eq!(
        secondary.reset_description().expect("description").as_str(),
        "Rate: 19/200 per 5 hours"
    );
    let monthly = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == "kimi-monthly")
        .expect("monthly");
    assert_percent(
        monthly
            .window()
            .used_percent()
            .expect("monthly percent")
            .get(),
        42.0,
    );
    assert_eq!(
        monthly
            .window()
            .duration()
            .expect("monthly duration")
            .seconds(),
        30 * 24 * 60 * 60
    );
    assert_eq!(
        monthly.window().resets_at(),
        Some(parsed_timestamp("2026-09-30T00:00:00Z"))
    );
    let code_weekly = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == "kimi-code-7d")
        .expect("distinct weekly");
    assert_percent(
        code_weekly
            .window()
            .used_percent()
            .expect("weekly percent")
            .get(),
        17.0,
    );
    assert_eq!(
        code_weekly.window().resets_at(),
        Some(parsed_timestamp("2026-09-05T15:00:00.876796734Z"))
    );
    assert_eq!(sample.provenance()[0].strategy(), "api_key");
}

fn assert_code_api_requests(code: &FakeHttpServer, web: &FakeHttpServer) {
    let code_requests = code.requests();
    assert_eq!(code_requests.len(), 1);
    assert_eq!(code_requests[0].method(), "GET");
    assert_eq!(code_requests[0].target(), "/coding/v1/usages");
    assert_eq!(
        code_requests[0].header("authorization"),
        Some("Bearer api-key-canary")
    );
    assert_eq!(code_requests[0].header("cookie"), None);

    let web_requests = web.requests();
    assert_eq!(web_requests.len(), 1);
    assert!(web_requests[0].target().ends_with("/GetSubscriptionStats"));
    assert_eq!(web_requests[0].body(), b"{}");
    assert_eq!(
        web_requests[0].header("authorization"),
        Some(format!("Bearer {JWT}").as_str())
    );
    assert_eq!(
        web_requests[0].header("cookie"),
        Some(format!("kimi-auth={JWT}").as_str())
    );
    assert_eq!(
        web_requests[0].header("x-msh-device-id"),
        Some("device-canary")
    );
    assert_eq!(
        web_requests[0].header("x-msh-session-id"),
        Some("session-canary")
    );
    assert_eq!(
        web_requests[0].header("x-traffic-id"),
        Some("traffic-canary")
    );
}

#[tokio::test]
async fn web_golden_uses_dual_auth_and_numeric_reset_variants() {
    let code = FakeHttpServer::start([]).await;
    let web = FakeHttpServer::start([
        FakeHttpResponse::new(200, WEB_USAGE.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
    ])
    .await;
    let sample = manual_provider(&code, &web, JWT)
        .with_web_timezone("Europe/Istanbul")
        .expect("fixture timezone")
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("web sample");

    assert_percent(
        sample
            .primary()
            .and_then(RateWindow::used_percent)
            .expect("weekly percent")
            .get(),
        375.0 / 2048.0 * 100.0,
    );
    assert_percent(
        sample
            .secondary()
            .and_then(RateWindow::used_percent)
            .expect("rate percent")
            .get(),
        9.5,
    );
    assert_eq!(
        sample.primary().and_then(RateWindow::resets_at),
        Some(parsed_timestamp("2026-09-05T12:00:00Z"))
    );
    assert_eq!(
        sample.secondary().and_then(RateWindow::resets_at),
        Some(parsed_timestamp("2026-08-30T17:00:00Z"))
    );
    let requests = web.requests();
    assert_eq!(requests.len(), 2);
    let usage = requests
        .iter()
        .find(|request| request.target().ends_with("/GetUsages"))
        .expect("usage request");
    assert_eq!(usage.body(), br#"{"scope":["FEATURE_CODING"]}"#);
    assert_eq!(
        usage.header("authorization"),
        Some(format!("Bearer {JWT}").as_str())
    );
    assert_eq!(
        usage.header("cookie"),
        Some(format!("kimi-auth={JWT}").as_str())
    );
    assert_eq!(usage.header("origin"), Some("https://www.kimi.com"));
    assert_eq!(
        usage.header("referer"),
        Some("https://www.kimi.com/code/console")
    );
    assert_eq!(usage.header("connect-protocol-version"), Some("1"));
    assert_eq!(usage.header("x-msh-platform"), Some("web"));
    assert_eq!(usage.header("r-timezone"), Some("Europe/Istanbul"));

    assert_eq!(
        manual_provider(&code, &web, JWT)
            .with_web_timezone("../private")
            .expect_err("unsafe timezone")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn cli_identity_headers_share_the_existing_code_request() {
    let code = FakeHttpServer::start([FakeHttpResponse::new(200, CODE_USAGE.to_vec())]).await;
    let web = FakeHttpServer::start([]).await;
    let identity =
        KimiCliIdentity::for_test("host-canary", "device-id-canary").expect("fixture identity");
    let provider = KimiProvider::from_code_token_routes(
        scope("account-a"),
        "oauth-canary",
        ProviderSource::Cli,
        Some(identity),
        routes(&code, &web),
    )
    .expect("CLI provider");

    provider
        .fetch_at(&context("account-a", ProviderSource::Cli), timestamp())
        .await
        .expect("CLI sample");
    let request = &code.requests()[0];
    assert_eq!(request.header("authorization"), Some("Bearer oauth-canary"));
    assert_eq!(request.header("x-msh-platform"), Some("kimi_code_cli"));
    assert_eq!(request.header("x-msh-device-name"), Some("host-canary"));
    assert_eq!(request.header("x-msh-device-id"), Some("device-id-canary"));
    assert_eq!(request.header("user-agent"), Some("omarchy-ai-bar/test"));
}

#[test]
fn api_environment_and_endpoint_normalization_are_fail_closed() {
    let mut environment = BTreeMap::from([("KIMI_API_KEY".to_owned(), "wrong".to_owned())]);
    assert_eq!(
        KimiProvider::new_api(scope("account-a"), &environment)
            .expect_err("generic key is unrelated")
            .kind(),
        ErrorKind::MissingCredential
    );
    environment.insert("KIMI_CODE_API_KEY".to_owned(), "right".to_owned());
    for invalid in [
        "http://proxy.example.com/kimi",
        "https://user:pass@proxy.example.com/kimi",
        "https://proxy.example.com/kimi?token=secret",
        "not a URL",
    ] {
        environment.insert("KIMI_CODE_BASE_URL".to_owned(), invalid.to_owned());
        assert_eq!(
            KimiProvider::new_api(scope("account-a"), &environment)
                .expect_err("invalid override")
                .kind(),
            ErrorKind::Api
        );
    }
    environment.insert(
        "KIMI_CODE_BASE_URL".to_owned(),
        "https://proxy.example.com/kimi/coding/v1/".to_owned(),
    );
    let provider =
        KimiProvider::new_api(scope("account-a"), &environment).expect("valid HTTPS override");
    let debug = format!("{provider:?}");
    assert!(!debug.contains("proxy.example.com"));
    assert!(!debug.contains("right"));
}

#[tokio::test]
async fn code_path_normalization_handles_root_coding_and_coding_v1() {
    for (base_path, expected) in [
        ("/", "/coding/v1/usages"),
        ("/proxy/coding", "/proxy/coding/v1/usages"),
        ("/proxy/coding/v1/", "/proxy/coding/v1/usages"),
    ] {
        let code = FakeHttpServer::start([FakeHttpResponse::new(200, CODE_USAGE.to_vec())]).await;
        let web = FakeHttpServer::start([]).await;
        let route =
            KimiRouteSet::loopback(&code.url(base_path), &web.url("/")).expect("normalized routes");
        let source = if base_path == "/" {
            ProviderSource::ApiKey
        } else {
            ProviderSource::ConfigurableEndpoint
        };
        let provider =
            KimiProvider::from_code_token_routes(scope("account-a"), "key", source, None, route)
                .expect("provider");
        let sample = provider
            .fetch_at(&context("account-a", source), timestamp())
            .await
            .expect("usage");
        assert_eq!(code.requests()[0].target(), expected);
        assert_eq!(
            sample.provenance()[0].strategy(),
            if source == ProviderSource::ConfigurableEndpoint {
                "configured"
            } else {
                "api_key"
            }
        );
    }
}

#[test]
fn fresh_cli_credentials_are_read_only_and_endpoint_bound() {
    let temporary = TempDir::new().expect("temporary home");
    let home = temporary.path().join("kimi-code");
    let credentials = home.join("credentials");
    fs::create_dir_all(&credentials).expect("credential directory");
    fs::write(home.join("device_id"), "existing-device\n").expect("device id");
    let credential_path = credentials.join("kimi-code.json");
    fs::write(
        &credential_path,
        format!(
            r#"{{"access_token":"oauth-canary","refresh_token":"never-use-canary","expires_at":{}}}"#,
            NOW_SECONDS + 3_600
        ),
    )
    .expect("credential");
    let before = fs::read(&credential_path).expect("before bytes");
    let environment = BTreeMap::from([
        ("KIMI_CODE_HOME".to_owned(), path_text(&home)),
        ("HOSTNAME".to_owned(), "fixture-host".to_owned()),
    ]);

    let credential =
        KimiCliCredential::resolve_at(&environment, timestamp()).expect("fresh credential");
    assert_eq!(credential.credential_path(), credential_path);
    assert_eq!(fs::read(&credential_path).expect("after bytes"), before);
    assert_eq!(
        fs::read_to_string(home.join("device_id")).expect("device id unchanged"),
        "existing-device\n"
    );
    assert!(!format!("{credential:?}").contains("oauth-canary"));
    assert!(!format!("{credential:?}").contains("never-use-canary"));

    for key in [
        "KIMI_CODE_BASE_URL",
        "KIMI_CODE_OAUTH_HOST",
        "KIMI_OAUTH_HOST",
    ] {
        let mut overridden = environment.clone();
        overridden.insert(key.to_owned(), "https://proxy.example.com".to_owned());
        assert_eq!(
            KimiCliCredential::resolve_at(&overridden, timestamp())
                .expect_err("CLI token cannot reach an override")
                .kind(),
            ErrorKind::Api
        );
    }
}

#[test]
fn cli_freshness_missing_expiry_and_path_safety_are_enforced() {
    for expiry in [
        Some((NOW_SECONDS + 60).to_string()),
        Some((NOW_SECONDS - 1).to_string()),
        Some("not-a-number".to_owned()),
        None,
    ] {
        let temporary = TempDir::new().expect("temporary home");
        let home = temporary.path().join("kimi-code");
        fs::create_dir_all(home.join("credentials")).expect("credential directory");
        let expiry =
            expiry.map_or_else(String::new, |value| format!(r#", "expires_at": "{value}""#));
        let document = format!(r#"{{"access_token":"oauth","refresh_token":"refresh"{expiry}}}"#);
        fs::write(home.join("credentials/kimi-code.json"), document).expect("credential");
        let environment = BTreeMap::from([("KIMI_CODE_HOME".to_owned(), path_text(&home))]);
        assert_eq!(
            KimiCliCredential::resolve_at(&environment, timestamp())
                .expect_err("stale credential")
                .kind(),
            ErrorKind::AuthenticationExpired
        );
    }

    let unsafe_environment = BTreeMap::from([(
        "KIMI_CODE_HOME".to_owned(),
        "/tmp/kimi/../escape".to_owned(),
    )]);
    assert_eq!(
        KimiCliCredential::resolve_at(&unsafe_environment, timestamp())
            .expect_err("parent traversal")
            .kind(),
        ErrorKind::Api
    );

    let missing_access = TempDir::new().expect("temporary home");
    let home = missing_access.path().join("kimi-code");
    fs::create_dir_all(home.join("credentials")).expect("credential directory");
    fs::write(
        home.join("credentials/kimi-code.json"),
        format!(
            r#"{{"refresh_token":"refresh","expires_at":{}}}"#,
            NOW_SECONDS + 3_600
        ),
    )
    .expect("credential");
    let environment = BTreeMap::from([("KIMI_CODE_HOME".to_owned(), path_text(&home))]);
    assert_eq!(
        KimiCliCredential::resolve_at(&environment, timestamp())
            .expect_err("missing access token is expired CLI state")
            .kind(),
        ErrorKind::AuthenticationExpired
    );

    fs::write(
        home.join("credentials/kimi-code.json"),
        format!(
            r#"{{"access_token":"oauth","refresh_token":"refresh","expires_at":{}}}"#,
            NOW_SECONDS + 3_600
        ),
    )
    .expect("fresh credential");
    fs::create_dir(home.join("device_id")).expect("unreadable-as-file device ID");
    KimiCliCredential::resolve_at(&environment, timestamp())
        .expect("device ID persistence/read errors are best effort");
}

#[test]
fn manual_jwt_cookie_authorization_and_curl_forms_are_supported() {
    let captures = [
        JWT.to_owned(),
        format!("kimi-auth={JWT}"),
        format!("Cookie: kimi-auth={JWT}; other=value"),
        format!("Authorization: Bearer {JWT}"),
        format!(
            "curl 'https://www.kimi.com/apiv2/kimi.gateway.billing.v1.BillingService/GetUsages?ignored=1' -H 'Cookie: kimi-auth={JWT}'"
        ),
    ];
    for capture in captures {
        let provider = KimiProvider::new_manual(scope("account-a"), &capture)
            .expect("supported manual capture");
        assert!(!format!("{provider:?}").contains("signature-canary"));
    }
    let invalid_captures = [
        String::new(),
        "not-a-jwt".to_owned(),
        format!("kimi-auth={JWT}; kimi-auth={JWT_TWO}"),
        format!("curl https://evil.example.com -H 'Cookie: kimi-auth={JWT}'"),
    ];
    for invalid in invalid_captures {
        assert!(KimiProvider::new_manual(scope("account-a"), &invalid).is_err());
    }
}

#[test]
fn opaque_tokens_are_accepted_only_from_explicit_cookie_or_header_forms() {
    for capture in [
        format!("kimi-auth={OPAQUE_TOKEN}"),
        format!("kimi-auth: {OPAQUE_TOKEN}"),
        format!("Cookie: kimi-auth={OPAQUE_TOKEN}"),
        format!("Authorization: Bearer {OPAQUE_TOKEN}"),
        format!(
            "curl 'https://www.kimi.com/apiv2/kimi.gateway.billing.v1.BillingService/GetUsages' -H 'Cookie: kimi-auth={OPAQUE_TOKEN}'"
        ),
    ] {
        KimiProvider::new_manual(scope("account-a"), &capture)
            .expect("explicit opaque cookie token");
    }
    assert!(KimiProvider::new_manual(scope("account-a"), OPAQUE_TOKEN).is_err());
    assert!(KimiProvider::new_manual(scope("account-a"), "kimi-auth=unsafe token").is_err());
}

#[tokio::test]
async fn manual_environment_precedence_and_invalid_primary_fallback_are_explicit() {
    let environment = BTreeMap::from([
        ("KIMI_MANUAL_COOKIE".to_owned(), format!("kimi-auth={JWT}")),
        ("KIMI_AUTH_TOKEN".to_owned(), JWT_TWO.to_owned()),
    ]);
    let code = FakeHttpServer::start([]).await;
    let web = FakeHttpServer::start([
        FakeHttpResponse::new(200, WEB_USAGE.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    let provider = KimiProvider::from_manual_environment_routes(
        scope("account-a"),
        &environment,
        routes(&code, &web),
    )
    .expect("manual environment");
    let debug = format!("{provider:?}");
    assert!(!debug.contains("signature-canary"));
    assert!(!debug.contains("signature-two"));
    provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(),
        )
        .await
        .expect("manual request");
    let requests = web.requests();
    let usage = requests
        .iter()
        .find(|request| request.target().ends_with("/GetUsages"))
        .expect("usage request");
    assert_eq!(
        usage.header("authorization"),
        Some(format!("Bearer {JWT}").as_str())
    );

    let fallback_environment = BTreeMap::from([
        (
            "KIMI_MANUAL_COOKIE".to_owned(),
            "invalid capture".to_owned(),
        ),
        (
            "KIMI_AUTH_TOKEN".to_owned(),
            format!("kimi-auth={OPAQUE_TOKEN}"),
        ),
    ]);
    let code = FakeHttpServer::start([]).await;
    let web = FakeHttpServer::start([
        FakeHttpResponse::new(200, WEB_USAGE.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    KimiProvider::from_manual_environment_routes(
        scope("account-a"),
        &fallback_environment,
        routes(&code, &web),
    )
    .expect("invalid manual capture falls through to resolved environment token")
    .fetch_at(
        &context("account-a", ProviderSource::ManualCookie),
        timestamp(),
    )
    .await
    .expect("fallback request");
    let requests = web.requests();
    let usage = requests
        .iter()
        .find(|request| request.target().ends_with("/GetUsages"))
        .expect("fallback usage request");
    assert_eq!(
        usage.header("authorization"),
        Some(format!("Bearer {OPAQUE_TOKEN}").as_str())
    );
}

#[tokio::test]
async fn malformed_counters_preserve_gauge_without_fabricating_pace() {
    let bodies = [
        (
            br#"{"usage":{"limit":"100","used":"invalid","remaining":"75"},"limits":[]}"#
                .as_slice(),
            25.0,
            true,
        ),
        (
            br#"{"usage":{"limit":"100","used":"125","remaining":"25"},"limits":[]}"#.as_slice(),
            100.0,
            true,
        ),
        (
            br#"{"usage":{"limit":"100","used":"-1","remaining":"75"},"limits":[]}"#.as_slice(),
            25.0,
            true,
        ),
        (
            br#"{"usage":{"limit":"100","remaining":"101"},"limits":[]}"#.as_slice(),
            0.0,
            false,
        ),
    ];
    for (body, expected, reliable) in bodies {
        let code = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
        let web = FakeHttpServer::start([]).await;
        let sample = code_provider(&code, &web, ProviderSource::ApiKey)
            .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
            .await
            .expect("counter semantics");
        let primary = sample.primary().expect("numeric limit keeps gauge");
        assert_percent(primary.used_percent().expect("known").get(), expected);
        assert_eq!(primary.duration().is_some(), reliable);
    }
}

#[tokio::test]
async fn duplicate_subscription_weekly_is_suppressed_only_with_reset_evidence() {
    let code_body = br#"{
      "usage":{"limit":"100","used":"29","remaining":"71","resetTime":"2026-09-05T12:00:00Z"},
      "limits":[]
    }"#;
    let matching = br#"{
      "ratelimitCode7d":{"ratio":0.2935,"enabled":true,"resetTime":"2026-09-05T12:01:00Z"}
    }"#;
    let code = FakeHttpServer::start([FakeHttpResponse::new(200, code_body.to_vec())]).await;
    let web = FakeHttpServer::start([FakeHttpResponse::new(200, matching.to_vec())]).await;
    let sample = code_provider(&code, &web, ProviderSource::ApiKey)
        .with_web_enrichment(JWT)
        .expect("enrichment")
        .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
        .await
        .expect("sample");
    assert!(sample.extra_windows().is_empty());

    let code_body = br#"{"usage":{"limit":"100","used":"29","remaining":"71"},"limits":[]}"#;
    let no_reset = br#"{"ratelimitCode7d":{"ratio":0.2935,"enabled":true}}"#;
    let code = FakeHttpServer::start([FakeHttpResponse::new(200, code_body.to_vec())]).await;
    let web = FakeHttpServer::start([FakeHttpResponse::new(200, no_reset.to_vec())]).await;
    let sample = code_provider(&code, &web, ProviderSource::ApiKey)
        .with_web_enrichment(JWT)
        .expect("enrichment")
        .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
        .await
        .expect("sample");
    assert_eq!(sample.extra_windows()[0].id().as_str(), "kimi-code-7d");

    let invalid_enabled = br#"{"ratelimitCode7d":{"ratio":0.5,"enabled":"false"}}"#;
    let code = FakeHttpServer::start([FakeHttpResponse::new(200, code_body.to_vec())]).await;
    let web = FakeHttpServer::start([FakeHttpResponse::new(200, invalid_enabled.to_vec())]).await;
    let sample = code_provider(&code, &web, ProviderSource::ApiKey)
        .with_web_enrichment(JWT)
        .expect("enrichment")
        .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
        .await
        .expect("malformed optional lane is omitted");
    assert!(sample.extra_windows().is_empty());
}

#[tokio::test]
async fn optional_enrichment_failure_and_total_budget_never_erase_code_usage() {
    let code = FakeHttpServer::start([
        FakeHttpResponse::new(200, CODE_USAGE.to_vec()),
        FakeHttpResponse::new(200, CODE_USAGE.to_vec()),
    ])
    .await;
    let web = FakeHttpServer::start([
        FakeHttpResponse::new(500, b"hidden".to_vec()),
        FakeHttpResponse::stall(),
    ])
    .await;
    let first = code_provider(&code, &web, ProviderSource::ApiKey)
        .with_web_enrichment(JWT)
        .expect("enrichment")
        .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
        .await
        .expect("best effort failure");
    assert!(first.primary().is_some());
    assert!(first.extra_windows().is_empty());

    let started = Instant::now();
    let second = code_provider(&code, &web, ProviderSource::ApiKey)
        .with_web_enrichment(JWT)
        .expect("enrichment")
        .with_subscription_grace(Duration::from_millis(30))
        .expect("test grace")
        .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
        .await
        .expect("bounded optional timeout");
    assert!(second.primary().is_some());
    assert!(second.extra_windows().is_empty());
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn status_classes_scope_and_cancellation_are_stable() {
    for (source, status, expected) in [
        (ProviderSource::ApiKey, 400, ErrorKind::Api),
        (
            ProviderSource::ApiKey,
            401,
            ErrorKind::AuthenticationExpired,
        ),
        (ProviderSource::ApiKey, 403, ErrorKind::PermissionDenied),
        (ProviderSource::ApiKey, 429, ErrorKind::RateLimited),
        (ProviderSource::ApiKey, 503, ErrorKind::ProviderUnavailable),
    ] {
        let code = FakeHttpServer::start([FakeHttpResponse::new(status, b"secret".to_vec())]).await;
        let web = FakeHttpServer::start([]).await;
        let error = code_provider(&code, &web, source)
            .fetch_at(&context("account-a", source), timestamp())
            .await
            .expect_err("status failure");
        assert_eq!(error.kind(), expected);
    }

    let code = FakeHttpServer::start([FakeHttpResponse::new(200, CODE_USAGE.to_vec())]).await;
    let web = FakeHttpServer::start([]).await;
    let provider = code_provider(&code, &web, ProviderSource::ApiKey);
    assert_eq!(
        provider
            .fetch_at(
                &context("other-account", ProviderSource::ApiKey),
                timestamp()
            )
            .await
            .expect_err("account isolation")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        provider
            .fetch_at(&context("account-a", ProviderSource::Cli), timestamp())
            .await
            .expect_err("source isolation")
            .kind(),
        ErrorKind::Api
    );

    let code = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let web = FakeHttpServer::start([]).await;
    let provider = code_provider(&code, &web, ProviderSource::ApiKey);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ProviderContext::new(scope("account-a"), ProviderSource::ApiKey, cancellation);
    assert_eq!(
        provider
            .fetch_at(&cancelled, timestamp())
            .await
            .expect_err("cancelled")
            .kind(),
        ErrorKind::Network
    );
}

#[tokio::test]
async fn web_401_and_403_are_both_expired_session_errors() {
    for status in [401, 403] {
        let code = FakeHttpServer::start([]).await;
        let web = FakeHttpServer::start([
            FakeHttpResponse::new(status, b"hidden".to_vec()),
            FakeHttpResponse::new(500, Vec::new()),
        ])
        .await;
        let error = manual_provider(&code, &web, JWT)
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(),
            )
            .await
            .expect_err("expired web token");
        assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    }
}

#[tokio::test]
async fn redirects_oversize_and_malformed_json_fail_without_leaking() {
    let foreign = FakeHttpServer::start([FakeHttpResponse::new(200, CODE_USAGE.to_vec())]).await;
    let code =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", foreign.url("/stolen").as_str())])
        .await;
    let web = FakeHttpServer::start([]).await;
    let error = code_provider(&code, &web, ProviderSource::ApiKey)
        .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
        .await
        .expect_err("redirect rejected");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(foreign.requests().is_empty());

    let valid_code_with_noise = |noise: &str| {
        format!(
            r#"{{"usage":{{"limit":"100","used":"1","remaining":"99"}},"limits":[],"noise":{noise}}}"#
        )
        .into_bytes()
    };
    let over_depth = valid_code_with_noise(&format!("{}0{}", "[".repeat(41), "]".repeat(41)));
    let over_nodes = valid_code_with_noise(&format!("[{}0]", "0,".repeat(32_768)));
    let oversized_string = valid_code_with_noise(&format!(r#""{}""#, "x".repeat(512 * 1024 + 1)));
    for body in [
        b"{not-json".to_vec(),
        over_depth,
        over_nodes,
        oversized_string,
        vec![b'x'; 2 * 1024 * 1024 + 1],
    ] {
        let code = FakeHttpServer::start([FakeHttpResponse::new(200, body)]).await;
        let web = FakeHttpServer::start([]).await;
        assert_eq!(
            code_provider(&code, &web, ProviderSource::ApiKey)
                .fetch_at(&context("account-a", ProviderSource::ApiKey), timestamp())
                .await
                .expect_err("bounded parse failure")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn ordered_merged_chromium_and_firefox_sessions_retry_without_profile_mixing() {
    let temporary = TempDir::new().expect("profile fixture");
    let home = temporary.path().join("home");
    let config = temporary.path().join("config");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&config).expect("config");
    create_chromium_profile(&config, OPAQUE_TOKEN);
    create_chromium_network_decoy(&config);
    create_firefox_profile(&home, JWT_TWO);
    let roots = BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("browser roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots);
    assert_eq!(discovery.discover().profiles().len(), 2);

    let code = FakeHttpServer::start([]).await;
    let web = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(500, Vec::new()),
        FakeHttpResponse::new(200, WEB_USAGE.to_vec()),
        FakeHttpResponse::new(500, Vec::new()),
    ])
    .await;
    let provider = KimiProvider::from_browser_routes(
        scope("account-a"),
        &discovery,
        &DisabledChromiumCookieDecryptor,
        now(),
        routes(&code, &web),
    )
    .expect("browser provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(),
        )
        .await
        .expect("second profile succeeds");
    assert!(sample.primary().is_some());
    let usage_requests = web
        .requests()
        .into_iter()
        .filter(|request| request.target().ends_with("/GetUsages"))
        .collect::<Vec<_>>();
    assert_eq!(usage_requests.len(), 2);
    assert_eq!(
        usage_requests[0].header("authorization"),
        Some(format!("Bearer {OPAQUE_TOKEN}").as_str())
    );
    assert_eq!(
        usage_requests[1].header("authorization"),
        Some(format!("Bearer {JWT_TWO}").as_str())
    );
}

#[test]
fn disabled_browser_discovery_and_missing_encryption_are_missing_credentials() {
    assert_eq!(
        KimiProvider::new_browser(
            scope("account-a"),
            &BrowserProfileDiscovery::disabled(),
            &DisabledChromiumCookieDecryptor,
            now(),
        )
        .expect_err("disabled discovery")
        .kind(),
        ErrorKind::MissingCredential
    );

    let environment = BTreeMap::new();
    let discovery = BrowserProfileDiscovery::enabled_from_environment(
        &environment,
        FlatpakProfileDiscovery::Disabled,
    );
    assert!(discovery.is_err());
}

#[test]
fn desktop_cookie_reader_selects_newest_host_and_never_mutates_files() {
    let temporary = TempDir::new().expect("desktop fixture");
    let root = temporary.path().join("desktop");
    fs::create_dir_all(&root).expect("desktop root");
    let database = root.join("Cookies");
    create_desktop_database(&database);
    let connection = Connection::open(&database).expect("desktop connection");
    insert_desktop_cookie(&connection, "www.kimi.com", JWT, 1);
    insert_desktop_cookie(&connection, ".kimi.com", JWT_TWO, 2);
    insert_desktop_cookie(&connection, "example.com", JWT, 3);
    drop(connection);
    let before = fs::metadata(&database).expect("metadata").len();

    let token = KimiDesktopCookieStore::load(&root, &DisabledChromiumCookieDecryptor)
        .expect("desktop read")
        .expect("desktop token");
    assert_eq!(token.as_str(), JWT_TWO);
    assert_eq!(fs::metadata(&database).expect("metadata").len(), before);
    assert!(!root.join("Cookies-wal").exists());
    assert!(!root.join("Cookies-shm").exists());
}

#[test]
fn desktop_cookie_reader_accepts_baseline_opaque_tokens() {
    let temporary = TempDir::new().expect("desktop fixture");
    let root = temporary.path().join("desktop");
    fs::create_dir_all(&root).expect("desktop root");
    let database = root.join("Cookies");
    create_desktop_database(&database);
    let connection = Connection::open(&database).expect("desktop connection");
    insert_desktop_cookie(&connection, "www.kimi.com", OPAQUE_TOKEN, 1);
    drop(connection);

    let token = KimiDesktopCookieStore::load(&root, &DisabledChromiumCookieDecryptor)
        .expect("desktop read")
        .expect("opaque desktop token");
    assert_eq!(token.as_str(), OPAQUE_TOKEN);
}

#[test]
fn desktop_cookie_reader_sees_active_wal_and_reports_encrypted_limitation_safely() {
    let temporary = TempDir::new().expect("desktop fixture");
    let root = temporary.path().join("desktop");
    fs::create_dir_all(&root).expect("desktop root");
    let database = root.join("Cookies");
    create_desktop_database(&database);
    let connection = Connection::open(&database).expect("desktop connection");
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .expect("WAL mode");
    insert_desktop_cookie(&connection, "www.kimi.com", JWT, 4);
    assert!(root.join("Cookies-wal").exists());
    let token = KimiDesktopCookieStore::load(&root, &DisabledChromiumCookieDecryptor)
        .expect("WAL read")
        .expect("WAL token");
    assert_eq!(token.as_str(), JWT);
    assert!(root.join("Cookies-wal").exists());
    drop(connection);

    let encrypted_root = temporary.path().join("encrypted");
    fs::create_dir_all(&encrypted_root).expect("encrypted root");
    let encrypted_database = encrypted_root.join("Cookies");
    create_desktop_database(&encrypted_database);
    let encrypted = Connection::open(&encrypted_database).expect("encrypted connection");
    encrypted
        .execute(
            "INSERT INTO cookies (host_key,name,value,encrypted_value,last_access_utc) \
             VALUES ('www.kimi.com','kimi-auth','',X'7631300011',1)",
            [],
        )
        .expect("encrypted row");
    drop(encrypted);
    assert!(
        KimiDesktopCookieStore::load(&encrypted_root, &DisabledChromiumCookieDecryptor)
            .expect("unavailable encrypted value is skipped")
            .is_none()
    );
}

#[test]
fn desktop_root_requires_an_explicit_safe_linux_path() {
    assert_eq!(
        KimiDesktopCookieStore::root_from_environment(&BTreeMap::new())
            .expect_err("no implicit Linux path")
            .kind(),
        ErrorKind::MissingCredential
    );
    let environment = BTreeMap::from([(
        "KIMI_DESKTOP_COOKIE_ROOT".to_owned(),
        "/tmp/kimi/../escape".to_owned(),
    )]);
    assert_eq!(
        KimiDesktopCookieStore::root_from_environment(&environment)
            .expect_err("unsafe path")
            .kind(),
        ErrorKind::Api
    );

    let temporary = TempDir::new().expect("desktop fixture");
    assert!(
        KimiDesktopCookieStore::load(temporary.path(), &DisabledChromiumCookieDecryptor)
            .expect("missing Desktop database is not malformed")
            .is_none()
    );
}

fn create_chromium_profile(config: &Path, token: &str) {
    let profile = config.join("chromium/Default");
    fs::create_dir_all(&profile).expect("Chromium profile");
    let connection = Connection::open(profile.join("Cookies")).expect("Chromium cookies");
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
        .expect("Chromium schema");
    connection
        .execute(
            "INSERT INTO cookies VALUES ('www.kimi.com','kimi-auth','/',0,1,?,X'')",
            [token],
        )
        .expect("Chromium token");
}

fn create_chromium_network_decoy(config: &Path) {
    let network = config.join("chromium/Default/Network");
    fs::create_dir_all(&network).expect("Chromium Network store");
    let connection = Connection::open(network.join("Cookies")).expect("Chromium Network cookies");
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
             INSERT INTO meta (key, value) VALUES ('version', 23);
             INSERT INTO cookies VALUES (
               'www.kimi.com','unrelated','/',0,1,'modern-decoy',X''
             );",
        )
        .expect("Chromium Network decoy");
}

fn create_firefox_profile(home: &Path, token: &str) {
    let root = home.join(".mozilla/firefox");
    let profile = root.join("fixture.default");
    fs::create_dir_all(&profile).expect("Firefox profile");
    fs::write(
        root.join("profiles.ini"),
        "[Profile0]\nName=fixture\nIsRelative=1\nPath=fixture.default\nDefault=1\n",
    )
    .expect("profiles.ini");
    let connection = Connection::open(profile.join("cookies.sqlite")).expect("Firefox cookies");
    connection
        .execute_batch(
            "CREATE TABLE moz_cookies (
               host TEXT NOT NULL,
               name TEXT NOT NULL,
               path TEXT NOT NULL,
               expiry INTEGER NOT NULL,
               isSecure INTEGER NOT NULL,
               value TEXT NOT NULL
             );",
        )
        .expect("Firefox schema");
    connection
        .execute(
            "INSERT INTO moz_cookies VALUES ('www.kimi.com','kimi-auth','/',2000000000,1,?)",
            [token],
        )
        .expect("Firefox token");
}

fn create_desktop_database(path: &Path) {
    let connection = Connection::open(path).expect("desktop database");
    connection
        .execute_batch(
            "CREATE TABLE cookies (
               host_key TEXT NOT NULL,
               name TEXT NOT NULL,
               value TEXT NOT NULL,
               encrypted_value BLOB NOT NULL DEFAULT X'',
               last_access_utc INTEGER NOT NULL
             );",
        )
        .expect("desktop schema");
}

fn insert_desktop_cookie(connection: &Connection, host: &str, token: &str, access: i64) {
    connection
        .execute(
            "INSERT INTO cookies (host_key,name,value,encrypted_value,last_access_utc) \
             VALUES (?,'kimi-auth',?,X'',?)",
            params![host, token, access],
        )
        .expect("desktop cookie");
}

fn path_text(path: &Path) -> String {
    path.to_str().expect("UTF-8 fixture path").to_owned()
}
