use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, Freshness, PrivacyKey, PrivacyPolicy, PrivacySurface,
    ProviderId, ProviderInstanceId, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
};
use oab_providers::browser_cookie::DisabledChromiumCookieDecryptor;
use oab_providers::browser_profile::{BrowserProfileDiscovery, BrowserProfileRoots};
use oab_providers::context::{FetchOutcome, ProviderAdapter, ProviderContext, preserve_last_good};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::copilot::{
    CopilotBudgetEnrichment, CopilotBudgetRouteSet, CopilotDeviceFlow, CopilotProvider,
    DeviceFlowClock, normalize_enterprise_host, normalized_billing_identifier,
    parse_budget_windows, usage_url,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{HttpTransport, TransportConfig};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use rusqlite::{Connection, params};
use time::{OffsetDateTime, UtcOffset};
use tokio_util::sync::CancellationToken;

const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/copilot/usage.json");
const MONTHLY: &[u8] = include_bytes!("../../../fixtures/providers/copilot/monthly.json");
const UNLIMITED: &[u8] = include_bytes!("../../../fixtures/providers/copilot/unlimited.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/copilot/malformed.json");
const BUDGET_NESTED: &[u8] =
    include_bytes!("../../../fixtures/providers/copilot/budget_nested.json");
const BUDGET_PAGE_ONE: &[u8] =
    include_bytes!("../../../fixtures/providers/copilot/budget_page_one.json");
const BUDGET_PAGE_TWO: &[u8] =
    include_bytes!("../../../fixtures/providers/copilot/budget_page_two.json");
const BUDGET_MALFORMED: &[u8] =
    include_bytes!("../../../fixtures/providers/copilot/budget_malformed.json");
const TOKEN_CANARY: &str = "fixture-copilot-oauth-token-canary";
const DEVICE_CODE_CANARY: &str = "fixture-copilot-device-code-canary";
const COOKIE_CANARY: &str = "fixture-copilot-browser-cookie-canary";

#[derive(Clone, Default)]
struct FakeDeviceFlowClock {
    state: Arc<Mutex<FakeDeviceFlowClockState>>,
}

#[derive(Default)]
struct FakeDeviceFlowClockState {
    now: Duration,
    sleeps: Vec<Duration>,
    expire_next_request: bool,
}

impl FakeDeviceFlowClock {
    fn sleeps(&self) -> Vec<Duration> {
        self.state.lock().expect("clock state").sleeps.clone()
    }

    fn advance(&self, duration: Duration) {
        let mut state = self.state.lock().expect("clock state");
        state.now = state.now.saturating_add(duration);
    }

    fn expire_next_request(&self) {
        self.state.lock().expect("clock state").expire_next_request = true;
    }
}

impl DeviceFlowClock for FakeDeviceFlowClock {
    fn monotonic_now(&self) -> Duration {
        self.state.lock().expect("clock state").now
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("clock state");
            state.now = state.now.saturating_add(duration);
            state.sleeps.push(duration);
        })
    }

    fn run_before_timeout<'a, F, T>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Option<T>> + Send + 'a>>
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        let expires = {
            let mut state = self.state.lock().expect("clock state");
            let expires = std::mem::take(&mut state.expire_next_request);
            if expires {
                state.now = state.now.saturating_add(duration);
            }
            expires
        };
        Box::pin(async move { if expires { None } else { Some(future.await) } })
    }
}

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
    scope_for(ProviderId::Copilot, account)
}

fn context_with_source(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn context(account: &str) -> ProviderContext {
    context_with_source(account, ProviderSource::OAuth)
}

fn config(max_response_bytes: usize) -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        max_response_bytes,
        0,
        RetryPolicy::none(),
    )
    .expect("transport config")
}

fn provider(server: &FakeHttpServer, account: &str) -> CopilotProvider {
    let client = FixedApiClient::new_authorization_scheme(
        scope(account),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        ApiKeyCredential::new(TOKEN_CANARY).expect("credential"),
        config(2 * 1024 * 1024),
    )
    .expect("OAuth client")
    .with_source(ProviderSource::OAuth)
    .expect("Copilot OAuth source");
    CopilotProvider::from_client(client).expect("Copilot provider")
}

fn budget_routes(server: &FakeHttpServer) -> CopilotBudgetRouteSet {
    CopilotBudgetRouteSet::loopback(server.url("/settings/billing/budgets"))
        .expect("loopback budget routes")
}

fn manual_budget_provider(
    usage_server: &FakeHttpServer,
    budget_server: &FakeHttpServer,
    cookie: &str,
) -> CopilotProvider {
    let enrichment =
        CopilotBudgetEnrichment::from_manual_capture_routes(cookie, budget_routes(budget_server))
            .expect("manual budget enrichment")
            .with_local_offset(UtcOffset::UTC);
    provider(usage_server, "account-a").with_budget_enrichment(enrichment)
}

fn oauth_identity() -> Vec<u8> {
    br#"{"id":123,"login":"octocat"}"#.to_vec()
}

fn budget_metadata(id: &str, login: &str, nonce: &str) -> Vec<u8> {
    format!(
        r#"<html><head>
        <meta content="{login}" name="user-login">
        <meta name="octolytics-actor-id" content="{id}">
        <meta name="x-fetch-nonce" content="{nonce}">
        </head></html>"#
    )
    .into_bytes()
}

fn create_chromium_budget_profile(config: &Path, profile_name: &str) {
    let profile = config.join("chromium").join(profile_name);
    let network = profile.join("Network");
    fs::create_dir_all(&network).expect("Chromium profile directories");
    let root = Connection::open(profile.join("Cookies")).expect("Chromium root cookies");
    create_chromium_cookie_schema(&root);
    root.execute(
        "INSERT INTO cookies VALUES ('.github.com','user_session','/settings/billing',0,1,?,X'')",
        [COOKIE_CANARY],
    )
    .expect("Chromium root session");
    root.execute(
        "INSERT INTO cookies VALUES ('.github.com','logged_in','/unrelated',0,1,'yes',X'')",
        [],
    )
    .expect("wrong-path decoy");

    let network = Connection::open(network.join("Cookies")).expect("Chromium Network cookies");
    create_chromium_cookie_schema(&network);
    network
        .execute(
            "INSERT INTO cookies VALUES ('.github.com','_gh_sess','/settings',0,1,'network-session',X'')",
            [],
        )
        .expect("Chromium Network session");
    network
        .execute(
            "INSERT INTO cookies VALUES ('.github.com','user_session','/settings/billing',0,1,'network-winner',X'')",
            [],
        )
        .expect("Chromium Network conflict winner");
    network
        .execute(
            "INSERT INTO cookies VALUES ('github.com.evil.test','user_session','/',0,1,'evil',X'')",
            [],
        )
        .expect("foreign decoy");
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

fn create_firefox_budget_profile(home: &Path) -> Connection {
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
            "INSERT INTO moz_cookies VALUES ('.github.com','__Host-user_session_same_site','/settings',2000000000,1,?)",
            params!["firefox-session"],
        )
        .expect("Firefox session");
    connection
}

fn device_flow(
    server: &FakeHttpServer,
    clock: FakeDeviceFlowClock,
) -> CopilotDeviceFlow<FakeDeviceFlowClock> {
    let endpoints = EndpointPolicy::new([(server.origin(), EndpointClass::LoopbackDevelopment)])
        .expect("loopback device endpoints");
    let transport =
        HttpTransport::new(endpoints, config(2 * 1024 * 1024)).expect("device transport");
    CopilotDeviceFlow::with_test_transport(&server.url("/"), transport, clock)
        .expect("loopback device flow")
}

fn device_code_response(expires_in: u64, interval: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "device_code": DEVICE_CODE_CANARY,
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://github.com/login/device",
        "verification_uri_complete": "https://github.com/login/device?user_code=ABCD-EFGH",
        "expires_in": expires_in,
        "interval": interval,
    }))
    .expect("device-code fixture")
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn row<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a oab_domain::DetailRow {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .expect("detail row")
}

#[test]
fn budget_parser_maps_nested_aliases_amounts_selectors_duplicates_and_local_reset() {
    let now = Timestamp::parse("2026-08-30T22:30:00Z").expect("fixture time");
    let offset = UtcOffset::from_hms(3, 0, 0).expect("UTC+3");
    let windows = parse_budget_windows(BUDGET_NESTED, now, offset).expect("budget windows");

    assert_eq!(windows.len(), 3);
    assert_eq!(windows[0].id().as_str(), "copilot-budget-product-budget");
    assert_eq!(windows[0].title().as_str(), "Budget - Copilot");
    assert_percent(
        windows[0]
            .window()
            .used_percent()
            .expect("product percent")
            .get(),
        15.0,
    );
    assert_eq!(windows[1].id().as_str(), "copilot-budget-42");
    assert_eq!(
        windows[1].title().as_str(),
        "Budget - Copilot Agent Premium Requests"
    );
    assert_percent(
        windows[1]
            .window()
            .used_percent()
            .expect("agent percent")
            .get(),
        25.0,
    );
    assert_percent(
        windows[2]
            .window()
            .used_percent()
            .expect("clamped percent")
            .get(),
        999.0,
    );
    let expected_reset = Timestamp::parse("2026-08-31T21:00:00Z").expect("local September");
    assert!(
        windows
            .iter()
            .all(|window| window.window().resets_at() == Some(expected_reset))
    );

    for (raw, expected) in [
        ("Copilot", "copilot"),
        ("Premium requests", "copilot_premium_request"),
        (
            "Copilot cloud agent premium requests",
            "copilot_agent_premium_request",
        ),
        ("Spark Premium Request", "spark_premium_request"),
        ("Bundled premium request budget", "copilot_premium_request"),
    ] {
        assert_eq!(
            normalized_billing_identifier(raw).as_deref(),
            Some(expected)
        );
    }

    let named = parse_budget_windows(
        br#"{"budgets":[{"id":"named","name":"  Example  ","skus":["copilot","unknown"],"amount":10}],"has_next_page":false}"#,
        now,
        offset,
    )
    .expect("named mixed-selector budget");
    assert_eq!(named[0].title().as_str(), "Budget - Example");
}

#[test]
fn budget_parser_rejects_malformed_shapes_and_embedded_minus_without_false_windows() {
    let now = timestamp(1_780_358_400);
    assert_eq!(
        parse_budget_windows(BUDGET_MALFORMED, now, UtcOffset::UTC)
            .expect_err("malformed budget page")
            .kind(),
        ErrorKind::Parse
    );
    let malformed_amounts = br#"{
      "budgets":[
        {"uuid":"one","pricingTargetId":"premium_requests","targetAmount":"1-5","currentAmount":"$5"},
        {"uuid":"two","pricingTargetId":"premium_requests","targetAmount":"-$15","currentAmount":"$5"}
      ],
      "has_next_page":false
    }"#;
    assert!(
        parse_budget_windows(malformed_amounts, now, UtcOffset::UTC)
            .expect("invalid amounts are non-positive")
            .is_empty()
    );
    let oversized = serde_json::to_vec(&serde_json::json!({
        "budgets": [{
            "id": "x",
            "sku": "copilot",
            "name": "n".repeat(64 * 1024 + 1),
            "amount": 1
        }]
    }))
    .expect("oversized fixture");
    assert_eq!(
        parse_budget_windows(&oversized, now, UtcOffset::UTC)
            .expect_err("oversized field")
            .kind(),
        ErrorKind::Parse
    );

    let mut nested = serde_json::json!({"budgets": []});
    for _ in 0..34 {
        nested = serde_json::json!({"payload": nested});
    }
    assert_eq!(
        parse_budget_windows(
            &serde_json::to_vec(&nested).expect("deep fixture"),
            now,
            UtcOffset::UTC,
        )
        .expect_err("tree depth bound")
        .kind(),
        ErrorKind::Parse
    );
    let records = (0..101)
        .map(|id| serde_json::json!({"id": id, "sku": "copilot", "amount": 1}))
        .collect::<Vec<_>>();
    assert_eq!(
        parse_budget_windows(
            &serde_json::to_vec(&serde_json::json!({"budgets": records})).expect("record fixture"),
            now,
            UtcOffset::UTC,
        )
        .expect_err("per-page record bound")
        .kind(),
        ErrorKind::Parse
    );
    assert_eq!(
        parse_budget_windows(
            br#"{"budgets":[],"hasNextPage":null,"has_next_page":"true"}"#,
            now,
            UtcOffset::UTC,
        )
        .expect_err("malformed snake pagination after null camel pagination")
        .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn manual_budget_enrichment_binds_oauth_identity_and_sends_pinned_get_headers() {
    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, budget_metadata("123", "octocat", "nonce-canary")),
        FakeHttpResponse::new(200, BUDGET_NESTED.to_vec()),
    ])
    .await;
    let capture = format!(
        "curl 'https://github.com/settings/billing/budgets?page=1' -H 'Cookie: user_session={COOKIE_CANARY}; private_cookie=do-not-forward'"
    );
    let provider = manual_budget_provider(&usage_server, &budget_server, &capture);
    let sample = provider
        .fetch_at(
            &context("account-a"),
            Timestamp::parse("2026-08-30T22:30:00Z").expect("fixture time"),
        )
        .await
        .expect("base usage plus budgets");

    assert_eq!(sample.extra_windows().len(), 3);
    assert_eq!(usage_server.requests().len(), 2);
    assert_eq!(usage_server.requests()[1].target(), "/user");
    assert_eq!(
        usage_server.requests()[1].header("authorization"),
        Some("token fixture-copilot-oauth-token-canary")
    );
    assert!(usage_server.requests()[0].header("cookie").is_none());
    assert!(usage_server.requests()[1].header("cookie").is_none());
    let requests = budget_server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target(), "/settings/billing/budgets");
    assert_eq!(
        requests[0].header("accept"),
        Some("text/html,application/xhtml+xml")
    );
    assert_eq!(requests[0].header("user-agent"), Some("omarchy-ai-bar"));
    assert!(requests[0].header("content-type").is_none());
    assert!(requests[0].header("authorization").is_none());
    assert_eq!(
        requests[1].target(),
        "/settings/billing/budgets?page=1&page_size=10&scope=customer"
    );
    assert_eq!(requests[1].header("accept"), Some("application/json"));
    assert_eq!(
        requests[1].header("x-requested-with"),
        Some("XMLHttpRequest")
    );
    assert_eq!(requests[1].header("github-verified-fetch"), Some("true"));
    assert_eq!(requests[1].header("x-fetch-nonce"), Some("nonce-canary"));
    assert_eq!(
        requests[1].header("referer"),
        Some(budget_server.url("/settings/billing/budgets").as_str())
    );
    assert!(requests[1].header("content-type").is_none());
    assert_eq!(requests[1].header("user-agent"), Some("omarchy-ai-bar"));
    assert!(requests[1].header("authorization").is_none());
    assert_eq!(
        requests[1].header("cookie"),
        Some("user_session=fixture-copilot-browser-cookie-canary")
    );
}

#[tokio::test]
async fn budget_pagination_preserves_order_and_allocates_stable_duplicate_ids() {
    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([
        FakeHttpResponse::new(
            200,
            br#"<meta name="octolytics-actor-id" content="123"><meta name="user-login" content="octocat">"#
                .to_vec(),
        ),
        FakeHttpResponse::new(200, BUDGET_PAGE_ONE.to_vec()),
        FakeHttpResponse::new(200, BUDGET_PAGE_TWO.to_vec()),
    ])
    .await;
    let provider = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    );

    let sample = provider
        .fetch_at(&context("account-a"), timestamp(1_780_358_400))
        .await
        .expect("paginated enrichment");

    assert_eq!(sample.extra_windows().len(), 2);
    assert_eq!(
        sample
            .extra_windows()
            .iter()
            .map(|window| window.id().as_str())
            .collect::<Vec<_>>(),
        ["copilot-budget-duplicate", "copilot-budget-duplicate-2"]
    );
    let requests = budget_server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[1].target().contains("page=1"));
    assert!(requests[2].target().contains("page=2"));
    assert!(requests[1].header("x-fetch-nonce").is_none());
    assert!(requests[2].header("x-fetch-nonce").is_none());
}

#[tokio::test]
async fn identity_mismatch_and_malformed_budget_are_best_effort_after_base_success() {
    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        budget_metadata("456", "other", "nonce"),
    )])
    .await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("mismatched browser identity keeps OAuth usage");
    assert!(sample.primary().is_some());
    assert!(sample.extra_windows().is_empty());
    assert_eq!(budget_server.requests().len(), 1);

    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        br#"<meta name="x-fetch-nonce" content="nonce">"#.to_vec(),
    )])
    .await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("missing browser identity keeps OAuth usage");
    assert!(sample.primary().is_some());
    assert!(sample.extra_windows().is_empty());
    assert_eq!(budget_server.requests().len(), 1);

    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, budget_metadata("123", "octocat", "nonce")),
        FakeHttpResponse::new(200, BUDGET_MALFORMED.to_vec()),
    ])
    .await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("invalid optional JSON keeps OAuth usage");
    assert!(sample.primary().is_some());
    assert!(sample.extra_windows().is_empty());

    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, budget_metadata("123", "octocat", "nonce")),
        FakeHttpResponse::new(200, br#"{"budgets":[],"has_next_page":false}"#.to_vec()),
    ])
    .await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("empty optional budget keeps OAuth usage");
    assert!(sample.primary().is_some());
    assert!(sample.extra_windows().is_empty());
}

#[tokio::test]
async fn missing_or_unavailable_oauth_identity_skips_all_cookie_requests() {
    for identity_response in [
        FakeHttpResponse::new(200, br#"{"id":123}"#.to_vec()),
        FakeHttpResponse::new(500, b"identity-error-token-canary".to_vec()),
    ] {
        let usage_server = FakeHttpServer::start([
            FakeHttpResponse::new(200, USAGE.to_vec()),
            identity_response,
        ])
        .await;
        let budget_server = FakeHttpServer::start([]).await;
        let sample = manual_budget_provider(
            &usage_server,
            &budget_server,
            &format!("user_session={COOKIE_CANARY}"),
        )
        .fetch_at(&context("account-a"), timestamp(1_780_358_400))
        .await
        .expect("OAuth identity enrichment failure keeps base");
        assert!(sample.primary().is_some());
        assert!(sample.extra_windows().is_empty());
        assert!(budget_server.requests().is_empty());
    }
}

#[tokio::test]
async fn enterprise_budget_policy_keeps_base_without_identity_or_cookie_requests() {
    let enterprise = CopilotProvider::new(
        scope("enterprise-account"),
        ApiKeyCredential::new(TOKEN_CANARY).expect("enterprise credential"),
        Some("github.enterprise.test"),
    )
    .expect("enterprise provider");
    assert!(!enterprise.public_budget_identity_allowed());

    let usage_server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let budget_server = FakeHttpServer::start([]).await;
    let enrichment = CopilotBudgetEnrichment::from_manual_capture_routes(
        &format!("user_session={COOKIE_CANARY}"),
        budget_routes(&budget_server),
    )
    .expect("enterprise policy fixture");
    let sample = provider(&usage_server, "account-a")
        .without_public_budget_identity()
        .with_budget_enrichment(enrichment)
        .fetch_at(&context("account-a"), timestamp(1_780_358_400))
        .await
        .expect("enterprise policy retains base usage");

    assert!(sample.primary().is_some());
    assert!(sample.extra_windows().is_empty());
    assert_eq!(usage_server.requests().len(), 1);
    assert_eq!(
        usage_server.requests()[0].target(),
        "/copilot_internal/user"
    );
    assert!(budget_server.requests().is_empty());
}

#[tokio::test]
async fn browser_budget_rotates_separate_chromium_stores_deduplicates_and_reads_firefox_wal() {
    let temporary = tempfile::tempdir().expect("temporary browser roots");
    let home = temporary.path().join("home");
    let config = temporary.path().join("config");
    fs::create_dir_all(&home).expect("home root");
    fs::create_dir_all(&config).expect("config root");
    create_chromium_budget_profile(&config, "Default");
    create_chromium_budget_profile(&config, "Profile 1");
    let _firefox_wal = create_firefox_budget_profile(&home);
    let roots = BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("browser roots");
    let discovery = BrowserProfileDiscovery::with_roots(roots);

    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, budget_metadata("456", "other", "first")),
        FakeHttpResponse::new(200, budget_metadata("789", "also-other", "second")),
        FakeHttpResponse::new(200, budget_metadata("123", "octocat", "third")),
        FakeHttpResponse::new(200, BUDGET_PAGE_TWO.to_vec()),
    ])
    .await;
    let enrichment = CopilotBudgetEnrichment::from_browser_routes(
        &discovery,
        &DisabledChromiumCookieDecryptor,
        OffsetDateTime::from_unix_timestamp(1_780_358_400).expect("browser cookie time"),
        budget_routes(&budget_server),
    )
    .expect("browser budget enrichment")
    .with_local_offset(UtcOffset::UTC);
    let debug = format!("{enrichment:?}");
    assert!(!debug.contains(COOKIE_CANARY));
    assert!(!debug.contains("firefox-session"));

    let sample = provider(&usage_server, "account-a")
        .with_budget_enrichment(enrichment)
        .fetch_at(&context("account-a"), timestamp(1_780_358_400))
        .await
        .expect("browser profile rotation");

    assert_eq!(sample.extra_windows().len(), 1);
    let requests = budget_server.requests();
    assert_eq!(
        requests.len(),
        4,
        "duplicate Chromium stores are suppressed without mixing candidates"
    );
    let network_cookie = requests[0]
        .header("cookie")
        .expect("Chromium Network cookie");
    assert!(network_cookie.contains("user_session=network-winner"));
    assert!(network_cookie.contains("_gh_sess=network-session"));
    assert!(!network_cookie.contains(COOKIE_CANARY));
    assert!(!network_cookie.contains("logged_in=yes"));
    assert!(!network_cookie.contains("evil"));
    assert_eq!(
        requests[1].header("cookie"),
        Some("user_session=fixture-copilot-browser-cookie-canary")
    );
    assert!(
        !requests[1]
            .header("cookie")
            .expect("Chromium root cookie")
            .contains("network-session")
    );
    assert_eq!(
        requests[2].header("cookie"),
        Some("__Host-user_session_same_site=firefox-session")
    );
    assert_eq!(requests[3].header("cookie"), requests[2].header("cookie"));
}

#[tokio::test]
async fn signed_out_and_erroring_budget_routes_never_erase_oauth_usage() {
    let cases = [
        FakeHttpResponse::new(401, b"signed-out-cookie-canary".to_vec()),
        FakeHttpResponse::new(403, b"forbidden-cookie-canary".to_vec()),
        FakeHttpResponse::new(500, b"provider-cookie-canary".to_vec()),
        FakeHttpResponse::new(
            200,
            br#"<html><title>Sign in to GitHub</title><form action="/session"></form></html>"#
                .to_vec(),
        ),
    ];
    for response in cases {
        let usage_server = FakeHttpServer::start([
            FakeHttpResponse::new(200, USAGE.to_vec()),
            FakeHttpResponse::new(200, oauth_identity()),
        ])
        .await;
        let budget_server = FakeHttpServer::start([response]).await;
        let sample = manual_budget_provider(
            &usage_server,
            &budget_server,
            &format!("user_session={COOKIE_CANARY}"),
        )
        .fetch_at(&context("account-a"), timestamp(1_780_358_400))
        .await
        .expect("budget status is best effort");
        assert!(sample.primary().is_some());
        assert!(sample.extra_windows().is_empty());
        assert_eq!(budget_server.requests().len(), 1);
    }
}

#[tokio::test]
async fn empty_browser_discovery_is_opt_in_no_session_and_manual_never_falls_back() {
    assert!(CopilotBudgetEnrichment::manual("Cookie:").is_err());
    assert!(
        CopilotBudgetEnrichment::manual("curl https://evil.test/ -H 'Cookie: user_session=x'")
            .is_err()
    );

    let temporary = tempfile::tempdir().expect("empty browser roots");
    let home = temporary.path().join("home");
    let config = temporary.path().join("config");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&config).expect("config");
    let discovery = BrowserProfileDiscovery::with_roots(
        BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("roots"),
    );
    let budget_server = FakeHttpServer::start([]).await;
    let enrichment = CopilotBudgetEnrichment::from_browser_routes(
        &discovery,
        &DisabledChromiumCookieDecryptor,
        OffsetDateTime::UNIX_EPOCH,
        budget_routes(&budget_server),
    )
    .expect("empty discovery remains optional");
    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let sample = provider(&usage_server, "account-a")
        .with_budget_enrichment(enrichment)
        .fetch_at(&context("account-a"), timestamp(1_780_358_400))
        .await
        .expect("no browser session keeps base");
    assert!(sample.extra_windows().is_empty());
    assert!(budget_server.requests().is_empty());
}

#[tokio::test]
async fn budget_redirects_cannot_forward_cookie_to_another_origin() {
    let unrelated = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        b"cookie-must-not-arrive".to_vec(),
    )])
    .await;
    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", unrelated.url("/steal").as_str())])
        .await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("redirect failure is optional");

    assert!(sample.primary().is_some());
    assert!(sample.extra_windows().is_empty());
    assert_eq!(budget_server.requests().len(), 1);
    assert!(unrelated.requests().is_empty());
}

#[tokio::test]
async fn cancellation_during_budget_enrichment_returns_the_successful_base_sample() {
    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    );
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move {
        let provider_context =
            ProviderContext::new(scope("account-a"), ProviderSource::OAuth, task_cancellation);
        provider
            .fetch_at(&provider_context, timestamp(1_780_358_400))
            .await
    });
    budget_server.wait_for_request_count(1).await;
    cancellation.cancel();
    let sample = task
        .await
        .expect("fetch task")
        .expect("cancelled optional budget keeps base");
    assert!(sample.primary().is_some());
    assert!(sample.extra_windows().is_empty());
}

#[tokio::test]
async fn budget_response_and_pagination_caps_are_fail_soft_and_deterministic() {
    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    let budget_server = FakeHttpServer::start([FakeHttpResponse::new(200, oversized)]).await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("oversized metadata keeps base");
    assert!(sample.extra_windows().is_empty());

    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([FakeHttpResponse::new(200, vec![0xc3, 0x28])]).await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("malformed HTML keeps base");
    assert!(sample.extra_windows().is_empty());

    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let budget_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, budget_metadata("123", "octocat", "oversize")),
        FakeHttpResponse::new(200, vec![b'x'; 2 * 1024 * 1024 + 1]),
    ])
    .await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("oversized JSON keeps base");
    assert!(sample.extra_windows().is_empty());

    let usage_server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, oauth_identity()),
    ])
    .await;
    let continuing_page = br#"{
      "budgets":[{"id":"same","sku":"copilot_premium_request","amount":10,"spent":1}],
      "has_next_page":true
    }"#
    .to_vec();
    let mut responses = vec![FakeHttpResponse::new(
        200,
        budget_metadata("123", "octocat", "cap-nonce"),
    )];
    responses.extend(std::iter::repeat_n(
        FakeHttpResponse::new(200, continuing_page),
        20,
    ));
    let budget_server = FakeHttpServer::start(responses).await;
    let sample = manual_budget_provider(
        &usage_server,
        &budget_server,
        &format!("user_session={COOKIE_CANARY}"),
    )
    .fetch_at(&context("account-a"), timestamp(1_780_358_400))
    .await
    .expect("page cap returns bounded extras");
    assert_eq!(sample.extra_windows().len(), 16);
    assert_eq!(budget_server.requests().len(), 21);
    assert!(
        budget_server
            .requests()
            .iter()
            .all(|request| !request.target().contains("page=21"))
    );
}

#[test]
fn token_resolution_and_enterprise_hosts_are_bounded_normalized_and_redacted() {
    let environment = BTreeMap::from([(
        "COPILOT_API_TOKEN".to_owned(),
        format!("  '{TOKEN_CANARY}'  "),
    )]);
    let credential = CopilotProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains(TOKEN_CANARY));
    assert_eq!(
        CopilotProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing token")
            .kind(),
        ErrorKind::MissingCredential
    );

    assert_eq!(
        normalize_enterprise_host(None).expect("default"),
        "github.com"
    );
    assert_eq!(
        normalize_enterprise_host(Some(" https://OctoCorp.GHE.com:8443/login "))
            .expect("enterprise"),
        "octocorp.ghe.com:8443"
    );
    assert_eq!(
        usage_url(None).expect("default usage").as_str(),
        "https://api.github.com/copilot_internal/user"
    );
    assert_eq!(
        usage_url(Some("api.octocorp.ghe.com:8443"))
            .expect("enterprise usage")
            .as_str(),
        "https://api.octocorp.ghe.com:8443/copilot_internal/user"
    );
    for invalid in ["foo bar", "https://user@example.com", "file:///tmp/socket"] {
        assert_eq!(
            normalize_enterprise_host(Some(invalid))
                .expect_err("invalid host")
                .kind(),
            ErrorKind::Api
        );
    }

    CopilotProvider::new(scope("account-a"), credential, None).expect("production client");
    CopilotProvider::new(
        scope("enterprise-account"),
        ApiKeyCredential::new(TOKEN_CANARY).expect("enterprise credential"),
        Some("github.internal.local"),
    )
    .expect("private HTTPS enterprise client");

    let device_flow = CopilotDeviceFlow::new(None).expect("production device flow");
    assert_eq!(
        device_flow.device_code_url().as_str(),
        "https://github.com/login/device/code"
    );
    assert_eq!(
        device_flow.access_token_url().as_str(),
        "https://github.com/login/oauth/access_token"
    );
    assert!(CopilotDeviceFlow::new(Some("127.0.0.1")).is_err());
}

#[tokio::test]
async fn device_code_request_is_exact_bounded_and_redacted() {
    let response = device_code_response(900, 5);
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, response)]).await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let challenge = flow
        .request_device_code(&CancellationToken::new())
        .await
        .expect("device challenge");

    assert_eq!(challenge.user_code(), "ABCD-EFGH");
    assert_eq!(challenge.expires_in(), Duration::from_mins(15));
    assert_eq!(challenge.interval(), Duration::from_secs(5));
    assert_eq!(
        challenge.verification_url_to_open().as_str(),
        "https://github.com/login/device?user_code=ABCD-EFGH"
    );
    let debug = format!("{challenge:?}");
    assert!(!debug.contains(DEVICE_CODE_CANARY));
    assert!(!debug.contains("ABCD-EFGH"));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/login/device/code");
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(
        requests[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        requests[0].body(),
        b"client_id=Iv1.b507a08c87ecfe98&scope=read%3Auser"
    );
    assert!(clock.sleeps().is_empty());
}

#[tokio::test]
async fn malformed_or_unbounded_device_challenges_fail_closed() {
    let base = || {
        serde_json::json!({
            "device_code": DEVICE_CODE_CANARY,
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://github.com/login/device",
            "verification_uri_complete": null,
            "expires_in": 900,
            "interval": 5,
        })
    };
    let mut cases = Vec::new();
    for (field, replacement) in [
        ("device_code", serde_json::json!("bad\ncode")),
        ("user_code", serde_json::json!("")),
        (
            "verification_uri",
            serde_json::json!("http://github.com/login/device"),
        ),
        ("expires_in", serde_json::json!(0)),
        ("expires_in", serde_json::json!(86_401)),
        ("interval", serde_json::json!(0)),
        ("interval", serde_json::json!(301)),
    ] {
        let mut payload = base();
        payload[field] = replacement;
        cases.push(payload);
    }
    let mut oversized_code = base();
    oversized_code["device_code"] = serde_json::json!("x".repeat(16 * 1024 + 1));
    cases.push(oversized_code);
    let mut insecure_complete = base();
    insecure_complete["verification_uri_complete"] =
        serde_json::json!("https://github.com/login/device#secret");
    cases.push(insecure_complete);

    for body in cases {
        let server = FakeHttpServer::start([FakeHttpResponse::new(
            200,
            serde_json::to_vec(&body).expect("invalid fixture"),
        )])
        .await;
        let flow = device_flow(&server, FakeDeviceFlowClock::default());

        assert_eq!(
            flow.request_device_code(&CancellationToken::new())
                .await
                .expect_err("invalid challenge")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn device_poll_handles_pending_slow_down_and_returns_redacted_credential() {
    let challenge_response = device_code_response(900, 2);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, challenge_response),
        FakeHttpResponse::new(200, br#"{"error":"authorization_pending"}"#.to_vec()),
        FakeHttpResponse::new(400, br#"{"error":"slow_down"}"#.to_vec()),
        FakeHttpResponse::new(
            200,
            format!(
                r#"{{"access_token":"{TOKEN_CANARY}","token_type":"bearer","scope":"read:user"}}"#
            )
            .into_bytes(),
        ),
    ])
    .await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    let credential = flow
        .poll_for_token(&challenge, &cancellation)
        .await
        .expect("authorized token");
    assert!(!format!("{credential:?}").contains(TOKEN_CANARY));
    assert_eq!(
        clock.sleeps(),
        vec![
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_secs(2),
        ]
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    for request in &requests[1..] {
        assert_eq!(request.method(), "POST");
        assert_eq!(request.target(), "/login/oauth/access_token");
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(
            request.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            request.body(),
            b"client_id=Iv1.b507a08c87ecfe98&device_code=fixture-copilot-device-code-canary&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
    }

    let usage_server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let client = FixedApiClient::new_authorization_scheme(
        scope("account-a"),
        usage_server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        credential,
        config(2 * 1024 * 1024),
    )
    .expect("client from device credential")
    .with_source(ProviderSource::OAuth)
    .expect("OAuth source");
    CopilotProvider::from_client(client)
        .expect("provider")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("usage with device token");
    assert_eq!(
        usage_server.requests()[0].header("authorization"),
        Some("token fixture-copilot-oauth-token-canary")
    );
}

#[tokio::test]
async fn device_poll_enforces_expiry_without_an_extra_request() {
    let challenge_response = device_code_response(3, 2);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, challenge_response),
        FakeHttpResponse::new(200, br#"{"error":"authorization_pending"}"#.to_vec()),
    ])
    .await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");

    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge expires")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(
        clock.sleeps(),
        vec![Duration::from_secs(2), Duration::from_secs(1)]
    );
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn device_expiry_includes_time_spent_waiting_before_polling() {
    let server =
        FakeHttpServer::start([FakeHttpResponse::new(200, device_code_response(3, 2))]).await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    clock.advance(Duration::from_secs(2));

    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge expires while waiting")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(1)]);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn device_in_flight_expiry_uses_the_injected_clock() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, device_code_response(60, 1)),
        FakeHttpResponse::stall(),
    ])
    .await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    clock.expire_next_request();

    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("request reaches challenge deadline")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(1)]);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn device_poll_maps_denial_expired_token_and_cancellation_safely() {
    for (oauth_error, expected) in [
        ("access_denied", ErrorKind::PermissionDenied),
        ("expired_token", ErrorKind::AuthenticationExpired),
        ("incorrect_device_code", ErrorKind::AuthenticationExpired),
    ] {
        let challenge_response = device_code_response(60, 1);
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, challenge_response),
            FakeHttpResponse::new(400, format!(r#"{{"error":"{oauth_error}"}}"#).into_bytes()),
        ])
        .await;
        let flow = device_flow(&server, FakeDeviceFlowClock::default());
        let cancellation = CancellationToken::new();
        let challenge = flow
            .request_device_code(&cancellation)
            .await
            .expect("device challenge");
        assert_eq!(
            flow.poll_for_token(&challenge, &cancellation)
                .await
                .expect_err("OAuth error")
                .kind(),
            expected
        );
    }

    let challenge_response = device_code_response(60, 1);
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, challenge_response)]).await;
    let clock = FakeDeviceFlowClock::default();
    let flow = device_flow(&server, clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = flow
        .request_device_code(&cancellation)
        .await
        .expect("device challenge");
    cancellation.cancel();
    assert_eq!(
        flow.poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("cancelled poll")
            .kind(),
        ErrorKind::Network
    );
    assert!(clock.sleeps().is_empty());
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn device_success_requires_the_complete_github_token_schema() {
    for incomplete in [
        format!(r#"{{"access_token":"{TOKEN_CANARY}"}}"#),
        format!(r#"{{"access_token":"{TOKEN_CANARY}","token_type":"bearer"}}"#),
    ] {
        let server = FakeHttpServer::start([
            FakeHttpResponse::new(200, device_code_response(60, 1)),
            FakeHttpResponse::new(200, incomplete.into_bytes()),
        ])
        .await;
        let flow = device_flow(&server, FakeDeviceFlowClock::default());
        let cancellation = CancellationToken::new();
        let challenge = flow
            .request_device_code(&cancellation)
            .await
            .expect("device challenge");

        assert_eq!(
            flow.poll_for_token(&challenge, &cancellation)
                .await
                .expect_err("incomplete token schema")
                .kind(),
            ErrorKind::Parse
        );
    }
}

#[tokio::test]
async fn device_challenge_cannot_cross_forward_to_another_origin() {
    let issuer =
        FakeHttpServer::start([FakeHttpResponse::new(200, device_code_response(60, 1))]).await;
    let unrelated = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        format!(r#"{{"access_token":"{TOKEN_CANARY}","token_type":"bearer","scope":"read:user"}}"#)
            .into_bytes(),
    )])
    .await;
    let issuer_flow = device_flow(&issuer, FakeDeviceFlowClock::default());
    let unrelated_clock = FakeDeviceFlowClock::default();
    let unrelated_flow = device_flow(&unrelated, unrelated_clock.clone());
    let cancellation = CancellationToken::new();
    let challenge = issuer_flow
        .request_device_code(&cancellation)
        .await
        .expect("issuer challenge");

    assert_eq!(
        unrelated_flow
            .poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge remains origin-bound")
            .kind(),
        ErrorKind::Api
    );
    assert!(unrelated.requests().is_empty());
    assert!(unrelated_clock.sleeps().is_empty());

    let same_origin_clock = FakeDeviceFlowClock::default();
    let same_origin_other_flow = device_flow(&issuer, same_origin_clock.clone());
    assert_eq!(
        same_origin_other_flow
            .poll_for_token(&challenge, &cancellation)
            .await
            .expect_err("challenge remains issuing-flow-bound")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(issuer.requests().len(), 1);
    assert!(same_origin_clock.sleeps().is_empty());
}

#[tokio::test]
async fn usage_fixture_projects_premium_chat_credits_request_and_cli_schema() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(&server, "account-a");
    let fetched_at = timestamp(1_788_220_800);
    let sample = provider
        .fetch_at(&context("account-a"), fetched_at)
        .await
        .expect("Copilot usage");

    assert_eq!(provider.descriptor().id, ProviderId::Copilot);
    assert_percent(
        sample
            .primary()
            .expect("premium")
            .used_percent()
            .expect("percent")
            .get(),
        21.9,
    );
    assert_percent(
        sample
            .secondary()
            .expect("chat")
            .used_percent()
            .expect("percent")
            .get(),
        20.0,
    );
    assert!(sample.tertiary().is_none());
    assert_eq!(
        sample.primary().expect("premium").resets_at(),
        Some(Timestamp::parse("2026-09-01T00:00:00Z").expect("reset"))
    );
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Individual"
    );
    assert_eq!(row(&sample, "Credits used").value(), "31");
    assert_eq!(sample.provenance()[0].strategy(), "oauth");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "GET");
    assert_eq!(requests[0].target(), "/copilot_internal/user");
    assert_eq!(
        requests[0].header("authorization"),
        Some("token fixture-copilot-oauth-token-canary")
    );
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(requests[0].header("editor-version"), Some("vscode/1.96.2"));
    assert_eq!(
        requests[0].header("editor-plugin-version"),
        Some("copilot-chat/0.26.7")
    );
    assert_eq!(
        requests[0].header("user-agent"),
        Some("GitHubCopilotChat/0.26.7")
    );
    assert_eq!(
        requests[0].header("x-github-api-version"),
        Some("2025-04-01")
    );
    assert!(requests[0].header("content-type").is_none());

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
        json["snapshots"][0]["last_known_good"]["secondary"]["usage"]["used_percent"],
        20.0
    );
}

#[tokio::test]
async fn monthly_fallback_merges_with_direct_chat_and_keeps_slot_labels() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, MONTHLY.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("monthly fallback");

    assert_percent(
        sample
            .primary()
            .expect("completion fallback")
            .used_percent()
            .expect("percent")
            .get(),
        80.0,
    );
    assert_percent(
        sample
            .secondary()
            .expect("direct chat")
            .used_percent()
            .expect("percent")
            .get(),
        62.5,
    );
}

#[tokio::test]
async fn token_billing_and_unlimited_quotas_are_identity_only_but_keep_credits() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, UNLIMITED.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("unlimited token billing");

    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert_eq!(row(&sample, "Credits used").value(), "31");
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Business"
    );
}

#[tokio::test]
async fn dynamic_keys_are_deterministic_overage_is_raw_and_placeholders_do_not_win() {
    let body = br#"{
      "copilot_plan":"paid",
      "quota_snapshots":{
        "premium_interactions":{},
        "zeta_bucket":{"entitlement":100,"remaining":40,"percent_remaining":40},
        "alpha_bucket":{"entitlement":500,"remaining":-75,"percent_remaining":-15}
      }
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let sample = provider(&server, "account-a")
        .fetch_at(&context("account-a"), timestamp(1))
        .await
        .expect("dynamic fallback");

    assert!(sample.primary().is_none());
    let chat = sample.secondary().expect("sorted first fallback");
    assert_percent(chat.used_percent().expect("percent").get(), 115.0);
    assert_eq!(
        chat.reset_description().expect("overage").as_str(),
        "115% used"
    );
}

#[tokio::test]
async fn statuses_parse_bounds_last_good_and_source_account_isolation_are_stable() {
    for status in [401, 403] {
        let server =
            FakeHttpServer::start([FakeHttpResponse::new(status, b"secret".to_vec())]).await;
        assert_eq!(
            provider(&server, "account-a")
                .fetch_at(&context("account-a"), timestamp(1))
                .await
                .expect_err("expired OAuth")
                .kind(),
            ErrorKind::AuthenticationExpired
        );
    }
    let server = FakeHttpServer::start([FakeHttpResponse::new(201, USAGE.to_vec())]).await;
    assert_eq!(
        provider(&server, "account-a")
            .fetch_at(&context("account-a"), timestamp(1))
            .await
            .expect_err("exact status")
            .kind(),
        ErrorKind::Api
    );

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
    ])
    .await;
    let provider = provider(&server, "account-a");
    let provider_context = context("account-a");
    let last_good = provider
        .fetch_at(&provider_context, timestamp(1))
        .await
        .expect("last good");
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        provider.fetch_at(&provider_context, timestamp(2)).await,
    );
    assert!(matches!(
        outcome,
        FetchOutcome::Retained { last_good: ref retained, ref error }
            if retained == &last_good && error.kind() == ErrorKind::Parse
    ));

    let before = server.requests().len();
    for wrong in [
        context("account-b"),
        context_with_source("account-a", ProviderSource::ApiKey),
    ] {
        assert_eq!(
            provider
                .fetch_at(&wrong, timestamp(3))
                .await
                .expect_err("context isolation")
                .kind(),
            ErrorKind::Api
        );
    }
    assert_eq!(server.requests().len(), before);

    let wrong = FixedApiClient::new_authorization_scheme(
        scope_for(ProviderId::OpenAi, "account-a"),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        ApiKeyCredential::new(TOKEN_CANARY).expect("credential"),
        config(1024),
    )
    .expect("wrong client");
    assert_eq!(
        CopilotProvider::from_client(wrong)
            .err()
            .expect("wrong provider")
            .kind(),
        ErrorKind::Api
    );

    let wrong_source = FixedApiClient::new_authorization_scheme(
        scope("account-a"),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "token",
        ApiKeyCredential::new(TOKEN_CANARY).expect("credential"),
        config(1024),
    )
    .expect("Copilot client with default source");
    assert_eq!(
        CopilotProvider::from_client(wrong_source)
            .err()
            .expect("wrong source")
            .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn malformed_optional_date_metadata_fails_like_the_typed_baseline_decoder() {
    for field in [r#""quota_reset_date":7"#, r#""assigned_date":{}"#] {
        let body = format!(
            r#"{{
                "copilot_plan":"individual",
                {field},
                "quota_snapshots":{{
                    "chat":{{"entitlement":100,"remaining":50,"percent_remaining":50}}
                }}
            }}"#
        );
        let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.into_bytes())]).await;

        assert_eq!(
            provider(&server, "account-a")
                .fetch_at(&context("account-a"), timestamp(1))
                .await
                .expect_err("date metadata type mismatch")
                .kind(),
            ErrorKind::Parse
        );
    }
}
