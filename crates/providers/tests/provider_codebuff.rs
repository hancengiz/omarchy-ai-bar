use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::codebuff::{
    CodebuffCredentialSource, CodebuffProvider, CodebuffSettings,
};
use oab_providers::registry::descriptor_for;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/codebuff/usage.json");
const SUBSCRIPTION: &[u8] =
    include_bytes!("../../../fixtures/providers/codebuff/subscription.json");
const CREDENTIALS: &[u8] = include_bytes!("../../../fixtures/providers/codebuff/credentials.json");
const KEY_CANARY: &str = "fixture-codebuff-request-key-canary";

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Codebuff,
        ProviderInstanceId::new("codebuff-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("fixture timestamp")
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        2 * 1024 * 1024,
        0,
        RetryPolicy::none(),
    )
    .expect("fixture config")
}

fn gated_config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_secs(5),
        2 * 1024 * 1024,
        0,
        RetryPolicy::none(),
    )
    .expect("gated fixture config")
}

fn provider(
    server: &FakeHttpServer,
    account: &str,
    source: ProviderSource,
    grace: Duration,
) -> CodebuffProvider {
    provider_at(server.url("/"), account, source, grace, config())
}

fn provider_at(
    base_url: Url,
    account: &str,
    source: ProviderSource,
    grace: Duration,
    transport: TransportConfig,
) -> CodebuffProvider {
    let client = FixedApiClient::new_bearer(
        scope(account),
        base_url,
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new(KEY_CANARY).expect("fixture credential"),
        transport,
    )
    .expect("fixed client")
    .with_source(source)
    .expect("source binding");
    CodebuffProvider::from_client_with_grace(client, grace).expect("Codebuff provider")
}

fn used_percent(window: Option<&oab_domain::RateWindow>) -> Option<f64> {
    window
        .and_then(oab_domain::RateWindow::used_percent)
        .map(oab_domain::UsagePercent::get)
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
fn descriptor_advertises_exact_api_key_and_local_data_sources() {
    let sources = descriptor_for(ProviderId::Codebuff).sources();
    assert_eq!(
        sources.iter().collect::<Vec<_>>(),
        vec![ProviderSource::ApiKey, ProviderSource::LocalData]
    );
}

#[test]
fn environment_key_precedes_file_without_opening_or_copying_it() {
    let environment = BTreeMap::from([
        (
            "CODEBUFF_API_KEY".to_owned(),
            " 'fixture-codebuff-environment-canary' ".to_owned(),
        ),
        (
            "CODEBUFF_API_URL".to_owned(),
            "staging.codebuff.com/gateway".to_owned(),
        ),
    ]);
    let settings = CodebuffSettings::resolve_with_auth_path(&environment, "relative-unused-path")
        .expect("environment must win before path validation");
    assert_eq!(
        settings.credential_source(),
        CodebuffCredentialSource::Environment
    );
    assert_eq!(
        settings.api_base().as_str(),
        "https://staging.codebuff.com/gateway/"
    );
    let debug = format!("{settings:?}");
    assert!(!debug.contains("fixture-codebuff-environment-canary"));
    assert!(!debug.contains("relative-unused-path"));

    let invalid_endpoint = BTreeMap::from([
        ("CODEBUFF_API_KEY".to_owned(), "key".to_owned()),
        (
            "CODEBUFF_API_URL".to_owned(),
            "http://www.codebuff.com".to_owned(),
        ),
    ]);
    assert_eq!(
        CodebuffSettings::resolve_with_auth_path(&invalid_endpoint, "relative-unused-path")
            .expect_err("authenticated HTTP must fail")
            .kind(),
        ErrorKind::Api
    );
}

#[test]
fn xdg_auth_file_is_bounded_zeroizing_and_prefers_default_profile() {
    let directory = TestDirectory::new("codebuff-settings");
    let auth_path = directory.path().join("xdg/manicode/credentials.json");
    fs::create_dir_all(auth_path.parent().expect("parent")).expect("create auth parent");
    fs::write(&auth_path, CREDENTIALS).expect("write fixture credentials");
    let environment = BTreeMap::from([
        (
            "HOME".to_owned(),
            directory.path().join("home").to_string_lossy().into_owned(),
        ),
        (
            "XDG_CONFIG_HOME".to_owned(),
            directory.path().join("xdg").to_string_lossy().into_owned(),
        ),
    ]);
    let settings = CodebuffSettings::resolve(&environment).expect("XDG credentials");
    assert_eq!(
        settings.credential_source(),
        CodebuffCredentialSource::AuthFile
    );
    let debug = format!("{settings:?}");
    assert!(!debug.contains("fixture-codebuff-file-token-canary"));
    assert!(!debug.contains("fixture-codebuff-top-level-token-canary"));
    assert!(!debug.contains(auth_path.to_string_lossy().as_ref()));

    let precedence = directory.path().join("precedence.json");
    fs::write(
        &precedence,
        br#"{"default":{"authToken":"invalid\nsecret"},"authToken":"valid-top-level"}"#,
    )
    .expect("write precedence fixture");
    assert_eq!(
        CodebuffSettings::resolve_with_auth_path(&BTreeMap::new(), &precedence)
            .expect_err("invalid selected default token must not fall back")
            .kind(),
        ErrorKind::MissingCredential
    );
    fs::write(
        &precedence,
        br#"{"default":{"authToken":"  'valid-default'  "},"authToken":"invalid\nsecret"}"#,
    )
    .expect("rewrite precedence fixture");
    CodebuffSettings::resolve_with_auth_path(&BTreeMap::new(), &precedence)
        .expect("valid default ignores lower-precedence top-level token");
    fs::write(
        &precedence,
        br#"{"default":{"authToken":"  ''  "},"authToken":"valid-top-level"}"#,
    )
    .expect("rewrite empty default fixture");
    CodebuffSettings::resolve_with_auth_path(&BTreeMap::new(), &precedence)
        .expect("cleaned-empty default falls back to top-level token");
}

#[test]
fn malformed_symlink_and_oversized_auth_files_fail_closed() {
    let directory = TestDirectory::new("codebuff-auth-errors");
    let malformed = directory.path().join("malformed.json");
    fs::write(&malformed, b"{not-json}").expect("write malformed");
    assert_eq!(
        CodebuffSettings::resolve_with_auth_path(&BTreeMap::new(), &malformed)
            .expect_err("malformed credentials")
            .kind(),
        ErrorKind::Parse
    );

    let valid = directory.path().join("valid.json");
    fs::write(&valid, CREDENTIALS).expect("write valid");
    let link = directory.path().join("credentials-link.json");
    symlink(&valid, &link).expect("create credential symlink");
    assert_eq!(
        CodebuffSettings::resolve_with_auth_path(&BTreeMap::new(), &link)
            .expect_err("credential symlink")
            .kind(),
        ErrorKind::Parse
    );

    let fifo = directory.path().join("credentials-fifo.json");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("create credential FIFO");
    let fifo_path = fifo.clone();
    let (sender, result_channel) = mpsc::channel();
    let reader = thread::spawn(move || {
        let kind = CodebuffSettings::resolve_with_auth_path(&BTreeMap::new(), &fifo_path)
            .expect_err("credential FIFO")
            .kind();
        sender.send(kind).expect("send FIFO result");
    });
    let fifo_result = result_channel.recv_timeout(Duration::from_millis(500));
    if fifo_result.is_err() {
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(&fifo)
            .expect("unblock a regressed FIFO reader");
        drop(writer);
    }
    reader.join().expect("FIFO reader thread");
    assert_eq!(
        fifo_result.expect("credential FIFO must be rejected without blocking"),
        ErrorKind::Parse
    );
    fs::remove_file(&fifo).expect("remove credential FIFO");

    let oversized = directory.path().join("oversized.json");
    fs::write(&oversized, vec![b'x'; 1024 * 1024 + 1]).expect("write oversized");
    assert_eq!(
        CodebuffSettings::resolve_with_auth_path(&BTreeMap::new(), &oversized)
            .expect_err("oversized credentials")
            .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn api_key_fetch_projects_credits_and_sends_no_subscription_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(
        &server,
        "account-a",
        ProviderSource::ApiKey,
        Duration::from_millis(50),
    );
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::ApiKey),
            timestamp("2026-08-30T12:00:00Z"),
        )
        .await
        .expect("usage fixture");

    assert_eq!(provider.descriptor().id, ProviderId::Codebuff);
    assert_eq!(used_percent(sample.primary()), Some(25.0));
    assert_eq!(
        sample.primary().and_then(oab_domain::RateWindow::resets_at),
        Some(timestamp("2026-09-01T00:00:00Z"))
    );
    assert!(sample.secondary().is_none());
    assert_eq!(detail(&sample, "Credits used"), Some("1,250"));
    assert_eq!(detail(&sample, "Credits total"), Some("5,000"));
    assert_eq!(detail(&sample, "Credits remaining"), Some("3,750"));
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("credit summary")
            .as_str(),
        "3,750 remaining · auto top-up"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/api/v1/usage");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-codebuff-request-key-canary")
    );
    assert_eq!(requests[0].header("content-type"), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(requests[0].body()).expect("request JSON")["fingerprintId"],
        "omarchy-ai-bar-usage"
    );
    assert!(!format!("{provider:?}").contains(KEY_CANARY));
    assert!(!format!("{sample:?}").contains(KEY_CANARY));
}

#[tokio::test]
async fn auth_file_fetch_adds_optional_subscription_window_and_identity() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(200, SUBSCRIPTION.to_vec()),
    ])
    .await;
    let sample = provider(
        &server,
        "account-a",
        ProviderSource::LocalData,
        Duration::from_millis(100),
    )
    .fetch_at(
        &context("account-a", ProviderSource::LocalData),
        timestamp("2026-08-30T12:00:00Z"),
    )
    .await
    .expect("usage plus subscription");

    assert_eq!(used_percent(sample.primary()), Some(25.0));
    assert_eq!(used_percent(sample.secondary()), Some(30.0));
    assert_eq!(
        sample
            .secondary()
            .and_then(oab_domain::RateWindow::duration)
            .map(oab_domain::WindowDuration::seconds),
        Some(7 * 24 * 60 * 60)
    );
    assert_eq!(
        sample
            .identity()
            .email()
            .map(oab_domain::BoundedText::as_str),
        Some("fixture-codebuff@example.com")
    );
    assert!(
        sample
            .identity()
            .login_method()
            .expect("plan summary")
            .as_str()
            .starts_with("Pro ")
    );
    assert_eq!(
        sample.subscription_expires_at(),
        Some(timestamp("2026-09-15T00:00:00Z"))
    );
    assert_eq!(detail(&sample, "Subscription status"), Some("active"));
    assert_eq!(
        server
            .requests()
            .iter()
            .map(oab_test_support::http::CapturedHttpRequest::target)
            .collect::<Vec<_>>(),
        vec!["/api/v1/usage", "/api/user/subscription"]
    );
}

#[tokio::test]
async fn optional_subscription_starts_concurrently_and_formats_like_baseline() {
    let subscription = br#"{
      "subscription":{"displayName":"pro team","status":"active"},
      "rateLimit":{"weeklyUsed":2100,"weeklyLimit":7000}
    }"#;
    let server = GatedHttpServer::start(200, USAGE.to_vec(), Some(subscription.to_vec())).await;
    let provider = provider_at(
        server.url(),
        "concurrent",
        ProviderSource::LocalData,
        Duration::from_secs(1),
        gated_config(),
    );
    let fetch_context = context("concurrent", ProviderSource::LocalData);
    let fetch = tokio::spawn(async move {
        provider
            .fetch_at(&fetch_context, timestamp("2026-08-30T12:00:00Z"))
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), server.wait_for_request_count(2))
        .await
        .expect("both requests must start while required usage is gated");
    let mut targets = server.targets();
    targets.sort_unstable();
    assert_eq!(targets, vec!["/api/user/subscription", "/api/v1/usage"]);
    server.release_usage();
    let sample = tokio::time::timeout(Duration::from_secs(1), fetch)
        .await
        .expect("concurrent fetch deadline")
        .expect("concurrent fetch task")
        .expect("concurrent usage");
    assert_eq!(used_percent(sample.primary()), Some(25.0));
    assert_eq!(used_percent(sample.secondary()), Some(30.0));
    assert_eq!(detail(&sample, "Credits used"), Some("1,250"));
    assert_eq!(detail(&sample, "Credits remaining"), Some("3,750"));
    assert_eq!(detail(&sample, "Weekly used"), Some("2,100"));
    assert_eq!(detail(&sample, "Weekly limit"), Some("7,000"));
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("formatted plan summary")
            .as_str(),
        "Pro Team · 3,750 remaining · auto top-up"
    );
}

#[tokio::test]
async fn required_usage_failure_cancels_in_flight_subscription() {
    let server = GatedHttpServer::start(503, b"required-usage-failure-canary".to_vec(), None).await;
    let provider = provider_at(
        server.url(),
        "required-failure",
        ProviderSource::LocalData,
        Duration::from_secs(2),
        gated_config(),
    );
    let fetch_context = context("required-failure", ProviderSource::LocalData);
    let fetch = tokio::spawn(async move {
        provider
            .fetch_at(&fetch_context, timestamp("2026-08-30T12:00:00Z"))
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), server.wait_for_request_count(2))
        .await
        .expect("required and optional requests start together");
    server.release_usage();
    let error = tokio::time::timeout(Duration::from_secs(1), fetch)
        .await
        .expect("required failure must not await optional grace")
        .expect("required failure task")
        .expect_err("required usage failure");
    assert_eq!(error.kind(), ErrorKind::ProviderUnavailable);
    assert!(!format!("{error:?}").contains("required-usage-failure-canary"));
    tokio::time::timeout(Duration::from_secs(1), server.wait_for_subscription_close())
        .await
        .expect("subscription connection closes when required usage fails");
}

#[tokio::test]
async fn optional_subscription_failure_and_timeout_preserve_required_usage() {
    let failure = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::new(503, b"provider-response-canary".to_vec()),
    ])
    .await;
    let sample = provider(
        &failure,
        "account-a",
        ProviderSource::LocalData,
        Duration::from_millis(50),
    )
    .fetch_at(
        &context("account-a", ProviderSource::LocalData),
        timestamp("2026-08-30T12:00:00Z"),
    )
    .await
    .expect("optional HTTP failure is ignored");
    assert_eq!(used_percent(sample.primary()), Some(25.0));
    assert!(sample.secondary().is_none());
    assert!(!format!("{sample:?}").contains("provider-response-canary"));

    let stalled = FakeHttpServer::start([
        FakeHttpResponse::new(200, USAGE.to_vec()),
        FakeHttpResponse::stall(),
    ])
    .await;
    let started = Instant::now();
    let sample = provider(
        &stalled,
        "account-a",
        ProviderSource::LocalData,
        Duration::from_millis(20),
    )
    .fetch_at(
        &context("account-a", ProviderSource::LocalData),
        timestamp("2026-08-30T12:00:00Z"),
    )
    .await
    .expect("optional timeout is ignored");
    assert_eq!(used_percent(sample.primary()), Some(25.0));
    assert!(started.elapsed() < Duration::from_millis(200));
}

#[tokio::test]
async fn malformed_auth_and_context_boundaries_are_stable_and_redacted() {
    let unauthorized = FakeHttpServer::start([FakeHttpResponse::new(
        401,
        b"fixture-auth-response-canary".to_vec(),
    )])
    .await;
    let error = provider(
        &unauthorized,
        "account-a",
        ProviderSource::ApiKey,
        Duration::from_millis(50),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ApiKey),
        timestamp("2026-08-30T12:00:00Z"),
    )
    .await
    .expect_err("unauthorized usage");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    assert!(!format!("{error:?}").contains("fixture-auth-response-canary"));
    assert!(!format!("{error:?}").contains(KEY_CANARY));

    let malformed = FakeHttpServer::start([FakeHttpResponse::new(
        200,
        b"{not-json-response-canary}".to_vec(),
    )])
    .await;
    let error = provider(
        &malformed,
        "account-a",
        ProviderSource::ApiKey,
        Duration::from_millis(50),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ApiKey),
        timestamp("2026-08-30T12:00:00Z"),
    )
    .await
    .expect_err("malformed usage");
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(!format!("{error:?}").contains("not-json-response-canary"));

    let isolated = FakeHttpServer::start([]).await;
    let provider = provider(
        &isolated,
        "account-a",
        ProviderSource::ApiKey,
        Duration::from_millis(50),
    );
    for wrong in [
        context("account-b", ProviderSource::ApiKey),
        context("account-a", ProviderSource::LocalData),
    ] {
        assert_eq!(
            provider
                .fetch_at(&wrong, timestamp("2026-08-30T12:00:00Z"))
                .await
                .expect_err("scope/source mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(isolated.requests().is_empty());
}

#[tokio::test]
async fn string_numbers_numeric_reset_and_degenerate_quota_match_baseline() {
    let payload = br#"{
      "usage":"12",
      "quota":"100",
      "remainingBalance":"88",
      "next_quota_reset":1788220800000
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, payload.to_vec())]).await;
    let sample = provider(
        &server,
        "account-a",
        ProviderSource::ApiKey,
        Duration::from_millis(50),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ApiKey),
        timestamp("2026-08-30T12:00:00Z"),
    )
    .await
    .expect("string-encoded values");
    assert_eq!(used_percent(sample.primary()), Some(12.0));
    assert_eq!(
        sample.primary().and_then(oab_domain::RateWindow::resets_at),
        Some(timestamp("2026-09-01T00:00:00Z"))
    );

    let degenerate =
        FakeHttpServer::start([FakeHttpResponse::new(200, br#"{"usage":42}"#.to_vec())]).await;
    let sample = provider(
        &degenerate,
        "account-a",
        ProviderSource::ApiKey,
        Duration::from_millis(50),
    )
    .fetch_at(
        &context("account-a", ProviderSource::ApiKey),
        timestamp("2026-08-30T12:00:00Z"),
    )
    .await
    .expect("degenerate quota");
    assert_eq!(used_percent(sample.primary()), Some(100.0));
}

struct GatedHttpServer {
    origin: String,
    shared: Arc<GatedServerShared>,
    task: JoinHandle<()>,
}

struct GatedServerShared {
    state: Mutex<GatedServerState>,
    requests_changed: Notify,
    usage_release: Notify,
    subscription_closed: Notify,
    cancellation: CancellationToken,
    usage_status: u16,
    usage_body: Vec<u8>,
    subscription_body: Option<Vec<u8>>,
}

#[derive(Default)]
struct GatedServerState {
    targets: Vec<String>,
    subscription_closed: bool,
}

impl GatedHttpServer {
    async fn start(
        usage_status: u16,
        usage_body: Vec<u8>,
        subscription_body: Option<Vec<u8>>,
    ) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("gated server binds loopback");
        let address = listener.local_addr().expect("gated server address");
        let shared = Arc::new(GatedServerShared {
            state: Mutex::new(GatedServerState::default()),
            requests_changed: Notify::new(),
            usage_release: Notify::new(),
            subscription_closed: Notify::new(),
            cancellation: CancellationToken::new(),
            usage_status,
            usage_body,
            subscription_body,
        });
        let server_shared = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            serve_gated(listener, server_shared).await;
        });
        Self {
            origin: format!("http://{address}"),
            shared,
            task,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&self.origin)
            .expect("gated origin URL")
            .join("/")
            .expect("gated root URL")
    }

    fn targets(&self) -> Vec<String> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .targets
            .clone()
    }

    async fn wait_for_request_count(&self, count: usize) {
        loop {
            let notified = self.shared.requests_changed.notified();
            if self
                .shared
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .targets
                .len()
                >= count
            {
                return;
            }
            notified.await;
        }
    }

    fn release_usage(&self) {
        self.shared.usage_release.notify_one();
    }

    async fn wait_for_subscription_close(&self) {
        loop {
            let notified = self.shared.subscription_closed.notified();
            if self
                .shared
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .subscription_closed
            {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for GatedHttpServer {
    fn drop(&mut self) {
        self.shared.cancellation.cancel();
        self.task.abort();
    }
}

async fn serve_gated(listener: TcpListener, shared: Arc<GatedServerShared>) {
    loop {
        let accepted = tokio::select! {
            () = shared.cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _address)) = accepted else {
            break;
        };
        let connection_shared = Arc::clone(&shared);
        tokio::spawn(async move {
            handle_gated_connection(stream, connection_shared).await;
        });
    }
}

async fn handle_gated_connection(mut stream: TcpStream, shared: Arc<GatedServerShared>) {
    let Some(target) = read_gated_request_target(&mut stream).await else {
        return;
    };
    {
        let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.targets.push(target.clone());
    }
    shared.requests_changed.notify_waiters();

    match target.as_str() {
        "/api/v1/usage" => {
            tokio::select! {
                () = shared.cancellation.cancelled() => {}
                () = shared.usage_release.notified() => {
                    write_gated_response(&mut stream, shared.usage_status, &shared.usage_body).await;
                }
            }
        }
        "/api/user/subscription" => {
            if let Some(body) = &shared.subscription_body {
                write_gated_response(&mut stream, 200, body).await;
                return;
            }
            let mut buffer = [0_u8; 64];
            let closed = loop {
                let read = tokio::select! {
                    () = shared.cancellation.cancelled() => break false,
                    read = stream.read(&mut buffer) => read,
                };
                match read {
                    Ok(0) | Err(_) => break true,
                    Ok(_) => {}
                }
            };
            if closed {
                shared
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .subscription_closed = true;
                shared.subscription_closed.notify_waiters();
            }
        }
        _ => write_gated_response(&mut stream, 404, &[]).await,
    }
}

async fn read_gated_request_target(stream: &mut TcpStream) -> Option<String> {
    const MAX_HEAD_BYTES: usize = 64 * 1024;
    const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let head_end = loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if bytes.len() > MAX_HEAD_BYTES {
            return None;
        }
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
    };
    let head = std::str::from_utf8(&bytes[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_ascii_whitespace();
    let _method = request_line.next()?;
    let target = request_line.next()?.to_owned();
    let _version = request_line.next()?;
    if request_line.next().is_some() {
        return None;
    }
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(Some(0), |(_, value)| value.trim().parse::<usize>().ok())?;
    if content_length > MAX_BODY_BYTES {
        return None;
    }
    let received_body = bytes.len().saturating_sub(head_end);
    if received_body < content_length {
        let mut remaining = vec![0_u8; content_length - received_body];
        stream.read_exact(&mut remaining).await.ok()?;
    }
    Some(target)
}

async fn write_gated_response(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Response",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(head.as_bytes()).await.is_ok() {
        let _ignored = stream.write_all(body).await;
        let _ignored = stream.shutdown().await;
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-{label}-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
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
