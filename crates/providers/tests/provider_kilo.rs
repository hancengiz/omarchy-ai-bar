use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::kilo::{
    KiloCliCredential, KiloProvider, KiloUsageScope, resolve_api_credential,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

const USAGE: &[u8] = include_bytes!("../../../fixtures/providers/kilo/usage.json");
const FALLBACK: &[u8] = include_bytes!("../../../fixtures/providers/kilo/fallback.json");
const NO_DATA: &[u8] = include_bytes!("../../../fixtures/providers/kilo/no_data.json");
const ORGANIZATIONS: &[u8] = include_bytes!("../../../fixtures/providers/kilo/organizations.json");
const PROFILE: &[u8] = include_bytes!("../../../fixtures/providers/kilo/profile.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/kilo/malformed.json");
const API_TOKEN_CANARY: &str = "fixture-kilo-api-token";
const CLI_TOKEN_CANARY: &str = "fixture-kilo-cli-token";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

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
    scope_for(ProviderId::Kilo, account)
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(500),
        2 * 1024 * 1024,
        0,
        RetryPolicy::none(),
    )
    .expect("fixture transport config")
}

fn provider_with_credential(
    server: &FakeHttpServer,
    account: &str,
    source: ProviderSource,
    usage_scope: KiloUsageScope,
    credential: ApiKeyCredential,
) -> KiloProvider {
    let account_scope = scope(account);
    let usage_client = FixedApiClient::new_bearer(
        account_scope.clone(),
        server.url("/api/trpc/"),
        EndpointClass::LoopbackDevelopment,
        credential.clone(),
        config(),
    )
    .expect("usage client");
    let profile_client = FixedApiClient::new_bearer(
        account_scope,
        server.url("/api/"),
        EndpointClass::LoopbackDevelopment,
        credential,
        config(),
    )
    .expect("profile client");
    let usage_client = if source == ProviderSource::ApiKey {
        usage_client
    } else {
        usage_client.with_source(source).expect("usage source")
    };
    let profile_client = if source == ProviderSource::ApiKey {
        profile_client
    } else {
        profile_client.with_source(source).expect("profile source")
    };
    KiloProvider::from_clients(usage_client, profile_client, usage_scope).expect("Kilo provider")
}

fn provider(
    server: &FakeHttpServer,
    account: &str,
    source: ProviderSource,
    usage_scope: KiloUsageScope,
) -> KiloProvider {
    let token = if source == ProviderSource::Cli {
        CLI_TOKEN_CANARY
    } else {
        API_TOKEN_CANARY
    };
    provider_with_credential(
        server,
        account,
        source,
        usage_scope,
        ApiKeyCredential::new(token).expect("fixture credential"),
    )
}

fn percent(window: &oab_domain::RateWindow) -> f64 {
    window.used_percent().expect("known fixture usage").get()
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-kilo-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temporary root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn write_auth(root: &Path, token: &str) -> PathBuf {
    let path = root.join("kilo/auth.json");
    fs::create_dir_all(path.parent().expect("auth parent")).expect("create auth directory");
    fs::write(&path, format!(r#"{{"kilo":{{"access":"{token}"}}}}"#)).expect("write auth fixture");
    path
}

#[test]
fn credentials_use_exact_source_precedence_and_redact_secrets_and_paths() {
    let temp = TempDirectory::new();
    let xdg = temp.path().join("xdg-data");
    let home = temp.path().join("home");
    let xdg_path = write_auth(&xdg, CLI_TOKEN_CANARY);
    let home_path = write_auth(&home.join(".local/share"), "lower-precedence-file-token");
    let environment = BTreeMap::from([
        (
            "KILO_API_KEY".to_owned(),
            format!("  '{API_TOKEN_CANARY}'  "),
        ),
        (
            "XDG_DATA_HOME".to_owned(),
            xdg.to_string_lossy().into_owned(),
        ),
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
    ]);

    let api = resolve_api_credential(&environment).expect("API credential");
    assert!(!format!("{api:?}").contains(API_TOKEN_CANARY));
    let cli = KiloCliCredential::resolve(&environment).expect("CLI credential");
    assert_eq!(cli.auth_path(), xdg_path);
    assert_ne!(cli.auth_path(), home_path);
    let debug = format!("{cli:?}");
    assert!(!debug.contains(CLI_TOKEN_CANARY));
    assert!(!debug.contains(xdg.to_string_lossy().as_ref()));

    let home_only = BTreeMap::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);
    let home_cli = KiloCliCredential::resolve(&home_only).expect("HOME auth fallback");
    assert_eq!(home_cli.auth_path(), home_path);

    let missing_api = BTreeMap::from([
        (
            "XDG_DATA_HOME".to_owned(),
            xdg.to_string_lossy().into_owned(),
        ),
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
    ]);
    assert_eq!(
        KiloProvider::resolve(
            scope("api-only"),
            ProviderSource::ApiKey,
            &missing_api,
            KiloUsageScope::Personal,
        )
        .expect_err("API mode never reads CLI state")
        .kind(),
        ErrorKind::MissingCredential
    );

    let missing_cli = BTreeMap::from([("KILO_API_KEY".to_owned(), API_TOKEN_CANARY.to_owned())]);
    assert_eq!(
        KiloProvider::resolve(
            scope("cli-only"),
            ProviderSource::Cli,
            &missing_cli,
            KiloUsageScope::Personal,
        )
        .expect_err("CLI mode never reads the API key")
        .kind(),
        ErrorKind::MissingCredential
    );
}

#[test]
fn present_invalid_cli_tokens_are_parse_errors() {
    let temp = TempDirectory::new();
    let data = temp.path().join("data");
    let auth_path = write_auth(&data, CLI_TOKEN_CANARY);
    let environment = BTreeMap::from([(
        "XDG_DATA_HOME".to_owned(),
        data.to_string_lossy().into_owned(),
    )]);
    let cases = [
        ("blank", "   ".to_owned()),
        ("oversized", "x".repeat(16 * 1024 + 1)),
        ("line-breaking", "token\r\ncontinuation".to_owned()),
    ];
    for (label, token) in cases {
        let document = serde_json::to_vec(&serde_json::json!({
            "kilo": {"access": token}
        }))
        .expect("auth JSON");
        fs::write(&auth_path, document).expect("write invalid auth token");
        assert_eq!(
            KiloCliCredential::resolve(&environment)
                .expect_err(label)
                .kind(),
            ErrorKind::Parse,
            "{label}"
        );
    }
}

#[tokio::test]
async fn api_fixture_normalizes_credits_pass_bonus_reset_plan_and_wire_contract() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(
        &server,
        "api-account",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    );
    let fetched_at = timestamp(1_788_071_400);
    let sample = provider
        .fetch_at(&context("api-account", ProviderSource::ApiKey), fetched_at)
        .await
        .expect("Kilo usage");

    assert_eq!(provider.descriptor().id, ProviderId::Kilo);
    assert_eq!(sample.fetched_at(), fetched_at);
    assert_percent(percent(sample.primary().expect("credits")), 20.0);
    assert_eq!(
        sample
            .primary()
            .expect("credits")
            .reset_description()
            .expect("credit detail")
            .as_str(),
        "6/30 credits"
    );
    assert_percent(
        percent(sample.secondary().expect("Kilo Pass")),
        9.5 / 59.0 * 100.0,
    );
    assert_eq!(
        sample
            .secondary()
            .expect("Kilo Pass")
            .reset_description()
            .expect("pass detail")
            .as_str(),
        "$9.50 / $49.00 (+ $10.00 bonus)"
    );
    assert_eq!(
        sample.secondary().expect("Kilo Pass").resets_at(),
        Some(Timestamp::parse("2026-09-28T04:00:00Z").expect("reset"))
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("plan/activity")
            .as_str(),
        "Pro · Auto top-up: visa"
    );
    assert_eq!(sample.provenance()[0].source(), "kilo");
    assert_eq!(sample.provenance()[0].strategy(), "api");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method(), "GET");
    let url = url::Url::parse(&format!("http://fixture{}", request.target())).expect("request URL");
    assert_eq!(
        url.path(),
        "/api/trpc/user.getCreditBlocks,kiloPass.getState,user.getAutoTopUpPaymentMethod"
    );
    let query = url.query_pairs().collect::<BTreeMap<_, _>>();
    assert_eq!(query.get("batch").map(AsRef::as_ref), Some("1"));
    let input: serde_json::Value =
        serde_json::from_str(query.get("input").expect("batch input").as_ref())
            .expect("batch JSON");
    assert!(
        input
            .get("0")
            .and_then(|value| value.get("json"))
            .is_some_and(serde_json::Value::is_null)
    );
    assert!(
        input
            .get("1")
            .and_then(|value| value.get("json"))
            .is_some_and(serde_json::Value::is_null)
    );
    assert!(
        input
            .get("2")
            .and_then(|value| value.get("json"))
            .is_some_and(serde_json::Value::is_null)
    );
    assert_eq!(
        request.header("authorization"),
        Some("Bearer fixture-kilo-api-token")
    );
    assert_eq!(request.header("accept"), Some("application/json"));
    assert!(request.header("x-kilocode-organizationid").is_none());
}

#[tokio::test]
async fn cli_auth_file_drives_an_independent_cli_source_request() {
    let temp = TempDirectory::new();
    let xdg = temp.path().join("data");
    write_auth(&xdg, CLI_TOKEN_CANARY);
    let environment = BTreeMap::from([(
        "XDG_DATA_HOME".to_owned(),
        xdg.to_string_lossy().into_owned(),
    )]);
    let cli = KiloCliCredential::resolve(&environment).expect("CLI auth file");
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, NO_DATA.to_vec())]).await;
    let provider = provider_with_credential(
        &server,
        "cli-account",
        ProviderSource::Cli,
        KiloUsageScope::Personal,
        cli.into_transport_credential(),
    );
    let sample = provider
        .fetch_at(&context("cli-account", ProviderSource::Cli), timestamp(10))
        .await
        .expect("CLI source usage");

    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.identity().login_method().is_none());
    assert_eq!(sample.provenance()[0].strategy(), "cli");
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Bearer fixture-kilo-cli-token")
    );
}

#[tokio::test]
async fn organization_scope_is_exact_and_fallback_shapes_remain_compatible() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, FALLBACK.to_vec())]).await;
    let usage_scope = KiloUsageScope::organization("org-42", "Acme").expect("organization scope");
    assert_eq!(usage_scope.scope_identifier(), "org:org-42");
    assert_eq!(usage_scope.display_name(), "Acme");
    let provider = provider(&server, "org-account", ProviderSource::ApiKey, usage_scope);
    let sample = provider
        .fetch_at(
            &context("org-account", ProviderSource::ApiKey),
            timestamp(20),
        )
        .await
        .expect("organization usage");

    assert_percent(percent(sample.primary().expect("credits")), 25.0);
    assert_eq!(
        sample
            .primary()
            .expect("credits")
            .reset_description()
            .expect("credit detail")
            .as_str(),
        "25/100 credits"
    );
    assert_eq!(
        sample
            .secondary()
            .expect("pass")
            .reset_description()
            .expect("pass detail")
            .as_str(),
        "$3.50 / $19.00 (+ $9.50 bonus)"
    );
    assert_eq!(
        sample.identity().login_method().expect("identity").as_str(),
        "Starter · Auto top-up: $50"
    );
    assert_eq!(
        server.requests()[0].header("x-kilocode-organizationid"),
        Some("org-42")
    );
}

#[tokio::test]
async fn required_and_optional_trpc_errors_keep_their_contract() {
    let required = br#"[
      {"result":{"data":{"json":{"creditsUsed":10,"creditsRemaining":90}}}},
      {"error":{"json":{"message":"Unauthorized","data":{"code":"UNAUTHORIZED"}}}}
    ]"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, required.to_vec())]).await;
    assert_eq!(
        provider(
            &server,
            "required-error",
            ProviderSource::ApiKey,
            KiloUsageScope::Personal,
        )
        .fetch_at(
            &context("required-error", ProviderSource::ApiKey),
            timestamp(30),
        )
        .await
        .expect_err("required tRPC error")
        .kind(),
        ErrorKind::AuthenticationExpired
    );

    let optional = br#"[
      {"result":{"data":{"json":{"creditsUsed":10,"creditsRemaining":90}}}},
      {"result":{"data":{"json":{"planName":"Starter"}}}},
      {"error":{"json":{"message":"Internal server error","data":{"code":"INTERNAL_SERVER_ERROR"}}}}
    ]"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, optional.to_vec())]).await;
    let sample = provider(
        &server,
        "optional-error",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    )
    .fetch_at(
        &context("optional-error", ProviderSource::ApiKey),
        timestamp(31),
    )
    .await
    .expect("optional tRPC degradation");
    assert_percent(percent(sample.primary().expect("credits")), 10.0);
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Starter"
    );

    let malformed_optional = br#"[
      {"result":{"data":{"json":{"creditsUsed":20,"creditsRemaining":80}}}},
      {"result":{"data":{"json":{"planName":"Pro"}}}},
      {"result":{"data":{"json":{"enabled":{"unexpected":true},"paymentMethod":["visa"]}}}}
    ]"#;
    let server =
        FakeHttpServer::start([FakeHttpResponse::new(200, malformed_optional.to_vec())]).await;
    let sample = provider(
        &server,
        "malformed-optional",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    )
    .fetch_at(
        &context("malformed-optional", ProviderSource::ApiKey),
        timestamp(32),
    )
    .await
    .expect("malformed optional enrichment degrades");
    assert_percent(percent(sample.primary().expect("credits")), 20.0);
    assert_eq!(
        sample.identity().login_method().expect("plan").as_str(),
        "Pro"
    );
}

#[tokio::test]
async fn http_statuses_malformed_and_response_bounds_are_classified_without_body_text() {
    for (status, expected) in [
        (401, ErrorKind::AuthenticationExpired),
        (403, ErrorKind::AuthenticationExpired),
        (404, ErrorKind::Api),
        (503, ErrorKind::ProviderUnavailable),
    ] {
        let server = FakeHttpServer::start([FakeHttpResponse::new(
            status,
            b"credential-adjacent provider body".to_vec(),
        )])
        .await;
        let error = provider(
            &server,
            "status-account",
            ProviderSource::ApiKey,
            KiloUsageScope::Personal,
        )
        .fetch_at(
            &context("status-account", ProviderSource::ApiKey),
            timestamp(40),
        )
        .await
        .expect_err("status failure");
        assert_eq!(error.kind(), expected, "status {status}");
        assert!(!format!("{error:?}").contains("credential-adjacent"));
    }

    let server = FakeHttpServer::start([FakeHttpResponse::new(200, MALFORMED.to_vec())]).await;
    assert_eq!(
        provider(
            &server,
            "malformed",
            ProviderSource::ApiKey,
            KiloUsageScope::Personal,
        )
        .fetch_at(&context("malformed", ProviderSource::ApiKey), timestamp(41))
        .await
        .expect_err("malformed tRPC shape")
        .kind(),
        ErrorKind::Parse
    );

    let oversized = vec![b' '; 2 * 1024 * 1024 + 1];
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, oversized)]).await;
    assert_eq!(
        provider(
            &server,
            "oversized",
            ProviderSource::ApiKey,
            KiloUsageScope::Personal,
        )
        .fetch_at(&context("oversized", ProviderSource::ApiKey), timestamp(42))
        .await
        .expect_err("oversized response")
        .kind(),
        ErrorKind::Parse
    );
}

#[tokio::test]
async fn schema_collection_bounds_reject_oversized_batch_and_nested_blocks() {
    let four_entries = br#"[
      {"result":{"data":{"json":{}}}},
      {"result":{"data":{"json":{}}}},
      {"result":{"data":{"json":{}}}},
      {"result":{"data":{"json":{}}}}
    ]"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, four_entries.to_vec())]).await;
    assert_eq!(
        provider(
            &server,
            "wide-batch",
            ProviderSource::ApiKey,
            KiloUsageScope::Personal,
        )
        .fetch_at(
            &context("wide-batch", ProviderSource::ApiKey),
            timestamp(50)
        )
        .await
        .expect_err("top-level bound")
        .kind(),
        ErrorKind::Parse
    );

    let blocks = std::iter::repeat_n(serde_json::json!({"used": 1}), 1_025).collect::<Vec<_>>();
    let response = serde_json::to_vec(&serde_json::json!([
        {"result": {"data": {"json": {"blocks": blocks}}}}
    ]))
    .expect("bounded JSON fixture");
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, response)]).await;
    assert_eq!(
        provider(
            &server,
            "wide-blocks",
            ProviderSource::ApiKey,
            KiloUsageScope::Personal,
        )
        .fetch_at(
            &context("wide-blocks", ProviderSource::ApiKey),
            timestamp(51)
        )
        .await
        .expect_err("nested collection bound")
        .kind(),
        ErrorKind::Parse
    );
}

#[test]
fn cli_reader_rejects_unsafe_roots_symlinks_non_files_and_oversized_documents() {
    for unsafe_root in ["relative/data", "/tmp/../escape", "/tmp/./ambiguous"] {
        let environment = BTreeMap::from([("XDG_DATA_HOME".to_owned(), unsafe_root.to_owned())]);
        assert_eq!(
            KiloCliCredential::resolve(&environment)
                .expect_err("unsafe XDG root")
                .kind(),
            ErrorKind::Api
        );

        let environment = BTreeMap::from([("HOME".to_owned(), unsafe_root.to_owned())]);
        assert_eq!(
            KiloCliCredential::resolve(&environment)
                .expect_err("unsafe HOME root")
                .kind(),
            ErrorKind::Api
        );
    }

    let temp = TempDirectory::new();
    let data = temp.path().join("data");
    let target_root = temp.path().join("target");
    let target = write_auth(&target_root, CLI_TOKEN_CANARY);
    let symlink_path = data.join("kilo/auth.json");
    fs::create_dir_all(symlink_path.parent().expect("symlink parent")).expect("create parent");
    symlink(&target, &symlink_path).expect("create auth symlink");
    let environment = BTreeMap::from([(
        "XDG_DATA_HOME".to_owned(),
        data.to_string_lossy().into_owned(),
    )]);
    assert_eq!(
        KiloCliCredential::resolve(&environment)
            .expect_err("auth symlink")
            .kind(),
        ErrorKind::Parse
    );

    fs::remove_file(&symlink_path).expect("remove symlink");
    fs::create_dir(&symlink_path).expect("create non-file auth path");
    assert_eq!(
        KiloCliCredential::resolve(&environment)
            .expect_err("auth directory")
            .kind(),
        ErrorKind::Parse
    );
    fs::remove_dir(&symlink_path).expect("remove auth directory");
    mkfifo(&symlink_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("create auth FIFO");
    let fifo_environment = environment.clone();
    let (sender, result_channel) = mpsc::channel();
    let reader = thread::spawn(move || {
        let kind = KiloCliCredential::resolve(&fifo_environment)
            .expect_err("auth FIFO")
            .kind();
        sender.send(kind).expect("send FIFO result");
    });
    let fifo_result = result_channel.recv_timeout(Duration::from_millis(500));
    if fifo_result.is_err() {
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(&symlink_path)
            .expect("unblock a regressed FIFO reader");
        drop(writer);
    }
    reader.join().expect("FIFO reader thread");
    assert_eq!(
        fifo_result.expect("auth FIFO must be rejected without blocking"),
        ErrorKind::Parse
    );
    fs::remove_file(&symlink_path).expect("remove auth FIFO");

    fs::write(&symlink_path, vec![b'x'; 256 * 1024 + 1]).expect("write oversized auth");
    assert_eq!(
        KiloCliCredential::resolve(&environment)
            .expect_err("oversized auth")
            .kind(),
        ErrorKind::Parse
    );

    fs::write(&symlink_path, b"not-json").expect("write malformed auth");
    assert_eq!(
        KiloCliCredential::resolve(&environment)
            .expect_err("malformed auth")
            .kind(),
        ErrorKind::Parse
    );

    let mut permissions = fs::metadata(&symlink_path)
        .expect("auth metadata")
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&symlink_path, permissions).expect("restore safe fixture permissions");
}

#[tokio::test]
async fn organization_discovery_uses_trpc_then_only_404_profile_fallback() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, ORGANIZATIONS.to_vec())]).await;
    let trpc_provider = provider(
        &server,
        "organizations",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    );
    let organizations = trpc_provider
        .fetch_organizations(&context("organizations", ProviderSource::ApiKey))
        .await
        .expect("tRPC organizations");
    assert_eq!(organizations.len(), 2);
    assert_eq!(organizations[0].id(), "org-alpha");
    assert_eq!(organizations[0].name(), "Alpha");
    assert_eq!(organizations[0].role(), Some("owner"));
    assert_eq!(server.requests().len(), 1);
    assert!(
        server.requests()[0]
            .target()
            .starts_with("/api/trpc/user.getOrganizations?batch=1&input=")
    );

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(404, Vec::new()),
        FakeHttpResponse::new(200, PROFILE.to_vec()),
    ])
    .await;
    let profile_provider = provider(
        &server,
        "profile-fallback",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    );
    let organizations = profile_provider
        .fetch_organizations(&context("profile-fallback", ProviderSource::ApiKey))
        .await
        .expect("profile fallback");
    assert_eq!(organizations.len(), 1);
    assert_eq!(organizations[0].id(), "org-profile");
    assert_eq!(organizations[0].role(), None);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].target(), "/api/profile");

    let server = FakeHttpServer::start([
        FakeHttpResponse::new(403, b"private denial body".to_vec()),
        FakeHttpResponse::new(200, PROFILE.to_vec()),
    ])
    .await;
    let denied_provider = provider(
        &server,
        "organization-denied",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    );
    assert_eq!(
        denied_provider
            .fetch_organizations(&context("organization-denied", ProviderSource::ApiKey))
            .await
            .expect_err("403 must not activate profile fallback")
            .kind(),
        ErrorKind::AuthenticationExpired
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn account_and_source_mismatches_fail_before_network_and_do_not_cross_forward() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, USAGE.to_vec())]).await;
    let provider = provider(
        &server,
        "account-a",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    );
    assert_eq!(
        provider
            .fetch_at(&context("account-b", ProviderSource::ApiKey), timestamp(60))
            .await
            .expect_err("cross-account context")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        provider
            .fetch_at(&context("account-a", ProviderSource::Cli), timestamp(61))
            .await
            .expect_err("cross-source context")
            .kind(),
        ErrorKind::Api
    );
    assert!(server.requests().is_empty());

    let wrong_scope = scope_for(ProviderId::Amp, "wrong-provider");
    assert_eq!(
        KiloProvider::new_api_key(
            wrong_scope,
            ApiKeyCredential::new(API_TOKEN_CANARY).expect("credential"),
            KiloUsageScope::Personal,
        )
        .expect_err("wrong provider")
        .kind(),
        ErrorKind::Api
    );
}

#[tokio::test]
async fn cancellation_interrupts_a_stalled_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let provider = provider(
        &server,
        "cancelled",
        ProviderSource::ApiKey,
        KiloUsageScope::Personal,
    );
    let cancellation = CancellationToken::new();
    let context = ProviderContext::new(
        scope("cancelled"),
        ProviderSource::ApiKey,
        cancellation.clone(),
    );
    let task = tokio::spawn(async move { provider.fetch_at(&context, timestamp(70)).await });
    server.wait_for_request_count(1).await;
    cancellation.cancel();
    let error = task
        .await
        .expect("fetch task")
        .expect_err("cancelled request");
    assert_eq!(error.kind(), ErrorKind::Network);
}
