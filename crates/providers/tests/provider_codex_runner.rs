use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oab_domain::{
    AccountKey, AccountScope, ProviderId, ProviderInstanceId, Timestamp, WindowDuration,
};
use oab_providers::executable::{ExecutablePath, resolve_executable};
use oab_providers::providers::codex::{CodexCredentialError, CodexSourceAttempt, CodexSourceMode};
use oab_providers::providers::codex_files::CodexCredentialPaths;
use oab_providers::providers::codex_http::CodexHttpRoutes;
use oab_providers::providers::codex_provider::{
    CodexAccountSelection, CodexAttemptOutcome, CodexAttemptRunner, CodexCoordinator,
    CodexCoordinatorError, CodexCoordinatorSettings, CodexManagedWorkspaceId,
};
use oab_providers::providers::codex_runner::CodexProductionRunner;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const FETCHED_AT: i64 = 1_800_000_000;
const PAT_SECRET: &str = "runner-pat-secret-canary";
const OAUTH_SECRET_CLAIM: &str = "runner-oauth-secret-canary";

struct CredentialFixture {
    temporary: TempDir,
}

impl CredentialFixture {
    fn new() -> Self {
        Self {
            temporary: tempfile::tempdir().expect("temporary credential home"),
        }
    }

    fn home(&self) -> &Path {
        self.temporary.path()
    }

    fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.home().join(relative)
    }

    fn write(&self, relative: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(path, contents).expect("fixture file");
    }

    fn paths(&self, codex_home: Option<&OsStr>) -> CodexCredentialPaths {
        CodexCredentialPaths::resolve(self.home(), codex_home, None)
            .expect("credential path fixture")
    }
}

struct FakeCli {
    _temporary: TempDir,
    executable: ExecutablePath,
    environment: PathBuf,
    marker: PathBuf,
}

impl FakeCli {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary CLI fixture");
        let script = temporary.path().join("codex-runner-fixture");
        let environment = temporary.path().join("environment");
        let marker = temporary.path().join("spawned");
        let source = format!(
            r#"#!/bin/sh
set -eu
printf '%s\n' spawned > {marker}
printf 'HOME=%s\nCODEX_HOME=%s\n' "${{HOME-}}" "${{CODEX_HOME-}}" > {environment}
IFS= read -r initialize
printf '%s\n' '{{"id":1,"result":{{}}}}'
IFS= read -r initialized
IFS= read -r rate
printf '%s\n' '{{"id":2,"result":{{"rateLimits":{{"primary":{{"usedPercent":15,"windowDurationMins":300,"resetsAt":1800003600}},"planType":"plus"}}}}}}'
IFS= read -r account
printf '%s\n' '{{"id":3,"result":{{"account":{{"type":"ChatGPT","email":"cli-owner@example.test","planType":"plus"}}}}}}'
while IFS= read -r ignored; do :; done
"#,
            marker = shell_quote(&marker),
            environment = shell_quote(&environment),
        );
        fs::write(&script, source).expect("CLI fixture script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .expect("executable CLI fixture");
        let executable = resolve_executable("codex-runner-fixture", script.to_str(), None, &[])
            .expect("valid executable lookup")
            .expect("fixture executable");
        Self {
            _temporary: temporary,
            executable,
            environment,
            marker,
        }
    }

    fn executable(&self) -> ExecutablePath {
        self.executable.clone()
    }

    fn was_spawned(&self) -> bool {
        self.marker.exists()
    }

    fn captured_environment(&self) -> String {
        fs::read_to_string(&self.environment).expect("captured CLI environment")
    }
}

fn shell_quote(path: &Path) -> String {
    format!(
        "'{}'",
        path.to_str()
            .expect("UTF-8 fixture path")
            .replace('\'', r#"'\"'\"'"#)
    )
}

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("codex-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn foreign_scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Claude,
        ProviderInstanceId::new("claude-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn timestamp() -> Timestamp {
    Timestamp::from_unix_timestamp(FETCHED_AT).expect("fixture timestamp")
}

fn transport() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(500),
        Duration::from_secs(2),
        1024 * 1024,
        3,
        RetryPolicy::none(),
    )
    .expect("fixture transport")
}

fn routes(server: &FakeHttpServer) -> CodexHttpRoutes {
    CodexHttpRoutes::loopback(server.url("/whoami"), server.url("/usage")).expect("loopback routes")
}

fn settings(
    mode: CodexSourceMode,
    account: CodexAccountSelection,
    allow_external_oauth: bool,
    version: Option<&str>,
) -> CodexCoordinatorSettings {
    CodexCoordinatorSettings::new(
        mode,
        account,
        allow_external_oauth,
        version.map(ToOwned::to_owned),
    )
    .expect("coordinator settings")
}

fn runner(
    paths: CodexCredentialPaths,
    cli: Option<ExecutablePath>,
    server: &FakeHttpServer,
) -> CodexProductionRunner {
    runner_with_environment(paths, cli, server, &BTreeMap::new())
}

fn runner_with_environment(
    paths: CodexCredentialPaths,
    cli: Option<ExecutablePath>,
    server: &FakeHttpServer,
    child_environment: &BTreeMap<String, String>,
) -> CodexProductionRunner {
    CodexProductionRunner::with_test_http_routes(
        paths,
        cli,
        child_environment,
        routes(server),
        transport(),
    )
    .expect("production runner")
}

fn jwt(payload: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("JWT payload"));
    format!("{header}.{payload}.signature")
}

fn native_oauth_auth(expires_at: i64, email: &str) -> Vec<u8> {
    let access = jwt(&json!({
        "exp": expires_at,
        "fixture_secret": OAUTH_SECRET_CLAIM
    }));
    let identity = jwt(&json!({
        "email": email,
        "chatgpt_plan_type": "jwt-plan"
    }));
    serde_json::to_vec(&json!({
        "tokens": {
            "access_token": access,
            "refresh_token": "runner-refresh-secret-canary",
            "id_token": identity,
            "account_id": "credential-account"
        },
        "last_refresh": "2027-01-15T08:00:00Z"
    }))
    .expect("native OAuth auth")
}

fn usage_body(used_percent: i64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "account_id": "response-account",
        "plan_type": "pro",
        "rate_limit": {
            "primary_window": {
                "used_percent": used_percent,
                "reset_at": FETCHED_AT + 3_600,
                "limit_window_seconds": 18_000
            }
        }
    }))
    .expect("usage response")
}

fn assert_sample_source(
    sample: &oab_domain::UsageSample,
    expected_scope: &AccountScope,
    strategy: &str,
) {
    assert_eq!(sample.scope(), expected_scope);
    assert_eq!(sample.provenance().len(), 1);
    assert_eq!(sample.provenance()[0].source(), "codex");
    assert_eq!(sample.provenance()[0].strategy(), strategy);
}

#[tokio::test]
async fn pat_uses_the_winning_profile_config_and_normalizes_token_identity() {
    let fixture = CredentialFixture::new();
    fixture.write(
        ".codex/config.toml",
        "chatgpt_base_url = 'http://ambient-config-must-not-win'\n",
    );
    fixture.write(
        "profiles/work/auth.json",
        format!(r#"{{"personal_access_token":"{PAT_SECRET}"}}"#),
    );
    fixture.write(
        "profiles/work/config.toml",
        "chatgpt_base_url = 'https://api.openai.com'\n",
    );
    let profile = fixture.path("profiles/work");
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(
            200,
            br#"{"chatgpt_account_id":"pat-owner","email":"pat-owner@example.test","chatgpt_plan_type":"team"}"#.to_vec(),
        ),
        FakeHttpResponse::new(200, usage_body(23)),
    ])
    .await;
    let production = runner(fixture.paths(Some(profile.as_os_str())), None, &server);
    let selected_scope = scope("profile-account");
    let coordinator = CodexCoordinator::new(
        selected_scope.clone(),
        settings(
            CodexSourceMode::Pat,
            CodexAccountSelection::Profile,
            false,
            Some("codex-version-secret-canary"),
        ),
        Arc::new(production),
    );

    let diagnostics = format!("{coordinator:?}");
    for secret in [
        PAT_SECRET,
        "codex-version-secret-canary",
        fixture.home().to_str().expect("UTF-8 fixture home"),
        server.url("/").as_str(),
    ] {
        assert!(!diagnostics.contains(secret), "debug leaked {secret}");
    }

    let sample = coordinator
        .fetch_at(timestamp(), &CancellationToken::new())
        .await
        .expect("profile PAT sample");
    assert_sample_source(&sample, &selected_scope, "pat");
    let used_percent = sample
        .primary()
        .and_then(oab_domain::RateWindow::used_percent)
        .expect("session usage")
        .get();
    assert!((used_percent - 23.0).abs() <= f64::EPSILON);
    assert_eq!(
        sample
            .identity()
            .provider_account_id()
            .expect("PAT account")
            .as_str(),
        "pat-owner"
    );
    assert_eq!(
        sample.identity().email().expect("PAT email").as_str(),
        "pat-owner@example.test"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer runner-pat-secret-canary")
    );
    assert_eq!(requests[1].header("chatgpt-account-id"), Some("pat-owner"));
}

#[tokio::test]
async fn fresh_oauth_uses_managed_header_and_managed_identity() {
    let fixture = CredentialFixture::new();
    fixture.write(
        ".codex/auth.json",
        native_oauth_auth(FETCHED_AT + 3_600, "oauth-owner@example.test"),
    );
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, usage_body(41))]).await;
    let managed_secret = "managed-workspace-secret-canary";
    let managed = CodexManagedWorkspaceId::new(managed_secret).expect("managed workspace");
    let selected_scope = scope("managed-local-account");
    let coordinator = CodexCoordinator::new(
        selected_scope.clone(),
        settings(
            CodexSourceMode::OAuth,
            CodexAccountSelection::Managed(managed),
            false,
            None,
        ),
        Arc::new(runner(fixture.paths(None), None, &server)),
    );

    let diagnostics = format!("{coordinator:?}");
    assert!(!diagnostics.contains(managed_secret));
    assert!(!diagnostics.contains(OAUTH_SECRET_CLAIM));

    let sample = coordinator
        .fetch_at(timestamp(), &CancellationToken::new())
        .await
        .expect("managed OAuth sample");
    assert_sample_source(&sample, &selected_scope, "oauth");
    assert_eq!(
        sample
            .identity()
            .provider_account_id()
            .expect("managed identity")
            .as_str(),
        managed_secret
    );
    assert_eq!(
        sample.identity().email().expect("OAuth email").as_str(),
        "oauth-owner@example.test"
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .expect("response plan")
            .as_str(),
        "pro"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header("chatgpt-account-id"),
        Some(managed_secret)
    );
}

#[tokio::test]
async fn stale_native_explicit_oauth_recovers_through_the_owner_cli() {
    let fixture = CredentialFixture::new();
    fixture.write(
        ".codex/auth.json",
        native_oauth_auth(FETCHED_AT - 1, "stale-native@example.test"),
    );
    fixture.write(".codex/config.toml", [0xff]);
    let cli = FakeCli::new();
    let server = FakeHttpServer::start(Vec::<FakeHttpResponse>::new()).await;
    let attacker_home = fixture.path("attacker-home");
    let attacker_codex_home = fixture.path("attacker-codex-home");
    let child_environment = BTreeMap::from([
        (
            "HOME".to_owned(),
            attacker_home.to_string_lossy().into_owned(),
        ),
        (
            "CODEX_HOME".to_owned(),
            attacker_codex_home.to_string_lossy().into_owned(),
        ),
    ]);
    let production = runner_with_environment(
        fixture.paths(None),
        Some(cli.executable()),
        &server,
        &child_environment,
    );
    let runner_debug = format!("{production:?}");
    assert!(!runner_debug.contains(fixture.home().to_str().expect("UTF-8 home")));
    assert!(!runner_debug.contains(cli.executable.as_path().to_string_lossy().as_ref()));
    assert!(!runner_debug.contains(server.url("/").as_str()));
    assert!(!runner_debug.contains(OAUTH_SECRET_CLAIM));
    let selected_scope = scope("native-owner-recovery");
    let coordinator = CodexCoordinator::new(
        selected_scope.clone(),
        settings(
            CodexSourceMode::OAuth,
            CodexAccountSelection::Ambient,
            false,
            Some("1.2.3"),
        ),
        Arc::new(production),
    );

    let sample = coordinator
        .fetch_at(timestamp(), &CancellationToken::new())
        .await
        .expect("CLI owner recovery sample");
    assert_sample_source(&sample, &selected_scope, "cli");
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::duration)
            .map(WindowDuration::seconds),
        Some(18_000)
    );
    assert_eq!(
        sample.identity().email().expect("CLI email").as_str(),
        "cli-owner@example.test"
    );
    assert!(cli.was_spawned());
    assert_eq!(
        cli.captured_environment(),
        format!(
            "HOME={}\nCODEX_HOME={}\n",
            fixture.home().display(),
            fixture.path(".codex").display()
        )
    );
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn managed_explicit_oauth_never_owner_recovers_through_the_cli() {
    let fixture = CredentialFixture::new();
    fixture.write(
        ".codex/auth.json",
        native_oauth_auth(FETCHED_AT - 1, "stale-managed@example.test"),
    );
    let cli = FakeCli::new();
    let server = FakeHttpServer::start(Vec::<FakeHttpResponse>::new()).await;
    let coordinator = CodexCoordinator::new(
        scope("managed-no-owner-recovery"),
        settings(
            CodexSourceMode::OAuth,
            CodexAccountSelection::Managed(
                CodexManagedWorkspaceId::new("managed-workspace").expect("managed workspace"),
            ),
            false,
            None,
        ),
        Arc::new(runner(fixture.paths(None), Some(cli.executable()), &server)),
    );

    let error = coordinator
        .fetch_at(timestamp(), &CancellationToken::new())
        .await
        .expect_err("managed OAuth cannot use native CLI owner recovery");
    assert_eq!(
        error,
        CodexCoordinatorError::Credential(CodexCredentialError::NativeRefreshRequired)
    );
    assert!(!cli.was_spawned());
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn stale_external_oauth_never_spawns_the_native_owner_cli() {
    let fixture = CredentialFixture::new();
    fixture.write(
        ".config/codex/auth.json",
        br#"{"tokens":{"access_token":"external-access-secret-canary","refresh_token":"external-refresh-secret-canary"},"last_refresh":"2000-01-01T00:00:00Z"}"#,
    );
    let cli = FakeCli::new();
    let server = FakeHttpServer::start(Vec::<FakeHttpResponse>::new()).await;
    let coordinator = CodexCoordinator::new(
        scope("external-read-only"),
        settings(
            CodexSourceMode::OAuth,
            CodexAccountSelection::Ambient,
            true,
            None,
        ),
        Arc::new(runner(fixture.paths(None), Some(cli.executable()), &server)),
    );

    let error = coordinator
        .fetch_at(timestamp(), &CancellationToken::new())
        .await
        .expect_err("stale external OAuth must fail read-only");
    assert_eq!(
        error,
        CodexCoordinatorError::Credential(CodexCredentialError::ReadOnlySource)
    );
    assert!(!cli.was_spawned());
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn fail_closed_managed_selection_reads_no_credential_and_spawns_no_process() {
    let fixture = CredentialFixture::new();
    let cli = FakeCli::new();
    let server = FakeHttpServer::start(Vec::<FakeHttpResponse>::new()).await;
    let coordinator = CodexCoordinator::new(
        scope("fail-closed-managed"),
        settings(
            CodexSourceMode::Auto,
            CodexAccountSelection::FailClosedManaged,
            true,
            Some("1.2.3"),
        ),
        Arc::new(runner(fixture.paths(None), Some(cli.executable()), &server)),
    );

    let error = coordinator
        .fetch_at(timestamp(), &CancellationToken::new())
        .await
        .expect_err("fail-closed managed source");
    assert_eq!(error, CodexCoordinatorError::MissingCredential);
    assert!(!cli.was_spawned());
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn in_flight_http_cancellation_is_terminal_and_never_falls_back() {
    let fixture = CredentialFixture::new();
    fixture.write(
        ".codex/auth.json",
        native_oauth_auth(FETCHED_AT + 3_600, "cancelled@example.test"),
    );
    let server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let coordinator = Arc::new(CodexCoordinator::new(
        scope("cancelled-http"),
        settings(
            CodexSourceMode::OAuth,
            CodexAccountSelection::Ambient,
            false,
            None,
        ),
        Arc::new(runner(fixture.paths(None), None, &server)),
    ));
    let cancellation = CancellationToken::new();
    let fetch_coordinator = Arc::clone(&coordinator);
    let fetch_cancellation = cancellation.clone();
    let fetch = tokio::spawn(async move {
        fetch_coordinator
            .fetch_at(timestamp(), &fetch_cancellation)
            .await
    });

    for _ in 0..100 {
        if !server.requests().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server.requests().len(),
        1,
        "OAuth request reached the stall"
    );
    cancellation.cancel();
    let error = fetch
        .await
        .expect("fetch task")
        .expect_err("cancelled production request");
    assert_eq!(error, CodexCoordinatorError::Cancelled);
}

#[tokio::test]
async fn missing_credentials_and_executable_are_reported_as_all_unavailable() {
    let fixture = CredentialFixture::new();
    let server = FakeHttpServer::start(Vec::<FakeHttpResponse>::new()).await;
    let coordinator = CodexCoordinator::new(
        scope("missing-all"),
        settings(
            CodexSourceMode::Auto,
            CodexAccountSelection::Ambient,
            false,
            None,
        ),
        Arc::new(runner(fixture.paths(None), None, &server)),
    );

    let error = coordinator
        .fetch_at(timestamp(), &CancellationToken::new())
        .await
        .expect_err("all production sources unavailable");
    assert_eq!(error, CodexCoordinatorError::MissingCredential);
    assert!(server.requests().is_empty());
}

#[test]
fn production_runner_rejects_non_loopback_injected_http_routes() {
    let fixture = CredentialFixture::new();
    let routes = CodexHttpRoutes::from_config_text(None).expect("production routes");

    let error = CodexProductionRunner::with_test_http_routes(
        fixture.paths(None),
        None,
        &BTreeMap::new(),
        routes,
        transport(),
    )
    .expect_err("test seam must remain loopback-only");

    assert_eq!(error, CodexCoordinatorError::Configuration);
}

#[tokio::test]
async fn direct_runner_rejects_foreign_scope_before_credentials_or_network() {
    let fixture = CredentialFixture::new();
    fixture.write(
        ".codex/auth.json",
        format!(r#"{{"personal_access_token":"{PAT_SECRET}"}}"#),
    );
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, Vec::new())]).await;
    let production = runner(fixture.paths(None), None, &server);
    let settings = settings(
        CodexSourceMode::Pat,
        CodexAccountSelection::Ambient,
        false,
        None,
    );
    let selected_scope = foreign_scope("foreign-provider");

    let outcome = production
        .run(
            CodexSourceAttempt::Pat,
            &settings,
            &selected_scope,
            timestamp(),
            &CancellationToken::new(),
        )
        .await;

    assert_eq!(
        outcome,
        CodexAttemptOutcome::Failed(CodexCoordinatorError::Configuration)
    );
    assert!(server.requests().is_empty());
}
