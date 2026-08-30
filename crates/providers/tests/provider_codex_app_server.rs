use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::fcntl::{Flock, FlockArg};
use oab_domain::{
    AccountKey, AccountScope, DataConfidence, ErrorKind, ProviderId, ProviderInstanceId, Timestamp,
};
use oab_providers::executable::{ExecutablePath, resolve_executable};
use oab_providers::providers::codex::CodexAttemptFailure;
use oab_providers::providers::codex_app_server::{
    CodexAppServerClient, CodexAppServerError, CodexAppServerStage,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const FETCHED_AT: i64 = 1_800_000_000;

fn scope(account: &str) -> AccountScope {
    provider_scope(ProviderId::Codex, account)
}

fn provider_scope(provider: ProviderId, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(format!("{}-primary", provider.as_str()))
            .expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("fixture timestamp")
}

fn envelope(id: u64, result: Value) -> String {
    let mut object = serde_json::Map::new();
    object.insert("id".to_owned(), Value::from(id));
    object.insert("result".to_owned(), result);
    Value::Object(object).to_string()
}

fn remote_envelope(id: u64, code: i64, message: &str) -> String {
    json!({"id": id, "error": {"code": code, "message": message}}).to_string()
}

struct AppServerFixture {
    _process_lock: Flock<File>,
    _directory: TempDir,
    executable: ExecutablePath,
    capture: PathBuf,
    arguments: PathBuf,
    environment: PathBuf,
    pid: PathBuf,
}

impl AppServerFixture {
    fn replies(rate: &str, account: &str) -> Self {
        Self::replies_after("", rate, account)
    }

    fn environment_replies(rate: &str, account: &str) -> Self {
        Self::replies_after(CAPTURE_ENVIRONMENT, rate, account)
    }

    fn replies_after(setup: &str, rate: &str, account: &str) -> Self {
        let rate = shell_quote(rate);
        let account = shell_quote(account);
        Self::script(&format!(
            r#"
{setup}
IFS= read -r initialize
printf '%s\n' "$initialize" >> "$capture"
printf '%s\n' '{{"id":1,"result":{{}}}}'
IFS= read -r initialized
printf '%s\n' "$initialized" >> "$capture"
IFS= read -r rate
printf '%s\n' "$rate" >> "$capture"
printf '%s\n' {rate}
IFS= read -r account
printf '%s\n' "$account" >> "$capture"
printf '%s\n' {account}
while IFS= read -r ignored; do :; done
"#,
        ))
    }

    fn hanging_rate() -> Self {
        Self::script(
            r#"
IFS= read -r initialize
printf '%s\n' "$initialize" >> "$capture"
printf '%s\n' '{"id":1,"result":{}}'
IFS= read -r initialized
printf '%s\n' "$initialized" >> "$capture"
IFS= read -r rate
printf '%s\n' "$rate" >> "$capture"
sleep 30
"#,
        )
    }

    fn hanging_account(rate: &str) -> Self {
        let rate = shell_quote(rate);
        Self::script(&format!(
            r#"
IFS= read -r initialize
printf '%s\n' "$initialize" >> "$capture"
printf '%s\n' '{{"id":1,"result":{{}}}}'
IFS= read -r initialized
printf '%s\n' "$initialized" >> "$capture"
IFS= read -r rate
printf '%s\n' "$rate" >> "$capture"
printf '%s\n' {rate}
IFS= read -r account
printf '%s\n' "$account" >> "$capture"
sleep 30
"#
        ))
    }

    fn script(body: &str) -> Self {
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(std::env::temp_dir().join("omarchy-ai-bar-codex-app-server-tests.lock"))
            .expect("open process fixture lock");
        let process_lock = Flock::lock(lock_file, FlockArg::LockExclusive)
            .unwrap_or_else(|(_, error)| panic!("lock process fixture: {error}"));
        let directory = tempfile::tempdir().expect("fixture directory");
        let script = directory.path().join("codex-fixture");
        let capture = directory.path().join("frames.jsonl");
        let arguments = directory.path().join("arguments.txt");
        let environment = directory.path().join("environment.txt");
        let pid = directory.path().join("pid.txt");
        let source = format!(
            r#"#!/bin/sh
set -eu
capture={capture}
arguments={arguments}
environment_file={environment}
pid_file={pid}
printf '%s\n' "$$" > "$pid_file"
printf '%s\n' "$#" "$@" > "$arguments"
[ "$#" -eq 5 ]
[ "$1" = '-s' ]
[ "$2" = 'read-only' ]
[ "$3" = '-a' ]
[ "$4" = 'never' ]
[ "$5" = 'app-server' ]
{body}
"#,
            capture = shell_quote_path(&capture),
            arguments = shell_quote_path(&arguments),
            environment = shell_quote_path(&environment),
            pid = shell_quote_path(&pid),
        );
        fs::write(&script, source).expect("write fixture executable");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .expect("make fixture executable");
        let executable = resolve_executable("codex-fixture", script.to_str(), None, &[])
            .expect("valid fixture lookup")
            .expect("fixture executable");
        Self {
            _process_lock: process_lock,
            _directory: directory,
            executable,
            capture,
            arguments,
            environment,
            pid,
        }
    }

    fn client(&self) -> CodexAppServerClient {
        CodexAppServerClient::new(self.executable.clone())
    }

    fn frames(&self) -> Vec<Value> {
        fs::read_to_string(&self.capture)
            .expect("captured frames")
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid captured frame"))
            .collect()
    }

    fn arguments(&self) -> Vec<String> {
        fs::read_to_string(&self.arguments)
            .expect("captured arguments")
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn environment(&self) -> BTreeMap<String, String> {
        fs::read_to_string(&self.environment)
            .expect("captured environment")
            .lines()
            .map(|line| {
                let (name, value) = line.split_once('=').expect("environment entry");
                (name.to_owned(), value.to_owned())
            })
            .collect()
    }

    fn pid(&self) -> u32 {
        fs::read_to_string(&self.pid)
            .expect("captured pid")
            .trim()
            .parse()
            .expect("numeric pid")
    }
}

const CAPTURE_ENVIRONMENT: &str = r#"
/usr/bin/env > "$environment_file"
"#;

const ALLOWED_CHILD_ENVIRONMENT: &[&str] = &[
    "HOME",
    "PATH",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_ADDRESS",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "NIX_SSL_CERT_FILE",
    "AWS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
];

const FORBIDDEN_CHILD_ENVIRONMENT: &[(&str, &str)] = &[
    ("OPENAI_API_KEY", "openai-secret-canary"),
    ("ANTHROPIC_API_KEY", "anthropic-secret-canary"),
    ("OMARCHY_AI_BAR_SECRET", "application-secret-canary"),
    ("LD_LIBRARY_PATH", "/tmp/loader-injection-canary"),
    ("LD_PRELOAD", ""),
    ("RUST_LOG", "trace"),
    ("USER", "arbitrary-user-canary"),
];

fn injected_child_environment() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut injected = BTreeMap::new();
    let mut expected = BTreeMap::new();
    for (index, name) in ALLOWED_CHILD_ENVIRONMENT.iter().enumerate() {
        let value = match *name {
            "HOME" => "/tmp/oab-allowed-home-canary".to_owned(),
            "PATH" => "/usr/bin:/bin".to_owned(),
            "LANG" | "LANGUAGE" | "LC_ALL" | "LC_ADDRESS" | "LC_COLLATE" | "LC_CTYPE"
            | "LC_IDENTIFICATION" | "LC_MEASUREMENT" | "LC_MESSAGES" | "LC_MONETARY"
            | "LC_NAME" | "LC_NUMERIC" | "LC_PAPER" | "LC_TELEPHONE" | "LC_TIME" => "C".to_owned(),
            "HTTP_PROXY" => "http://proxy-secret-canary@example.test:8080".to_owned(),
            _ => format!("/tmp/oab-allowed-{index}"),
        };
        injected.insert((*name).to_owned(), value.clone());
        expected.insert((*name).to_owned(), value);
    }
    for (name, value) in FORBIDDEN_CHILD_ENVIRONMENT {
        injected.insert((*name).to_owned(), (*value).to_owned());
    }
    (injected, expected)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'\"'\"'"#))
}

fn shell_quote_path(path: &Path) -> String {
    shell_quote(path.to_str().expect("UTF-8 fixture path"))
}

async fn assert_process_gone(pid: u32) {
    let process = PathBuf::from(format!("/proc/{pid}"));
    for _ in 0..100 {
        if !process.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("fixture process {pid} survived bounded shutdown");
}

fn assert_percent(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

fn rich_rate_envelope() -> String {
    envelope(
        2,
        json!({
            "rateLimits": {
                "primary": {
                    "used_percent": "80.5",
                    "window_duration_mins": 10080.0,
                    "resets_at": "1800007200"
                },
                "secondary": {
                    "usedPercent": 12,
                    "windowDurationMins": "300",
                    "resetsAt": 1_800_003_600.9
                },
                "credits": {
                    "has_credits": true,
                    "unlimited": false,
                    "balance": 42.50
                },
                "individualLimit": {"limit": 0},
                "plan_type": "rate-plan"
            },
            "rate_limits_by_limit_id": {
                "z": {
                    "limit_name": "Z limit",
                    "individual_limit": {"limit": "200", "used": "10"}
                },
                "a": {
                    "limitId": "a-id",
                    "limitName": "A limit",
                    "individualLimit": {
                        "limit": "100.5",
                        "remaining_percent": "75",
                        "resets_at": 1_800_010_000.8
                    }
                }
            }
        }),
    )
}

fn rich_account_envelope() -> String {
    envelope(
        3,
        json!({
            "account": {
                "type": "ChatGPT",
                "email": " user@example.test ",
                "planType": " private-plan-canary "
            },
            "requiresOpenaiAuth": false
        }),
    )
}

#[tokio::test]
async fn empty_environment_constructor_does_not_inherit_ambient_values() {
    let fixture = AppServerFixture::environment_replies(
        &envelope(2, json!({"rateLimits": {"planType": "plus"}})),
        &envelope(3, json!({"account": null})),
    );
    fixture
        .client()
        .fetch(
            scope("empty-environment"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("app-server result");

    let child_environment = fixture.environment();
    let mut checked_ambient_values = 0_usize;
    for name in ["HOME", "USER", "LANG"] {
        if std::env::var_os(name).is_some() {
            checked_ambient_values += 1;
            assert!(
                !child_environment.contains_key(name),
                "ambient {name} reached the child"
            );
        }
    }
    assert!(
        checked_ambient_values > 0,
        "fixture requires one conventional ambient variable"
    );
    assert_process_gone(fixture.pid()).await;
}

#[tokio::test]
async fn injected_environment_passes_only_the_closed_linux_allowlist() {
    let (injected, expected) = injected_child_environment();

    let fixture = AppServerFixture::environment_replies(
        &envelope(2, json!({"rateLimits": {"planType": "plus"}})),
        &envelope(3, json!({"account": null})),
    );
    let client = CodexAppServerClient::from_environment(fixture.executable.clone(), &injected)
        .expect("valid allowlisted environment");
    let rendered = format!("{client:?}");
    assert!(!rendered.contains("oab-allowed-home-canary"));
    assert!(!rendered.contains("proxy-secret-canary"));
    assert!(!rendered.contains("openai-secret-canary"));
    assert!(!rendered.contains(fixture.executable.as_path().to_string_lossy().as_ref()));

    client
        .fetch(
            scope("selected-environment"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("app-server result");
    let child_environment = fixture.environment();
    for (name, expected_value) in expected {
        assert_eq!(
            child_environment.get(&name),
            Some(&expected_value),
            "allowed environment variable {name}"
        );
    }
    for (name, _) in FORBIDDEN_CHILD_ENVIRONMENT {
        assert!(
            !child_environment.contains_key(*name),
            "forbidden environment variable {name} reached the child"
        );
    }
    assert_process_gone(fixture.pid()).await;
}

#[test]
fn invalid_allowed_environment_is_rejected_before_process_launch() {
    let fixture = AppServerFixture::environment_replies(
        &envelope(2, json!({"rateLimits": {"planType": "plus"}})),
        &envelope(3, json!({"account": null})),
    );
    for invalid in ["invalid\0value".to_owned(), "x".repeat(64 * 1024 + 1)] {
        let environment = BTreeMap::from([("HOME".to_owned(), invalid)]);
        let error =
            CodexAppServerClient::from_environment(fixture.executable.clone(), &environment)
                .expect_err("invalid selected value");
        assert_eq!(error, CodexAppServerError::InvalidConfiguration);
        assert!(!fixture.pid.exists(), "invalid value must not launch child");
    }
}

#[tokio::test]
async fn exact_wire_and_flexible_aliases_normalize_authoritative_rate_response() {
    let rate = rich_rate_envelope();
    let account = rich_account_envelope();
    let fixture = AppServerFixture::replies(&rate, &account);

    let snapshot = fixture
        .client()
        .fetch(
            scope("wire"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("app-server snapshot");

    let usage = snapshot.usage().expect("rate usage");
    let primary = usage.primary().expect("session lane");
    let secondary = usage.secondary().expect("weekly lane");
    assert_eq!(
        primary.duration().expect("session duration").seconds(),
        18_000
    );
    assert_eq!(
        secondary.duration().expect("weekly duration").seconds(),
        604_800
    );
    assert_percent(primary.used_percent().expect("session percent").get(), 12.0);
    assert_percent(
        secondary.used_percent().expect("weekly percent").get(),
        80.5,
    );
    assert_eq!(
        usage.identity().email().expect("email").as_str(),
        "user@example.test"
    );
    assert_eq!(
        usage
            .identity()
            .login_method()
            .expect("account plan")
            .as_str(),
        "private-plan-canary"
    );
    assert_eq!(usage.confidence(), DataConfidence::Unknown);
    assert_eq!(usage.provenance()[0].source(), "codex");
    assert_eq!(usage.provenance()[0].strategy(), "cli");
    let credits = snapshot.credits().expect("credits");
    assert_eq!(credits.remaining().to_string(), "42.5");
    assert_eq!(usage.credits(), Some(credits));
    let limit = credits.limit().expect("spend limit");
    assert_eq!(limit.title(), "A limit");
    assert_eq!(limit.limit().to_string(), "100.5");
    assert_eq!(limit.used().to_string(), "25.125");
    assert_percent(limit.remaining_percent().get(), 75.0);
    assert_eq!(
        limit.resets_at().expect("limit reset").unix_timestamp(),
        1_800_010_000
    );
    assert_eq!(
        fixture.arguments(),
        ["5", "-s", "read-only", "-a", "never", "app-server"]
    );
    let frames = fixture.frames();
    assert_eq!(frames.len(), 4);
    assert!(frames.iter().all(|frame| frame.get("jsonrpc").is_none()));
    assert_eq!(frames[0]["method"], "initialize");
    assert_eq!(frames[0]["params"]["clientInfo"]["name"], "omarchy-ai-bar");
    assert_eq!(
        frames[0]["params"]["clientInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(frames[1], json!({"method": "initialized", "params": {}}));
    assert_eq!(frames[2]["method"], "account/rateLimits/read");
    assert_eq!(frames[2]["params"], json!({}));
    assert_eq!(frames[3]["method"], "account/read");
    let rendered = format!("{snapshot:?}");
    assert!(!rendered.contains("user@example.test"));
    assert!(!rendered.contains("private-plan-canary"));
    let merged = snapshot
        .clone()
        .into_usage_sample()
        .expect("single runtime sample");
    assert!(merged.primary().is_some());
    assert_eq!(
        merged
            .credits()
            .expect("merged credits")
            .remaining()
            .to_string(),
        "42.5"
    );
    assert_process_gone(fixture.pid()).await;
}

#[tokio::test]
async fn malformed_camel_limit_map_falls_back_to_snake_and_rate_plan_survives_account_failure() {
    let rate = envelope(
        2,
        json!({
            "rateLimits": {"planType": "team"},
            "rateLimitsByLimitId": "malformed",
            "rate_limits_by_limit_id": {
                "monthly": {
                    "limit_name": "Monthly",
                    "individual_limit": {"limit": 50, "used": 5}
                }
            }
        }),
    );
    let account = remote_envelope(3, -32000, "account secret must stay private");
    let fixture = AppServerFixture::replies(&rate, &account);

    let snapshot = fixture
        .client()
        .fetch(
            scope("fallback"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("rate response remains authoritative");

    let usage = snapshot.usage().expect("identity-only usage");
    assert!(usage.primary().is_none());
    assert_eq!(
        usage.identity().login_method().expect("rate plan").as_str(),
        "team"
    );
    assert_eq!(
        snapshot
            .credits()
            .expect("limit-only credits")
            .limit()
            .expect("monthly limit")
            .used()
            .to_string(),
        "5"
    );
}

#[tokio::test]
async fn credits_only_and_identity_only_results_remain_representable() {
    let credits_rate = envelope(
        2,
        json!({
            "rateLimits": {
                "credits": {
                    "hasCredits": false,
                    "unlimited": true,
                    "balance": "not-a-number"
                }
            }
        }),
    );
    let credits_account = envelope(
        3,
        json!({
            "account": {
                "type": "chatgpt",
                "email": "credits@example.test",
                "planType": "plus"
            }
        }),
    );
    let credits_fixture = AppServerFixture::replies(&credits_rate, &credits_account);
    let credits = credits_fixture
        .client()
        .fetch(
            scope("credits-only"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("credits-only snapshot");
    assert!(credits.usage().is_none());
    assert_eq!(
        credits
            .credits()
            .expect("zero credit marker")
            .remaining()
            .to_string(),
        "0"
    );
    assert!(credits.identity().is_some());
    let credits = credits
        .into_usage_sample()
        .expect("credits-only runtime sample");
    assert!(credits.primary().is_none());
    assert!(credits.secondary().is_none());
    assert_eq!(credits.confidence(), DataConfidence::Unknown);
    assert_eq!(
        credits.identity().email().expect("retained email").as_str(),
        "credits@example.test"
    );
    assert_eq!(
        credits
            .identity()
            .login_method()
            .expect("retained plan")
            .as_str(),
        "plus"
    );
    assert_eq!(
        credits
            .credits()
            .expect("merged zero credit marker")
            .remaining()
            .to_string(),
        "0"
    );
    assert_eq!(credits.provenance()[0].source(), "codex");
    assert_eq!(credits.provenance()[0].strategy(), "cli");
    drop(credits_fixture);

    let identity_rate = envelope(2, json!({"rateLimits": {}}));
    let chatgpt = envelope(3, json!({"account": {"type": "chatgpt"}}));
    let identity_fixture = AppServerFixture::replies(&identity_rate, &chatgpt);
    let identity = identity_fixture
        .client()
        .fetch(
            scope("identity-only"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("identity-only snapshot");
    let usage = identity.usage().expect("unavailable usage marker");
    assert_eq!(
        usage.identity().email().expect("default email").as_str(),
        "unknown"
    );
    assert_eq!(
        usage
            .identity()
            .login_method()
            .expect("default plan")
            .as_str(),
        "unknown"
    );
    assert_eq!(usage.confidence(), DataConfidence::Unknown);
    assert!(identity.credits().is_none());
}

#[tokio::test]
async fn api_key_with_empty_authoritative_rate_response_reports_no_limits() {
    let fixture = AppServerFixture::replies(
        &envelope(2, json!({"rateLimits": {}})),
        &envelope(3, json!({"account": {"type": "apikey"}})),
    );
    let error = fixture
        .client()
        .fetch(
            scope("empty"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect_err("empty API-key response");
    assert_eq!(error, CodexAppServerError::NoRateLimits);
    assert_process_gone(fixture.pid()).await;
}

#[tokio::test]
async fn invalid_optional_windows_fail_soft_without_erasing_plan_identity() {
    let fixture = AppServerFixture::replies(
        &envelope(
            2,
            json!({
                "rateLimits": {
                    "primary": {"usedPercent": "not-a-number", "windowDurationMins": 300},
                    "secondary": {"usedPercent": 25, "windowDurationMins": -1},
                    "planType": "pro"
                }
            }),
        ),
        &envelope(3, json!({"account": null})),
    );
    let snapshot = fixture
        .client()
        .fetch(
            scope("optional"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("optional fields fail soft");
    let usage = snapshot.usage().expect("secondary usage");
    assert_percent(
        usage
            .primary()
            .expect("unknown-duration lane")
            .used_percent()
            .expect("percent")
            .get(),
        25.0,
    );
    assert!(usage.primary().expect("primary").duration().is_none());
}

#[tokio::test]
async fn unknown_primary_and_session_secondary_preserve_provider_order() {
    let fixture = AppServerFixture::replies(
        &envelope(
            2,
            json!({
                "rateLimits": {
                    "primary": {"usedPercent": 17, "windowDurationMins": 540},
                    "secondary": {"usedPercent": 31, "windowDurationMins": 300}
                }
            }),
        ),
        &envelope(3, json!({"account": {"type": "apiKey"}})),
    );
    let snapshot = fixture
        .client()
        .fetch(
            scope("unknown-session-order"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("ordered rate result");
    let usage = snapshot.usage().expect("usage");
    let primary = usage.primary().expect("unknown primary");
    let secondary = usage.secondary().expect("session secondary");
    assert_eq!(
        primary.duration().expect("unknown duration").seconds(),
        32_400
    );
    assert_percent(primary.used_percent().expect("primary used").get(), 17.0);
    assert_eq!(
        secondary.duration().expect("session duration").seconds(),
        18_000
    );
    assert_percent(
        secondary.used_percent().expect("secondary used").get(),
        31.0,
    );
}

#[tokio::test]
async fn remote_body_recovery_handles_nested_braces_and_preserves_identity_and_credits() {
    let body = json!({
        "email": "body@example.test",
        "plan_type": "plus",
        "note": "literal } brace and escaped quote \"",
        "rate_limit": {
            "primary_window": {
                "used_percent": "15",
                "reset_at": 1_800_003_600.9,
                "limit_window_seconds": 18000.0
            },
            "secondary_window": {
                "used_percent": 40,
                "reset_at": "1800007200",
                "limit_window_seconds": 604_800
            }
        },
        "credits": {"has_credits": true, "unlimited": false, "balance": "19.75"}
    });
    let message = format!("upstream failed body={body} trailing-secret");
    let fixture =
        AppServerFixture::replies(&remote_envelope(2, 429, &message), &envelope(3, json!({})));

    let snapshot = fixture
        .client()
        .fetch(
            scope("body"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("safe error-body recovery");

    let usage = snapshot.usage().expect("recovered usage");
    assert_percent(
        usage
            .primary()
            .expect("session")
            .used_percent()
            .expect("used")
            .get(),
        15.0,
    );
    assert_percent(
        usage
            .secondary()
            .expect("weekly")
            .used_percent()
            .expect("used")
            .get(),
        40.0,
    );
    assert_eq!(
        usage.identity().email().expect("body email").as_str(),
        "body@example.test"
    );
    assert_eq!(
        snapshot
            .credits()
            .expect("body credits")
            .remaining()
            .to_string(),
        "19.75"
    );
    assert_eq!(
        usage
            .credits()
            .expect("same-sample body credits")
            .remaining()
            .to_string(),
        "19.75"
    );
    assert_eq!(
        fixture.frames().len(),
        3,
        "account enrichment must not run after rate error"
    );
}

#[tokio::test]
async fn malformed_session_lane_cannot_publish_weekly_only_but_credits_still_recover() {
    let body = json!({
        "email": "must-not-publish@example.test",
        "rate_limit": {
            "primary_window": {"used_percent": "bad", "reset_at": 1, "limit_window_seconds": 18000},
            "secondary_window": {
                "used_percent": 50,
                "reset_at": 1_800_007_200,
                "limit_window_seconds": 604_800
            }
        },
        "credits": {"balance": 7}
    });
    let canary = "body-email-canary-must-be-redacted";
    let fixture = AppServerFixture::replies(
        &remote_envelope(2, -32001, &format!("{canary} body={body}")),
        &envelope(3, json!({})),
    );

    let snapshot = fixture
        .client()
        .fetch(
            scope("guard"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("credits survive unsafe usage rejection");
    assert!(snapshot.usage().is_none());
    assert!(snapshot.identity().is_none());
    assert_eq!(
        snapshot
            .credits()
            .expect("recovered credits")
            .remaining()
            .to_string(),
        "7"
    );
    let rendered = format!("{snapshot:?}");
    assert!(!rendered.contains(canary));
    assert!(!rendered.contains("must-not-publish@example.test"));
    let merged = snapshot
        .into_usage_sample()
        .expect("credits survive as a blank usage sample");
    assert!(merged.primary().is_none());
    assert!(merged.secondary().is_none());
    assert!(merged.identity().email().is_none());
    assert!(merged.identity().login_method().is_none());
    assert_eq!(merged.confidence(), DataConfidence::Unknown);
    assert_eq!(
        merged
            .credits()
            .expect("recovered credits")
            .remaining()
            .to_string(),
        "7"
    );
}

#[tokio::test]
async fn a_valid_session_lane_allows_safe_partial_recovery_after_other_lane_failure() {
    let body = json!({
        "plan_type": "team",
        "rate_limit": {
            "primary_window": {"used_percent": "bad"},
            "secondary_window": {
                "used_percent": 30,
                "reset_at": 1_800_003_600,
                "limit_window_seconds": 18_000
            }
        }
    });
    let fixture = AppServerFixture::replies(
        &remote_envelope(2, -32002, &format!("body={body}")),
        &envelope(3, json!({})),
    );

    let snapshot = fixture
        .client()
        .fetch(
            scope("partial"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("session-safe partial recovery");
    let usage = snapshot.usage().expect("session usage");
    assert_percent(
        usage
            .primary()
            .expect("session")
            .used_percent()
            .expect("used")
            .get(),
        30.0,
    );
    assert!(usage.secondary().is_none());
}

#[tokio::test]
async fn malformed_or_bounded_remote_body_fails_closed_and_never_exposes_peer_text() {
    let mut nested = json!({"rate_limit": {}});
    for _ in 0..40 {
        nested = json!({"nested": nested});
    }
    let canary = "remote-secret-canary-0123456789";
    let fixture = AppServerFixture::replies(
        &remote_envelope(2, 17, &format!("{canary} body={nested}")),
        &envelope(3, json!({})),
    );
    let error = fixture
        .client()
        .fetch(
            scope("bounded"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect_err("deep recovery body");
    assert_eq!(error, CodexAppServerError::Remote { code: Some(17) });
    assert!(!error.to_string().contains(canary));
    assert!(!format!("{error:?}").contains(canary));
}

#[tokio::test]
async fn oversized_rate_frame_is_rejected_at_the_app_server_boundary() {
    let oversized = json!({
        "id": 2,
        "result": {
            "rateLimits": {"planType": "x".repeat(1024 * 1024)}
        }
    })
    .to_string();
    let fixture = AppServerFixture::replies(&oversized, &envelope(3, json!({})));
    let error = fixture
        .client()
        .fetch(
            scope("frame-bound"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect_err("oversized app-server response");
    assert_eq!(error, CodexAppServerError::ResponseTooLarge);
    assert_process_gone(fixture.pid()).await;
}

#[tokio::test]
async fn oversized_optional_limit_map_is_discarded_without_hiding_main_plan() {
    let entries = (0..129)
        .map(|index| (format!("limit-{index}"), json!({"planType": "noise"})))
        .collect::<serde_json::Map<_, _>>();
    let fixture = AppServerFixture::replies(
        &envelope(
            2,
            json!({"rateLimits": {"planType": "main"}, "rateLimitsByLimitId": entries}),
        ),
        &envelope(3, json!({"account": {"type": "apiKey"}})),
    );
    let snapshot = fixture
        .client()
        .fetch(
            scope("map-bound"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("main result");
    assert!(snapshot.credits().is_none());
    assert_eq!(
        snapshot
            .usage()
            .expect("plan usage")
            .identity()
            .login_method()
            .expect("main plan")
            .as_str(),
        "main"
    );
}

#[tokio::test]
async fn overflowing_spend_limit_derivations_fail_soft_without_erasing_usage() {
    const DECIMAL_MAX: &str = "79228162514264337593543950335";
    for (account, individual_limit) in [
        (
            "limit-overflow",
            json!({"limit": DECIMAL_MAX, "remainingPercent": 0}),
        ),
        ("used-overflow", json!({"limit": 1, "used": DECIMAL_MAX})),
    ] {
        let fixture = AppServerFixture::replies(
            &envelope(
                2,
                json!({
                    "rateLimits": {
                        "planType": "pro",
                        "individualLimit": individual_limit
                    }
                }),
            ),
            &envelope(3, json!({"account": {"type": "apiKey"}})),
        );
        let snapshot = fixture
            .client()
            .fetch(
                scope(account),
                timestamp(FETCHED_AT),
                &CancellationToken::new(),
            )
            .await
            .expect("usage survives optional spend-limit overflow");
        assert!(snapshot.credits().is_none());
        assert_eq!(
            snapshot
                .usage()
                .expect("plan usage")
                .identity()
                .login_method()
                .expect("plan")
                .as_str(),
            "pro"
        );
    }
}

#[tokio::test]
async fn cancellation_stops_the_mandatory_request_and_reaps_the_child() {
    let fixture = AppServerFixture::hanging_rate();
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let cancellation_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
    });
    let error = fixture
        .client()
        .fetch(scope("cancel"), timestamp(FETCHED_AT), &cancellation)
        .await
        .expect_err("cancelled rate request");
    cancellation_task.await.expect("cancellation task");
    assert_eq!(error, CodexAppServerError::Cancelled);
    assert_process_gone(fixture.pid()).await;
}

#[tokio::test]
async fn mandatory_rate_request_has_the_fixed_three_second_deadline() {
    let fixture = AppServerFixture::hanging_rate();
    let started = tokio::time::Instant::now();
    let error = fixture
        .client()
        .fetch(
            scope("timeout"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect_err("rate timeout");
    assert_eq!(
        error,
        CodexAppServerError::Timeout {
            stage: CodexAppServerStage::RateLimits
        }
    );
    assert!(started.elapsed() >= Duration::from_millis(2_900));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert_process_gone(fixture.pid()).await;
}

#[tokio::test]
async fn account_timeout_is_best_effort_and_cannot_erase_authoritative_rate_usage() {
    let fixture = AppServerFixture::hanging_account(&envelope(
        2,
        json!({
            "rateLimits": {
                "primary": {"usedPercent": 22, "windowDurationMins": 300}
            }
        }),
    ));
    let started = tokio::time::Instant::now();
    let snapshot = fixture
        .client()
        .fetch(
            scope("account-timeout"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect("rate result after account timeout");
    assert_percent(
        snapshot
            .usage()
            .expect("rate usage")
            .primary()
            .expect("primary")
            .used_percent()
            .expect("percent")
            .get(),
        22.0,
    );
    assert!(started.elapsed() >= Duration::from_millis(2_900));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert_eq!(fixture.frames().len(), 4);
    assert_process_gone(fixture.pid()).await;
}

#[tokio::test]
async fn missing_or_invalid_authoritative_rate_result_is_a_protocol_error() {
    for (account, result) in [
        ("missing", json!({})),
        ("wrong-type", json!({"rateLimits": []})),
    ] {
        let fixture = AppServerFixture::replies(
            &envelope(2, result),
            &envelope(3, json!({"account": {"type": "chatgpt"}})),
        );
        let error = fixture
            .client()
            .fetch(
                scope(account),
                timestamp(FETCHED_AT),
                &CancellationToken::new(),
            )
            .await
            .expect_err("invalid mandatory rate result");
        assert_eq!(error, CodexAppServerError::Protocol);
        assert_eq!(fixture.frames().len(), 3, "account request must not run");
    }
}

#[tokio::test]
async fn removed_resolved_executable_maps_to_a_redacted_start_failure() {
    let fixture = AppServerFixture::replies(
        &envelope(2, json!({"rateLimits": {"planType": "plus"}})),
        &envelope(3, json!({"account": null})),
    );
    let executable = fixture.executable.clone();
    let path = executable.as_path().to_owned();
    fs::remove_file(&path).expect("remove resolved fixture");
    let client = CodexAppServerClient::new(executable);
    let error = client
        .fetch(
            scope("spawn"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect_err("removed executable");
    assert_eq!(error, CodexAppServerError::Start);
    assert!(!format!("{client:?}").contains(path.to_str().expect("fixture path")));
}

#[tokio::test]
async fn foreign_provider_scope_is_rejected_before_process_launch() {
    let fixture = AppServerFixture::replies(
        &envelope(2, json!({"rateLimits": {"planType": "plus"}})),
        &envelope(3, json!({"account": null})),
    );
    let error = fixture
        .client()
        .fetch(
            provider_scope(ProviderId::Claude, "wrong-provider"),
            timestamp(FETCHED_AT),
            &CancellationToken::new(),
        )
        .await
        .expect_err("foreign scope");
    assert_eq!(error, CodexAppServerError::InvalidConfiguration);
    assert!(!fixture.pid.exists(), "foreign scope must not launch child");
}

#[test]
fn error_attempt_and_public_classifications_are_exhaustive() {
    let cases = [
        (
            CodexAppServerError::InvalidConfiguration,
            CodexAttemptFailure::Other,
            ErrorKind::Api,
        ),
        (
            CodexAppServerError::Start,
            CodexAttemptFailure::Unavailable,
            ErrorKind::ProviderUnavailable,
        ),
        (
            CodexAppServerError::Cancelled,
            CodexAttemptFailure::Other,
            ErrorKind::Network,
        ),
        (
            CodexAppServerError::Timeout {
                stage: CodexAppServerStage::Initialize,
            },
            CodexAttemptFailure::Network,
            ErrorKind::Network,
        ),
        (
            CodexAppServerError::Timeout {
                stage: CodexAppServerStage::RateLimits,
            },
            CodexAttemptFailure::Network,
            ErrorKind::Network,
        ),
        (
            CodexAppServerError::Timeout {
                stage: CodexAppServerStage::Account,
            },
            CodexAttemptFailure::Network,
            ErrorKind::Network,
        ),
        (
            CodexAppServerError::Transport,
            CodexAttemptFailure::Network,
            ErrorKind::Network,
        ),
        (
            CodexAppServerError::ResponseTooLarge,
            CodexAttemptFailure::InvalidResponse,
            ErrorKind::Parse,
        ),
        (
            CodexAppServerError::Protocol,
            CodexAttemptFailure::InvalidResponse,
            ErrorKind::Parse,
        ),
        (
            CodexAppServerError::Remote { code: Some(17) },
            CodexAttemptFailure::Server,
            ErrorKind::ProviderUnavailable,
        ),
        (
            CodexAppServerError::Remote { code: None },
            CodexAttemptFailure::Server,
            ErrorKind::ProviderUnavailable,
        ),
        (
            CodexAppServerError::NoRateLimits,
            CodexAttemptFailure::InvalidResponse,
            ErrorKind::Parse,
        ),
    ];

    for (error, expected_attempt, expected_kind) in cases {
        assert_eq!(error.attempt_failure(), expected_attempt, "{error:?}");
        assert_eq!(error.classified().kind(), expected_kind, "{error:?}");
    }
}
