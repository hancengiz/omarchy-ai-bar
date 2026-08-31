use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::providers::kiro::{
    KiroCliSettings, KiroCommandTimeouts, KiroProvider, parse_context_report, parse_usage_limits,
    parse_usage_report, parse_usage_report_with_local_offset,
};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{HttpTransport, TransportConfig};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use rust_decimal::Decimal;
use time::UtcOffset;
use tokio_util::sync::CancellationToken;

const LEGACY: &str = include_str!("../../../fixtures/providers/kiro/usage_legacy.txt");
const V2: &str = include_str!("../../../fixtures/providers/kiro/usage_v2.txt");
const CONTEXT: &str = include_str!("../../../fixtures/providers/kiro/context.txt");
const LIMITS: &[u8] = include_bytes!("../../../fixtures/providers/kiro/usage_limits.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/providers/kiro/malformed.json");
const STATE_SQL: &str = include_str!("../../../fixtures/providers/kiro/state.sql");
const ACCESS_TOKEN: &str = "fixture-kiro-access-token-canary";
const AUTHORIZATION: &str = "Bearer fixture-kiro-access-token-canary";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("omarchy-ai-bar-kiro-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path().join(name);
        fs::write(&path, body).expect("fixture script");
        let mut permissions = fs::metadata(&path).expect("script metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("script permissions");
        path
    }

    fn database(&self) -> PathBuf {
        let database = self.path().join("data.sqlite3");
        let mut child = Command::new("/usr/bin/sqlite3")
            .arg(&database)
            .stdin(Stdio::piped())
            .spawn()
            .expect("sqlite fixture process");
        child
            .stdin
            .as_mut()
            .expect("sqlite stdin")
            .write_all(STATE_SQL.as_bytes())
            .expect("sqlite fixture schema");
        assert!(child.wait().expect("sqlite status").success());
        database
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
        ProviderId::Kiro,
        ProviderInstanceId::new("kiro-primary").expect("instance"),
        AccountKey::new(account).expect("account"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn environment(directory: &TestDirectory) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "HOME".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        ),
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
    ])
}

fn settings(
    directory: &TestDirectory,
    cli: &Path,
    database: Option<&Path>,
    timeouts: Option<KiroCommandTimeouts>,
) -> KiroCliSettings {
    if let Some(database) = database {
        assert!(
            database.starts_with(directory.path()),
            "integration tests must use isolated fixture state"
        );
        if let Some(home) = std::env::var_os("HOME") {
            assert_ne!(
                database,
                Path::new(&home).join(".local/share/kiro-cli/data.sqlite3"),
                "integration tests must never read the developer's live Kiro state"
            );
        }
    }
    let environment = environment(directory);
    let settings = KiroCliSettings::from_paths(
        cli,
        database,
        database.map(|_| Path::new("/usr/bin/sqlite3")),
        &environment,
    )
    .expect("fixture settings");
    timeouts.map_or(settings.clone(), |timeouts| {
        settings.with_timeouts(timeouts)
    })
}

fn transport(server: &FakeHttpServer) -> HttpTransport {
    let policy = EndpointPolicy::new([(server.origin(), EndpointClass::LoopbackDevelopment)])
        .expect("loopback policy");
    let config = TransportConfig::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
        2 * 1024 * 1024,
        0,
        RetryPolicy::none(),
    )
    .expect("transport config");
    HttpTransport::new(policy, config).expect("transport")
}

fn provider(server: &FakeHttpServer, settings: KiroCliSettings, account: &str) -> KiroProvider {
    KiroProvider::from_transport(scope(account), settings, server.url("/"), transport(server))
        .expect("fixture provider")
}

fn percent(window: &oab_domain::RateWindow) -> f64 {
    window.used_percent().expect("known percentage").get()
}

fn assert_close(actual: f64, expected: f64) {
    assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

async fn wait_for_marker(path: &Path) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(contents) = fs::read_to_string(path)
            && !contents.trim().is_empty()
        {
            return contents;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "process marker was not written: {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn assert_recorded_processes_gone(path: &Path) {
    let contents = wait_for_marker(path).await;
    let pids = contents
        .lines()
        .map(|line| line.trim().parse::<i32>().expect("recorded PID"))
        .collect::<Vec<_>>();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let live = pids
            .iter()
            .copied()
            .filter(|pid| process_is_live(*pid))
            .collect::<Vec<_>>();
        if live.is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "processes survived cleanup: {live:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn process_is_live(pid: i32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(after_name) = stat.rfind(')').and_then(|index| stat.get(index + 1..)) else {
        return false;
    };
    !matches!(after_name.split_whitespace().next(), Some("Z" | "X"))
}

fn standard_cli_script() -> &'static str {
    r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf 'kiro-cli 2.1.0\n'
  exit 0
fi
if [ "$1" = "whoami" ]; then
  printf 'Logged in with AWS Builder ID\nEmail: person@example.com\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ]; then
  printf 'Estimated Usage | resets on 2026-09-01 | KIRO POWER\n'
  printf 'Credits (10000.00 of 10000 covered in plan)\n'
  printf 'Overages: Enabled billed at $0.04 per request\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/context" ]; then
  printf 'Context window: 1.3%% used (estimated)\n'
  printf 'Context files 0.5%%\nTools 0.8%%\nKiro responses 0.0%%\nYour prompts 0.0%%\n'
  exit 0
fi
exit 17
"#
}

#[test]
fn parses_legacy_v2_managed_context_and_rejects_changed_formats() {
    let at = timestamp(1_777_680_000);
    let legacy = parse_usage_report(LEGACY, at, None, None, None).expect("legacy report");
    assert_eq!(legacy.plan_name, "KIRO PRO");
    assert_eq!(legacy.display_plan_name, "Kiro Pro");
    assert_close(legacy.credits_used, 40.0);
    assert_close(legacy.credits_total, 50.0);
    assert_close(legacy.credits_percent, 80.0);
    assert_eq!(legacy.bonus_used, Some(5.0));
    assert_eq!(legacy.bonus_total, Some(10.0));
    assert_eq!(legacy.bonus_expiry_days, Some(7));
    assert!(legacy.resets_at.is_some());

    let context = parse_context_report(CONTEXT).expect("context report");
    assert_close(context.total, 1.3);
    assert_eq!(context.context_files, Some(0.5));
    assert_eq!(context.tools, Some(0.8));
    assert_eq!(context.responses, Some(0.0));
    assert_eq!(context.prompts, Some(0.0));

    let v2 = parse_usage_report(
        V2,
        at,
        Some("person@example.com".to_owned()),
        Some("AWS Builder ID".to_owned()),
        Some(context),
    )
    .expect("v2 report");
    assert_eq!(v2.plan_name, "KIRO POWER");
    assert_close(v2.credits_used, 10_000.0);
    assert_eq!(v2.overage_used, Some(40.29));
    assert_eq!(v2.estimated_overage_cost_usd, Some(1.61));
    assert_eq!(
        v2.manage_url.as_deref(),
        Some("https://app.kiro.dev/account/usage")
    );
    assert_eq!(v2.account_email.as_deref(), Some("person@example.com"));

    let managed = parse_usage_report(
        "Plan: Q Developer Pro\nYour plan is managed by admin\nBonus credits: 2/10\nexpires in 4 days\n",
        at,
        None,
        None,
        None,
    )
    .expect("managed plan");
    assert_eq!(managed.plan_name, "Q Developer Pro");
    assert_close(managed.credits_total, 0.0);
    assert_eq!(managed.bonus_used, Some(2.0));
    assert_eq!(managed.bonus_total, Some(10.0));
    assert_eq!(managed.bonus_expiry_days, Some(4));

    for invalid in [
        "",
        "Welcome to Kiro!\nUsage: future format\n",
        "Could not retrieve usage information from backend",
    ] {
        assert_eq!(
            parse_usage_report(invalid, at, None, None, None)
                .expect_err("invalid transcript")
                .kind(),
            ErrorKind::Parse
        );
    }
    assert_eq!(
        parse_usage_report(
            "Failed to initialize auth portal; run kiro-cli login",
            at,
            None,
            None,
            None,
        )
        .expect_err("login transcript")
        .kind(),
        ErrorKind::AuthenticationExpired
    );
}

#[test]
fn percentage_managed_bonus_bounds_and_turkey_midnight_match_cli_semantics() {
    let at = timestamp(1_777_680_000);
    let percent_only = parse_usage_report(
        "Estimated Usage | resets on 2026-09-01 | KIRO FREE\n████ 37%\n",
        at,
        None,
        None,
        None,
    )
    .expect("percentage-only report");
    assert_close(percent_only.credits_percent, 37.0);
    assert_close(percent_only.credits_used, 0.0);
    assert_close(percent_only.credits_total, 50.0);

    let managed_percent = parse_usage_report(
        "Plan: Q Developer Pro\nYour plan is managed by organization\n████ 63%\n",
        at,
        None,
        None,
        None,
    )
    .expect("managed percentage-only report");
    assert_close(managed_percent.credits_percent, 63.0);

    let huge_expiry = parse_usage_report(
        "Estimated Usage | KIRO FREE\nCredits (1 of 50 covered in plan)\nBonus credits: 1/2\nexpires in 4294967295 days\n",
        at,
        None,
        None,
        None,
    )
    .expect("bounded optional bonus expiry");
    assert_eq!(huge_expiry.bonus_expiry_days, None);

    let turkey = parse_usage_report_with_local_offset(
        "Estimated Usage | resets on 2026-09-01 | KIRO FREE\nCredits (1 of 50 covered in plan)\n",
        at,
        None,
        None,
        None,
        UtcOffset::from_hms(3, 0, 0).expect("Turkey offset"),
    )
    .expect("Turkey-local reset");
    assert_eq!(turkey.resets_at, Some(timestamp(1_788_210_000)));
}

#[test]
fn usage_limits_preserve_plan_overage_bonus_and_reset_invariants() {
    let limits = parse_usage_limits(LIMITS).expect("captured limits");
    assert_eq!(limits.plan_limit, Decimal::from(10_000_u32));
    assert_eq!(limits.plan_used, Decimal::from(10_000_u32));
    assert_eq!(limits.overage_used, Decimal::new(360_349, 2));
    assert_eq!(limits.overage_cap, Some(Decimal::from(10_000_u32)));
    assert_eq!(limits.overage_enabled, Some(true));
    assert_eq!(limits.overage_rate, Some(Decimal::new(4, 2)));
    assert_eq!(limits.overage_charge_limit(), Some(Decimal::from(400_u16)));
    assert_eq!(limits.resets_at, timestamp(1_788_220_800));

    assert_eq!(
        parse_usage_limits(MALFORMED)
            .expect_err("numeric strings are rejected")
            .kind(),
        ErrorKind::Parse
    );

    let impossible = String::from_utf8(LIMITS.to_vec())
        .expect("utf8 fixture")
        .replace("13603.49", "100.00");
    assert_eq!(
        parse_usage_limits(impossible.as_bytes())
            .expect_err("overage cannot exceed total")
            .kind(),
        ErrorKind::Parse
    );

    let disabled = String::from_utf8(LIMITS.to_vec())
        .expect("utf8 fixture")
        .replace("\"ENABLED\"", "\"DISABLED\"");
    let disabled = parse_usage_limits(disabled.as_bytes()).expect("disabled overage");
    assert_eq!(disabled.overage_enabled, Some(false));
    assert_eq!(disabled.overage_cap, None);

    let bonus = String::from_utf8(LIMITS.to_vec())
        .expect("utf8 fixture")
        .replace("\"bonuses\": []", "\"bonuses\": [{}]")
        .replace("13603.49", "14603.49");
    let bonus = parse_usage_limits(bonus.as_bytes()).expect("bonus-inclusive usage");
    assert!(bonus.has_unseparated_bonus);
    assert_eq!(bonus.plan_used, Decimal::from(11_000_u32));
}

#[test]
fn settings_resolution_is_linux_bounded_authoritative_and_redacted() {
    let directory = TestDirectory::new();
    let cli = directory.script("kiro-cli", standard_cli_script());
    let mut env = environment(&directory);
    env.insert(
        "OMARCHY_AI_BAR_KIRO_CLI_PATH".to_owned(),
        cli.to_string_lossy().into_owned(),
    );
    env.insert(
        "KIRO_DATA_DIR".to_owned(),
        directory
            .path()
            .join("kiro-state")
            .to_string_lossy()
            .into_owned(),
    );
    env.insert("UNRELATED_SECRET".to_owned(), ACCESS_TOKEN.to_owned());
    let settings = KiroCliSettings::resolve(&env).expect("resolved settings");
    assert_eq!(settings.executable(), cli);
    assert_eq!(
        settings.state_database(),
        Some(directory.path().join("kiro-state/data.sqlite3").as_path())
    );
    let debug = format!("{settings:?}");
    assert!(!debug.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!debug.contains(ACCESS_TOKEN));

    env.insert(
        "OMARCHY_AI_BAR_KIRO_CLI_PATH".to_owned(),
        directory
            .path()
            .join("missing")
            .to_string_lossy()
            .into_owned(),
    );
    assert_eq!(
        KiroCliSettings::resolve(&env)
            .expect_err("override is authoritative")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn test_harness_resolve_cannot_reach_process_state_without_opt_in() {
    let directory = TestDirectory::new();
    let cli = directory.script("kiro-cli", standard_cli_script());
    let mut env = environment(&directory);
    for name in ["HOME", "XDG_DATA_HOME", "KIRO_DATA_DIR"] {
        match std::env::var(name) {
            Ok(value) => {
                env.insert(name.to_owned(), value);
            }
            Err(_) => {
                env.remove(name);
            }
        }
    }
    env.insert(
        "OMARCHY_AI_BAR_KIRO_CLI_PATH".to_owned(),
        cli.to_string_lossy().into_owned(),
    );
    let guarded = KiroCliSettings::resolve(&env).expect("guarded production resolution");
    assert_eq!(guarded.state_database(), None);

    let server = FakeHttpServer::start([]).await;
    provider(&server, guarded, "live-state-guard")
        .fetch_at(
            &context("live-state-guard", ProviderSource::Cli),
            timestamp(1_777_680_000),
        )
        .await
        .expect("CLI remains available with live enrichment blocked");
    assert!(server.requests().is_empty());

    env.insert(
        "OMARCHY_AI_BAR_KIRO_ALLOW_LIVE_STATE_IN_DEBUG".to_owned(),
        "1".to_owned(),
    );
    let opted_in = KiroCliSettings::resolve(&env).expect("explicit debug opt-in");
    assert!(opted_in.state_database().is_some());
}

#[tokio::test]
async fn pipe_cli_fetch_maps_plan_bonus_context_identity_and_version() {
    let directory = TestDirectory::new();
    let cli = directory.script("kiro-cli", standard_cli_script());
    let settings = settings(&directory, &cli, None, None);
    let version = KiroProvider::detect_version(&settings, &CancellationToken::new())
        .await
        .expect("version");
    assert_eq!(version, "2.1.0");

    let server = FakeHttpServer::start([]).await;
    let sample = provider(&server, settings, "pipe-account")
        .fetch_at(
            &context("pipe-account", ProviderSource::Cli),
            timestamp(1_777_680_000),
        )
        .await
        .expect("CLI report survives missing enrichment");
    assert_close(percent(sample.primary().expect("primary")), 100.0);
    assert_eq!(
        sample
            .identity()
            .email()
            .map(oab_domain::BoundedText::as_str),
        Some("person@example.com")
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .map(oab_domain::BoundedText::as_str),
        Some("Kiro Power")
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .map(oab_domain::BoundedText::as_str),
        Some("AWS Builder ID")
    );
    let rows = sample.detail_sections()[0].rows();
    assert!(
        rows.iter()
            .any(|row| row.label() == "Context used" && row.value() == "1.3%")
    );
    assert_eq!(sample.provenance()[0].strategy(), "cli");
}

#[tokio::test]
async fn shell_free_pty_fallback_supports_terminal_only_older_cli() {
    let directory = TestDirectory::new();
    let cli = directory.script(
        "kiro-cli",
        r#"#!/bin/sh
if [ ! -t 1 ]; then
  exit 9
fi
if [ "$1" = "whoami" ]; then
  printf 'Logged in with Device Flow\r\nEmail: tty@example.com\r\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ]; then
  printf 'Estimated Usage | resets on 2026-09-01 | KIRO FREE\r\n'
  printf 'Credits (12.50 of 50 covered in plan)\r\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/context" ]; then
  exit 0
fi
exit 1
"#,
    );
    let timeouts = KiroCommandTimeouts::new(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_millis(100),
    )
    .expect("timeouts");
    let settings = settings(&directory, &cli, None, Some(timeouts));
    let server = FakeHttpServer::start([]).await;
    let sample = provider(&server, settings, "tty-account")
        .fetch_at(
            &context("tty-account", ProviderSource::Cli),
            timestamp(1_777_680_000),
        )
        .await
        .expect("PTY fallback");
    assert_close(percent(sample.primary().expect("primary")), 25.0);
    assert_eq!(
        sample
            .identity()
            .email()
            .map(oab_domain::BoundedText::as_str),
        Some("tty@example.com")
    );
}

#[tokio::test]
async fn pty_cleanup_reaps_same_group_and_setsid_double_fork_holders_after_normal_exit() {
    let directory = TestDirectory::new();
    let same_marker = directory.path().join("same-group.pids");
    let detached_marker = directory.path().join("detached.pids");
    let same_holder = directory.script(
        "same-holder",
        &format!(
            "#!/bin/sh\nexec </dev/null >/dev/null 2>&1\ntrap '' TERM\nprintf '%s\\n' \"$$\" >> {}\nwhile :; do sleep 1; done\n",
            same_marker.display()
        ),
    );
    let detached_holder = directory.script(
        "detached-holder",
        &format!(
            "#!/usr/bin/python3\nimport os, signal, time\nfirst = os.fork()\nif first:\n    os.waitpid(first, 0)\n    raise SystemExit\nos.setsid()\nsecond = os.fork()\nif second:\n    raise SystemExit\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nwith open({:?}, 'a', encoding='ascii') as marker:\n    marker.write(str(os.getpid()) + '\\n')\n    marker.flush()\nwhile True:\n    time.sleep(1)\n",
            detached_marker.display().to_string()
        ),
    );
    let cli = directory.script(
        "kiro-cli",
        &format!(
            r#"#!/bin/sh
if [ ! -t 1 ]; then exit 9; fi
if [ "$1" = "whoami" ]; then
  printf 'Logged in with PTY\r\nEmail: cleanup@example.com\r\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ]; then
  {same_holder} &
  {detached_holder}
  count=0
  while [ ! -s {detached_marker} ] && [ "$count" -lt 100 ]; do
    sleep 0.01
    count=$((count + 1))
  done
  printf 'Estimated Usage | KIRO FREE\r\nCredits (5 of 50 covered in plan)\r\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/context" ]; then exit 0; fi
exit 1
"#,
            same_holder = same_holder.display(),
            detached_holder = detached_holder.display(),
            detached_marker = detached_marker.display(),
        ),
    );
    let timeouts = KiroCommandTimeouts::new(
        Duration::from_secs(2),
        Duration::from_secs(3),
        Duration::from_secs(2),
        Duration::from_millis(50),
    )
    .expect("cleanup timeouts");
    let server = FakeHttpServer::start([]).await;
    let sample = provider(
        &server,
        settings(&directory, &cli, None, Some(timeouts)),
        "cleanup-normal",
    )
    .fetch_at(
        &context("cleanup-normal", ProviderSource::Cli),
        timestamp(1_777_680_000),
    )
    .await
    .expect("normal PTY result with escaped holders");
    assert_close(percent(sample.primary().expect("primary")), 10.0);
    assert_recorded_processes_gone(&same_marker).await;
    assert_recorded_processes_gone(&detached_marker).await;
}

#[tokio::test]
async fn pty_cancellation_reaps_ignored_term_roots_and_detached_holders() {
    let directory = TestDirectory::new();
    let root_marker = directory.path().join("cancel-root.pids");
    let detached_marker = directory.path().join("cancel-detached.pids");
    let detached_holder = directory.script(
        "cancel-detached-holder",
        &format!(
            "#!/usr/bin/python3\nimport os, signal, time\nfirst = os.fork()\nif first:\n    os.waitpid(first, 0)\n    raise SystemExit\nos.setsid()\nsecond = os.fork()\nif second:\n    raise SystemExit\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nwith open({:?}, 'a', encoding='ascii') as marker:\n    marker.write(str(os.getpid()) + '\\n')\n    marker.flush()\nwhile True:\n    time.sleep(1)\n",
            detached_marker.display().to_string()
        ),
    );
    let cli = directory.script(
        "kiro-cli",
        &format!(
            r#"#!/bin/sh
if [ ! -t 1 ]; then exit 9; fi
trap '' TERM
printf '%s\n' "$$" >> {root_marker}
{detached_holder}
while :; do sleep 1; done
"#,
            root_marker = root_marker.display(),
            detached_holder = detached_holder.display(),
        ),
    );
    let timeouts = KiroCommandTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_millis(50),
    )
    .expect("cancel cleanup timeouts");
    let server = FakeHttpServer::start([]).await;
    let cancellation = CancellationToken::new();
    let fetch_context = ProviderContext::new(
        scope("cleanup-cancel"),
        ProviderSource::Cli,
        cancellation.clone(),
    );
    let provider = provider(
        &server,
        settings(&directory, &cli, None, Some(timeouts)),
        "cleanup-cancel",
    );
    let task = tokio::spawn(async move {
        provider
            .fetch_at(&fetch_context, timestamp(1_777_680_000))
            .await
    });
    let _roots = wait_for_marker(&root_marker).await;
    let _detached = wait_for_marker(&detached_marker).await;
    cancellation.cancel();
    assert_eq!(
        task.await
            .expect("cancel fetch task")
            .expect_err("cancelled PTY fetch")
            .kind(),
        ErrorKind::Network
    );
    assert_recorded_processes_gone(&root_marker).await;
    assert_recorded_processes_gone(&detached_marker).await;
}

#[tokio::test]
async fn pipe_activity_forbids_pty_and_residual_pipe_holders_are_reaped_first() {
    let directory = TestDirectory::new();
    let holder_marker = directory.path().join("pipe-holder.pids");
    let pty_marker = directory.path().join("unexpected-pty");
    let holder = directory.script(
        "pipe-holder",
        &format!(
            "#!/bin/sh\ntrap '' TERM\nprintf '%s\\n' \"$$\" >> {}\nwhile :; do sleep 1; done\n",
            holder_marker.display()
        ),
    );
    let cli = directory.script(
        "kiro-cli",
        &format!(
            r#"#!/bin/sh
if [ -t 1 ]; then
  printf 'pty\n' >> {pty_marker}
  printf 'Estimated Usage | KIRO FREE\r\nCredits (49 of 50 covered in plan)\r\n'
  exit 0
fi
if [ "$1" = "whoami" ]; then
  printf 'Logged in with Pipe\nEmail: pipe@example.com\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ]; then
  printf 'Estimated Usage | KIRO FREE\n'
  sleep 0.25
  /usr/bin/setsid -f {holder}
  printf 'Credits (10 of 50 covered in plan)\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/context" ]; then exit 0; fi
exit 1
"#,
            pty_marker = pty_marker.display(),
            holder = holder.display(),
        ),
    );
    let timeouts = KiroCommandTimeouts::new(
        Duration::from_secs(1),
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_millis(300),
    )
    .expect("pipe activity timeouts");
    let server = FakeHttpServer::start([]).await;
    let sample = provider(
        &server,
        settings(&directory, &cli, None, Some(timeouts)),
        "pipe-activity",
    )
    .fetch_at(
        &context("pipe-activity", ProviderSource::Cli),
        timestamp(1_777_680_000),
    )
    .await
    .expect("slow active pipe remains authoritative");
    assert_close(percent(sample.primary().expect("primary")), 20.0);
    assert!(!pty_marker.exists(), "PTY started after pipe activity");
    assert_recorded_processes_gone(&holder_marker).await;
}

#[tokio::test]
async fn inactive_pipe_and_holders_finish_cleanup_before_pty_fallback_starts() {
    let directory = TestDirectory::new();
    let holder_marker = directory.path().join("fallback-pipe-holder.pids");
    let overlap_marker = directory.path().join("pipe-pty-overlap");
    let lock = directory.path().join("pipe-holder.lock");
    let holder = directory.script(
        "fallback-pipe-holder",
        &format!(
            "#!/bin/sh\nexec 9>{lock}\n/usr/bin/flock -x 9\nprintf '%s\\n' \"$$\" >> {marker}\ntrap '' TERM\nwhile :; do sleep 1; done\n",
            lock = lock.display(),
            marker = holder_marker.display(),
        ),
    );
    let cli = directory.script(
        "kiro-cli",
        &format!(
            r#"#!/bin/sh
if [ "$1" = "whoami" ]; then
  printf 'Logged in with Pipe\nEmail: fallback@example.com\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/context" ]; then exit 0; fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ] && [ ! -t 1 ]; then
  {holder} &
  trap '' TERM
  while :; do sleep 1; done
fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ]; then
  if ! /usr/bin/flock -n {lock} -c true; then
    printf 'overlap\n' >> {overlap_marker}
    exit 23
  fi
  printf 'Estimated Usage | KIRO FREE\r\nCredits (15 of 50 covered in plan)\r\n'
  exit 0
fi
exit 1
"#,
            holder = holder.display(),
            lock = lock.display(),
            overlap_marker = overlap_marker.display(),
        ),
    );
    let timeouts = KiroCommandTimeouts::new(
        Duration::from_secs(1),
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_millis(100),
    )
    .expect("sequential fallback timeouts");
    let server = FakeHttpServer::start([]).await;
    let sample = provider(
        &server,
        settings(&directory, &cli, None, Some(timeouts)),
        "sequential-fallback",
    )
    .fetch_at(
        &context("sequential-fallback", ProviderSource::Cli),
        timestamp(1_777_680_000),
    )
    .await
    .expect("PTY starts only after pipe cleanup");
    assert_close(percent(sample.primary().expect("primary")), 30.0);
    assert!(!overlap_marker.exists(), "pipe and PTY overlapped");
    assert_recorded_processes_gone(&holder_marker).await;
}

#[tokio::test]
async fn incomplete_proc_scan_fails_closed_without_starting_pty_fallback() {
    let directory = TestDirectory::new();
    let pty_marker = directory.path().join("incomplete-scan-pty");
    let holder_marker = directory.path().join("incomplete-scan-holder.pids");
    let holder = directory.script(
        "incomplete-scan-holder",
        &format!(
            "#!/usr/bin/python3\nimport os, signal, time\nfirst = os.fork()\nif first:\n    os.waitpid(first, 0)\n    raise SystemExit\nos.setsid()\nsecond = os.fork()\nif second:\n    raise SystemExit\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nwith open({:?}, 'a', encoding='ascii') as marker:\n    marker.write(str(os.getpid()) + '\\n')\n    marker.flush()\nwhile True:\n    time.sleep(1)\n",
            holder_marker.display().to_string()
        ),
    );
    let cli = directory.script(
        "kiro-cli",
        &format!(
            r#"#!/bin/sh
if [ "$1" = "whoami" ]; then
  printf 'Logged in with Pipe\nEmail: reaper@example.com\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/context" ]; then exit 0; fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ] && [ -t 1 ]; then
  printf 'pty\n' >> {pty_marker}
  printf 'Estimated Usage | KIRO FREE\r\nCredits (1 of 50 covered in plan)\r\n'
  exit 0
fi
{holder}
count=0
while [ ! -s {holder_marker} ] && [ "$count" -lt 400 ]; do
  sleep 0.01
  count=$((count + 1))
done
trap '' TERM
while :; do sleep 1; done
"#,
            pty_marker = pty_marker.display(),
            holder = holder.display(),
            holder_marker = holder_marker.display(),
        ),
    );
    let timeouts = KiroCommandTimeouts::new(
        Duration::from_secs(1),
        Duration::from_secs(5),
        Duration::from_secs(1),
        Duration::from_millis(50),
    )
    .expect("incomplete scan timeouts");
    let guarded =
        settings(&directory, &cli, None, Some(timeouts)).with_forced_incomplete_proc_scan();
    let server = FakeHttpServer::start([]).await;
    let error = provider(&server, guarded, "scan-indeterminate")
        .fetch_at(
            &context("scan-indeterminate", ProviderSource::Cli),
            timestamp(1_777_680_000),
        )
        .await
        .expect_err("indeterminate ownership must fail closed");
    assert_eq!(error.kind(), ErrorKind::ProviderUnavailable);
    assert!(!pty_marker.exists(), "PTY launched after uncertain cleanup");
    assert_recorded_processes_gone(&holder_marker).await;
}

#[tokio::test]
async fn post_commit_pipe_output_cannot_revoke_latched_pty_fallback() {
    let directory = TestDirectory::new();
    let pty_marker = directory.path().join("committed-pty");
    let cli = directory.script(
        "kiro-cli",
        &format!(
            r#"#!/bin/sh
if [ "$1" = "whoami" ]; then
  printf 'Logged in with Pipe\nEmail: boundary@example.com\n'
  exit 0
fi
if [ "$1" = "chat" ] && [ "$3" = "/context" ]; then exit 0; fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ] && [ ! -t 1 ]; then
  sleep 0.12
  printf 'late post-commit bytes\n'
  trap '' TERM
  while :; do sleep 1; done
fi
if [ "$1" = "chat" ] && [ "$3" = "/usage" ]; then
  printf 'pty\n' >> {pty_marker}
  printf 'Estimated Usage | KIRO FREE\r\nCredits (20 of 50 covered in plan)\r\n'
  exit 0
fi
exit 1
"#,
            pty_marker = pty_marker.display(),
        ),
    );
    let timeouts = KiroCommandTimeouts::new(
        Duration::from_secs(1),
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_millis(100),
    )
    .expect("boundary timeouts");
    let boundary = settings(&directory, &cli, None, Some(timeouts))
        .with_fallback_commit_observation(Duration::from_millis(100))
        .expect("boundary observation");
    let server = FakeHttpServer::start([]).await;
    let sample = provider(&server, boundary, "fallback-boundary")
        .fetch_at(
            &context("fallback-boundary", ProviderSource::Cli),
            timestamp(1_777_680_000),
        )
        .await
        .expect("latched fallback");
    assert_close(percent(sample.primary().expect("primary")), 40.0);
    assert!(pty_marker.exists(), "committed PTY fallback was revoked");
}

#[tokio::test]
async fn sqlite_enrichment_uses_exact_wire_contract_and_normalizes_overage() {
    let directory = TestDirectory::new();
    let cli = directory.script("kiro-cli", standard_cli_script());
    let database = directory.database();
    let enriched_settings = settings(&directory, &cli, Some(&database), None);
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, LIMITS.to_vec())]).await;
    let sample = provider(&server, enriched_settings, "enriched-account")
        .fetch_at(
            &context("enriched-account", ProviderSource::Cli),
            timestamp(1_777_680_000),
        )
        .await
        .expect("enriched sample");
    assert_close(percent(sample.primary().expect("primary")), 100.0);
    let overage = sample
        .extra_windows()
        .iter()
        .find(|window| window.id().as_str() == "kiro-overage")
        .expect("overage window");
    assert!((percent(overage.window()) - 36.0349).abs() < 1e-9);
    let cost = sample.cost().expect("overage cost");
    assert_eq!(cost.limit().get(), Decimal::from(400_u16));
    assert_eq!(
        cost.used().amount().get(),
        Decimal::from_str_exact("144.139711109352").expect("decimal")
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), "POST");
    assert_eq!(requests[0].target(), "/");
    assert_eq!(requests[0].header("authorization"), Some(AUTHORIZATION));
    assert_eq!(
        requests[0].header("content-type"),
        Some("application/x-amz-json-1.0")
    );
    assert_eq!(
        requests[0].header("x-amz-target"),
        Some("AmazonCodeWhispererService.GetUsageLimits")
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(requests[0].body()).expect("request body"),
        serde_json::json!({
            "profileArn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/fixture"
        })
    );
    let debug = format!(
        "{:?}",
        provider(
            &FakeHttpServer::start([]).await,
            settings(&directory, &cli, Some(&database), None),
            "debug-account"
        )
    );
    assert!(!debug.contains(ACCESS_TOKEN));
    assert!(!debug.contains(directory.path().to_string_lossy().as_ref()));
}

#[tokio::test]
async fn malformed_http_status_and_unreadable_state_are_best_effort() {
    for response in [
        FakeHttpResponse::new(401, b"secret-auth-body".to_vec()),
        FakeHttpResponse::new(200, MALFORMED.to_vec()),
        FakeHttpResponse::truncated(200, 400, b"{}".to_vec()),
    ] {
        let directory = TestDirectory::new();
        let cli = directory.script("kiro-cli", standard_cli_script());
        let database = directory.database();
        let server = FakeHttpServer::start([response]).await;
        let sample = provider(
            &server,
            settings(&directory, &cli, Some(&database), None),
            "best-effort",
        )
        .fetch_at(
            &context("best-effort", ProviderSource::Cli),
            timestamp(1_777_680_000),
        )
        .await
        .expect("CLI usage survives enrichment failure");
        assert_close(percent(sample.primary().expect("primary")), 100.0);
        assert!(sample.extra_windows().is_empty());
        assert!(sample.cost().is_none());
    }

    let directory = TestDirectory::new();
    let cli = directory.script("kiro-cli", standard_cli_script());
    let missing = directory.path().join("missing.sqlite3");
    let server = FakeHttpServer::start([]).await;
    let sample = provider(
        &server,
        settings(&directory, &cli, Some(&missing), None),
        "missing-state",
    )
    .fetch_at(
        &context("missing-state", ProviderSource::Cli),
        timestamp(1_777_680_000),
    )
    .await
    .expect("missing state is optional");
    assert!(sample.extra_windows().is_empty());
}

#[tokio::test]
async fn authentication_nonzero_timeout_cancellation_and_output_caps_are_classified() {
    let directory = TestDirectory::new();
    let auth_cli = directory.script(
        "kiro-cli-auth",
        "#!/bin/sh\nprintf 'Not logged in; run kiro-cli login\\n' >&2\nexit 1\n",
    );
    // The shared resolver requires the executable basename to match.
    let auth_path = directory.path().join("kiro-cli");
    fs::rename(auth_cli, &auth_path).expect("auth CLI name");
    let server = FakeHttpServer::start([]).await;
    let error = provider(
        &server,
        settings(&directory, &auth_path, None, None),
        "auth-account",
    )
    .fetch_at(
        &context("auth-account", ProviderSource::Cli),
        timestamp(1_777_680_000),
    )
    .await
    .expect_err("auth failure");
    assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);

    let hanging = directory.script(
        "hanging",
        "#!/bin/sh\ntrap '' TERM\nwhile :; do sleep 1; done\n",
    );
    fs::rename(hanging, &auth_path).expect("hanging CLI name");
    let short = KiroCommandTimeouts::new(
        Duration::from_millis(250),
        Duration::from_millis(300),
        Duration::from_millis(200),
        Duration::from_millis(50),
    )
    .expect("short timeouts");
    let started = Instant::now();
    let error = provider(
        &server,
        settings(&directory, &auth_path, None, Some(short)),
        "timeout-account",
    )
    .fetch_at(
        &context("timeout-account", ProviderSource::Cli),
        timestamp(1_777_680_000),
    )
    .await
    .expect_err("timeout");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(started.elapsed() < Duration::from_secs(3));

    let cancellation = CancellationToken::new();
    let cancelled_context = ProviderContext::new(
        scope("cancel-account"),
        ProviderSource::Cli,
        cancellation.clone(),
    );
    let cancel_provider = provider(
        &server,
        settings(
            &directory,
            &auth_path,
            None,
            Some(
                KiroCommandTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    Duration::from_millis(50),
                )
                .expect("cancel timeouts"),
            ),
        ),
        "cancel-account",
    );
    let task = tokio::spawn(async move {
        cancel_provider
            .fetch_at(&cancelled_context, timestamp(1_777_680_000))
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancellation.cancel();
    let error = task
        .await
        .expect("fetch task")
        .expect_err("cancelled fetch");
    assert_eq!(error.kind(), ErrorKind::Network);

    let oversized = directory.script(
        "oversized",
        "#!/bin/sh\nhead -c 700000 /dev/zero | tr '\\000' x\n",
    );
    fs::rename(oversized, &auth_path).expect("oversized CLI name");
    let error = provider(
        &server,
        settings(&directory, &auth_path, None, Some(short)),
        "cap-account",
    )
    .fetch_at(
        &context("cap-account", ProviderSource::Cli),
        timestamp(1_777_680_000),
    )
    .await
    .expect_err("output cap");
    assert_eq!(error.kind(), ErrorKind::Parse);
}

#[tokio::test]
async fn account_and_source_isolation_precede_process_and_network_access() {
    let directory = TestDirectory::new();
    let cli = directory.script("kiro-cli", standard_cli_script());
    let server = FakeHttpServer::start([]).await;
    let resolved = settings(&directory, &cli, None, None);
    for endpoint in [
        "https://attacker.example/",
        "https://codewhisperer.us-east-1.amazonaws.com.evil.example/",
        "http://attacker.example/",
    ] {
        assert_eq!(
            KiroProvider::from_transport(
                scope("exfiltration"),
                resolved.clone(),
                url::Url::parse(endpoint).expect("endpoint"),
                transport(&server),
            )
            .expect_err("credential exfiltration endpoint")
            .kind(),
            ErrorKind::Api
        );
    }
    KiroProvider::from_transport(
        scope("loopback-https"),
        resolved.clone(),
        url::Url::parse("https://localhost:443/").expect("loopback HTTPS"),
        transport(&server),
    )
    .expect("explicit loopback HTTPS seam");

    let provider = provider(&server, resolved, "account-a");
    for invalid in [
        context("account-b", ProviderSource::Cli),
        context("account-a", ProviderSource::LocalData),
    ] {
        assert_eq!(
            provider
                .fetch_at(&invalid, timestamp(1_777_680_000))
                .await
                .expect_err("isolated context")
                .kind(),
            ErrorKind::Api
        );
    }
    assert!(server.requests().is_empty());
}
