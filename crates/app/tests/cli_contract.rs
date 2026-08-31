mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use serde_json::Value;

use support::{DaemonFixture, EXPECTED_PROVIDER_IDS, terminate, wait_for_exit};

const UNAVAILABLE: i32 = 69;

#[test]
fn help_registers_the_complete_command_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .arg("--help")
        .output()
        .expect("run help");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    for command in [
        "daemon",
        "usage",
        "cards",
        "dashboard",
        "cost",
        "serve",
        "config",
        "hooks",
        "guard",
        "cookie",
        "cache",
        "plugins",
        "sessions",
        "diagnose",
        "bridge",
        "completion",
        "version",
    ] {
        assert!(help.contains(command), "help omitted {command}");
    }
}

#[test]
fn unavailable_handlers_and_daemon_commands_without_a_daemon_are_stable() {
    let fixture = DaemonFixture::new("placeholders");
    let cases: &[&[&str]] = &[
        &["usage"],
        &["cards"],
        &["cost"],
        &["guard"],
        &["sessions"],
        &["diagnose"],
    ];

    for arguments in cases {
        let output = fixture
            .command()
            .args(*arguments)
            .output()
            .expect("run placeholder");
        assert_eq!(output.status.code(), Some(UNAVAILABLE), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(!output.stderr.is_empty(), "{arguments:?}");
    }
}

#[test]
fn local_server_is_loopback_only_and_projects_daemon_json() {
    let fixture = DaemonFixture::new("local-server");
    let rejected = fixture
        .command()
        .args(["serve", "--listen", "0.0.0.0:43129"])
        .output()
        .expect("reject non-loopback listener");
    assert_eq!(rejected.status.code(), Some(2));

    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let address = reservation.local_addr().expect("reserved address");
    drop(reservation);
    let mut server = fixture
        .command()
        .args([
            "serve",
            "--listen",
            &address.to_string(),
            "--max-requests",
            "2",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn local server");
    let mut announcement = String::new();
    BufReader::new(server.stdout.take().expect("server stdout"))
        .read_line(&mut announcement)
        .expect("read server announcement");
    assert!(announcement.contains(&address.to_string()));

    let health = http_get(address, "/health");
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(health.contains("\r\nCache-Control: no-store\r\n"));
    assert!(health.ends_with("{\"daemon\":\"running\",\"status\":\"ok\"}"));
    let usage = http_get(address, "/v1/usage");
    assert!(usage.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(usage.contains("\"snapshots\":"));
    assert!(server.wait().expect("wait for local server").success());

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
}

fn http_get(address: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("connect to local server");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("write HTTP request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read HTTP response");
    response
}

#[test]
fn config_init_show_and_validate_use_the_private_xdg_file() {
    let fixture = DaemonFixture::new("config-cli");
    let initial = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show missing config");
    assert!(initial.status.success());
    let initial: Value = serde_json::from_slice(&initial.stdout).expect("initial JSON");
    assert_eq!(initial["initialized"], false);

    let initialized = fixture
        .command()
        .args(["config", "init"])
        .output()
        .expect("initialize config");
    assert!(initialized.status.success());

    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show config");
    assert!(shown.status.success());
    assert!(shown.stderr.is_empty());
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("shown JSON");
    assert_eq!(shown["initialized"], true);
    assert_eq!(shown["config"]["schema_version"], 1);
    assert_eq!(shown["config"]["providers"], serde_json::json!([]));

    let validated = fixture
        .command()
        .args(["config", "validate"])
        .output()
        .expect("validate config");
    assert!(validated.status.success());
    assert_eq!(validated.stdout, b"Configuration is valid.\n");
}

#[test]
fn cache_status_and_clear_are_scoped_to_the_application_cache() {
    let fixture = DaemonFixture::new("cache-cli");
    let empty = fixture
        .command()
        .args(["cache", "status", "--format", "json"])
        .output()
        .expect("inspect empty cache");
    assert!(empty.status.success());
    let empty: Value = serde_json::from_slice(&empty.stdout).expect("empty cache JSON");
    assert_eq!(empty["entries"], 0);
    let cache_path = std::path::PathBuf::from(empty["path"].as_str().expect("cache path"));
    std::fs::create_dir_all(cache_path.join("pricing")).expect("create cache fixture");
    std::fs::write(cache_path.join("pricing/models.json"), b"model-data")
        .expect("write cache fixture");

    let populated = fixture
        .command()
        .args(["cache", "status", "--format", "json"])
        .output()
        .expect("inspect populated cache");
    let populated: Value = serde_json::from_slice(&populated.stdout).expect("populated JSON");
    assert_eq!(populated["entries"], 2);
    assert_eq!(populated["bytes"], 10);

    let cleared = fixture
        .command()
        .args(["cache", "clear"])
        .output()
        .expect("clear cache");
    assert!(cleared.status.success());
    assert!(cache_path.is_dir());
    assert_eq!(
        std::fs::read_dir(cache_path).expect("read cache").count(),
        0
    );
}

#[test]
fn cookie_registry_is_machine_readable_and_never_echoes_credentials() {
    let fixture = DaemonFixture::new("cookie-cli");
    let listed = fixture
        .command()
        .args(["cookie", "list", "--format", "json"])
        .output()
        .expect("list manual credentials");
    assert!(listed.status.success());
    assert!(listed.stderr.is_empty());
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("credential registry JSON");
    let entries = listed.as_array().expect("credential entries");
    assert!(entries.len() >= 20);
    assert!(entries.iter().all(|entry| {
        entry["provider"].is_string()
            && entry["environment_override"].is_string()
            && entry.get("value").is_none()
    }));

    let unsupported = fixture
        .command()
        .args(["cookie", "status", "unknown-provider"])
        .output()
        .expect("reject unsupported credential provider");
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(unsupported.stdout.is_empty());
}

#[test]
fn hooks_are_shell_free_bounded_and_owned_by_the_user() {
    let fixture = DaemonFixture::new("hooks-cli");
    let path = fixture
        .command()
        .args(["hooks", "path"])
        .output()
        .expect("resolve hooks path");
    assert!(path.status.success());
    let path = std::path::PathBuf::from(
        String::from_utf8(path.stdout)
            .expect("UTF-8 hook path")
            .trim(),
    );
    std::fs::create_dir_all(&path).expect("create hook directory");
    let executable = path.join("warning");
    std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("write hook");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("secure hook");

    let listed = fixture
        .command()
        .args(["hooks", "list", "--format", "json"])
        .output()
        .expect("list hooks");
    assert!(listed.status.success());
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("hooks JSON");
    assert!(listed.as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row["event"] == "warning" && row["installed"] == true)
    }));

    let run = fixture
        .command()
        .args(["hooks", "run", "warning"])
        .output()
        .expect("run hook");
    assert!(run.status.success());
    assert_eq!(run.stdout, b"Hook warning completed.\n");
}

#[test]
fn plugins_run_inside_the_embedded_bounded_javascript_contract() {
    let fixture = DaemonFixture::new("plugins-cli");
    let path = fixture
        .command()
        .args(["plugins", "path"])
        .output()
        .expect("resolve plugins path");
    let directory = std::path::PathBuf::from(
        String::from_utf8(path.stdout)
            .expect("UTF-8 plugin path")
            .trim(),
    );
    std::fs::create_dir_all(&directory).expect("create plugin directory");
    let source = directory.join("fixture.js");
    std::fs::write(
        &source,
        br#"
            globalThis.omarchyAiBarPlugin = {
                id: "fixture-provider",
                name: "Fixture Provider",
                version: 1,
                collect() { return { used_percent: 17, node: typeof process }; }
            };
        "#,
    )
    .expect("write plugin source");

    let validated = fixture
        .command()
        .args(["plugins", "validate", source.to_str().expect("plugin path")])
        .output()
        .expect("validate plugin");
    assert!(validated.status.success());

    let run = fixture
        .command()
        .args([
            "plugins",
            "run",
            source.to_str().expect("plugin path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run plugin");
    assert!(run.status.success());
    assert!(run.stderr.is_empty());
    let run: Value = serde_json::from_slice(&run.stdout).expect("plugin JSON");
    assert_eq!(run["manifest"]["id"], "fixture-provider");
    assert_eq!(run["sample"]["used_percent"], 17);
    assert_eq!(run["sample"]["node"], "undefined");
}

#[test]
fn packaged_shell_completions_are_generated_from_the_cli_tree() {
    for shell in ["bash", "zsh", "fish"] {
        let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
            .args(["completion", shell])
            .output()
            .expect("generate completion");
        assert!(output.status.success(), "{shell}");
        assert!(output.stderr.is_empty(), "{shell}");
        let completion = String::from_utf8(output.stdout).expect("UTF-8 completion");
        assert!(completion.contains("omarchy-ai-bar"), "{shell}");
    }
}

#[test]
fn json_and_toon_stdout_are_data_only_and_diagnostics_stay_on_stderr() {
    let fixture = DaemonFixture::new("machine-output");
    for format in ["json", "toon"] {
        let output = fixture
            .command()
            .args(["usage", "--format", format])
            .output()
            .expect("run usage placeholder");
        assert_eq!(output.status.code(), Some(UNAVAILABLE));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with("omarchy-ai-bar: "),
            "diagnostic must remain on stderr"
        );
    }

    let version = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .args(["version", "--json"])
        .output()
        .expect("run JSON version");
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    let value: Value = serde_json::from_slice(&version.stdout).expect("data-only JSON stdout");
    assert_eq!(value["name"], "omarchy-ai-bar");
}

#[test]
fn invalid_command_uses_clap_usage_status_without_stdout_noise() {
    let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .arg("not-a-command")
        .output()
        .expect("run invalid command");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn bridge_status_is_an_implemented_read_only_command() {
    let fixture = DaemonFixture::new("bridge-status");
    let output = fixture
        .command()
        .args(["bridge", "status"])
        .output()
        .expect("run bridge status");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 bridge status"),
        "Omarchy bridge: not installed\n"
    );
}

#[test]
fn running_daemon_serves_usage_cards_and_redacted_diagnostics() {
    let fixture = DaemonFixture::new("live-cli-output");
    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);

    let usage = fixture
        .command()
        .args(["usage", "--format", "json"])
        .output()
        .expect("run JSON usage");
    assert!(
        usage.status.success(),
        "{}",
        String::from_utf8_lossy(&usage.stderr)
    );
    assert!(usage.stderr.is_empty());
    let usage: Value = serde_json::from_slice(&usage.stdout).expect("usage JSON");
    assert_eq!(usage["schema_version"], 1);
    assert_eq!(
        usage["snapshots"].as_array().map(Vec::len),
        Some(EXPECTED_PROVIDER_IDS.len())
    );

    let cards = fixture
        .command()
        .args(["cards", "--format", "json"])
        .output()
        .expect("run JSON cards");
    assert!(cards.status.success());
    assert!(cards.stderr.is_empty());
    let cards: Value = serde_json::from_slice(&cards.stdout).expect("cards JSON");
    assert_eq!(
        cards.as_array().map(Vec::len),
        Some(EXPECTED_PROVIDER_IDS.len())
    );
    assert!(cards.as_array().is_some_and(|items| {
        items
            .iter()
            .all(|item| item.get("provider").is_some() && item.get("state").is_some())
    }));

    let diagnose = fixture
        .command()
        .args(["diagnose", "--format", "json"])
        .output()
        .expect("run JSON diagnostics");
    assert!(diagnose.status.success());
    assert!(diagnose.stderr.is_empty());
    let diagnose: Value = serde_json::from_slice(&diagnose.stdout).expect("diagnostics JSON");
    assert_eq!(diagnose["daemon"], "running");
    assert_eq!(
        diagnose["providers"].as_array().map(Vec::len),
        Some(EXPECTED_PROVIDER_IDS.len())
    );
    let diagnosed = diagnose["providers"]
        .as_array()
        .expect("diagnosed providers")
        .iter()
        .filter_map(|provider| provider["provider"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(diagnosed, EXPECTED_PROVIDER_IDS.into_iter().collect());
    let encoded = serde_json::to_string(&diagnose).expect("encode diagnostics");
    for private_field in [
        "email",
        "account_label",
        "provider_account_id",
        "organization",
    ] {
        assert!(!encoded.contains(private_field));
    }

    let toon = fixture
        .command()
        .args(["cards", "--format", "toon"])
        .output()
        .expect("run TOON cards");
    assert!(toon.status.success());
    assert!(toon.stderr.is_empty());
    let toon = String::from_utf8(toon.stdout).expect("UTF-8 TOON");
    assert!(toon.contains("provider:"));
    assert!(!toon.contains('{'));

    assert_extended_daemon_commands(&fixture);

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
}

fn assert_extended_daemon_commands(fixture: &DaemonFixture) {
    let cost = fixture
        .command()
        .args(["cost", "--format", "json"])
        .output()
        .expect("run JSON cost");
    assert!(cost.status.success());
    let cost: Value = serde_json::from_slice(&cost.stdout).expect("cost JSON");
    assert_eq!(cost["schema_version"], 1);
    assert!(cost["providers"].is_array());

    let sessions = fixture
        .command()
        .args(["sessions", "--format", "json"])
        .output()
        .expect("run JSON sessions");
    assert!(sessions.status.success());
    let sessions: Value = serde_json::from_slice(&sessions.stdout).expect("sessions JSON");
    assert_eq!(sessions["schema_version"], 1);
    assert!(sessions["sessions"].is_array());

    let guard = fixture
        .command()
        .args(["guard", "--max-used", "100"])
        .output()
        .expect("run guard");
    assert!(guard.status.success());
    assert!(String::from_utf8_lossy(&guard.stdout).starts_with("ALLOW:"));
}
