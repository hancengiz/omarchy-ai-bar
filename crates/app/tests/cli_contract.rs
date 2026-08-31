mod support;

use std::process::Command;

use serde_json::Value;

use support::{DaemonFixture, terminate, wait_for_exit};

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
fn every_unimplemented_handler_returns_stable_unavailable() {
    let fixture = DaemonFixture::new("placeholders");
    let cases: &[&[&str]] = &[
        &["usage"],
        &["cards"],
        &["dashboard"],
        &["cost"],
        &["serve"],
        &["config"],
        &["hooks"],
        &["guard"],
        &["cookie"],
        &["cache"],
        &["plugins"],
        &["sessions"],
        &["diagnose"],
        &["completion"],
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
    assert_eq!(usage["snapshots"].as_array().map(Vec::len), Some(4));

    let cards = fixture
        .command()
        .args(["cards", "--format", "json"])
        .output()
        .expect("run JSON cards");
    assert!(cards.status.success());
    assert!(cards.stderr.is_empty());
    let cards: Value = serde_json::from_slice(&cards.stdout).expect("cards JSON");
    assert_eq!(cards.as_array().map(Vec::len), Some(4));
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
    assert_eq!(diagnose["providers"].as_array().map(Vec::len), Some(4));
    let diagnosed = diagnose["providers"]
        .as_array()
        .expect("diagnosed providers")
        .iter()
        .filter_map(|provider| provider["provider"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        diagnosed,
        std::collections::BTreeSet::from(["claude", "codex", "grok", "zai"])
    );
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

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
}
