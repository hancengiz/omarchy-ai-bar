mod support;

use std::process::Command;

use serde_json::Value;

use support::DaemonFixture;

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
