//! Full CLI lifecycle tests with isolated homes and a fake login executable.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

struct Fixture(TempDir);
impl Fixture {
    fn new() -> Self {
        let fixture = Self(tempfile::tempdir().unwrap());
        for directory in ["home", "config", "data", "cache", "runtime"] {
            fs::create_dir(fixture.path(directory)).unwrap();
        }
        fixture.write("fake-codex", b"#!/bin/sh\n[ \"$1\" = login ] || exit 1\numask 077\nprintf '%s' \"$OAB_TEST_AUTH\" > \"$CODEX_HOME/auth.json\"\n", 0o700);
        fixture.write("home/.codex/auth.json", b"native-account-canary", 0o600);
        fixture
    }
    fn path(&self, relative: &str) -> PathBuf {
        self.0.path().join(relative)
    }
    fn write(&self, relative: &str, content: &[u8], mode: u32) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"));
        cmd.env_clear();
        for (key, directory) in [
            ("HOME", "home"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_RUNTIME_DIR", "runtime"),
        ] {
            cmd.env(key, self.path(directory));
        }
        // Never contact the real user service from a lifecycle fixture.
        cmd.env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", self.path("no-bus").display()),
        );
        cmd.env("OMARCHY_AI_BAR_CODEX_EXECUTABLE", self.path("fake-codex"));
        cmd
    }
    fn login(&self, identity_payload: &str, workspace: &str, token: &str) -> Output {
        let auth = json!({"tokens": {"access_token": token, "refresh_token": "refresh-fixture", "account_id": workspace, "id_token": format!("e30.{identity_payload}.fixture")}});
        self.command()
            .args(["codex", "login"])
            .env("OAB_TEST_AUTH", auth.to_string())
            .output()
            .unwrap()
    }
    fn accounts(&self) -> Vec<Value> {
        let output = self
            .command()
            .args(["codex", "list", "--format", "json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["ambient"] == false)
            .cloned()
            .collect()
    }
    fn managed_home(&self, account: &Value) -> PathBuf {
        self.path("data/omarchy-ai-bar/codex/managed-accounts")
            .join(account["id"].as_str().unwrap())
    }
}

const ALPHA: &str = "eyJlbWFpbCI6ImFscGhhQGV4YW1wbGUudGVzdCJ9";
const BETA: &str = "eyJlbWFpbCI6ImJldGFAZXhhbXBsZS50ZXN0In0";

#[test]
fn codex_login_preserves_users_and_workspaces_and_reauth_keeps_id_and_history() {
    let f = Fixture::new();
    assert!(
        f.login(ALPHA, "workspace-shared", "old-token")
            .status
            .success()
    );
    let first = f.accounts()[0].clone();
    let home = f.managed_home(&first);
    fs::create_dir(home.join("sessions")).unwrap();
    fs::write(home.join("sessions/history.jsonl"), b"history-canary").unwrap();
    fs::write(home.join("config.toml"), b"config-canary").unwrap();
    assert!(
        f.login(BETA, "workspace-shared", "beta-token")
            .status
            .success()
    );
    assert!(
        f.login(ALPHA, "workspace-other", "other-token")
            .status
            .success()
    );
    assert_eq!(f.accounts().len(), 3);
    assert!(
        f.login(ALPHA, "workspace-shared", "new-token")
            .status
            .success()
    );
    let accounts = f.accounts();
    assert_eq!(accounts.len(), 3);
    let active = accounts
        .iter()
        .find(|account| account["active"] == true)
        .unwrap();
    assert_eq!(active["id"], first["id"]);
    assert_eq!(
        fs::read(home.join("sessions/history.jsonl")).unwrap(),
        b"history-canary"
    );
    assert_eq!(
        fs::read(home.join("config.toml")).unwrap(),
        b"config-canary"
    );
    let auth: Value = serde_json::from_slice(&fs::read(home.join("auth.json")).unwrap()).unwrap();
    assert_eq!(auth["tokens"]["access_token"], "new-token");
    assert!(!home.join("auth.json.previous").exists());
    assert_eq!(
        fs::read(f.path("home/.codex/auth.json")).unwrap(),
        b"native-account-canary"
    );
    assert_eq!(
        fs::read_dir(f.path("data/omarchy-ai-bar/codex/managed-accounts"))
            .unwrap()
            .count(),
        3
    );
}

#[test]
fn codex_failed_reauth_preserves_old_auth_and_cleans_staging_home() {
    let f = Fixture::new();
    assert!(
        f.login(ALPHA, "workspace-shared", "old-token")
            .status
            .success()
    );
    let account = f.accounts()[0].clone();
    let auth_path = f.managed_home(&account).join("auth.json");
    let old_auth = fs::read(&auth_path).unwrap();
    let previous = f.path("config/omarchy-ai-bar/config.json.previous");
    if previous.exists() {
        fs::remove_file(&previous).unwrap();
    }
    std::os::unix::fs::symlink(Path::new("/nonexistent/audit-target"), &previous).unwrap();
    assert!(
        !f.login(ALPHA, "workspace-shared", "new-token")
            .status
            .success()
    );
    assert_eq!(fs::read(auth_path).unwrap(), old_auth);
    assert_eq!(
        fs::read_dir(f.path("data/omarchy-ai-bar/codex/managed-accounts"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn codex_invalid_login_and_missing_executable_leave_no_managed_homes() {
    let f = Fixture::new();
    assert!(
        !f.command()
            .args(["codex", "login"])
            .env("OAB_TEST_AUTH", "{}")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !f.command()
            .args(["codex", "login"])
            .env("OMARCHY_AI_BAR_CODEX_EXECUTABLE", f.path("absent"))
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        fs::read_dir(f.path("data/omarchy-ai-bar/codex/managed-accounts"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn display_selection_never_switches_native_codex_credentials() {
    let f = Fixture::new();
    assert!(
        f.login(ALPHA, "workspace-alpha", "managed-token")
            .status
            .success()
    );
    let account = f.accounts()[0].clone();
    let managed_auth = f.managed_home(&account).join("auth.json");
    let before = fs::read(&managed_auth).unwrap();
    for id in [account["id"].as_str().unwrap(), "ambient"] {
        assert!(
            f.command()
                .args(["codex", "activate", id])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(
            fs::read(f.path("home/.codex/auth.json")).unwrap(),
            b"native-account-canary"
        );
        assert_eq!(fs::read(&managed_auth).unwrap(), before);
    }
}
