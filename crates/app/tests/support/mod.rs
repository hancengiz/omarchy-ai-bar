#![allow(
    dead_code,
    reason = "shared integration-test support is compiled separately for each test target"
)]

use std::fs;
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

const PROCESS_DEADLINE: Duration = Duration::from_secs(5);
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub const EXPECTED_PROVIDER_IDS: [&str; 69] = [
    "abacus",
    "aiand",
    "alibaba",
    "alibabatokenplan",
    "amp",
    "antigravity",
    "azureopenai",
    "augment",
    "bedrock",
    "chutes",
    "claude",
    "clawrouter",
    "clinepass",
    "codebuff",
    "codex",
    "commandcode",
    "copilot",
    "crof",
    "cursor",
    "deepgram",
    "deepinfra",
    "deepseek",
    "devin",
    "doubao",
    "elevenlabs",
    "factory",
    "fireworks",
    "gemini",
    "grok",
    "groq",
    "ibmbob",
    "jetbrains",
    "kilo",
    "kimi",
    "kiro",
    "litellm",
    "llmproxy",
    "longcat",
    "manus",
    "minimax",
    "mimo",
    "mistral",
    "moonshot",
    "neuralwatt",
    "notion",
    "ollama",
    "openai",
    "opencode",
    "opencodego",
    "openrouter",
    "perplexity",
    "poe",
    "qoder",
    "qwencloud",
    "sakana",
    "stepfun",
    "sub2api",
    "synthetic",
    "t3chat",
    "venice",
    "vertexai",
    "warp",
    "wayfinder",
    "windsurf",
    "xai",
    "zai",
    "zed",
    "zenmux",
    "zoommate",
];

pub struct DaemonFixture {
    root: PathBuf,
}

pub struct DaemonProcess {
    child: Child,
}

impl Deref for DaemonProcess {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl DerefMut for DaemonProcess {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ignored = self.child.kill();
            let _ignored = self.child.wait();
        }
    }
}

impl DaemonFixture {
    pub fn new(label: &str) -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-task9-{}-{label}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        Self { root }
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"));
        command
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_RUNTIME_DIR", self.root.join("runtime"));
        command
    }

    pub fn configure_all_providers_enabled(&self) {
        let directory = self.root.join("config").join("omarchy-ai-bar");
        fs::create_dir_all(&directory).expect("create fixture configuration directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("secure fixture configuration directory");
        let providers = EXPECTED_PROVIDER_IDS
            .iter()
            .map(|provider| {
                serde_json::json!({
                    "id": provider,
                    "instance_id": "default",
                    "enabled": true,
                    "accounts": [],
                })
            })
            .collect::<Vec<_>>();
        let document = serde_json::json!({
            "schema_version": 1,
            "providers": providers,
            "provider_order": EXPECTED_PROVIDER_IDS.to_vec(),
        });
        let file = directory.join("config.json");
        fs::write(
            &file,
            serde_json::to_vec_pretty(&document).expect("encode fixture configuration"),
        )
        .expect("write fixture configuration");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))
            .expect("secure fixture configuration");
    }

    pub fn socket_path(&self) -> PathBuf {
        self.root
            .join("runtime")
            .join("omarchy-ai-bar")
            .join("daemon.sock")
    }

    pub fn display_socket_path(&self) -> PathBuf {
        self.root
            .join("runtime")
            .join("omarchy-ai-bar")
            .join("display.sock")
    }

    pub fn spawn_daemon(&self) -> DaemonProcess {
        let child = self
            .command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn daemon");
        DaemonProcess { child }
    }

    pub fn wait_until_listening(&self, child: &mut Child) {
        let deadline = Instant::now() + PROCESS_DEADLINE;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().expect("poll daemon") {
                panic!("daemon exited before readiness: {status}");
            }
            if self.socket_path().exists() && self.display_socket_path().exists() {
                for path in [self.socket_path(), self.display_socket_path()] {
                    let metadata = fs::symlink_metadata(path).expect("socket metadata");
                    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                }
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ignored = child.kill();
        let _ignored = child.wait();
        panic!("daemon socket did not appear before deadline");
    }

    pub fn activate(&self) -> Output {
        let child = self
            .command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn forwarding invocation");
        wait_with_output(child)
    }

    pub fn socket_identity(&self) -> (u64, u64) {
        let metadata = fs::symlink_metadata(self.socket_path()).expect("socket metadata");
        (metadata.dev(), metadata.ino())
    }
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove fixture root");
        }
    }
}

pub fn read_child_output(child: &mut Child, status: ExitStatus) -> Output {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout).expect("read child stdout");
    }
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr).expect("read child stderr");
    }
    Output {
        status,
        stdout,
        stderr,
    }
}

pub fn terminate(child: &Child) {
    let raw_pid = i32::try_from(child.id()).expect("child PID fits i32");
    kill(Pid::from_raw(raw_pid), Signal::SIGTERM).expect("send SIGTERM");
}

pub fn wait_for_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll daemon exit") {
            return status;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ignored = child.kill();
    let _ignored = child.wait();
    panic!("daemon did not exit before deadline");
}

fn wait_with_output(mut child: Child) -> Output {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return read_child_output(&mut child, status);
        }
        if Instant::now() >= deadline {
            let _ignored = child.kill();
            let _ignored = child.wait();
            panic!("child did not exit before deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub fn assert_removed(path: &Path) {
    assert!(!path.exists(), "daemon socket should be removed");
}
