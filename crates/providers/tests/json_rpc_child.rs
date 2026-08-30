use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::kill;
use nix::unistd::Pid;
use oab_providers::executable::{ExecutablePath, resolve_executable};
use oab_providers::json_rpc_child::{JsonRpcChildError, JsonRpcChildRequest, JsonRpcVersion};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const FRAME_LIMIT: usize = 16 * 1024;
const STDERR_LIMIT: usize = 16 * 1024;

#[tokio::test]
async fn codex_dialect_omits_version_and_preserves_initialize_sequence() {
    let fixture = ScriptFixture::new(
        r#"
IFS= read -r initialize
printf '%s\n' "$initialize" > "$OAB_CAPTURE"
printf '%s\n%s\n%s\n' \
  '{"method":"account/updated","params":{}}' \
  '{"id":77,"result":{"unrelated":true}}' \
  '{"id":1,"result":{"ready":true}}'
IFS= read -r initialized
printf '%s\n' "$initialized" >> "$OAB_CAPTURE"
IFS= read -r account
printf '%s\n' "$account" >> "$OAB_CAPTURE"
printf '%s\n' '{"id":2,"result":{"account":{"email":"safe@example.test"}}}'
while IFS= read -r ignored; do :; done
"#,
    );
    let capture = fixture.path("frames.jsonl");
    let mut child = fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .with_cleared_environment()
        .with_environment("OAB_CAPTURE", capture.as_os_str())
        .expect("valid capture environment")
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");
    let cancellation = CancellationToken::new();

    let initialized = child
        .request(
            "initialize",
            Some(json!({"clientInfo": {"name": "omarchy-ai-bar", "version": "0.1.0"}})),
            Duration::from_secs(2),
            &cancellation,
        )
        .await
        .expect("initialize response");
    assert_eq!(initialized, json!({"ready": true}));
    child
        .notify("initialized", None, Duration::from_secs(2), &cancellation)
        .await
        .expect("initialized notification");
    let account = child
        .request("account/read", None, Duration::from_secs(2), &cancellation)
        .await
        .expect("account response");
    assert_eq!(account["account"]["email"], "safe@example.test");
    child.shutdown().await;

    let frames = read_json_lines(&capture);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0]["id"], 1);
    assert_eq!(frames[0]["method"], "initialize");
    assert!(frames[0].get("jsonrpc").is_none());
    assert_eq!(frames[1]["method"], "initialized");
    assert!(frames[1].get("id").is_none());
    assert!(frames[1].get("jsonrpc").is_none());
    assert_eq!(frames[2]["id"], 2);
    assert_eq!(frames[2]["method"], "account/read");
    assert_eq!(frames[2]["params"], json!({}));
}

#[tokio::test]
async fn grok_dialect_sends_v2_and_keeps_slashes_unescaped() {
    let fixture = ScriptFixture::new(
        r#"
IFS= read -r initialize
printf '%s\n' "$initialize" > "$OAB_CAPTURE"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
IFS= read -r billing
printf '%s\n' "$billing" >> "$OAB_CAPTURE"
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"monthlyLimit":{"val":100}}}'
while IFS= read -r ignored; do :; done
"#,
    );
    let capture = fixture.path("frames.jsonl");
    let mut child = fixture
        .request(JsonRpcVersion::V2, FRAME_LIMIT, STDERR_LIMIT)
        .with_cleared_environment()
        .with_environment("OAB_CAPTURE", capture.as_os_str())
        .expect("valid capture environment")
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");
    let cancellation = CancellationToken::new();

    child
        .request(
            "initialize",
            Some(json!({"protocolVersion": "1", "clientCapabilities": {}})),
            Duration::from_secs(2),
            &cancellation,
        )
        .await
        .expect("initialize response");
    let billing = child
        .request("x.ai/billing", None, Duration::from_secs(2), &cancellation)
        .await
        .expect("billing response");
    assert_eq!(billing["monthlyLimit"]["val"], 100);
    child.shutdown().await;

    let raw = fs::read_to_string(&capture).expect("captured frames");
    assert!(!raw.contains("x.ai\\/billing"));
    let frames = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("valid captured JSON"))
        .collect::<Vec<_>>();
    assert_eq!(frames[0]["jsonrpc"], "2.0");
    assert_eq!(frames[1]["jsonrpc"], "2.0");
    assert_eq!(frames[1]["method"], "x.ai/billing");
}

#[tokio::test]
async fn fragmented_response_and_blank_frames_are_handled_without_unbounded_reads() {
    let fixture = ScriptFixture::new(
        r#"
IFS= read -r request
printf '\n   \n'
printf '%s' '{"id":1,"res'
sleep 0.02
printf '%s\n' 'ult":{"fragmented":true}}'
while IFS= read -r ignored; do :; done
"#,
    );
    let mut child = fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");

    let result = child
        .request(
            "account/read",
            None,
            Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await
        .expect("fragmented response");
    assert_eq!(result, json!({"fragmented": true}));
    child.shutdown().await;
}

#[tokio::test]
async fn remote_error_message_is_explicitly_accessed_and_redacted_everywhere_else() {
    let secret = "remote-fixture-secret-must-not-leak";
    let fixture = ScriptFixture::new(&format!(
        r#"
IFS= read -r request
printf '%s\n' '{{"jsonrpc":"2.0","id":1,"error":{{"code":401,"message":"{secret}"}}}}'
while IFS= read -r ignored; do :; done
"#
    ));
    let mut child = fixture
        .request(JsonRpcVersion::V2, FRAME_LIMIT, STDERR_LIMIT)
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");

    let error = child
        .request(
            "x.ai/billing",
            None,
            Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await
        .expect_err("remote error");
    let JsonRpcChildError::Remote(remote) = &error else {
        panic!("expected remote error, got {error:?}");
    };
    assert_eq!(remote.code(), Some(401));
    assert_eq!(remote.expose_message(), secret);
    assert!(!format!("{error}").contains(secret));
    assert!(!format!("{error:?}").contains(secret));
    child.shutdown().await;
}

#[tokio::test]
async fn malformed_or_ambiguous_matching_envelopes_fail_closed() {
    for response in [
        "not-json",
        r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"message":"ambiguous"}}"#,
        r#"{"id":1,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
    ] {
        let fixture = ScriptFixture::new(&format!(
            r"
IFS= read -r request
printf '%s\n' '{response}'
while IFS= read -r ignored; do :; done
"
        ));
        let mut child = fixture
            .request(JsonRpcVersion::V2, FRAME_LIMIT, STDERR_LIMIT)
            .spawn(&CancellationToken::new())
            .await
            .expect("spawn fixture");

        let error = child
            .request(
                "initialize",
                None,
                Duration::from_secs(2),
                &CancellationToken::new(),
            )
            .await
            .expect_err("invalid envelope");
        assert!(matches!(error, JsonRpcChildError::Protocol));
    }
}

#[tokio::test]
async fn unterminated_or_oversized_stdout_terminates_and_reaps_the_child() {
    let fixture = ScriptFixture::new(
        r#"
printf '%s\n' "$$" > "$OAB_PID_FILE"
IFS= read -r request
/usr/bin/head -c 512 /dev/zero
sleep 30
"#,
    );
    let pid_file = fixture.path("child.pid");
    let mut child = fixture
        .request(JsonRpcVersion::Omitted, 128, STDERR_LIMIT)
        .with_cleared_environment()
        .with_environment("OAB_PID_FILE", pid_file.as_os_str())
        .expect("valid pid environment")
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");

    let error = child
        .request(
            "initialize",
            None,
            Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await
        .expect_err("oversized stdout");
    assert!(matches!(error, JsonRpcChildError::StdoutTooLarge));
    assert_process_gone(read_pid(&pid_file)).await;

    let unterminated = ScriptFixture::new(
        r#"
IFS= read -r request
printf '%s' '{"id":1,"result":{}}'
"#,
    );
    let mut child = unterminated
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn unterminated fixture");
    let error = child
        .request(
            "initialize",
            None,
            Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await
        .expect_err("unterminated frame");
    assert!(matches!(error, JsonRpcChildError::Protocol));
}

#[tokio::test]
async fn oversized_stderr_is_never_retained_or_exposed_and_kills_the_child() {
    let fixture = ScriptFixture::new(
        r#"
printf '%s\n' "$$" > "$OAB_PID_FILE"
/usr/bin/head -c 512 /dev/zero >&2
sleep 30
"#,
    );
    let pid_file = fixture.path("child.pid");
    let mut child = fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, 128)
        .with_cleared_environment()
        .with_environment("OAB_PID_FILE", pid_file.as_os_str())
        .expect("valid pid environment")
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");
    wait_for_file(&pid_file).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    let error = child
        .request(
            "initialize",
            None,
            Duration::from_secs(2),
            &CancellationToken::new(),
        )
        .await
        .expect_err("oversized stderr");
    assert!(matches!(error, JsonRpcChildError::StderrTooLarge));
    assert_process_gone(read_pid(&pid_file)).await;
}

#[tokio::test]
async fn timeout_and_cancellation_kill_and_reap_the_process_group() {
    let fixture = ScriptFixture::new(
        r#"
trap '' TERM
sleep 30 &
descendant=$!
printf '%s %s\n' "$$" "$descendant" > "$OAB_PID_FILE"
while IFS= read -r request; do :; done
while :; do sleep 1; done
"#,
    );
    let pid_file = fixture.path("pids");
    let mut child = fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .with_cleared_environment()
        .with_environment("OAB_PID_FILE", pid_file.as_os_str())
        .expect("valid pid environment")
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn timeout fixture");
    wait_for_file(&pid_file).await;

    let started = Instant::now();
    let error = child
        .request(
            "initialize",
            None,
            Duration::from_millis(40),
            &CancellationToken::new(),
        )
        .await
        .expect_err("request timeout");
    assert!(matches!(error, JsonRpcChildError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(3));
    for pid in read_pids(&pid_file) {
        assert_process_gone(pid).await;
    }

    let cancelled_fixture = ScriptFixture::new(
        r#"
printf '%s\n' "$$" > "$OAB_PID_FILE"
while IFS= read -r request; do :; done
"#,
    );
    let cancelled_pid_file = cancelled_fixture.path("pid");
    let mut child = cancelled_fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .with_environment("OAB_PID_FILE", cancelled_pid_file.as_os_str())
        .expect("valid pid environment")
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn cancellation fixture");
    wait_for_file(&cancelled_pid_file).await;
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    let cancellation_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        trigger.cancel();
    });
    let error = child
        .request("initialize", None, Duration::from_secs(2), &cancellation)
        .await
        .expect_err("request cancellation");
    cancellation_task.await.expect("cancellation task");
    assert!(matches!(error, JsonRpcChildError::Cancelled));
    assert_process_gone(read_pid(&cancelled_pid_file)).await;
}

#[tokio::test]
async fn closed_stdin_is_a_normal_redacted_error_not_sigpipe() {
    let fixture = ScriptFixture::new(
        r"
exec 0<&-
sleep 0.05
exit 0
",
    );
    let mut child = fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let error = child
        .notify(
            "initialized",
            None,
            Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await
        .expect_err("closed stdin");
    assert!(matches!(error, JsonRpcChildError::StdinClosed));
}

#[tokio::test]
async fn configuration_input_and_debug_contracts_are_bounded_and_redacted() {
    let fixture = ScriptFixture::new("while IFS= read -r ignored; do :; done");
    let secret = "environment-fixture-secret";
    let request = fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .with_environment("OAB_SECRET", secret)
        .expect("valid secret environment");
    let debug = format!("{request:?}");
    assert!(!debug.contains(secret));
    assert!(!debug.contains(fixture.root().to_string_lossy().as_ref()));

    assert!(matches!(
        JsonRpcChildRequest::new(
            fixture.executable.clone(),
            std::iter::empty::<OsString>(),
            JsonRpcVersion::Omitted,
            0,
            STDERR_LIMIT,
        ),
        Err(JsonRpcChildError::InvalidConfiguration)
    ));
    assert!(matches!(
        JsonRpcChildRequest::new(
            fixture.executable.clone(),
            std::iter::empty::<OsString>(),
            JsonRpcVersion::Omitted,
            FRAME_LIMIT,
            0,
        ),
        Err(JsonRpcChildError::InvalidConfiguration)
    ));
    assert!(matches!(
        fixture
            .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
            .with_environment("BAD=NAME", "value"),
        Err(JsonRpcChildError::InvalidConfiguration)
    ));
    assert!(matches!(
        fixture.request_with_arguments([OsString::from_vec(vec![b'x', 0, b'y'])]),
        Err(JsonRpcChildError::InvalidConfiguration)
    ));

    let mut child = request
        .spawn(&CancellationToken::new())
        .await
        .expect("spawn fixture");
    for (method, params, timeout) in [
        ("", None, Duration::from_secs(1)),
        ("line\nbreak", None, Duration::from_secs(1)),
        ("valid", Some(json!(42)), Duration::from_secs(1)),
        ("valid", None, Duration::ZERO),
    ] {
        let error = child
            .notify(method, params, timeout, &CancellationToken::new())
            .await
            .expect_err("invalid operation");
        assert!(matches!(error, JsonRpcChildError::InvalidConfiguration));
    }

    let mut too_deep = json!(null);
    for _ in 0..66 {
        too_deep = Value::Array(vec![too_deep]);
    }
    let error = child
        .notify(
            "valid",
            Some(too_deep),
            Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await
        .expect_err("deep parameters");
    assert!(matches!(error, JsonRpcChildError::InvalidConfiguration));
    child.shutdown().await;

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let error = fixture
        .request(JsonRpcVersion::Omitted, FRAME_LIMIT, STDERR_LIMIT)
        .spawn(&cancelled)
        .await
        .expect_err("pre-cancelled spawn");
    assert!(matches!(error, JsonRpcChildError::Cancelled));
}

struct ScriptFixture {
    directory: TempDir,
    executable: ExecutablePath,
    script: PathBuf,
}

impl ScriptFixture {
    fn new(body: &str) -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        let script = directory.path().join("rpc-fixture");
        fs::write(&script, format!("#!/bin/sh\nset -eu\n{body}\n")).expect("write fixture script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .expect("make fixture executable");
        let executable = resolve_executable("sh", Some("/bin/sh"), None, &[])
            .expect("valid fixture lookup")
            .expect("fixture executable");
        Self {
            directory,
            executable,
            script,
        }
    }

    fn root(&self) -> &Path {
        self.directory.path()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn request(
        &self,
        version: JsonRpcVersion,
        max_frame_bytes: usize,
        max_stderr_bytes: usize,
    ) -> JsonRpcChildRequest {
        JsonRpcChildRequest::new(
            self.executable.clone(),
            [self.script.as_os_str().to_os_string()],
            version,
            max_frame_bytes,
            max_stderr_bytes,
        )
        .expect("valid fixture request")
    }

    fn request_with_arguments<I>(
        &self,
        arguments: I,
    ) -> Result<JsonRpcChildRequest, JsonRpcChildError>
    where
        I: IntoIterator<Item = OsString>,
    {
        JsonRpcChildRequest::new(
            self.executable.clone(),
            arguments,
            JsonRpcVersion::Omitted,
            FRAME_LIMIT,
            STDERR_LIMIT,
        )
    }
}

fn read_json_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .expect("captured frames")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid captured JSON"))
        .collect()
}

fn read_pid(path: &Path) -> i32 {
    fs::read_to_string(path)
        .expect("pid fixture")
        .trim()
        .parse()
        .expect("numeric pid")
}

fn read_pids(path: &Path) -> Vec<i32> {
    fs::read_to_string(path)
        .expect("pid fixtures")
        .split_whitespace()
        .map(|value| value.parse().expect("numeric pid"))
        .collect()
}

async fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !path.is_file() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(path.is_file(), "fixture file was not created");
}

async fn assert_process_gone(process_id: i32) {
    let pid = Pid::from_raw(process_id);
    let deadline = Instant::now() + Duration::from_secs(2);
    while kill(pid, None).is_ok() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        kill(pid, None).is_err(),
        "process {process_id} is still alive"
    );
}
