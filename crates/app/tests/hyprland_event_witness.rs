use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::unistd::pipe2;

const TARGET: &[u8] = "fallback\u{00a0}\u{1680}".as_bytes();
const TARGET_BASE64: &str = "ZmFsbGJhY2vCoOGagA==";
const FAILURE_MESSAGE: &[u8] = b"omarchy-ai-bar: Hyprland event witness failed\n";
const PROCESS_DEADLINE: Duration = Duration::from_secs(5);

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn executable_emits_only_exact_target_monitor_events() {
    let fixture = EventSocketFixture::new("filter");
    let (mut child, mut handshake) = spawn_witness(&fixture.socket_path, TARGET_BASE64);
    let mut server = accept_before_deadline(&fixture.listener, &mut child);
    handshake.complete(&mut child);
    let secret = b"PRIVATE window title must not escape";

    server
        .write_all(b"activewindow>>kitty,")
        .expect("write title prefix");
    server.write_all(secret).expect("write private title");
    server.write_all(b"\nmonitoraddedv2>>7,").expect("write v2");
    server.write_all(TARGET).expect("write near-match target");
    server
        .write_all(b",Internal display\nmonitoradded>>")
        .expect("write exact add prefix");
    server.write_all(TARGET).expect("write exact add target");
    server
        .write_all(b"\nwindowtitlev2>>deadbeef,")
        .expect("write second title prefix");
    server.write_all(secret).expect("write second title");
    server
        .write_all(b"\nmonitorremoved>>")
        .expect("write exact remove prefix");
    server.write_all(TARGET).expect("write exact remove target");
    server.write_all(b"\n").expect("finish event line");
    drop(server);

    let output = wait_with_deadline(child);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let mut expected = b"monitoradded>>".to_vec();
    expected.extend_from_slice(TARGET);
    expected.extend_from_slice(b"\nmonitorremoved>>");
    expected.extend_from_slice(TARGET);
    expected.push(b'\n');
    assert_eq!(output.stdout, expected);
    assert!(
        !output
            .stdout
            .windows(secret.len())
            .any(|window| window == secret)
    );
}

#[test]
fn executable_rejects_oversized_stream_record_without_leaking_it() {
    let fixture = EventSocketFixture::new("oversized");
    let (mut child, mut handshake) = spawn_witness(&fixture.socket_path, TARGET_BASE64);
    let mut server = accept_before_deadline(&fixture.listener, &mut child);
    handshake.complete(&mut child);
    let private_bytes = vec![b'p'; 64 * 1024 + 1];

    let _ = server.write_all(&private_bytes);
    let _ = server.write_all(b"\nmonitoradded>>fallback\n");
    drop(server);

    let output = wait_with_deadline(child);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, FAILURE_MESSAGE);
    assert!(
        !output
            .stderr
            .windows(16)
            .any(|window| window == &private_bytes[..16])
    );
}

#[test]
fn executable_rejects_malformed_base64_with_generic_diagnostic() {
    let socket_path = std::env::temp_dir().join("not-opened-by-invalid-witness.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .args(["bridge", "hyprland-events", "--socket"])
        .arg(socket_path)
        .args([
            "--monitor-name-base64",
            "not+canonical===PRIVATE",
            "--parent-pid",
        ])
        .arg(std::process::id().to_string())
        .args(["--ready-fd", "3", "--authorization-fd", "4"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("event witness command should run");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, FAILURE_MESSAGE);
    assert!(
        !output
            .stderr
            .windows(b"PRIVATE".len())
            .any(|window| window == b"PRIVATE")
    );
}

#[test]
fn connected_witness_terminates_when_its_launcher_parent_dies() {
    let fixture = EventSocketFixture::new("parent-death");
    let mut handshake = WitnessHandshake::new();
    let ready_fd = handshake.child_ready_fd();
    let authorization_fd = handshake.child_authorization_fd();
    let spawn_guard = SPAWN_LOCK.lock().expect("lock witness process spawn");
    handshake.make_child_ends_inheritable();
    let mut launcher = Command::new("/usr/bin/bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            r#"
                setsid /usr/bin/env --ignore-signal=TERM --block-signal=TERM \
                  "$1" bridge hyprland-events \
                  --socket "$2" --monitor-name-base64 "$3" --parent-pid "$$" \
                  --ready-fd "$4" --authorization-fd "$5" \
                  >/dev/null 2>/dev/null &
                witness_pid=$!
                ready_fd=$4
                authorization_fd=$5
                exec {ready_fd}>&-
                exec {authorization_fd}>&-
                printf '%s\n' "$witness_pid"
                read -r _gate || true
            "#,
            "event-witness-parent",
        ])
        .arg(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .arg(&fixture.socket_path)
        .arg(TARGET_BASE64)
        .arg(ready_fd.to_string())
        .arg(authorization_fd.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("event witness launcher should start");
    handshake.drop_child_ends();
    drop(spawn_guard);
    let mut launcher_output = BufReader::new(
        launcher
            .stdout
            .take()
            .expect("launcher stdout should be piped"),
    );
    let mut pid_line = String::new();
    launcher_output
        .read_line(&mut pid_line)
        .expect("read witness pid");
    let witness_pid: u32 = pid_line
        .trim()
        .parse()
        .expect("witness pid should be numeric");
    let _server = accept_before_deadline_untracked(&fixture.listener);
    handshake.wait_ready(&mut launcher);
    assert_signal_mask_contains(witness_pid, "SigBlk", 15);
    assert_signal_mask_contains(witness_pid, "SigIgn", 15);
    handshake.authorize(&mut launcher);

    drop(launcher.stdin.take());
    let launcher_status = launcher.wait().expect("wait for witness launcher");
    assert!(launcher_status.success());

    let deadline = Instant::now() + PROCESS_DEADLINE;
    let process_path = PathBuf::from(format!("/proc/{witness_pid}"));
    while process_path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !process_path.exists(),
        "event witness survived its launcher parent"
    );
}

fn spawn_witness(socket_path: &Path, monitor_name_base64: &str) -> (Child, WitnessHandshake) {
    let mut handshake = WitnessHandshake::new();
    let ready_fd = handshake.child_ready_fd();
    let authorization_fd = handshake.child_authorization_fd();
    let spawn_guard = SPAWN_LOCK.lock().expect("lock witness process spawn");
    handshake.make_child_ends_inheritable();
    let child = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .args(["bridge", "hyprland-events", "--socket"])
        .arg(socket_path)
        .args(["--monitor-name-base64", monitor_name_base64, "--parent-pid"])
        .arg(std::process::id().to_string())
        .args(["--ready-fd", &ready_fd.to_string()])
        .args(["--authorization-fd", &authorization_fd.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("event witness command should start");
    handshake.drop_child_ends();
    drop(spawn_guard);
    (child, handshake)
}

fn assert_signal_mask_contains(pid: u32, field: &str, signal: u32) {
    let status =
        fs::read_to_string(format!("/proc/{pid}/status")).expect("read witness process status");
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .map(str::trim)
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .expect("read signal mask from witness status");
    assert_ne!(mask & (1_u64 << (signal - 1)), 0);
}

struct WitnessHandshake {
    ready_reader: File,
    authorization_writer: Option<File>,
    child_ready: Option<OwnedFd>,
    child_authorization: Option<OwnedFd>,
    ready_seen: bool,
}

impl WitnessHandshake {
    fn new() -> Self {
        let (ready_reader, child_ready) =
            pipe2(OFlag::O_CLOEXEC).expect("create witness ready pipe");
        let (child_authorization, authorization_writer) =
            pipe2(OFlag::O_CLOEXEC).expect("create witness authorization pipe");
        fcntl(&ready_reader, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .expect("make witness ready pipe nonblocking");
        Self {
            ready_reader: File::from(ready_reader),
            authorization_writer: Some(File::from(authorization_writer)),
            child_ready: Some(child_ready),
            child_authorization: Some(child_authorization),
            ready_seen: false,
        }
    }

    fn child_ready_fd(&self) -> i32 {
        self.child_ready
            .as_ref()
            .expect("child ready pipe should be open")
            .as_raw_fd()
    }

    fn child_authorization_fd(&self) -> i32 {
        self.child_authorization
            .as_ref()
            .expect("child authorization pipe should be open")
            .as_raw_fd()
    }

    fn drop_child_ends(&mut self) {
        self.child_ready.take();
        self.child_authorization.take();
    }

    fn make_child_ends_inheritable(&self) {
        fcntl(
            self.child_ready
                .as_ref()
                .expect("child ready pipe should be open"),
            FcntlArg::F_SETFD(FdFlag::empty()),
        )
        .expect("make child ready endpoint inheritable");
        fcntl(
            self.child_authorization
                .as_ref()
                .expect("child authorization pipe should be open"),
            FcntlArg::F_SETFD(FdFlag::empty()),
        )
        .expect("make child authorization endpoint inheritable");
    }

    fn wait_ready(&mut self, child: &mut Child) {
        assert!(!self.ready_seen, "witness readiness was already consumed");
        self.read_byte_before_deadline(child, b'R');
        self.ready_seen = true;
    }

    fn authorize(&mut self, child: &mut Child) {
        assert!(
            self.ready_seen,
            "witness must be ready before authorization"
        );
        self.authorization_writer
            .take()
            .expect("authorization writer should be open")
            .write_all(b"A")
            .expect("authorize witness event reads");
        self.read_byte_before_deadline(child, b'D');
        self.wait_for_ready_eof(child);
    }

    fn complete(&mut self, child: &mut Child) {
        self.wait_ready(child);
        self.authorize(child);
    }

    fn read_byte_before_deadline(&mut self, child: &mut Child, expected: u8) {
        let deadline = Instant::now() + PROCESS_DEADLINE;
        let mut byte = [0_u8; 1];
        loop {
            match self.ready_reader.read(&mut byte) {
                Ok(1) => {
                    assert_eq!(byte[0], expected, "unexpected witness handshake byte");
                    return;
                }
                Ok(0) => panic!("witness handshake closed before byte {expected:?}"),
                Ok(_) => unreachable!("single-byte read returned too many bytes"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("read witness handshake: {error}"),
            }
            if let Some(status) = child.try_wait().expect("inspect event witness launcher") {
                panic!("event witness launcher exited during handshake: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "event witness handshake timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_ready_eof(&mut self, child: &mut Child) {
        let deadline = Instant::now() + PROCESS_DEADLINE;
        let mut byte = [0_u8; 1];
        loop {
            match self.ready_reader.read(&mut byte) {
                Ok(0) => return,
                Ok(1) => panic!("unexpected trailing witness handshake byte: {:?}", byte[0]),
                Ok(_) => unreachable!("single-byte read returned too many bytes"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("read witness handshake EOF: {error}"),
            }
            if let Some(status) = child.try_wait().expect("inspect event witness launcher") {
                panic!("event witness launcher exited before handshake EOF: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "event witness handshake EOF timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn accept_before_deadline(listener: &UnixListener, child: &mut Child) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("set fixture listener nonblocking");
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        match listener.accept() {
            Ok((stream, _address)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept event witness: {error}"),
        }
        if let Some(status) = child.try_wait().expect("inspect event witness") {
            panic!("event witness exited before connecting: {status}");
        }
        assert!(Instant::now() < deadline, "event witness did not connect");
        thread::sleep(Duration::from_millis(10));
    }
}

fn accept_before_deadline_untracked(listener: &UnixListener) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("set fixture listener nonblocking");
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        match listener.accept() {
            Ok((stream, _address)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept event witness: {error}"),
        }
        assert!(Instant::now() < deadline, "event witness did not connect");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_with_deadline(mut child: Child) -> Output {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        if child
            .try_wait()
            .expect("inspect event witness process")
            .is_some()
        {
            return child
                .wait_with_output()
                .expect("collect event witness output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .expect("collect timed out event witness output");
            panic!("event witness exceeded deadline: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct EventSocketFixture {
    directory: PathBuf,
    socket_path: PathBuf,
    listener: UnixListener,
}

impl EventSocketFixture {
    fn new(label: &str) -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-event-test-{}-{label}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create private event fixture directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("make event fixture directory private");
        let socket_path = directory.join("events.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind event fixture socket");

        Self {
            directory,
            socket_path,
            listener,
        }
    }
}

impl Drop for EventSocketFixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_dir(&self.directory);
    }
}
