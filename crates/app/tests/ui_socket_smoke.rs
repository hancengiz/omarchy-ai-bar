#![cfg(target_os = "linux")]

use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use oab_domain::{SnapshotEnvelopeV1, SurfaceSnapshotEnvelope};
use oab_ipc::codec::{JsonLineDecoder, MAX_JSON_LINE_BYTES, decode_json_line, encode_json_line};
use oab_ipc::protocol::{
    BridgeVersion, Capability, CapabilitySet, ClientHello, ClientMessage, FrontendSessionId,
    RequestId, RuntimeAction, Sequence, ServerMessage, V1_PROTOCOL,
};
use oab_ipc::socket::{DisplaySocket, DisplaySocketError};
use serde_json::{Value, json};

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[test]
fn executable_bridge_forwards_hello_snapshot_and_typed_action() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind mock display socket");

    let server = thread::spawn(move || {
        let mut stream = accept_mock_connection(&listener);
        stream
            .set_read_timeout(Some(TEST_TIMEOUT))
            .expect("bound mock read");
        let mut reader = BufReader::new(stream.try_clone().expect("clone mock stream"));

        let hello: ClientMessage = read_protocol_line(&mut reader);
        assert_eq!(hello, client_hello());

        write_protocol_line(
            &mut stream,
            &json!({
                "type": "hello",
                "protocol": { "major": 1, "minor": 0 },
                "stream_id": "fedcba9876543210fedcba9876543210",
                "capabilities": ["display_snapshots", "runtime_actions"]
            }),
        );
        write_protocol_line(
            &mut stream,
            &json!({
                "type": "snapshot",
                "sequence": 1,
                "snapshot": {
                    "schema_version": 1,
                    "generated_at": "2026-08-29T00:00:00Z",
                    "snapshots": []
                }
            }),
        );

        let action: ClientMessage = read_protocol_line(&mut reader);
        assert_eq!(
            action,
            ClientMessage::Action {
                request_id: RequestId::new(7).expect("valid request ID"),
                action: RuntimeAction::RefreshAll {},
            }
        );
    });

    let mut child = spawn_bridge(&socket_path, Stdio::piped());
    let mut child_input = child.stdin.take().expect("bridge stdin should be piped");
    let child_output = child.stdout.take().expect("bridge stdout should be piped");
    let (output_reader, output_receiver) = read_frames_async(child_output, 2);

    write_protocol_line(&mut child_input, &client_hello());
    let frames = receive_frames_or_kill(&mut child, &output_receiver);

    write_protocol_line(
        &mut child_input,
        &ClientMessage::Action {
            request_id: RequestId::new(7).expect("valid request ID"),
            action: RuntimeAction::RefreshAll {},
        },
    );
    drop(child_input);

    server.join().expect("mock server should finish");
    let status = wait_for_child(&mut child);
    output_reader.join().expect("output reader should finish");
    assert!(status.success());

    let [hello, snapshot]: [Value; 2] = frames.try_into().expect("two forwarded frames");
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["protocol"], json!({ "major": 1, "minor": 0 }));
    assert_eq!(hello["stream_id"], "fedcba9876543210fedcba9876543210");
    assert_eq!(snapshot["type"], "snapshot");
    assert_eq!(snapshot["sequence"], 1);
    assert_eq!(snapshot["snapshot"]["snapshots"], json!([]));

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("bridge stderr should be piped")
        .read_to_string(&mut stderr)
        .expect("read bridge stderr");
    assert!(stderr.is_empty(), "clean bridge exit must be silent");
}

#[test]
fn overlong_unterminated_server_record_emits_no_stdout() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind mock display socket");

    let server = thread::spawn(move || {
        let mut stream = accept_mock_connection(&listener);
        let oversized = vec![b'x'; MAX_JSON_LINE_BYTES];
        let _ = stream.write_all(&oversized);
        let _ = stream.shutdown(Shutdown::Write);
    });

    let mut child = spawn_bridge(&socket_path, Stdio::piped());
    let child_input = child.stdin.take().expect("bridge stdin should be piped");
    let status = wait_for_child(&mut child);
    drop(child_input);
    let stdout = read_child_stdout(&mut child);
    let stderr = read_child_stderr(&mut child);

    server.join().expect("mock server should finish");
    assert!(!status.success());
    assert!(
        stdout.is_empty(),
        "a rejected record must never be partially forwarded"
    );
    assert_eq!(stderr, b"omarchy-ai-bar: UI bridge failed\n");
}

#[test]
fn overlong_unterminated_child_record_reaches_no_socket_bytes() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind mock display socket");

    let server = thread::spawn(move || {
        let mut stream = accept_mock_connection(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound mock read");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        received
    });

    let mut child = spawn_bridge(&socket_path, Stdio::piped());
    let mut child_input = child.stdin.take().expect("bridge stdin should be piped");
    child_input
        .write_all(&vec![b'x'; MAX_JSON_LINE_BYTES])
        .expect("write adversarial input");
    drop(child_input);

    let status = wait_for_child(&mut child);
    let received = server.join().expect("mock server should finish");
    assert!(!status.success());
    assert!(
        received.is_empty(),
        "a rejected child record must never be partially forwarded"
    );

    let stdout = read_child_stdout(&mut child);
    assert!(stdout.is_empty());

    let stderr = read_child_stderr(&mut child);
    assert_eq!(stderr, b"omarchy-ai-bar: UI bridge failed\n");
}

#[test]
fn server_eof_exits_while_child_stdin_remains_open() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind mock display socket");
    let server = thread::spawn(move || drop(accept_mock_connection(&listener)));

    let mut child = spawn_bridge(&socket_path, Stdio::piped());
    let child_input = child.stdin.take().expect("bridge stdin should be piped");
    let status = wait_for_child(&mut child);
    drop(child_input);
    server.join().expect("mock server should finish");

    assert!(status.success());
    assert!(read_child_stdout(&mut child).is_empty());
    assert!(read_child_stderr(&mut child).is_empty());
}

#[test]
fn child_stdin_eof_exits_while_server_holds_connection_open() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind mock display socket");
    let (eof_sender, eof_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let mut stream = accept_mock_connection(&listener);
        stream
            .set_read_timeout(Some(TEST_TIMEOUT))
            .expect("bound mock read");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        eof_sender.send(received).expect("report child EOF");
        let _ = release_receiver.recv_timeout(TEST_TIMEOUT);
    });

    let mut child = spawn_bridge(&socket_path, Stdio::piped());
    drop(child.stdin.take().expect("bridge stdin should be piped"));
    let received = eof_receiver
        .recv_timeout(TEST_TIMEOUT)
        .expect("server should observe child EOF");
    let status = wait_for_child(&mut child);
    release_sender.send(()).expect("release mock server");
    server.join().expect("mock server should finish");

    assert!(received.is_empty());
    assert!(status.success());
    assert!(read_child_stdout(&mut child).is_empty());
    assert!(read_child_stderr(&mut child).is_empty());
}

#[test]
fn exact_u64_domain_snapshot_is_preserved() {
    let frames = vec![
        server_hello(&["display_snapshots"]),
        json!({
            "type": "snapshot",
            "sequence": 1,
            "snapshot": full_snapshot_wire()
        }),
    ];
    let result = run_server_frames(&frames);

    assert!(result.status.success());
    assert_eq!(decode_output_frames(&result.stdout), frames);
    assert!(result.stderr.is_empty());
}

#[test]
fn unknown_missing_stream_and_snapshot_before_hello_fail_closed() {
    for (case, frames) in [
        ("unknown", vec![json!({ "type": "surprise" })]),
        (
            "missing_stream",
            vec![json!({
                "type": "hello",
                "protocol": { "major": 1, "minor": 0 },
                "capabilities": ["display_snapshots"]
            })],
        ),
        (
            "malformed_stream",
            vec![json!({
                "type": "hello",
                "protocol": { "major": 1, "minor": 0 },
                "stream_id": "not-a-canonical-stream-id",
                "capabilities": ["display_snapshots"]
            })],
        ),
        (
            "extra_stream_field",
            vec![json!({
                "type": "hello",
                "protocol": { "major": 1, "minor": 0 },
                "stream_id": "fedcba9876543210fedcba9876543210",
                "extra_stream_id": "0123456789abcdef0123456789abcdef",
                "capabilities": ["display_snapshots"]
            })],
        ),
        (
            "snapshot_before_hello",
            vec![json!({
                "type": "snapshot",
                "sequence": 1,
                "snapshot": empty_snapshot_wire()
            })],
        ),
    ] {
        let result = run_server_frames(&frames);
        assert!(!result.status.success(), "{case} must fail closed");
        assert!(result.stdout.is_empty(), "{case} must not reach stdout");
        assert_eq!(
            result.stderr, b"omarchy-ai-bar: UI bridge failed\n",
            "{case} must expose only a generic diagnostic"
        );
    }
}

#[test]
fn same_major_forward_minor_is_accepted_and_other_major_is_rejected() {
    let mut forward_minor = server_hello(&[]);
    forward_minor["protocol"]["minor"] = json!(42);
    let accepted = run_server_frames(&[forward_minor.clone()]);
    assert!(accepted.status.success());
    assert_eq!(decode_output_frames(&accepted.stdout), vec![forward_minor]);
    assert!(accepted.stderr.is_empty());

    let mut other_major = server_hello(&[]);
    other_major["protocol"]["major"] = json!(2);
    let rejected = run_server_frames(&[other_major]);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(rejected.stderr, b"omarchy-ai-bar: UI bridge failed\n");
}

#[test]
fn stream_id_is_rejected_outside_server_hello() {
    let hello = server_hello(&["display_snapshots"]);
    let result = run_server_frames(&[
        hello.clone(),
        json!({
            "type": "snapshot",
            "stream_id": "fedcba9876543210fedcba9876543210",
            "sequence": 1,
            "snapshot": empty_snapshot_wire()
        }),
    ]);

    assert!(!result.status.success());
    assert_only_optional_hello(&result.stdout, &hello);
    assert_eq!(result.stderr, b"omarchy-ai-bar: UI bridge failed\n");
}

#[test]
fn numeric_snapshot_u64_is_rejected_after_valid_hello() {
    let hello = server_hello(&["display_snapshots"]);
    let mut snapshot = full_snapshot_wire();
    snapshot["snapshots"][0]["last_known_good"]["primary"]["duration_seconds"] = json!(18000);
    let result = run_server_frames(&[
        hello.clone(),
        json!({
            "type": "snapshot",
            "sequence": 1,
            "snapshot": snapshot
        }),
    ]);

    assert!(!result.status.success());
    assert_only_optional_hello(&result.stdout, &hello);
    assert_eq!(result.stderr, b"omarchy-ai-bar: UI bridge failed\n");
}

#[test]
fn unknown_domain_fields_and_impossible_variants_are_rejected() {
    let hello = server_hello(&["display_snapshots"]);
    let mut unknown_field = empty_snapshot_wire();
    unknown_field["unreviewed"] = json!(true);
    let impossible_variant = json!({
        "schema_version": 1,
        "generated_at": "2026-08-29T00:00:00Z",
        "snapshots": [{ "state": "impossible" }]
    });

    for (case, snapshot) in [
        ("unknown_domain_field", unknown_field),
        ("impossible_variant", impossible_variant),
    ] {
        let result = run_server_frames(&[
            hello.clone(),
            json!({
                "type": "snapshot",
                "sequence": 1,
                "snapshot": snapshot
            }),
        ]);
        assert!(!result.status.success(), "{case} must fail closed");
        assert_only_optional_hello(&result.stdout, &hello);
        assert_eq!(result.stderr, b"omarchy-ai-bar: UI bridge failed\n");
    }
}

#[test]
fn duplicate_snapshot_keys_are_rejected() {
    let hello = server_hello(&["display_snapshots"]);
    let hello_wire = encode_json_line(&hello).expect("encode server hello");
    let duplicate_snapshot = br#"{"type":"snapshot","sequence":1,"snapshot":{"schema_version":1,"schema_version":1,"generated_at":"2026-08-29T00:00:00Z","snapshots":[]}}"#
        .iter()
        .copied()
        .chain(*b"\n")
        .collect::<Vec<_>>();
    let result = run_server_payloads(&[hello_wire, duplicate_snapshot]);

    assert!(!result.status.success());
    assert_only_optional_hello(&result.stdout, &hello);
    assert_eq!(result.stderr, b"omarchy-ai-bar: UI bridge failed\n");
}

#[test]
fn action_progress_requires_its_negotiated_capability() {
    let hello = server_hello(&["display_snapshots"]);
    let result = run_server_frames(&[
        hello.clone(),
        json!({
            "type": "action_progress",
            "request_id": 1,
            "state": "running"
        }),
    ]);

    assert!(!result.status.success());
    assert_only_optional_hello(&result.stdout, &hello);
    assert_eq!(result.stderr, b"omarchy-ai-bar: UI bridge failed\n");
}

#[test]
fn duplicate_hello_and_unnegotiated_snapshot_are_rejected() {
    let hello = server_hello(&[]);
    for frames in [
        vec![hello.clone(), hello.clone()],
        vec![
            hello.clone(),
            json!({
                "type": "snapshot",
                "sequence": 1,
                "snapshot": empty_snapshot_wire()
            }),
        ],
    ] {
        let result = run_server_frames(&frames);
        assert!(!result.status.success());
        assert_only_optional_hello(&result.stdout, &hello);
        assert_eq!(result.stderr, b"omarchy-ai-bar: UI bridge failed\n");
    }
}

fn client_hello() -> ClientMessage {
    let capabilities =
        CapabilitySet::new([Capability::DisplaySnapshots, Capability::RuntimeActions])
            .expect("valid capabilities");
    ClientMessage::hello(ClientHello::new(
        V1_PROTOCOL,
        BridgeVersion::new(0, 1, 0),
        FrontendSessionId::parse("0123456789abcdef0123456789abcdef")
            .expect("valid frontend session ID"),
        capabilities,
    ))
}

fn spawn_bridge(socket_path: &Path, stdin: Stdio) -> Child {
    Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .args(["bridge", "stdio", "--socket"])
        .arg(socket_path)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("bridge command should start")
}

fn accept_mock_connection(listener: &DisplaySocket) -> std::os::unix::net::UnixStream {
    listener
        .set_nonblocking(true)
        .expect("configure bounded mock accept");
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match listener.accept_verified() {
            Ok(stream) => {
                let stream = stream.into_stream();
                stream
                    .set_nonblocking(false)
                    .expect("configure blocking mock stream");
                return stream;
            }
            Err(DisplaySocketError::Operation { source, .. })
                if source.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => panic!("accept mock bridge: {error}"),
        }
    }
}

fn wait_for_child(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match child.try_wait().expect("inspect bridge process") {
            Some(status) => return status,
            None if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            None => {
                kill_and_reap(child);
                panic!("bridge process exceeded its test deadline");
            }
        }
    }
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_frames_async(
    stdout: ChildStdout,
    count: usize,
) -> (thread::JoinHandle<()>, Receiver<Result<Vec<Value>, ()>>) {
    let (sender, receiver) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let result = (0..count)
            .map(|_| read_protocol_line_result(&mut reader))
            .collect();
        let _ = sender.send(result);
    });
    (handle, receiver)
}

fn receive_frames_or_kill(
    child: &mut Child,
    receiver: &Receiver<Result<Vec<Value>, ()>>,
) -> Vec<Value> {
    match receiver.recv_timeout(TEST_TIMEOUT) {
        Ok(Ok(frames)) => frames,
        Ok(Err(())) => {
            kill_and_reap(child);
            panic!("bridge stdout ended before the expected frames");
        }
        Err(error) => {
            kill_and_reap(child);
            panic!("timed out reading bridge stdout: {error}");
        }
    }
}

struct ProcessResult {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_server_frames(frames: &[Value]) -> ProcessResult {
    let payloads = frames
        .iter()
        .map(|frame| encode_json_line(frame).expect("encode bounded mock frame"))
        .collect::<Vec<_>>();
    run_server_payloads(&payloads)
}

fn run_server_payloads(payloads: &[Vec<u8>]) -> ProcessResult {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind mock display socket");
    let payloads = payloads.to_vec();
    let server = thread::spawn(move || {
        let mut stream = accept_mock_connection(&listener);
        for payload in payloads {
            if stream.write_all(&payload).is_err() {
                break;
            }
        }
        let _ = stream.shutdown(Shutdown::Write);
    });

    let mut child = spawn_bridge(&socket_path, Stdio::piped());
    let child_input = child.stdin.take().expect("bridge stdin should be piped");
    let status = wait_for_child(&mut child);
    drop(child_input);
    server.join().expect("mock server should finish");
    let stdout = read_child_stdout(&mut child);
    let stderr = read_child_stderr(&mut child);
    ProcessResult {
        status,
        stdout,
        stderr,
    }
}

fn read_child_stdout(child: &mut Child) -> Vec<u8> {
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .expect("bridge stdout should be piped")
        .read_to_end(&mut output)
        .expect("read bridge stdout");
    output
}

fn read_child_stderr(child: &mut Child) -> Vec<u8> {
    let mut output = Vec::new();
    child
        .stderr
        .take()
        .expect("bridge stderr should be piped")
        .read_to_end(&mut output)
        .expect("read bridge stderr");
    output
}

fn server_hello(capabilities: &[&str]) -> Value {
    json!({
        "type": "hello",
        "protocol": { "major": 1, "minor": 0 },
        "stream_id": "fedcba9876543210fedcba9876543210",
        "capabilities": capabilities
    })
}

fn empty_snapshot_wire() -> Value {
    json!({
        "schema_version": 1,
        "generated_at": "2026-08-29T00:00:00Z",
        "snapshots": []
    })
}

fn full_snapshot_wire() -> Value {
    let envelope: SnapshotEnvelopeV1 =
        serde_json::from_str(include_str!("../../../fixtures/domain/snapshot-v1.json"))
            .expect("valid domain snapshot fixture");
    let frame = serde_json::to_value(ServerMessage::Snapshot {
        sequence: Sequence::new(1).expect("valid sequence"),
        snapshot: SurfaceSnapshotEnvelope::Trusted(envelope.private_view()),
    })
    .expect("serialize exact-u64 snapshot frame");
    frame["snapshot"].clone()
}

fn decode_output_frames(output: &[u8]) -> Vec<Value> {
    let mut decoder = JsonLineDecoder::new();
    let frames = decoder.feed(output).expect("decode forwarded output");
    decoder.finish().expect("forwarded output is terminated");
    frames
}

fn assert_only_optional_hello(output: &[u8], hello: &Value) {
    let frames = decode_output_frames(output);
    assert!(frames.is_empty() || frames == [hello.clone()]);
}

fn read_protocol_line<T>(reader: &mut impl BufRead) -> T
where
    T: serde::de::DeserializeOwned,
{
    read_protocol_line_result(reader).expect("decode protocol frame")
}

fn read_protocol_line_result<T>(reader: &mut impl BufRead) -> Result<T, ()>
where
    T: serde::de::DeserializeOwned,
{
    let mut frame = Vec::new();
    let bytes_read = reader.read_until(b'\n', &mut frame).map_err(|_| ())?;
    if bytes_read == 0 {
        return Err(());
    }
    decode_json_line(&frame).map_err(|_| ())
}

fn write_protocol_line(writer: &mut impl Write, message: &impl serde::Serialize) {
    let encoded = encode_json_line(message).expect("encode bounded protocol frame");
    writer.write_all(&encoded).expect("write protocol frame");
    writer.flush().expect("flush protocol frame");
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let base = std::env::temp_dir();
        for _ in 0..128 {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = base.join(format!(
                "omarchy-ai-bar-ui-smoke-{}-{sequence}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => {
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))
                        .expect("secure test directory");
                    return Self { path: candidate };
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create test directory: {error}"),
            }
        }
        panic!("could not allocate a unique test directory");
    }

    fn socket_path(&self) -> PathBuf {
        self.path.join("runtime").join("display.sock")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
