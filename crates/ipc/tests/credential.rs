use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use oab_ipc::credential::{
    Credential, CredentialTransportError, CredentialValidationError, MAX_CREDENTIAL_BYTES,
    OneShotCredentialReceiver,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);
type ErrorMatcher = fn(&CredentialTransportError) -> bool;
type MalformedCase<'a> = (&'a str, &'a [u8], ErrorMatcher);

#[test]
fn credential_is_bounded_and_debug_output_is_redacted() {
    let secret = "sk-live-private-canary";
    let credential = Credential::new(secret).expect("valid credential");

    assert_eq!(credential.expose_secret(), secret);
    let debug = format!("{credential:?}");
    assert_eq!(debug, "Credential([REDACTED])");
    assert!(!debug.contains(secret));
    assert!(matches!(
        Credential::new(""),
        Err(CredentialValidationError::Empty)
    ));
    assert!(matches!(
        Credential::new("x".repeat(MAX_CREDENTIAL_BYTES + 1)),
        Err(CredentialValidationError::TooLarge)
    ));
}

#[test]
fn one_shot_socket_is_private_unlinked_after_accept_and_returns_no_echo() {
    let fixture = SocketFixture::new("success");
    let receiver = OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT)
        .expect("bind credential receiver");
    let mode = fs::symlink_metadata(&fixture.socket)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let handle = thread::spawn(move || {
        receiver
            .receive()
            .map(|credential| credential.expose_secret().to_owned())
    });
    let mut client = UnixStream::connect(&fixture.socket).expect("connect first client");
    wait_until_absent(&fixture.socket);
    assert!(UnixStream::connect(&fixture.socket).is_err());

    write_frame(&mut client, b"private-token");
    client.shutdown(Shutdown::Write).expect("close write half");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("read response EOF");

    assert!(response.is_empty(), "credential receiver must not echo");
    assert_eq!(
        handle.join().expect("receiver thread").expect("credential"),
        "private-token"
    );
    assert!(!fixture.socket.exists());
}

#[test]
fn netstring_length_counts_utf8_bytes() {
    let fixture = SocketFixture::new("utf8-netstring");
    let receiver = OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT)
        .expect("bind credential receiver");
    let secret = "şifre-🔐";
    let mut client = UnixStream::connect(&fixture.socket).expect("connect client");
    write_frame(&mut client, secret.as_bytes());
    client.shutdown(Shutdown::Write).expect("close write half");

    let credential = receiver.receive().expect("receive UTF-8 credential");

    assert_eq!(credential.expose_secret(), secret);
}

#[test]
fn malformed_frames_fail_closed_and_leave_no_socket() {
    let cases: &[MalformedCase<'_>] = &[
        ("empty", b"0:,", |error| {
            matches!(
                error,
                CredentialTransportError::InvalidCredential(CredentialValidationError::Empty)
            )
        }),
        ("truncated", b"5:ab", |error| {
            matches!(error, CredentialTransportError::TruncatedFrame)
        }),
        ("invalid-utf8", b"2:\xff\xfe,", |error| {
            matches!(
                error,
                CredentialTransportError::InvalidCredential(CredentialValidationError::InvalidUtf8)
            )
        }),
        ("missing-terminator", b"1:a", |error| {
            matches!(error, CredentialTransportError::MissingTerminator)
        }),
        ("invalid-terminator", b"1:a!", |error| {
            matches!(error, CredentialTransportError::MissingTerminator)
        }),
        ("trailing", b"1:a,1:b,", |error| {
            matches!(error, CredentialTransportError::TrailingData)
        }),
        ("leading-zero", b"01:a,", |error| {
            matches!(error, CredentialTransportError::InvalidLengthPrefix)
        }),
        ("empty-length", b":a,", |error| {
            matches!(error, CredentialTransportError::InvalidLengthPrefix)
        }),
        ("non-decimal", b"x:a,", |error| {
            matches!(error, CredentialTransportError::InvalidLengthPrefix)
        }),
        ("overlong-length", b"123456:", |error| {
            matches!(error, CredentialTransportError::InvalidLengthPrefix)
        }),
    ];

    for (name, bytes, matches_error) in cases {
        let fixture = SocketFixture::new(name);
        let receiver = OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT)
            .expect("bind credential receiver");
        let mut client = UnixStream::connect(&fixture.socket).expect("connect client");
        client.write_all(bytes).expect("write malformed frame");
        client.shutdown(Shutdown::Write).expect("close write half");

        let error = receiver.receive().expect_err("frame must be rejected");
        assert!(matches_error(&error), "{name}: unexpected error {error:?}");
        assert!(!fixture.socket.exists(), "{name}: socket was not removed");
    }
}

#[test]
fn declared_oversize_is_rejected_without_reading_a_payload() {
    let fixture = SocketFixture::new("oversize");
    let receiver = OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT)
        .expect("bind credential receiver");
    let mut client = UnixStream::connect(&fixture.socket).expect("connect client");
    let length = MAX_CREDENTIAL_BYTES + 1;
    client
        .write_all(format!("{length}:").as_bytes())
        .expect("write length");
    client.shutdown(Shutdown::Write).expect("close write half");

    assert!(matches!(
        receiver.receive(),
        Err(CredentialTransportError::InvalidCredential(
            CredentialValidationError::TooLarge
        ))
    ));
    assert!(!fixture.socket.exists());
}

#[test]
fn deadline_expiry_and_drop_cleanup_the_socket() {
    let expiry_fixture = SocketFixture::new("expiry");
    let receiver =
        OneShotCredentialReceiver::bind(&expiry_fixture.socket, Duration::from_millis(25))
            .expect("bind expiring receiver");
    assert!(matches!(
        receiver.receive(),
        Err(CredentialTransportError::DeadlineElapsed)
    ));
    assert!(!expiry_fixture.socket.exists());

    let drop_fixture = SocketFixture::new("drop");
    let receiver = OneShotCredentialReceiver::bind(&drop_fixture.socket, TEST_TIMEOUT)
        .expect("bind droppable receiver");
    assert!(drop_fixture.socket.exists());
    drop(receiver);
    assert!(!drop_fixture.socket.exists());
}

#[test]
fn accepted_client_cannot_hold_the_read_open_past_the_deadline() {
    let fixture = SocketFixture::new("read-deadline");
    let receiver = OneShotCredentialReceiver::bind(&fixture.socket, Duration::from_millis(50))
        .expect("bind credential receiver");
    let mut client = UnixStream::connect(&fixture.socket).expect("connect client");
    client
        .write_all(b"4:")
        .expect("write only the frame length");

    assert!(matches!(
        receiver.receive(),
        Err(CredentialTransportError::DeadlineElapsed)
    ));
    assert!(!fixture.socket.exists());
}

#[test]
fn cleanup_never_unlinks_a_replacement_socket() {
    let drop_fixture = SocketFixture::new("replacement-drop");
    let receiver = OneShotCredentialReceiver::bind(&drop_fixture.socket, TEST_TIMEOUT)
        .expect("bind credential receiver");
    fs::remove_file(&drop_fixture.socket).expect("unlink original socket path");
    let replacement = UnixListener::bind(&drop_fixture.socket).expect("bind replacement socket");
    fs::set_permissions(&drop_fixture.socket, fs::Permissions::from_mode(0o600))
        .expect("secure replacement socket");

    drop(receiver);
    assert!(drop_fixture.socket.exists());
    drop(replacement);

    let accept_fixture = SocketFixture::new("replacement-accept");
    let receiver = OneShotCredentialReceiver::bind(&accept_fixture.socket, TEST_TIMEOUT)
        .expect("bind credential receiver");
    let client = UnixStream::connect(&accept_fixture.socket).expect("queue original client");
    fs::remove_file(&accept_fixture.socket).expect("unlink original socket path");
    let replacement = UnixListener::bind(&accept_fixture.socket).expect("bind replacement socket");
    fs::set_permissions(&accept_fixture.socket, fs::Permissions::from_mode(0o600))
        .expect("secure replacement socket");

    assert!(matches!(
        receiver.receive(),
        Err(CredentialTransportError::SocketPathChanged)
    ));
    assert!(accept_fixture.socket.exists());
    drop(client);
    drop(replacement);
}

#[test]
fn endpoint_lifecycle_lock_serializes_credential_receivers() {
    let fixture = SocketFixture::new("lock-contention");
    let first = OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT)
        .expect("bind first receiver");

    let error = match OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT) {
        Ok(_receiver) => panic!("lock contender unexpectedly bound"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CredentialTransportError::Permissions(
            oab_ipc::permissions::PermissionError::EndpointLockBusy
        )
    ));

    drop(first);
    let second = OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT)
        .expect("reuse persistent lock file");
    drop(second);
}

#[test]
fn pinned_cleanup_ignores_a_replacement_at_the_original_parent_path() {
    let fixture = SocketFixture::new("parent-replacement");
    let receiver = OneShotCredentialReceiver::bind(&fixture.socket, TEST_TIMEOUT)
        .expect("bind credential receiver");
    let moved_directory = fixture.directory.with_extension("moved");
    fs::rename(&fixture.directory, &moved_directory).expect("move pinned directory");
    fs::create_dir(&fixture.directory).expect("create replacement directory");
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700))
        .expect("secure replacement directory");
    let replacement = UnixListener::bind(&fixture.socket).expect("bind replacement socket");
    fs::set_permissions(&fixture.socket, fs::Permissions::from_mode(0o600))
        .expect("secure replacement socket");

    drop(receiver);

    assert!(fixture.socket.exists());
    assert!(!moved_directory.join("credential.sock").exists());
    drop(replacement);
    fs::remove_dir_all(moved_directory).expect("remove moved directory");
}

#[test]
fn socket_requires_an_absolute_normal_child_of_a_private_runtime_directory() {
    assert!(matches!(
        OneShotCredentialReceiver::bind("relative.sock", TEST_TIMEOUT),
        Err(CredentialTransportError::InvalidPath)
    ));

    let unsafe_fixture = SocketFixture::new("unsafe-parent");
    fs::set_permissions(&unsafe_fixture.directory, fs::Permissions::from_mode(0o755))
        .expect("make parent unsafe");
    assert!(matches!(
        OneShotCredentialReceiver::bind(&unsafe_fixture.socket, TEST_TIMEOUT),
        Err(CredentialTransportError::Permissions(_))
    ));
    assert!(!unsafe_fixture.socket.exists());

    let abnormal_fixture = SocketFixture::new("abnormal-path");
    let abnormal_path = abnormal_fixture
        .directory
        .join("missing")
        .join("..")
        .join("credential.sock");
    assert!(matches!(
        OneShotCredentialReceiver::bind(abnormal_path, TEST_TIMEOUT),
        Err(CredentialTransportError::InvalidPath)
    ));

    let oversized_fixture = SocketFixture::new("oversized-public-path");
    let oversized_path = oversized_fixture
        .directory
        .join(format!("{}.sock", "x".repeat(180)));
    assert!(matches!(
        OneShotCredentialReceiver::bind(oversized_path, TEST_TIMEOUT),
        Err(CredentialTransportError::InvalidPath)
    ));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn mismatched_peer_uid_is_rejected_after_unlink() {
    let fixture = SocketFixture::new("peer-uid");
    let actual_uid = nix::unistd::Uid::effective().as_raw();
    let wrong_uid = actual_uid.wrapping_add(1);
    let receiver =
        OneShotCredentialReceiver::bind_for_uid(&fixture.socket, TEST_TIMEOUT, wrong_uid)
            .expect("bind credential receiver");
    let mut client = UnixStream::connect(&fixture.socket).expect("connect client");
    write_frame(&mut client, b"must-not-be-read");
    client.shutdown(Shutdown::Write).expect("close write half");

    assert!(matches!(
        receiver.receive(),
        Err(CredentialTransportError::PeerUidMismatch)
    ));
    assert!(!fixture.socket.exists());
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) {
    stream
        .write_all(format!("{}:", payload.len()).as_bytes())
        .expect("write frame length");
    stream.write_all(payload).expect("write frame payload");
    stream.write_all(b",").expect("write frame terminator");
}

fn wait_until_absent(path: &Path) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    while path.exists() {
        assert!(Instant::now() < deadline, "socket was not unlinked");
        thread::sleep(Duration::from_millis(2));
    }
}

struct SocketFixture {
    directory: PathBuf,
    socket: PathBuf,
}

impl SocketFixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-credential-test-{}-{id}-{label}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create temporary directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("restrict temporary directory");
        let socket = directory.join("credential.sock");
        Self { directory, socket }
    }
}

impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
