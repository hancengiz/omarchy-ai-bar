//! One-shot transport for credentials entered by the frontend.
//!
//! This channel is deliberately separate from the long-lived display protocol.
//! A frame is a canonical ASCII netstring: the decimal UTF-8 byte length, a
//! colon, one non-empty UTF-8 credential, and a comma. The sender must close
//! its write half after that frame.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::socket::UnixAddr;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::permissions::{
    EndpointLock, PermissionError, RuntimeDirectory, SocketIdentity,
    cleanup_socket_after_capture_failure, effective_uid, is_same_socket_child,
    owned_socket_identity_child, remove_socket_child_if_same, secure_private_socket_child,
    socket_child_exists, validate_private_socket_child,
};

/// Maximum accepted credential size, in UTF-8 bytes.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

const MAX_LENGTH_DIGITS: usize = 5;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// An in-memory credential received through the one-shot transport.
///
/// The value is intentionally neither cloneable nor serializable and is erased
/// when dropped. Callers must opt in to borrowing the plaintext with
/// [`Credential::expose_secret`].
///
/// ```compile_fail
/// use oab_ipc::credential::Credential;
///
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<Credential>();
/// ```
///
/// ```compile_fail
/// use oab_ipc::credential::Credential;
///
/// let credential = Credential::new("secret").unwrap();
/// let copied = credential.clone();
/// ```
///
/// ```compile_fail
/// use oab_ipc::credential::Credential;
///
/// let credential = Credential::new("secret").unwrap();
/// let displayed = format!("{credential}");
/// ```
pub struct Credential {
    value: String,
}

impl Credential {
    /// Creates a bounded, non-empty UTF-8 credential.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialValidationError::Empty`] for an empty value or
    /// [`CredentialValidationError::TooLarge`] above [`MAX_CREDENTIAL_BYTES`].
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialValidationError> {
        let mut value = value.into();
        if value.is_empty() {
            value.zeroize();
            return Err(CredentialValidationError::Empty);
        }
        if value.len() > MAX_CREDENTIAL_BYTES {
            value.zeroize();
            return Err(CredentialValidationError::TooLarge);
        }
        Ok(Self { value })
    }

    /// Borrows the credential plaintext.
    ///
    /// Keep this borrow as short-lived as possible and do not log it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.value
    }

    fn from_bytes(mut value: Vec<u8>) -> Result<Self, CredentialValidationError> {
        if value.is_empty() {
            value.zeroize();
            return Err(CredentialValidationError::Empty);
        }
        if value.len() > MAX_CREDENTIAL_BYTES {
            value.zeroize();
            return Err(CredentialValidationError::TooLarge);
        }

        match String::from_utf8(value) {
            Ok(value) => Ok(Self { value }),
            Err(error) => {
                let mut value = error.into_bytes();
                value.zeroize();
                Err(CredentialValidationError::InvalidUtf8)
            }
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential([REDACTED])")
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Validation failures that reveal no part of the submitted credential.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialValidationError {
    /// The submitted value had no bytes.
    #[error("credential must not be empty")]
    Empty,
    /// The submitted value exceeded [`MAX_CREDENTIAL_BYTES`].
    #[error("credential exceeds the maximum size")]
    TooLarge,
    /// The submitted bytes were not valid UTF-8.
    #[error("credential is not valid UTF-8")]
    InvalidUtf8,
}

/// A receiver backed by a single-use Unix-domain socket.
///
/// The socket path is mode `0600` inside a pinned mode-`0700` runtime
/// directory. The path is unlinked as soon as one client is accepted and is
/// also cleaned up when this value is dropped or expires.
pub struct OneShotCredentialReceiver {
    listener: UnixListener,
    cleanup: SocketCleanup,
    expected_peer_uid: u32,
    deadline: Instant,
}

impl OneShotCredentialReceiver {
    /// Binds a receiver for the effective user ID of this process.
    ///
    /// # Errors
    ///
    /// Returns an error if the timeout is invalid or the socket cannot be
    /// created, restricted, pinned, locked, or configured. An existing path is
    /// left untouched.
    pub fn bind(
        socket_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self, CredentialTransportError> {
        Self::bind_for_uid(socket_path, timeout, effective_uid())
    }

    /// Binds a receiver with an explicit expected peer user ID.
    ///
    /// The runtime directory and socket are still required to belong to the
    /// process's effective UID. Normal callers should use [`Self::bind`].
    ///
    /// # Errors
    ///
    /// Returns an error if the timeout is invalid or the socket cannot be
    /// created, restricted, pinned, locked, or configured. An existing path is
    /// left untouched.
    pub fn bind_for_uid(
        socket_path: impl AsRef<Path>,
        timeout: Duration,
        expected_peer_uid: u32,
    ) -> Result<Self, CredentialTransportError> {
        if timeout.is_zero() {
            return Err(CredentialTransportError::InvalidTimeout);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(CredentialTransportError::InvalidTimeout)?;
        let socket_path = socket_path.as_ref();
        let (runtime_path, endpoint_name) = checked_endpoint(socket_path)?;
        let owner_uid = effective_uid();
        let runtime = RuntimeDirectory::prepare_for_uid(runtime_path, owner_uid)?;
        let endpoint_lock = EndpointLock::acquire(&runtime, endpoint_name)?;
        if socket_child_exists(&runtime, endpoint_name)? {
            return Err(CredentialTransportError::Bind(io::Error::from(
                io::ErrorKind::AddrInUse,
            )));
        }

        let anchored_path = runtime.anchored_child_path(endpoint_name)?;
        let listener = UnixListener::bind(anchored_path).map_err(CredentialTransportError::Bind)?;

        // Capture the created node before any other fallible post-bind work so
        // every later error is covered by inode-aware cleanup.
        let socket_identity = match capture_bound_socket(&runtime, endpoint_name) {
            Ok(identity) => identity,
            Err(error) => {
                cleanup_socket_after_capture_failure(&runtime, endpoint_name);
                return Err(error.into());
            }
        };
        let cleanup = SocketCleanup::new(
            runtime,
            endpoint_lock,
            endpoint_name.to_os_string(),
            socket_path.to_path_buf(),
            socket_identity,
        );

        if !secure_private_socket_child(&cleanup.runtime, &cleanup.endpoint_name, socket_identity)?
        {
            return Err(CredentialTransportError::SocketPathChanged);
        }
        validate_private_socket_child(&cleanup.runtime, &cleanup.endpoint_name)?;
        if !cleanup.is_same_socket() {
            return Err(CredentialTransportError::SocketPathChanged);
        }
        listener
            .set_nonblocking(true)
            .map_err(CredentialTransportError::ConfigureListener)?;
        cleanup.runtime.verify_original_path()?;

        Ok(Self {
            listener,
            cleanup,
            expected_peer_uid,
            deadline,
        })
    }

    /// Returns the public path at which this receiver is listening.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.cleanup.public_path
    }

    /// Accepts and consumes exactly one credential netstring.
    ///
    /// The socket is unlinked immediately after `accept`, before peer
    /// verification or reading any credential bytes. The absolute deadline set
    /// at bind time covers both accepting and reading.
    ///
    /// # Errors
    ///
    /// Returns an error on timeout, peer mismatch, unsupported peer
    /// authentication, I/O failure, malformed framing, an invalid credential,
    /// or any bytes after the single netstring.
    pub fn receive(mut self) -> Result<Credential, CredentialTransportError> {
        let stream = self.accept_before_deadline()?;
        self.cleanup.unlink()?;
        verify_peer_uid(&stream, self.expected_peer_uid)?;
        read_one_frame(stream, self.deadline)
    }

    fn accept_before_deadline(&self) -> Result<UnixStream, CredentialTransportError> {
        loop {
            let remaining = remaining_until(self.deadline)?;
            match self.listener.accept() {
                Ok((stream, _address)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL_INTERVAL.min(remaining));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(CredentialTransportError::Accept(error)),
            }
        }
    }
}

/// Failures for the one-shot credential transport.
#[derive(Debug, Error)]
pub enum CredentialTransportError {
    /// The socket must be an absolute direct child with a normal file name.
    #[error("credential socket path is invalid")]
    InvalidPath,
    /// The timeout was zero or could not be represented as a deadline.
    #[error("credential transport requires a finite, non-zero timeout")]
    InvalidTimeout,
    /// The socket could not be bound. Existing paths are never replaced.
    #[error("could not bind credential socket")]
    Bind(#[source] io::Error),
    /// The new socket could not be restricted to mode `0600`.
    #[error("could not restrict credential socket permissions")]
    SetPermissions(#[source] io::Error),
    /// The listener could not be configured for deadline-aware acceptance.
    #[error("could not configure credential socket")]
    ConfigureListener(#[source] io::Error),
    /// The runtime directory, lifecycle lock, or socket failed its security
    /// checks.
    #[error(transparent)]
    Permissions(#[from] PermissionError),
    /// Accepting a client failed.
    #[error("could not accept credential connection")]
    Accept(#[source] io::Error),
    /// The pathname stopped identifying the socket inode created by this receiver.
    #[error("credential socket path changed unexpectedly")]
    SocketPathChanged,
    /// Peer credentials could not be read on a platform that supports them.
    #[error("could not verify credential peer")]
    PeerCredentials(#[source] io::Error),
    /// The connecting process had a different user ID.
    #[error("credential peer user ID does not match the receiver")]
    PeerUidMismatch,
    /// The platform cannot authenticate the credential peer.
    #[error("credential peer authentication is unsupported on this platform")]
    PeerCredentialsUnsupported,
    /// The absolute accept/read deadline elapsed.
    #[error("credential transport deadline elapsed")]
    DeadlineElapsed,
    /// The peer closed its write side before completing a frame.
    #[error("credential frame was truncated")]
    TruncatedFrame,
    /// The decimal length was empty, noncanonical, or too long.
    #[error("credential frame length is invalid")]
    InvalidLengthPrefix,
    /// The byte following the declared payload was not a comma.
    #[error("credential frame is missing its terminator")]
    MissingTerminator,
    /// Bytes followed the single declared credential value.
    #[error("credential connection contained trailing data")]
    TrailingData,
    /// Reading the accepted connection failed.
    #[error("could not read credential frame")]
    Read(#[source] io::Error),
    /// The submitted credential was invalid.
    #[error(transparent)]
    InvalidCredential(#[from] CredentialValidationError),
}

fn read_one_frame(
    mut stream: UnixStream,
    deadline: Instant,
) -> Result<Credential, CredentialTransportError> {
    stream
        .set_nonblocking(false)
        .map_err(CredentialTransportError::Read)?;

    let declared_length = read_length_prefix(&mut stream, deadline)?;
    if declared_length == 0 {
        return Err(CredentialValidationError::Empty.into());
    }
    if declared_length > MAX_CREDENTIAL_BYTES {
        return Err(CredentialValidationError::TooLarge.into());
    }

    let mut payload = Zeroizing::new(vec![0_u8; declared_length]);
    read_exact_before(&mut stream, &mut payload, deadline)?;
    read_terminator_before(&mut stream, deadline)?;
    require_end_of_stream(&mut stream, deadline)?;
    Credential::from_bytes(std::mem::take(&mut *payload)).map_err(Into::into)
}

fn read_length_prefix(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<usize, CredentialTransportError> {
    let mut digits = [0_u8; MAX_LENGTH_DIGITS];
    let mut digit_count = 0_usize;
    loop {
        let mut byte = [0_u8; 1];
        read_exact_before(stream, &mut byte, deadline)?;
        match byte[0] {
            b':' if digit_count == 0 => return Err(CredentialTransportError::InvalidLengthPrefix),
            b':' => break,
            digit @ b'0'..=b'9' if digit_count < MAX_LENGTH_DIGITS => {
                digits[digit_count] = digit;
                digit_count += 1;
            }
            _ => return Err(CredentialTransportError::InvalidLengthPrefix),
        }
    }

    if digit_count > 1 && digits[0] == b'0' {
        return Err(CredentialTransportError::InvalidLengthPrefix);
    }
    let mut length = 0_usize;
    for digit in &digits[..digit_count] {
        length = length
            .checked_mul(10)
            .and_then(|value| value.checked_add(usize::from(*digit - b'0')))
            .ok_or(CredentialTransportError::InvalidLengthPrefix)?;
    }
    Ok(length)
}

fn read_exact_before(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), CredentialTransportError> {
    let mut filled = 0;
    while filled < buffer.len() {
        set_remaining_read_timeout(stream, deadline)?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(CredentialTransportError::TruncatedFrame),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(CredentialTransportError::DeadlineElapsed);
            }
            Err(error) => return Err(CredentialTransportError::Read(error)),
        }
    }
    Ok(())
}

fn read_terminator_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<(), CredentialTransportError> {
    let mut terminator = Zeroizing::new([0_u8; 1]);
    loop {
        set_remaining_read_timeout(stream, deadline)?;
        match stream.read(&mut *terminator) {
            Ok(1) if terminator[0] == b',' => return Ok(()),
            Ok(0 | 1) => return Err(CredentialTransportError::MissingTerminator),
            Ok(_) => {
                return Err(CredentialTransportError::Read(io::Error::other(
                    "invalid one-byte read result",
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(CredentialTransportError::DeadlineElapsed);
            }
            Err(error) => return Err(CredentialTransportError::Read(error)),
        }
    }
}

fn require_end_of_stream(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<(), CredentialTransportError> {
    let mut trailing = Zeroizing::new([0_u8; 1]);
    loop {
        set_remaining_read_timeout(stream, deadline)?;
        match stream.read(&mut *trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(CredentialTransportError::TrailingData),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(CredentialTransportError::DeadlineElapsed);
            }
            Err(error) => return Err(CredentialTransportError::Read(error)),
        }
    }
}

fn set_remaining_read_timeout(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(), CredentialTransportError> {
    let remaining = remaining_until(deadline)?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(CredentialTransportError::Read)
}

fn remaining_until(deadline: Instant) -> Result<Duration, CredentialTransportError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(CredentialTransportError::DeadlineElapsed)
}

fn checked_endpoint(path: &Path) -> Result<(&Path, &OsStr), CredentialTransportError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || !matches!(path.components().next_back(), Some(Component::Normal(_)))
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(CredentialTransportError::InvalidPath);
    }
    UnixAddr::new(path).map_err(|_error| CredentialTransportError::InvalidPath)?;
    let parent = path.parent().ok_or(CredentialTransportError::InvalidPath)?;
    let name = path
        .file_name()
        .ok_or(CredentialTransportError::InvalidPath)?;
    Ok((parent, name))
}

fn capture_bound_socket(
    runtime: &RuntimeDirectory,
    endpoint_name: &OsStr,
) -> Result<SocketIdentity, PermissionError> {
    #[cfg(test)]
    if FAIL_NEXT_SOCKET_CAPTURE.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(PermissionError::Filesystem {
            operation: "capture bound socket",
            source: io::Error::other("injected capture failure"),
        });
    }
    owned_socket_identity_child(runtime, endpoint_name)
}

#[cfg(test)]
static FAIL_NEXT_SOCKET_CAPTURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(target_os = "linux", target_os = "android"))]
fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), CredentialTransportError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let credentials = getsockopt(stream, PeerCredentials)
        .map_err(|error| CredentialTransportError::PeerCredentials(io::Error::from(error)))?;
    if credentials.uid() != expected_uid {
        return Err(CredentialTransportError::PeerUidMismatch);
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn verify_peer_uid(
    _stream: &UnixStream,
    _expected_uid: u32,
) -> Result<(), CredentialTransportError> {
    Err(CredentialTransportError::PeerCredentialsUnsupported)
}

struct SocketCleanup {
    runtime: RuntimeDirectory,
    _endpoint_lock: EndpointLock,
    endpoint_name: OsString,
    public_path: PathBuf,
    identity: SocketIdentity,
    linked: bool,
}

impl SocketCleanup {
    const fn new(
        runtime: RuntimeDirectory,
        endpoint_lock: EndpointLock,
        endpoint_name: OsString,
        public_path: PathBuf,
        identity: SocketIdentity,
    ) -> Self {
        Self {
            runtime,
            _endpoint_lock: endpoint_lock,
            endpoint_name,
            public_path,
            identity,
            linked: true,
        }
    }

    fn is_same_socket(&self) -> bool {
        is_same_socket_child(&self.runtime, &self.endpoint_name, self.identity)
    }

    fn unlink(&mut self) -> Result<(), CredentialTransportError> {
        if !self.is_same_socket() {
            return Err(CredentialTransportError::SocketPathChanged);
        }
        if !remove_socket_child_if_same(&self.runtime, &self.endpoint_name, self.identity)? {
            return Err(CredentialTransportError::SocketPathChanged);
        }
        self.linked = false;
        Ok(())
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if self.linked {
            let _ = remove_socket_child_if_same(&self.runtime, &self.endpoint_name, self.identity);
        }
        self.linked = false;
    }
}

#[cfg(all(test, target_os = "linux"))]
mod transport_tests {
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::DirBuilderExt;

    use super::*;

    #[test]
    fn injected_post_bind_capture_failure_cleans_created_node() {
        let root = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-credential-capture-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("create fixture root");
        let socket_path = root.join("runtime").join("credential.sock");
        FAIL_NEXT_SOCKET_CAPTURE.store(true, std::sync::atomic::Ordering::SeqCst);

        let error = match OneShotCredentialReceiver::bind(&socket_path, Duration::from_secs(1)) {
            Ok(_receiver) => panic!("injected capture unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            CredentialTransportError::Permissions(PermissionError::Filesystem {
                operation: "capture bound socket",
                ..
            })
        ));
        assert!(!socket_path.exists());
        fs::remove_dir_all(root).expect("remove fixture root");
    }
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "android"))))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_peer_authentication_fails_closed() {
        let (first, second) = UnixStream::pair().expect("create socket pair");
        drop(second);
        assert!(matches!(
            verify_peer_uid(&first, effective_uid()),
            Err(CredentialTransportError::PeerCredentialsUnsupported)
        ));
    }
}
