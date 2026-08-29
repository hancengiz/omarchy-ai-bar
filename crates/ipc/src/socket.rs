//! Secure long-lived display socket transport.

use std::ffi::{OsStr, OsString};
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};

use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket, sockopt,
};
use thiserror::Error;

use crate::permissions::{
    EndpointLock, PermissionError, RuntimeDirectory, SocketIdentity,
    cleanup_socket_after_capture_failure, effective_uid, is_same_socket_child,
    owned_socket_identity_child, remove_socket_child_if_same, secure_private_socket_child,
    socket_child_exists, validate_private_socket_child,
};

/// Errors raised while creating or accepting a private display socket.
#[derive(Debug, Error)]
pub enum DisplaySocketError {
    /// The socket must be an absolute direct child of a runtime directory.
    #[error("the display socket path is invalid")]
    InvalidPath,

    /// Filesystem ownership is always anchored to the current effective UID.
    #[error("the requested display socket owner is not the effective UID")]
    EffectiveUidMismatch,

    /// The runtime directory, lifecycle lock, or socket did not meet the
    /// filesystem security contract.
    #[error(transparent)]
    Permissions(#[from] PermissionError),

    /// A listener is already serving the requested pathname.
    #[error("an active display socket already exists")]
    AlreadyActive,

    /// The old pathname changed while it was being checked for staleness.
    #[error("the stale display socket changed during replacement")]
    StaleSocketChanged,

    /// The old socket could not be safely probed.
    #[error("could not determine whether the existing display socket is stale")]
    ProbeExisting(#[source] io::Error),

    /// A filesystem or socket operation failed. Paths are deliberately not
    /// included in the message.
    #[error("could not {operation} the display socket")]
    Operation {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    /// The platform could not provide peer credentials.
    #[error("could not authenticate the display socket peer")]
    PeerCredentials(#[source] nix::errno::Errno),

    /// The connected process does not have the required UID.
    #[error("display socket peer UID mismatch (expected {expected}, found {actual})")]
    PeerUidMismatch { expected: u32, actual: u32 },

    /// Peer credential lookup is unavailable on this platform.
    #[error("display socket peer credentials are unsupported on this platform")]
    PeerCredentialsUnsupported,
}

/// An authenticated stream accepted from [`DisplaySocket`].
#[derive(Debug)]
pub struct VerifiedDisplayStream {
    stream: UnixStream,
    peer_uid: u32,
}

impl VerifiedDisplayStream {
    /// Returns the authenticated peer UID.
    #[must_use]
    pub const fn peer_uid(&self) -> u32 {
        self.peer_uid
    }

    /// Borrows the authenticated stream.
    #[must_use]
    pub const fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Borrows the authenticated stream mutably.
    #[must_use]
    pub const fn stream_mut(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// Consumes the wrapper and returns the authenticated stream.
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }
}

/// A long-lived display listener with descriptor-anchored cleanup and a
/// per-endpoint lifecycle lock.
#[derive(Debug)]
pub struct DisplaySocket {
    listener: UnixListener,
    cleanup: SocketCleanup,
    expected_peer_uid: u32,
}

impl AsRawFd for DisplaySocket {
    fn as_raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }
}

impl DisplaySocket {
    /// Binds a display listener owned by the effective UID.
    ///
    /// The parent directory is created with `0700` when absent. An existing
    /// pathname is removed only when it is an owned Unix stream socket that
    /// refuses a nonblocking connection and remains the same inode throughout
    /// inspection.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or runtime directory is insecure, the
    /// endpoint lifecycle is locked, an active listener exists, stale
    /// replacement is unsafe, or binding fails.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, DisplaySocketError> {
        let expected_uid = effective_uid();
        Self::bind_for_uid(path, expected_uid)
    }

    /// Binds a display listener using an explicit filesystem and peer UID.
    ///
    /// Most callers should use [`Self::bind`]. This form is available to make
    /// the effective-UID invariant directly testable; it rejects any value
    /// other than the process's current effective UID.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or runtime directory is insecure, the
    /// endpoint lifecycle is locked, an active listener exists, stale
    /// replacement is unsafe, or binding fails.
    pub fn bind_for_uid(
        path: impl AsRef<Path>,
        expected_uid: u32,
    ) -> Result<Self, DisplaySocketError> {
        if expected_uid != effective_uid() {
            return Err(DisplaySocketError::EffectiveUidMismatch);
        }
        let path = path.as_ref();
        let (runtime_path, endpoint_name) = checked_endpoint(path)?;
        let runtime = RuntimeDirectory::prepare_for_uid(runtime_path, expected_uid)?;
        let endpoint_lock = EndpointLock::acquire(&runtime, endpoint_name)?;

        prepare_socket_path(&runtime, endpoint_name)?;
        let anchored_path = runtime.anchored_child_path(endpoint_name)?;
        let listener =
            UnixListener::bind(anchored_path).map_err(|source| DisplaySocketError::Operation {
                operation: "bind",
                source,
            })?;

        // Capture the created node before any other fallible post-bind work so
        // every later error is covered by inode-aware cleanup.
        let identity = match capture_bound_socket(&runtime, endpoint_name) {
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
            path.to_path_buf(),
            identity,
        );

        if !secure_private_socket_child(&cleanup.runtime, &cleanup.endpoint_name, identity)? {
            return Err(DisplaySocketError::StaleSocketChanged);
        }
        validate_private_socket_child(&cleanup.runtime, &cleanup.endpoint_name)?;
        if !cleanup.is_same_socket() {
            return Err(DisplaySocketError::StaleSocketChanged);
        }
        cleanup.runtime.verify_original_path()?;

        Ok(Self {
            listener,
            cleanup,
            expected_peer_uid: expected_uid,
        })
    }

    /// Accepts one stream and rejects it unless its kernel-reported UID
    /// matches the UID captured when the listener was created.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails, peer credentials are unavailable,
    /// or the peer UID does not match.
    pub fn accept_verified(&self) -> Result<VerifiedDisplayStream, DisplaySocketError> {
        self.accept_verified_for_uid(self.expected_peer_uid)
    }

    /// Accepts one stream and checks it against an explicit expected UID.
    ///
    /// This is primarily useful for testing the fail-closed mismatch path.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails, peer credentials are unavailable,
    /// or the peer UID does not match `expected_uid`.
    pub fn accept_verified_for_uid(
        &self,
        expected_uid: u32,
    ) -> Result<VerifiedDisplayStream, DisplaySocketError> {
        let (stream, _) =
            self.listener
                .accept()
                .map_err(|source| DisplaySocketError::Operation {
                    operation: "accept from",
                    source,
                })?;
        let peer_uid = match verify_peer_uid(&stream, expected_uid) {
            Ok(peer_uid) => peer_uid,
            Err(error) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(error);
            }
        };
        Ok(VerifiedDisplayStream { stream, peer_uid })
    }

    /// Enables or disables nonblocking accepts.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system rejects the configuration.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), DisplaySocketError> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|source| DisplaySocketError::Operation {
                operation: "configure",
                source,
            })
    }

    /// Returns the public socket pathname guarded by this listener.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.cleanup.public_path
    }
}

/// Reads kernel-authenticated credentials from a connected Unix stream and
/// verifies its UID.
///
/// # Errors
///
/// Returns an error when peer credentials are unavailable or the peer UID does
/// not match `expected_uid`.
pub fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<u32, DisplaySocketError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let credentials = getsockopt(stream, sockopt::PeerCredentials)
            .map_err(DisplaySocketError::PeerCredentials)?;
        let actual_uid = credentials.uid();
        if actual_uid != expected_uid {
            return Err(DisplaySocketError::PeerUidMismatch {
                expected: expected_uid,
                actual: actual_uid,
            });
        }
        Ok(actual_uid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (stream, expected_uid);
        Err(DisplaySocketError::PeerCredentialsUnsupported)
    }
}

fn checked_endpoint(path: &Path) -> Result<(&Path, &OsStr), DisplaySocketError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || !matches!(path.components().next_back(), Some(Component::Normal(_)))
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(DisplaySocketError::InvalidPath);
    }
    UnixAddr::new(path).map_err(|_error| DisplaySocketError::InvalidPath)?;
    let parent = path.parent().ok_or(DisplaySocketError::InvalidPath)?;
    let name = path.file_name().ok_or(DisplaySocketError::InvalidPath)?;
    Ok((parent, name))
}

fn prepare_socket_path(
    runtime: &RuntimeDirectory,
    endpoint_name: &OsStr,
) -> Result<(), DisplaySocketError> {
    if !socket_child_exists(runtime, endpoint_name)? {
        return Ok(());
    }
    let identity = owned_socket_identity_child(runtime, endpoint_name)?;
    match probe_existing_socket(runtime, endpoint_name)? {
        ExistingSocketState::Active => return Err(DisplaySocketError::AlreadyActive),
        ExistingSocketState::Missing => return Ok(()),
        ExistingSocketState::Stale => {}
    }

    if !remove_socket_child_if_same(runtime, endpoint_name, identity)? {
        return Err(DisplaySocketError::StaleSocketChanged);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingSocketState {
    Active,
    Missing,
    Stale,
}

fn probe_existing_socket(
    runtime: &RuntimeDirectory,
    endpoint_name: &OsStr,
) -> Result<ExistingSocketState, DisplaySocketError> {
    let path = runtime.anchored_child_path(endpoint_name)?;
    let address = UnixAddr::new(&path)
        .map_err(|source| DisplaySocketError::ProbeExisting(io::Error::from(source)))?;
    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(|source| DisplaySocketError::ProbeExisting(io::Error::from(source)))?;

    match connect(descriptor.as_raw_fd(), &address) {
        Ok(())
        | Err(
            nix::errno::Errno::EINPROGRESS
            | nix::errno::Errno::EALREADY
            | nix::errno::Errno::EAGAIN,
        ) => Ok(ExistingSocketState::Active),
        Err(nix::errno::Errno::ECONNREFUSED) => Ok(ExistingSocketState::Stale),
        Err(nix::errno::Errno::ENOENT) => Ok(ExistingSocketState::Missing),
        Err(source) => Err(DisplaySocketError::ProbeExisting(io::Error::from(source))),
    }
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

#[derive(Debug)]
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
mod tests {
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::DirBuilderExt;

    use super::*;

    #[test]
    fn injected_post_bind_capture_failure_cleans_created_node() {
        let root = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-socket-capture-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("create fixture root");
        let socket_path = root.join("runtime").join("display.sock");
        FAIL_NEXT_SOCKET_CAPTURE.store(true, std::sync::atomic::Ordering::SeqCst);

        let error = DisplaySocket::bind(&socket_path).expect_err("inject capture failure");

        assert!(matches!(
            error,
            DisplaySocketError::Permissions(PermissionError::Filesystem {
                operation: "capture bound socket",
                ..
            })
        ));
        assert!(!socket_path.exists());
        fs::remove_dir_all(root).expect("remove fixture root");
    }
}
