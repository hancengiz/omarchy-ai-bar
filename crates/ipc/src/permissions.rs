//! Ownership, pinning, and mode checks for private Unix-domain sockets.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, FileType, Metadata};
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, open, openat};
#[cfg(target_os = "linux")]
use nix::sys::stat::{FchmodatFlags, Mode, SFlag, fchmod, fchmodat, fstatat};
#[cfg(target_os = "linux")]
use nix::unistd::{UnlinkatFlags, unlinkat};
use thiserror::Error;

/// The only accepted mode for an application runtime directory.
pub const RUNTIME_DIRECTORY_MODE: u32 = 0o700;

/// The only accepted mode for a private Unix-domain socket.
pub const PRIVATE_SOCKET_MODE: u32 = 0o600;

const ENDPOINT_LOCK_MODE: u32 = 0o600;

/// Errors raised while establishing the filesystem boundary around an IPC socket.
#[derive(Debug, Error)]
pub enum PermissionError {
    /// Runtime paths must be absolute so their security does not depend on the
    /// daemon's current working directory.
    #[error("the runtime directory path must be absolute")]
    RuntimePathNotAbsolute,

    /// The runtime directory itself must never be a symbolic link.
    #[error("the runtime directory is a symbolic link")]
    RuntimeDirectorySymlink,

    /// An existing runtime path was not a directory.
    #[error("the runtime path is not a directory")]
    RuntimePathNotDirectory,

    /// The directory is not owned by the UID the daemon is running as.
    #[error(
        "the runtime directory has an unexpected owner (expected UID {expected}, found {actual})"
    )]
    RuntimeOwnerMismatch { expected: u32, actual: u32 },

    /// The directory has permissions other than `0700`.
    #[error("the runtime directory has an unsafe mode (expected {expected:#o}, found {actual:#o})")]
    RuntimeModeMismatch { expected: u32, actual: u32 },

    /// The path that named a pinned runtime directory was replaced.
    #[error("the runtime directory path changed after verification")]
    RuntimeDirectoryChanged,

    /// Descriptor-anchored path handling is unavailable.
    #[error("private IPC filesystem pinning is unsupported on this platform")]
    UnsupportedPlatform,

    /// A private socket pathname must not be a symbolic link.
    #[error("the private socket path is a symbolic link")]
    SocketPathSymlink,

    /// A private socket pathname resolved to some other filesystem object.
    #[error("the private socket path is not a Unix socket")]
    SocketPathNotSocket,

    /// The socket is not owned by the UID the daemon is running as.
    #[error("the private socket has an unexpected owner (expected UID {expected}, found {actual})")]
    SocketOwnerMismatch { expected: u32, actual: u32 },

    /// The socket has permissions other than `0600`.
    #[error("the private socket has an unsafe mode (expected {expected:#o}, found {actual:#o})")]
    SocketModeMismatch { expected: u32, actual: u32 },

    /// The endpoint lock pathname was a symbolic link.
    #[error("the private endpoint lock path is a symbolic link")]
    EndpointLockSymlink,

    /// The endpoint lock was not a regular single-link file.
    #[error("the private endpoint lock is not a regular single-link file")]
    EndpointLockNotRegular,

    /// The endpoint lock is owned by another user.
    #[error("the private endpoint lock has an unexpected owner")]
    EndpointLockOwnerMismatch,

    /// The endpoint lock mode was not exactly `0600`.
    #[error("the private endpoint lock has an unsafe mode")]
    EndpointLockModeMismatch,

    /// Another cooperating process owns the endpoint lifecycle.
    #[error("the private endpoint lifecycle is already locked")]
    EndpointLockBusy,

    /// The endpoint lock pathname changed during acquisition.
    #[error("the private endpoint lock changed during acquisition")]
    EndpointLockChanged,

    /// A filesystem operation failed. Paths are intentionally excluded from
    /// the display representation.
    #[error("could not {operation} the private IPC filesystem object")]
    Filesystem {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

/// A runtime directory retained by an open descriptor after verification.
#[derive(Debug)]
pub struct RuntimeDirectory {
    path: PathBuf,
    owner_uid: u32,
    identity: FileIdentity,
    #[cfg(target_os = "linux")]
    directory: File,
}

impl RuntimeDirectory {
    /// Creates a runtime directory if needed and verifies it against the
    /// process's effective UID.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is relative, cannot be created, pinned,
    /// or inspected, or does not have the required type, owner, and mode.
    pub fn prepare(path: impl AsRef<Path>) -> Result<Self, PermissionError> {
        Self::prepare_for_uid(path, effective_uid())
    }

    /// Creates and verifies a runtime directory against an explicit UID.
    ///
    /// The explicit form exists so callers can test and enforce a previously
    /// captured security context without changing process credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is relative, cannot be created, pinned,
    /// or inspected, or does not have the required type, owner, and mode.
    pub fn prepare_for_uid(
        path: impl AsRef<Path>,
        expected_uid: u32,
    ) -> Result<Self, PermissionError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(PermissionError::RuntimePathNotAbsolute);
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected_uid;
            return Err(PermissionError::UnsupportedPlatform);
        }

        #[cfg(target_os = "linux")]
        {
            create_runtime_directory_if_absent(path)?;
            reject_known_bad_runtime_type(path)?;

            let directory = File::from(
                open(
                    path,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|source| filesystem("pin", source))?,
            );
            let metadata = directory
                .metadata()
                .map_err(|source| PermissionError::Filesystem {
                    operation: "inspect pinned",
                    source,
                })?;
            validate_runtime_metadata(&metadata, expected_uid)?;
            let identity = FileIdentity::from_metadata(&metadata);

            let runtime = Self {
                path: path.to_path_buf(),
                owner_uid: expected_uid,
                identity,
                directory,
            };
            runtime.verify_proc_anchor()?;
            runtime.verify_original_path()?;
            Ok(runtime)
        }
    }

    /// Returns the verified directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the UID used during verification.
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub(crate) fn verify_original_path(&self) -> Result<(), PermissionError> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|_source| PermissionError::RuntimeDirectoryChanged)?;
        validate_runtime_metadata(&metadata, self.owner_uid)
            .map_err(|_error| PermissionError::RuntimeDirectoryChanged)?;
        if FileIdentity::from_metadata(&metadata) != self.identity {
            return Err(PermissionError::RuntimeDirectoryChanged);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn anchored_child_path(&self, child: &OsStr) -> Result<PathBuf, PermissionError> {
        validate_child_name(child)?;
        Ok(self.proc_anchor_path().join(child))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn anchored_child_path(&self, _child: &OsStr) -> Result<PathBuf, PermissionError> {
        Err(PermissionError::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    fn proc_anchor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    #[cfg(target_os = "linux")]
    fn verify_proc_anchor(&self) -> Result<(), PermissionError> {
        let metadata = fs::metadata(self.proc_anchor_path()).map_err(|source| {
            PermissionError::Filesystem {
                operation: "verify pin",
                source,
            }
        })?;
        if FileIdentity::from_metadata(&metadata) != self.identity {
            return Err(PermissionError::RuntimeDirectoryChanged);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn child_stat(&self, child: &OsStr) -> Result<Option<nix::libc::stat>, PermissionError> {
        validate_child_name(child)?;
        match fstatat(&self.directory, child, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(source) => Err(filesystem("inspect child", source)),
        }
    }

    #[cfg(target_os = "linux")]
    fn unlink_child(&self, child: &OsStr) -> Result<(), PermissionError> {
        validate_child_name(child)?;
        unlinkat(&self.directory, child, UnlinkatFlags::NoRemoveDir)
            .map_err(|source| filesystem("unlink child", source))
    }
}

/// Returns the effective UID that owns this process's private IPC endpoints.
#[must_use]
pub fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// Verifies that a runtime directory is a real directory with exact private
/// ownership and permissions.
///
/// # Errors
///
/// Returns an error when the path cannot be inspected or is not an absolute,
/// non-symlink directory owned by `expected_uid` with mode `0700`.
pub fn validate_runtime_directory(
    path: impl AsRef<Path>,
    expected_uid: u32,
) -> Result<(), PermissionError> {
    let path = path.as_ref();
    if !path.is_absolute() {
        return Err(PermissionError::RuntimePathNotAbsolute);
    }

    let metadata = fs::symlink_metadata(path).map_err(|source| PermissionError::Filesystem {
        operation: "inspect",
        source,
    })?;
    validate_runtime_metadata(&metadata, expected_uid)
}

/// Verifies that a socket path is a real Unix socket with exact private
/// ownership and permissions.
///
/// This path-based helper is intended for diagnostics. Transport code uses the
/// descriptor-anchored equivalent internally.
///
/// # Errors
///
/// Returns an error when the path cannot be inspected or is not a non-symlink
/// Unix socket owned by `expected_uid` with mode `0600`.
pub fn validate_private_socket(
    path: impl AsRef<Path>,
    expected_uid: u32,
) -> Result<(), PermissionError> {
    private_socket_identity(path.as_ref(), expected_uid, true).map(drop)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(target_os = "linux")]
    const fn from_stat(stat: &nix::libc::stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct EndpointLock {
    _file: Flock<File>,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) struct EndpointLock;

impl EndpointLock {
    pub(crate) fn acquire(
        runtime: &RuntimeDirectory,
        endpoint_name: &OsStr,
    ) -> Result<Self, PermissionError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (runtime, endpoint_name);
            Err(PermissionError::UnsupportedPlatform)
        }

        #[cfg(target_os = "linux")]
        {
            validate_child_name(endpoint_name)?;
            let lock_name = endpoint_lock_name(endpoint_name);
            let create_flags = OFlag::O_RDWR
                | OFlag::O_CLOEXEC
                | OFlag::O_NOFOLLOW
                | OFlag::O_CREAT
                | OFlag::O_EXCL;
            let (file, created) = match openat(
                &runtime.directory,
                lock_name.as_os_str(),
                create_flags,
                Mode::from_bits_truncate(ENDPOINT_LOCK_MODE),
            ) {
                Ok(descriptor) => (File::from(descriptor), true),
                Err(nix::errno::Errno::EEXIST) => {
                    let descriptor = openat(
                        &runtime.directory,
                        lock_name.as_os_str(),
                        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|source| classify_lock_open_error(runtime, &lock_name, source))?;
                    (File::from(descriptor), false)
                }
                Err(source) => {
                    return Err(classify_lock_open_error(runtime, &lock_name, source));
                }
            };

            let before = file
                .metadata()
                .map_err(|source| PermissionError::Filesystem {
                    operation: "inspect endpoint lock",
                    source,
                })?;
            validate_endpoint_lock_metadata(&before, runtime.owner_uid, created)?;
            if created {
                fchmod(&file, Mode::from_bits_truncate(ENDPOINT_LOCK_MODE))
                    .map_err(|source| filesystem("secure endpoint lock", source))?;
            }
            let after = file
                .metadata()
                .map_err(|source| PermissionError::Filesystem {
                    operation: "inspect secured endpoint lock",
                    source,
                })?;
            validate_endpoint_lock_metadata(&after, runtime.owner_uid, false)?;
            let identity = FileIdentity::from_metadata(&after);
            verify_lock_path_identity(runtime, &lock_name, identity)?;

            let file =
                Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_file, source)| {
                    if source == nix::errno::Errno::EWOULDBLOCK {
                        PermissionError::EndpointLockBusy
                    } else {
                        filesystem("lock endpoint", source)
                    }
                })?;
            let locked_metadata =
                file.metadata()
                    .map_err(|source| PermissionError::Filesystem {
                        operation: "reinspect locked endpoint",
                        source,
                    })?;
            validate_endpoint_lock_metadata(&locked_metadata, runtime.owner_uid, false)?;
            if FileIdentity::from_metadata(&locked_metadata) != identity {
                return Err(PermissionError::EndpointLockChanged);
            }
            verify_lock_path_identity(runtime, &lock_name, identity)?;
            Ok(Self { _file: file })
        }
    }
}

pub(crate) fn owned_socket_identity_child(
    runtime: &RuntimeDirectory,
    child: &OsStr,
) -> Result<SocketIdentity, PermissionError> {
    private_socket_identity_child(runtime, child, false)
}

pub(crate) fn validate_private_socket_child(
    runtime: &RuntimeDirectory,
    child: &OsStr,
) -> Result<(), PermissionError> {
    private_socket_identity_child(runtime, child, true).map(drop)
}

pub(crate) fn is_same_socket_child(
    runtime: &RuntimeDirectory,
    child: &OsStr,
    expected_identity: SocketIdentity,
) -> bool {
    owned_socket_identity_child(runtime, child)
        .is_ok_and(|actual_identity| actual_identity == expected_identity)
}

pub(crate) fn remove_socket_child_if_same(
    runtime: &RuntimeDirectory,
    child: &OsStr,
    expected_identity: SocketIdentity,
) -> Result<bool, PermissionError> {
    if !is_same_socket_child(runtime, child, expected_identity) {
        return Ok(false);
    }

    #[cfg(target_os = "linux")]
    {
        runtime.unlink_child(child)?;
        Ok(true)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (runtime, child, expected_identity);
        Err(PermissionError::UnsupportedPlatform)
    }
}

pub(crate) fn secure_private_socket_child(
    runtime: &RuntimeDirectory,
    child: &OsStr,
    expected_identity: SocketIdentity,
) -> Result<bool, PermissionError> {
    if !is_same_socket_child(runtime, child, expected_identity) {
        return Ok(false);
    }

    #[cfg(target_os = "linux")]
    {
        fchmodat(
            &runtime.directory,
            child,
            Mode::from_bits_truncate(PRIVATE_SOCKET_MODE),
            FchmodatFlags::NoFollowSymlink,
        )
        .map_err(|source| filesystem("secure socket", source))?;
        if !is_same_socket_child(runtime, child, expected_identity) {
            return Ok(false);
        }
        validate_private_socket_child(runtime, child)?;
        Ok(true)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (runtime, child, expected_identity);
        Err(PermissionError::UnsupportedPlatform)
    }
}

pub(crate) fn cleanup_socket_after_capture_failure(runtime: &RuntimeDirectory, child: &OsStr) {
    if let Ok(identity) = owned_socket_identity_child(runtime, child) {
        let _ = remove_socket_child_if_same(runtime, child, identity);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn socket_child_exists(
    runtime: &RuntimeDirectory,
    child: &OsStr,
) -> Result<bool, PermissionError> {
    Ok(runtime.child_stat(child)?.is_some())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn socket_child_exists(
    _runtime: &RuntimeDirectory,
    _child: &OsStr,
) -> Result<bool, PermissionError> {
    Err(PermissionError::UnsupportedPlatform)
}

fn create_runtime_directory_if_absent(path: &Path) -> Result<(), PermissionError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match DirBuilder::new().mode(RUNTIME_DIRECTORY_MODE).create(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
                Err(source) => Err(PermissionError::Filesystem {
                    operation: "create",
                    source,
                }),
            }
        }
        Err(source) => Err(PermissionError::Filesystem {
            operation: "inspect",
            source,
        }),
    }
}

fn reject_known_bad_runtime_type(path: &Path) -> Result<(), PermissionError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PermissionError::Filesystem {
        operation: "inspect",
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(PermissionError::RuntimeDirectorySymlink);
    }
    if !metadata.is_dir() {
        return Err(PermissionError::RuntimePathNotDirectory);
    }
    Ok(())
}

fn validate_runtime_metadata(
    metadata: &Metadata,
    expected_uid: u32,
) -> Result<(), PermissionError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(PermissionError::RuntimeDirectorySymlink);
    }
    if !file_type.is_dir() {
        return Err(PermissionError::RuntimePathNotDirectory);
    }
    let actual_uid = metadata.uid();
    if actual_uid != expected_uid {
        return Err(PermissionError::RuntimeOwnerMismatch {
            expected: expected_uid,
            actual: actual_uid,
        });
    }
    let actual_mode = permission_bits(metadata.mode());
    if actual_mode != RUNTIME_DIRECTORY_MODE {
        return Err(PermissionError::RuntimeModeMismatch {
            expected: RUNTIME_DIRECTORY_MODE,
            actual: actual_mode,
        });
    }
    Ok(())
}

fn private_socket_identity(
    path: &Path,
    expected_uid: u32,
    require_private_mode: bool,
) -> Result<SocketIdentity, PermissionError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PermissionError::Filesystem {
        operation: "inspect",
        source,
    })?;
    validate_socket_file_type(metadata.file_type())?;
    validate_socket_owner_mode(
        metadata.uid(),
        metadata.mode(),
        expected_uid,
        require_private_mode,
    )?;
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn private_socket_identity_child(
    runtime: &RuntimeDirectory,
    child: &OsStr,
    require_private_mode: bool,
) -> Result<SocketIdentity, PermissionError> {
    #[cfg(target_os = "linux")]
    {
        let stat = runtime
            .child_stat(child)?
            .ok_or_else(|| PermissionError::Filesystem {
                operation: "inspect child",
                source: io::Error::from(io::ErrorKind::NotFound),
            })?;
        let kind = SFlag::from_bits_truncate(stat.st_mode);
        if kind.contains(SFlag::S_IFLNK) {
            return Err(PermissionError::SocketPathSymlink);
        }
        if !kind.contains(SFlag::S_IFSOCK) {
            return Err(PermissionError::SocketPathNotSocket);
        }
        validate_socket_owner_mode(
            stat.st_uid,
            stat.st_mode,
            runtime.owner_uid,
            require_private_mode,
        )?;
        Ok(SocketIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (runtime, child, require_private_mode);
        Err(PermissionError::UnsupportedPlatform)
    }
}

fn validate_socket_owner_mode(
    actual_uid: u32,
    mode: u32,
    expected_uid: u32,
    require_private_mode: bool,
) -> Result<(), PermissionError> {
    if actual_uid != expected_uid {
        return Err(PermissionError::SocketOwnerMismatch {
            expected: expected_uid,
            actual: actual_uid,
        });
    }
    if require_private_mode {
        let actual_mode = permission_bits(mode);
        if actual_mode != PRIVATE_SOCKET_MODE {
            return Err(PermissionError::SocketModeMismatch {
                expected: PRIVATE_SOCKET_MODE,
                actual: actual_mode,
            });
        }
    }
    Ok(())
}

fn validate_socket_file_type(file_type: FileType) -> Result<(), PermissionError> {
    if file_type.is_symlink() {
        return Err(PermissionError::SocketPathSymlink);
    }
    if !file_type.is_socket() {
        return Err(PermissionError::SocketPathNotSocket);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_endpoint_lock_metadata(
    metadata: &Metadata,
    expected_uid: u32,
    allow_creation_mode: bool,
) -> Result<(), PermissionError> {
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(PermissionError::EndpointLockNotRegular);
    }
    if metadata.uid() != expected_uid {
        return Err(PermissionError::EndpointLockOwnerMismatch);
    }
    if !allow_creation_mode && permission_bits(metadata.mode()) != ENDPOINT_LOCK_MODE {
        return Err(PermissionError::EndpointLockModeMismatch);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_lock_path_identity(
    runtime: &RuntimeDirectory,
    lock_name: &OsStr,
    expected: FileIdentity,
) -> Result<(), PermissionError> {
    let stat = runtime
        .child_stat(lock_name)?
        .ok_or(PermissionError::EndpointLockChanged)?;
    let kind = SFlag::from_bits_truncate(stat.st_mode);
    if kind.contains(SFlag::S_IFLNK) {
        return Err(PermissionError::EndpointLockSymlink);
    }
    if !kind.contains(SFlag::S_IFREG) || stat.st_nlink != 1 {
        return Err(PermissionError::EndpointLockNotRegular);
    }
    if FileIdentity::from_stat(&stat) != expected {
        return Err(PermissionError::EndpointLockChanged);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn classify_lock_open_error(
    runtime: &RuntimeDirectory,
    lock_name: &OsStr,
    source: nix::errno::Errno,
) -> PermissionError {
    match runtime.child_stat(lock_name) {
        Ok(Some(stat)) => {
            let kind = SFlag::from_bits_truncate(stat.st_mode);
            if kind.contains(SFlag::S_IFLNK) {
                PermissionError::EndpointLockSymlink
            } else if !kind.contains(SFlag::S_IFREG) {
                PermissionError::EndpointLockNotRegular
            } else {
                filesystem("open endpoint lock", source)
            }
        }
        Ok(None) | Err(_) => filesystem("open endpoint lock", source),
    }
}

fn endpoint_lock_name(endpoint_name: &OsStr) -> OsString {
    let mut name = OsString::from(".");
    name.push(endpoint_name);
    name.push(".lock");
    name
}

fn validate_child_name(child: &OsStr) -> Result<(), PermissionError> {
    let path = Path::new(child);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(PermissionError::Filesystem {
            operation: "validate child name",
            source: io::Error::from(io::ErrorKind::InvalidInput),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn filesystem(operation: &'static str, source: nix::errno::Errno) -> PermissionError {
    PermissionError::Filesystem {
        operation,
        source: io::Error::from(source),
    }
}

const fn permission_bits(mode: u32) -> u32 {
    mode & 0o7777
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;

    use super::*;

    #[test]
    fn pinned_directory_detects_original_path_replacement() {
        let root = unique_directory("pin-replacement");
        let runtime_path = root.join("runtime");
        let runtime = RuntimeDirectory::prepare(&runtime_path).expect("pin runtime directory");
        let moved_path = root.join("moved");
        fs::rename(&runtime_path, &moved_path).expect("rename pinned directory");
        DirBuilder::new()
            .mode(RUNTIME_DIRECTORY_MODE)
            .create(&runtime_path)
            .expect("create replacement directory");

        assert!(matches!(
            runtime.verify_original_path(),
            Err(PermissionError::RuntimeDirectoryChanged)
        ));
        fs::remove_dir_all(root).expect("remove fixture");
    }

    fn unique_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-permissions-{}-{label}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        DirBuilder::new()
            .mode(RUNTIME_DIRECTORY_MODE)
            .create(&path)
            .expect("create fixture root");
        path
    }
}
