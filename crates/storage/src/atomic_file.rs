//! Durable same-directory replacement for private configuration files.
//!
//! The transaction has two explicit phases. [`StagedWrite::prepare`] publishes
//! a recoverable predecessor while the current pathname still names the old
//! inode. [`PreparedWrite::commit`] then atomically renames the fully synced new
//! file over the current pathname and syncs the containing directory. Dropping
//! either phase removes its uncommitted temporary file.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{Mode, fchmod, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, fsync, linkat, unlinkat};
use thiserror::Error;

use crate::lock::{
    ExclusiveLock, LockError, SafeParent, absolute_file_components, validate_open_regular,
    validate_regular_or_absent,
};

const PRIVATE_FILE_MODE: Mode = Mode::from_bits_truncate(0o600);
const UNIQUE_NAME_ATTEMPTS: usize = 128;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// A staged-write or durable-commit failure.
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    /// Path or lock validation failed.
    #[error(transparent)]
    Lock(#[from] LockError),

    /// The operating system failed a filesystem operation.
    #[error("could not {operation} {path}: {source}")]
    Io {
        /// Short operation description.
        operation: &'static str,
        /// Managed target path, never document contents.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },

    /// Secure random temporary-name generation failed.
    #[error("could not generate a private temporary name: {0}")]
    Random(String),

    /// Too many randomly named entries already existed.
    #[error("could not allocate a unique temporary entry beside {0}")]
    TemporaryNameExhausted(PathBuf),

    /// A non-cooperating writer replaced one of the pathnames mid-transaction.
    #[error("storage entry changed during atomic replacement: {0}")]
    ConcurrentMutation(PathBuf),

    /// A private file exceeded the caller-provided read bound.
    #[error("private storage file exceeds its size limit: {0}")]
    TooLarge(PathBuf),
}

/// A fully written and synced file that has not yet published its predecessor.
#[derive(Debug)]
pub struct StagedWrite {
    state: WriteState,
}

impl StagedWrite {
    /// Atomically publishes the existing target as `<target>.previous` without
    /// removing or renaming the current target.
    ///
    /// The returned value is an intentional interruption seam: dropping it
    /// preserves both the current file and its recoverable predecessor while
    /// deleting the uncommitted new-file temporary entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the current or predecessor entry is unsafe, a
    /// concurrent mutation is detected, or predecessor publication cannot be
    /// made durable.
    pub fn prepare(mut self) -> Result<PreparedWrite, AtomicWriteError> {
        self.state.expected_current = publish_predecessor(&mut self.state)?;
        Ok(PreparedWrite { state: self.state })
    }

    /// Returns the eventual destination pathname.
    #[must_use]
    pub fn target_path(&self) -> &Path {
        &self.state.target_path
    }

    /// Commits the staged file without retaining the old inode under another name.
    ///
    /// This variant exists for secret material, where a recoverable plaintext
    /// predecessor would create an unwanted second copy. The existing target,
    /// when present, must have exactly one hard link.
    ///
    /// # Errors
    ///
    /// Returns an error if the current entry is unsafe, has another hard link,
    /// changes during the transaction, has an existing predecessor pathname,
    /// or cannot be durably replaced.
    pub fn commit_without_predecessor(mut self) -> Result<(), AtomicWriteError> {
        let previous_display = self
            .state
            .target_path
            .with_file_name(&self.state.previous_name);
        if validate_regular_or_absent(
            &self.state.parent.directory,
            &self.state.previous_name,
            &previous_display,
        )?
        .is_some()
        {
            return Err(LockError::UnsafeEntry {
                path: previous_display,
                reason: "private no-predecessor storage forbids a backup entry",
            }
            .into());
        }
        self.state.expected_current = pin_private_current(&self.state)?;
        PreparedWrite { state: self.state }.commit()
    }
}

/// A synced staged file whose recoverable predecessor has been published.
#[derive(Debug)]
pub struct PreparedWrite {
    state: WriteState,
}

impl PreparedWrite {
    /// Atomically installs the staged file and syncs the containing directory.
    ///
    /// # Errors
    ///
    /// Returns an error when an entry changed after preparation, the atomic
    /// rename fails, or the containing directory cannot be synced.
    pub fn commit(mut self) -> Result<(), AtomicWriteError> {
        validate_expected_current(&self.state)?;
        validate_staged_identity(&self.state)?;

        let Some(temporary_name) = self.state.temporary_name.as_ref() else {
            return Err(AtomicWriteError::ConcurrentMutation(
                self.state.target_path.clone(),
            ));
        };
        renameat(
            &self.state.parent.directory,
            temporary_name.as_os_str(),
            &self.state.parent.directory,
            self.state.parent.file_name.as_os_str(),
        )
        .map_err(|error| {
            atomic_nix_io(
                "commit atomic replacement of",
                &self.state.target_path,
                error,
            )
        })?;
        self.state.temporary_name = None;

        fsync(&self.state.parent.directory).map_err(|error| {
            atomic_nix_io("sync parent directory for", &self.state.target_path, error)
        })?;
        Ok(())
    }

    /// Returns the eventual destination pathname.
    #[must_use]
    pub fn target_path(&self) -> &Path {
        &self.state.target_path
    }
}

/// Writes `contents` with a private mode, but does not change `target` yet.
///
/// The exclusive advisory lock is held until the returned value is committed
/// or dropped. The containing directory must already exist, be owned by the
/// current user, and not be writable by group or other users.
///
/// # Errors
///
/// Returns an error for an unsafe path or entry, lock failure, temporary-file
/// creation failure, write failure, or file-sync failure.
pub fn stage_write(
    target: impl AsRef<Path>,
    contents: &[u8],
) -> Result<StagedWrite, AtomicWriteError> {
    let target = target.as_ref();
    let parent = SafeParent::open(target)?;
    let target_path = target.to_path_buf();
    let lock_name = suffixed_name(&parent.file_name, ".lock");
    let lock_path = target.with_file_name(&lock_name);
    let previous_name = suffixed_name(&parent.file_name, ".previous");
    let previous_display = target.with_file_name(&previous_name);

    let lock = ExclusiveLock::acquire_at(&parent.directory, &lock_name, &lock_path)?;
    validate_regular_or_absent(&parent.directory, &parent.file_name, target)?;
    validate_regular_or_absent(&parent.directory, &previous_name, &previous_display)?;

    let (temporary_name, mut temporary_file) = create_new_temporary(&parent, target)?;
    let write_result = (|| {
        fchmod(&temporary_file, PRIVATE_FILE_MODE).map_err(|error| {
            atomic_nix_io("set private permissions on staged file for", target, error)
        })?;
        temporary_file
            .write_all(contents)
            .map_err(|source| AtomicWriteError::Io {
                operation: "write staged file for",
                path: target.to_path_buf(),
                source,
            })?;
        temporary_file
            .sync_all()
            .map_err(|source| AtomicWriteError::Io {
                operation: "sync staged file for",
                path: target.to_path_buf(),
                source,
            })?;
        Ok(())
    })();
    if let Err(error) = write_result {
        remove_entry_if_present(&parent.directory, &temporary_name);
        return Err(error);
    }

    let state = WriteState {
        parent,
        _lock: lock,
        target_path,
        previous_name,
        temporary_name: Some(temporary_name),
        temporary_file,
        expected_current: None,
    };
    validate_staged_identity(&state)?;
    Ok(StagedWrite { state })
}

/// Stages, prepares, and durably commits `contents` to `target`.
///
/// # Errors
///
/// Returns any validation, locking, staging, predecessor-publication, rename,
/// or durability error encountered by the transaction.
pub fn atomic_write(target: impl AsRef<Path>, contents: &[u8]) -> Result<(), AtomicWriteError> {
    stage_write(target, contents)?.prepare()?.commit()
}

/// Durably replaces a private file without preserving its predecessor.
///
/// Use this only for data, such as credentials, whose previous plaintext must
/// not survive under a backup pathname. The target and lock remain mode
/// `0600`, and every path component is opened without following symlinks.
///
/// # Errors
///
/// Returns any path, locking, staging, identity, permission, replacement, or
/// durability error encountered by the transaction.
pub fn atomic_write_without_predecessor(
    target: impl AsRef<Path>,
    contents: &[u8],
) -> Result<(), AtomicWriteError> {
    stage_write(target, contents)?.commit_without_predecessor()
}

/// Reads a bounded private regular file while holding its writer lock.
///
/// Missing files return `Ok(None)`. Existing files must be owned by the current
/// user, have exactly one hard link, and have mode `0600`. The path is resolved
/// through pinned directory descriptors without following symlinks.
///
/// # Errors
///
/// Returns an error for unsafe paths or entries, permission mismatches,
/// concurrent replacement, I/O failure, or contents larger than `max_bytes`.
pub fn read_private_file(
    target: impl AsRef<Path>,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, AtomicWriteError> {
    let target = target.as_ref();
    let parent = SafeParent::open(target)?;
    let lock_name = suffixed_name(&parent.file_name, ".lock");
    let lock_path = target.with_file_name(&lock_name);
    let _lock = ExclusiveLock::acquire_at(&parent.directory, &lock_name, &lock_path)?;
    let Some(named) = validate_regular_or_absent(&parent.directory, &parent.file_name, target)?
    else {
        return Ok(None);
    };

    let fd = openat(
        &parent.directory,
        parent.file_name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| atomic_nix_io("open private file", target, error))?;
    let mut file = File::from(fd);
    validate_open_private(&file, target)?;
    let opened =
        fstat(&file).map_err(|error| atomic_nix_io("inspect private file", target, error))?;
    let identity = FileIdentity::from_stat(&opened);
    if identity != FileIdentity::from_stat(&named) {
        return Err(AtomicWriteError::ConcurrentMutation(target.to_path_buf()));
    }

    let read_bound = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut contents = Vec::new();
    Read::by_ref(&mut file)
        .take(read_bound)
        .read_to_end(&mut contents)
        .map_err(|source| AtomicWriteError::Io {
            operation: "read private file",
            path: target.to_path_buf(),
            source,
        })?;
    if contents.len() > max_bytes {
        return Err(AtomicWriteError::TooLarge(target.to_path_buf()));
    }
    let current = fstatat(
        &parent.directory,
        parent.file_name.as_os_str(),
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|error| atomic_nix_io("reinspect private file", target, error))?;
    if FileIdentity::from_stat(&current) != identity {
        return Err(AtomicWriteError::ConcurrentMutation(target.to_path_buf()));
    }
    Ok(Some(contents))
}

/// Returns the recoverable predecessor pathname for a syntactically safe
/// absolute target path.
///
/// # Errors
///
/// Returns an error when `target` is relative, traversing, non-canonical, or
/// does not name a file.
pub fn previous_path(target: impl AsRef<Path>) -> Result<PathBuf, AtomicWriteError> {
    let target = target.as_ref();
    let components = absolute_file_components(target)?;
    let Some(name) = components.last() else {
        return Err(LockError::UnsafePath {
            path: target.to_path_buf(),
            reason: "path must name a file",
        }
        .into());
    };
    Ok(target.with_file_name(suffixed_name(name, ".previous")))
}

#[derive(Debug)]
struct WriteState {
    parent: SafeParent,
    _lock: ExclusiveLock,
    target_path: PathBuf,
    previous_name: OsString,
    temporary_name: Option<OsString>,
    temporary_file: File,
    expected_current: Option<FileIdentity>,
}

impl Drop for WriteState {
    fn drop(&mut self) {
        if let Some(name) = self.temporary_name.as_deref() {
            remove_entry_if_present(&self.parent.directory, name);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_stat(stat: &nix::libc::stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

fn pin_private_current(state: &WriteState) -> Result<Option<FileIdentity>, AtomicWriteError> {
    let Some(named) = validate_regular_or_absent(
        &state.parent.directory,
        &state.parent.file_name,
        &state.target_path,
    )?
    else {
        return Ok(None);
    };
    let fd = openat(
        &state.parent.directory,
        state.parent.file_name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| atomic_nix_io("open current private file", &state.target_path, error))?;
    let file = File::from(fd);
    validate_open_private(&file, &state.target_path)?;
    let opened = fstat(&file).map_err(|error| {
        atomic_nix_io("inspect current private file", &state.target_path, error)
    })?;
    let identity = FileIdentity::from_stat(&opened);
    if identity != FileIdentity::from_stat(&named) {
        return Err(AtomicWriteError::ConcurrentMutation(
            state.target_path.clone(),
        ));
    }
    fsync(&file)
        .map_err(|error| atomic_nix_io("sync current private file", &state.target_path, error))?;
    Ok(Some(identity))
}

fn validate_open_private(file: &File, target: &Path) -> Result<(), AtomicWriteError> {
    validate_open_regular(file, target)?;
    let stat = fstat(file)
        .map_err(|error| atomic_nix_io("inspect private file metadata for", target, error))?;
    if stat.st_nlink != 1 {
        return Err(LockError::UnsafeEntry {
            path: target.to_path_buf(),
            reason: "private entry must have exactly one hard link",
        }
        .into());
    }
    if stat.st_mode & 0o777 != PRIVATE_FILE_MODE.bits() as nix::libc::mode_t {
        return Err(LockError::UnsafeEntry {
            path: target.to_path_buf(),
            reason: "private entry must have mode 0600",
        }
        .into());
    }
    Ok(())
}

fn publish_predecessor(state: &mut WriteState) -> Result<Option<FileIdentity>, AtomicWriteError> {
    let previous_display = state.target_path.with_file_name(&state.previous_name);
    let previous = validate_regular_or_absent(
        &state.parent.directory,
        &state.previous_name,
        &previous_display,
    )?;
    if let Some(previous_stat) = previous.as_ref() {
        make_existing_entry_private(
            &state.parent.directory,
            &state.previous_name,
            &previous_display,
            FileIdentity::from_stat(previous_stat),
        )?;
    }
    let Some(named_current) = validate_regular_or_absent(
        &state.parent.directory,
        &state.parent.file_name,
        &state.target_path,
    )?
    else {
        return Ok(None);
    };

    let current_fd = openat(
        &state.parent.directory,
        state.parent.file_name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| atomic_nix_io("open current file for", &state.target_path, error))?;
    let current_file = File::from(current_fd);
    validate_open_regular(&current_file, &state.target_path)?;
    let pinned = fstat(&current_file)
        .map_err(|error| atomic_nix_io("inspect current file for", &state.target_path, error))?;
    let identity = FileIdentity::from_stat(&pinned);
    if identity != FileIdentity::from_stat(&named_current) {
        return Err(AtomicWriteError::ConcurrentMutation(
            state.target_path.clone(),
        ));
    }

    fchmod(&current_file, PRIVATE_FILE_MODE).map_err(|error| {
        atomic_nix_io(
            "set private permissions on current file for",
            &state.target_path,
            error,
        )
    })?;
    fsync(&current_file)
        .map_err(|error| atomic_nix_io("sync current file for", &state.target_path, error))?;

    if previous.as_ref().map(FileIdentity::from_stat) == Some(identity) {
        fsync(&state.parent.directory).map_err(|error| {
            atomic_nix_io(
                "sync existing predecessor directory for",
                &state.target_path,
                error,
            )
        })?;
        return Ok(Some(identity));
    }

    replace_predecessor_link(state, identity)?;
    Ok(Some(identity))
}

fn replace_predecessor_link(
    state: &WriteState,
    identity: FileIdentity,
) -> Result<(), AtomicWriteError> {
    let backup_name = create_predecessor_link(state, identity)?;
    let publish_result = renameat(
        &state.parent.directory,
        backup_name.as_os_str(),
        &state.parent.directory,
        state.previous_name.as_os_str(),
    )
    .map_err(|error| {
        atomic_nix_io(
            "publish recoverable predecessor for",
            &state.target_path,
            error,
        )
    });
    if let Err(error) = publish_result {
        remove_entry_if_present(&state.parent.directory, &backup_name);
        return Err(error);
    }

    // POSIX permits rename to be a no-op when both names are hard links to
    // the same inode. Removing the random source name is therefore required
    // even after a successful rename, and is harmless after a normal rename.
    remove_entry(&state.parent.directory, &backup_name, &state.target_path)?;
    let published = fstatat(
        &state.parent.directory,
        state.previous_name.as_os_str(),
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|error| {
        atomic_nix_io(
            "verify recoverable predecessor for",
            &state.target_path,
            error,
        )
    })?;
    if FileIdentity::from_stat(&published) != identity {
        return Err(AtomicWriteError::ConcurrentMutation(
            state.target_path.clone(),
        ));
    }

    fsync(&state.parent.directory).map_err(|error| {
        atomic_nix_io(
            "sync recoverable predecessor for",
            &state.target_path,
            error,
        )
    })?;
    Ok(())
}

fn make_existing_entry_private(
    directory: &File,
    name: &OsStr,
    display_path: &Path,
    expected: FileIdentity,
) -> Result<(), AtomicWriteError> {
    let fd = openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| atomic_nix_io("open existing predecessor for", display_path, error))?;
    let file = File::from(fd);
    validate_open_regular(&file, display_path)?;
    let opened = fstat(&file)
        .map_err(|error| atomic_nix_io("inspect existing predecessor for", display_path, error))?;
    if FileIdentity::from_stat(&opened) != expected {
        return Err(AtomicWriteError::ConcurrentMutation(
            display_path.to_path_buf(),
        ));
    }
    fchmod(&file, PRIVATE_FILE_MODE).map_err(|error| {
        atomic_nix_io(
            "set private permissions on existing predecessor for",
            display_path,
            error,
        )
    })?;
    fsync(&file)
        .map_err(|error| atomic_nix_io("sync existing predecessor for", display_path, error))?;
    let named = fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|error| {
        atomic_nix_io("reinspect existing predecessor for", display_path, error)
    })?;
    if FileIdentity::from_stat(&named) != expected {
        return Err(AtomicWriteError::ConcurrentMutation(
            display_path.to_path_buf(),
        ));
    }
    Ok(())
}

fn create_predecessor_link(
    state: &WriteState,
    expected: FileIdentity,
) -> Result<OsString, AtomicWriteError> {
    for _ in 0..UNIQUE_NAME_ATTEMPTS {
        let name = random_temporary_name(&state.parent.file_name, "previous")?;
        match linkat(
            &state.parent.directory,
            state.parent.file_name.as_os_str(),
            &state.parent.directory,
            name.as_os_str(),
            AtFlags::empty(),
        ) {
            Ok(()) => {
                let linked = fstatat(
                    &state.parent.directory,
                    name.as_os_str(),
                    AtFlags::AT_SYMLINK_NOFOLLOW,
                )
                .map_err(|error| {
                    atomic_nix_io("inspect predecessor link for", &state.target_path, error)
                })?;
                let current = fstatat(
                    &state.parent.directory,
                    state.parent.file_name.as_os_str(),
                    AtFlags::AT_SYMLINK_NOFOLLOW,
                )
                .map_err(|error| {
                    atomic_nix_io("reinspect current file for", &state.target_path, error)
                })?;
                if FileIdentity::from_stat(&linked) != expected
                    || FileIdentity::from_stat(&current) != expected
                {
                    remove_entry_if_present(&state.parent.directory, &name);
                    return Err(AtomicWriteError::ConcurrentMutation(
                        state.target_path.clone(),
                    ));
                }
                return Ok(name);
            }
            Err(Errno::EEXIST) => {}
            Err(error) => {
                return Err(atomic_nix_io(
                    "create recoverable predecessor for",
                    &state.target_path,
                    error,
                ));
            }
        }
    }
    Err(AtomicWriteError::TemporaryNameExhausted(
        state.target_path.clone(),
    ))
}

fn validate_expected_current(state: &WriteState) -> Result<(), AtomicWriteError> {
    let current = validate_regular_or_absent(
        &state.parent.directory,
        &state.parent.file_name,
        &state.target_path,
    )?;
    if current.as_ref().map(FileIdentity::from_stat) != state.expected_current {
        return Err(AtomicWriteError::ConcurrentMutation(
            state.target_path.clone(),
        ));
    }
    Ok(())
}

fn validate_staged_identity(state: &WriteState) -> Result<(), AtomicWriteError> {
    let Some(name) = state.temporary_name.as_ref() else {
        return Err(AtomicWriteError::ConcurrentMutation(
            state.target_path.clone(),
        ));
    };
    let named = fstatat(
        &state.parent.directory,
        name.as_os_str(),
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|error| atomic_nix_io("inspect staged pathname for", &state.target_path, error))?;
    let opened = fstat(&state.temporary_file)
        .map_err(|error| atomic_nix_io("inspect staged file for", &state.target_path, error))?;
    if FileIdentity::from_stat(&named) != FileIdentity::from_stat(&opened) {
        return Err(AtomicWriteError::ConcurrentMutation(
            state.target_path.clone(),
        ));
    }
    validate_open_regular(&state.temporary_file, &state.target_path)?;
    Ok(())
}

fn create_new_temporary(
    parent: &SafeParent,
    target: &Path,
) -> Result<(OsString, File), AtomicWriteError> {
    for _ in 0..UNIQUE_NAME_ATTEMPTS {
        let name = random_temporary_name(&parent.file_name, "new")?;
        match openat(
            &parent.directory,
            name.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            PRIVATE_FILE_MODE,
        ) {
            Ok(fd) => return Ok((name, File::from(fd))),
            Err(Errno::EEXIST) => {}
            Err(error) => {
                return Err(atomic_nix_io("create staged file for", target, error));
            }
        }
    }
    Err(AtomicWriteError::TemporaryNameExhausted(
        target.to_path_buf(),
    ))
}

fn random_temporary_name(target_name: &OsStr, kind: &str) -> Result<OsString, AtomicWriteError> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| AtomicWriteError::Random(error.to_string()))?;
    let mut suffix = String::with_capacity(2 + kind.len() + 1 + random.len() * 2);
    suffix.push_str(".oab-");
    suffix.push_str(kind);
    suffix.push('-');
    for byte in random {
        suffix.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        suffix.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    let mut name = OsString::from(".");
    name.push(target_name);
    name.push(suffix);
    Ok(name)
}

fn suffixed_name(name: &OsStr, suffix: &str) -> OsString {
    let mut suffixed = name.to_os_string();
    suffixed.push(suffix);
    suffixed
}

fn remove_entry_if_present(directory: &File, name: &OsStr) {
    // Drop cannot report an error. Names are cryptographically random, opened
    // with O_EXCL, and scoped to this still-open directory descriptor.
    let _ = unlinkat(directory, name, UnlinkatFlags::NoRemoveDir);
}

fn remove_entry(directory: &File, name: &OsStr, target: &Path) -> Result<(), AtomicWriteError> {
    match unlinkat(directory, name, UnlinkatFlags::NoRemoveDir) {
        Ok(()) | Err(Errno::ENOENT) => Ok(()),
        Err(error) => Err(atomic_nix_io(
            "remove predecessor temporary entry for",
            target,
            error,
        )),
    }
}

fn atomic_nix_io(operation: &'static str, path: &Path, error: Errno) -> AtomicWriteError {
    AtomicWriteError::Io {
        operation,
        path: path.to_path_buf(),
        source: io::Error::from_raw_os_error(error as i32),
    }
}
