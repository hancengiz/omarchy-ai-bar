//! Bounded, race-resistant reads of provider-owned files on Linux.
//!
//! Provider credentials and local telemetry remain owned by their respective
//! CLIs. This module opens an explicitly selected root once, walks beneath it
//! with directory descriptors and `openat(2)`, and never follows symlinks. All
//! returned bytes are zeroized on drop and all diagnostic views hide paths and
//! contents.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use nix::dir::Dir;
use nix::fcntl::{AtFlags, OFlag, PosixFadviseAdvice, open, openat, posix_fadvise};
use nix::sys::stat::{Mode, SFlag, fstat, fstatat};
use nix::unistd::geteuid;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Absolute ceiling for one in-memory provider file.
pub const MAX_PROVIDER_FILE_BYTES: usize = 512 * 1024 * 1024;
/// Absolute ceiling for aggregate file sizes observed by one scan.
pub const MAX_PROVIDER_SCAN_BYTES: usize = 1024 * 1024 * 1024;
/// Absolute ceiling for entries observed by one scan.
pub const MAX_PROVIDER_SCAN_ENTRIES: usize = 25_000;
/// Absolute ceiling for files returned by one scan.
pub const MAX_PROVIDER_SCAN_FILES: usize = 25_000;
/// Absolute ceiling for recursive directory levels below a scan root.
pub const MAX_PROVIDER_SCAN_DEPTH: usize = 16;

const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_ROOT_COMPONENTS: usize = 64;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const MAX_PROVIDER_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Caller-selected scan ceilings, themselves constrained by hard limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderFileScanLimits {
    depth: usize,
    entries: usize,
    files: usize,
    file_bytes: usize,
    total_bytes: usize,
}

impl ProviderFileScanLimits {
    /// Builds a complete-scan budget beneath an already selected provider root.
    ///
    /// A depth of zero accepts files directly in the selected directory but
    /// rejects nested directories. All other limits must be nonzero and no
    /// limit may exceed its process-wide hard ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFileError::InvalidLimits`] for an empty or excessive
    /// budget.
    pub const fn new(
        maximum_depth: usize,
        maximum_entries: usize,
        maximum_files: usize,
        maximum_file_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<Self, ProviderFileError> {
        if maximum_depth > MAX_PROVIDER_SCAN_DEPTH
            || maximum_entries == 0
            || maximum_entries > MAX_PROVIDER_SCAN_ENTRIES
            || maximum_files == 0
            || maximum_files > MAX_PROVIDER_SCAN_FILES
            || maximum_file_bytes == 0
            || maximum_file_bytes > MAX_PROVIDER_FILE_BYTES
            || maximum_total_bytes == 0
            || maximum_total_bytes > MAX_PROVIDER_SCAN_BYTES
            || maximum_file_bytes > maximum_total_bytes
        {
            return Err(ProviderFileError::InvalidLimits);
        }
        Ok(Self {
            depth: maximum_depth,
            entries: maximum_entries,
            files: maximum_files,
            file_bytes: maximum_file_bytes,
            total_bytes: maximum_total_bytes,
        })
    }
}

impl Default for ProviderFileScanLimits {
    fn default() -> Self {
        Self {
            depth: 4,
            entries: 1024,
            files: 512,
            file_bytes: 4 * 1024 * 1024,
            total_bytes: 32 * 1024 * 1024,
        }
    }
}

/// An opened, identity-pinned provider-owned directory.
pub struct ProviderFileRoot {
    directory: File,
    identity: FileKey,
    owner: u32,
}

impl ProviderFileRoot {
    /// Opens an absolute provider root without following any path component.
    ///
    /// The selected root (but not system-owned ancestors such as `/` and
    /// `/home`) must be a directory owned by the current effective user.
    ///
    /// # Errors
    ///
    /// Rejects relative, root-wide, overlong, missing, symlinked, non-directory,
    /// or differently owned roots.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ProviderFileError> {
        let root = root.as_ref();
        let owner = geteuid().as_raw();
        let directory = open_absolute_directory(root, owner)?;
        let stat = fstat(&directory).map_err(|_| ProviderFileError::UnsafeLayout)?;
        validate_directory(&stat, owner)?;
        Ok(Self {
            directory,
            identity: FileKey::from_stat(&stat),
            owner,
        })
    }

    /// Reads one exact relative file into zeroizing memory.
    ///
    /// # Errors
    ///
    /// Rejects invalid paths, missing or non-regular files, symlinks, files not
    /// owned by the current effective user, files above `maximum_bytes`, races,
    /// I/O failures, and cancellation.
    pub fn read(
        &self,
        relative_file: impl AsRef<Path>,
        maximum_bytes: usize,
        cancellation: &CancellationToken,
    ) -> Result<ProviderFileContents, ProviderFileError> {
        check_cancelled(cancellation)?;
        validate_read_limit(maximum_bytes)?;
        let relative_file = relative_file.as_ref();
        validate_relative_path(relative_file, false)?;
        self.ensure_root_identity()?;
        read_relative_file(
            &self.directory,
            relative_file,
            maximum_bytes,
            self.owner,
            None,
            cancellation,
        )
    }

    /// Completely scans a relative directory using deterministic bytewise path
    /// order and returns identity-pinned regular-file candidates.
    ///
    /// Empty `relative_directory` selects the root itself. A scan is fail-closed:
    /// symlinks, special files, ownership mismatches, excessive nesting, budget
    /// exhaustion, or concurrent directory mutation fail the whole operation.
    ///
    /// # Errors
    ///
    /// Returns a stable, path-free [`ProviderFileError`] for an unsafe or
    /// incomplete scan and [`ProviderFileError::Cancelled`] on cancellation.
    pub fn scan(
        &self,
        relative_directory: impl AsRef<Path>,
        limits: ProviderFileScanLimits,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ProviderFileCandidate>, ProviderFileError> {
        check_cancelled(cancellation)?;
        self.ensure_root_identity()?;
        let relative_directory = relative_directory.as_ref();
        validate_relative_path(relative_directory, true)?;
        let chain = open_directory_chain(
            &self.directory,
            relative_directory,
            self.owner,
            cancellation,
        )?;
        let directory = chain.last();
        let mut budget = ScanBudget::new(limits);
        let mut candidates = Vec::new();
        scan_directory(
            directory,
            relative_directory,
            0,
            self.identity,
            self.owner,
            &mut budget,
            &mut candidates,
            cancellation,
        )?;
        chain.verify(self.owner)?;
        candidates.sort_by(|left, right| {
            left.relative_path
                .as_os_str()
                .as_bytes()
                .cmp(right.relative_path.as_os_str().as_bytes())
        });
        check_cancelled(cancellation)?;
        Ok(candidates)
    }

    /// Reads a candidate returned by [`Self::scan`] only if its root and file
    /// identities are unchanged.
    ///
    /// # Errors
    ///
    /// Rejects candidates from a different root, changed or removed files,
    /// unsafe path layouts, I/O failures, and cancellation.
    pub fn read_candidate(
        &self,
        candidate: &ProviderFileCandidate,
        cancellation: &CancellationToken,
    ) -> Result<ProviderFileContents, ProviderFileError> {
        check_cancelled(cancellation)?;
        self.ensure_root_identity()?;
        if candidate.root != self.identity {
            return Err(ProviderFileError::WrongRoot);
        }
        read_relative_file(
            &self.directory,
            &candidate.relative_path,
            candidate.size,
            self.owner,
            Some(candidate.snapshot),
            cancellation,
        )
    }

    /// Streams bounded lines from an identity-pinned scan candidate.
    ///
    /// Lines larger than `maximum_line_bytes` are skipped without allocating
    /// the whole line. This keeps large append-only provider logs from
    /// temporarily occupying their full on-disk size in process memory while
    /// preserving the same ownership, symlink, identity, and mutation checks
    /// as [`Self::read_candidate`]. Newline bytes are not passed to `visitor`.
    ///
    /// # Errors
    ///
    /// Rejects invalid line limits, changed or unsafe candidates, read
    /// failures, and cancellation.
    pub fn visit_candidate_lines(
        &self,
        candidate: &ProviderFileCandidate,
        maximum_line_bytes: usize,
        cancellation: &CancellationToken,
        visitor: impl FnMut(&[u8]),
    ) -> Result<(), ProviderFileError> {
        check_cancelled(cancellation)?;
        if maximum_line_bytes == 0 || maximum_line_bytes > MAX_PROVIDER_LINE_BYTES {
            return Err(ProviderFileError::InvalidLimits);
        }
        self.ensure_root_identity()?;
        if candidate.root != self.identity {
            return Err(ProviderFileError::WrongRoot);
        }
        inspect_relative_file(
            &self.directory,
            &candidate.relative_path,
            candidate.size,
            self.owner,
            Some(candidate.snapshot),
            cancellation,
            |file, expected_size, cancellation| {
                visit_bounded_lines(
                    file,
                    expected_size,
                    maximum_line_bytes,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn ensure_root_identity(&self) -> Result<(), ProviderFileError> {
        if geteuid().as_raw() != self.owner {
            return Err(ProviderFileError::WrongOwner);
        }
        let stat = fstat(&self.directory).map_err(|_| ProviderFileError::UnsafeLayout)?;
        validate_directory(&stat, self.owner)?;
        if FileKey::from_stat(&stat) != self.identity {
            return Err(ProviderFileError::Changed);
        }
        Ok(())
    }
}

impl Debug for ProviderFileRoot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderFileRoot(<redacted>)")
    }
}

/// One regular file discovered during a complete provider-root scan.
///
/// The relative path is available for fixed provider-specific selection, while
/// its diagnostic representation stays redacted because names may identify an
/// account or project.
pub struct ProviderFileCandidate {
    relative_path: PathBuf,
    size: usize,
    snapshot: FileSnapshot,
    root: FileKey,
}

impl ProviderFileCandidate {
    /// Returns the path relative to the opened provider root.
    #[must_use]
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    /// Returns the identity-pinned byte length observed by the scan.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.size
    }

    /// Reports whether the observed file was empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns the identity-pinned modification time observed by the scan.
    #[must_use]
    pub const fn modified_unix_time(&self) -> (i64, i64) {
        (
            self.snapshot.modified_seconds,
            self.snapshot.modified_nanoseconds,
        )
    }
}

impl Debug for ProviderFileCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderFileCandidate(<redacted>)")
    }
}

/// Bounded provider-file bytes that are erased when dropped.
pub struct ProviderFileContents {
    bytes: Zeroizing<Vec<u8>>,
}

impl ProviderFileContents {
    /// Borrows the acquired bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the byte length without copying the secret allocation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether the acquired file was empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Transfers the already-zeroizing allocation to the caller.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl Debug for ProviderFileContents {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderFileContents(<redacted>)")
    }
}

/// Stable, path-free provider-file acquisition failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderFileError {
    /// The configured root was not a narrow absolute directory path.
    #[error("provider file root is invalid")]
    InvalidRoot,
    /// A relative path was absolute, empty where forbidden, or contained traversal syntax.
    #[error("provider file relative path is invalid")]
    InvalidRelativePath,
    /// A caller-provided byte or scan ceiling was invalid.
    #[error("provider file limits are invalid")]
    InvalidLimits,
    /// The selected path did not exist.
    #[error("provider file is missing")]
    Missing,
    /// A path component was a symlink, special file, or unexpected type.
    #[error("provider file layout is unsafe")]
    UnsafeLayout,
    /// The selected provider directory or file belongs to another user.
    #[error("provider file owner is unsafe")]
    WrongOwner,
    /// A file or aggregate scan exceeded its byte ceiling.
    #[error("provider file exceeds its size bound")]
    TooLarge,
    /// A scan exceeded its entry or file-count ceiling.
    #[error("provider file scan exceeds its entry bound")]
    TooManyEntries,
    /// A scan encountered nesting beyond its complete-scan depth.
    #[error("provider file scan exceeds its depth bound")]
    TooDeep,
    /// A scanned candidate was passed to a different opened root.
    #[error("provider file candidate belongs to a different root")]
    WrongRoot,
    /// A path or file changed identity while it was being acquired.
    #[error("provider file changed during acquisition")]
    Changed,
    /// The bounded file read failed.
    #[error("provider file could not be read")]
    Read,
    /// The caller cancelled acquisition.
    #[error("provider file acquisition was cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileKey {
    device: u64,
    inode: u64,
}

impl FileKey {
    fn from_stat(stat: &nix::libc::stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    key: FileKey,
    size: i64,
    mode: nix::libc::mode_t,
    owner: nix::libc::uid_t,
    group: nix::libc::gid_t,
    links: nix::libc::nlink_t,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileSnapshot {
    fn from_stat(stat: &nix::libc::stat) -> Self {
        Self {
            key: FileKey::from_stat(stat),
            size: stat.st_size,
            mode: stat.st_mode,
            owner: stat.st_uid,
            group: stat.st_gid,
            links: stat.st_nlink,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

struct DirectoryChain {
    directories: Vec<File>,
    names: Vec<OsString>,
    identities: Vec<FileKey>,
}

impl DirectoryChain {
    fn last(&self) -> &File {
        self.directories
            .last()
            .expect("directory chain always contains its root")
    }

    fn verify(&self, owner: u32) -> Result<(), ProviderFileError> {
        for (index, name) in self.names.iter().enumerate() {
            let stat = fstatat(
                &self.directories[index],
                name.as_os_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| ProviderFileError::Changed)?;
            validate_directory(&stat, owner)?;
            if FileKey::from_stat(&stat) != self.identities[index + 1] {
                return Err(ProviderFileError::Changed);
            }
        }
        Ok(())
    }
}

struct ScanBudget {
    limits: ProviderFileScanLimits,
    entries: usize,
    files: usize,
    bytes: usize,
}

impl ScanBudget {
    const fn new(limits: ProviderFileScanLimits) -> Self {
        Self {
            limits,
            entries: 0,
            files: 0,
            bytes: 0,
        }
    }

    fn observe_entry(&mut self) -> Result<(), ProviderFileError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(ProviderFileError::TooManyEntries)?;
        if self.entries > self.limits.entries {
            return Err(ProviderFileError::TooManyEntries);
        }
        Ok(())
    }

    fn observe_file(&mut self, size: usize) -> Result<(), ProviderFileError> {
        if size > self.limits.file_bytes {
            return Err(ProviderFileError::TooLarge);
        }
        self.files = self
            .files
            .checked_add(1)
            .ok_or(ProviderFileError::TooManyEntries)?;
        if self.files > self.limits.files {
            return Err(ProviderFileError::TooManyEntries);
        }
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or(ProviderFileError::TooLarge)?;
        if self.bytes > self.limits.total_bytes {
            return Err(ProviderFileError::TooLarge);
        }
        Ok(())
    }
}

fn open_absolute_directory(path: &Path, owner: u32) -> Result<File, ProviderFileError> {
    let raw = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path == Path::new("/")
        || raw.len() > MAX_PATH_BYTES
        || raw.strip_prefix(b"/").is_none_or(|tail| {
            tail.split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || matches!(component, b"." | b".."))
        })
    {
        return Err(ProviderFileError::InvalidRoot);
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(ProviderFileError::InvalidRoot);
    }
    let names = components
        .map(|component| match component {
            Component::Normal(name)
                if !name.is_empty() && name.as_bytes().len() <= MAX_COMPONENT_BYTES =>
            {
                Ok(name.to_os_string())
            }
            _ => Err(ProviderFileError::InvalidRoot),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names.is_empty() || names.len() > MAX_ROOT_COMPONENTS {
        return Err(ProviderFileError::InvalidRoot);
    }

    let descriptor = open(
        Path::new("/"),
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ProviderFileError::InvalidRoot)?;
    let mut directory = File::from(descriptor);
    for name in names {
        let descriptor = openat(
            &directory,
            name.as_os_str(),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(map_root_open_error)?;
        directory = File::from(descriptor);
    }

    let stat = fstat(&directory).map_err(|_| ProviderFileError::UnsafeLayout)?;
    validate_directory(&stat, owner)?;

    let descriptor = openat(
        &directory,
        Path::new("."),
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_CLOEXEC
            | OFlag::O_NOATIME
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ProviderFileError::UnsafeLayout)?;
    Ok(File::from(descriptor))
}

fn map_root_open_error(error: nix::errno::Errno) -> ProviderFileError {
    if error == nix::errno::Errno::ENOENT {
        ProviderFileError::InvalidRoot
    } else {
        ProviderFileError::UnsafeLayout
    }
}

fn validate_read_limit(maximum_bytes: usize) -> Result<(), ProviderFileError> {
    if maximum_bytes == 0 || maximum_bytes > MAX_PROVIDER_FILE_BYTES {
        return Err(ProviderFileError::InvalidLimits);
    }
    Ok(())
}

fn validate_relative_path(path: &Path, allow_empty: bool) -> Result<(), ProviderFileError> {
    let raw = path.as_os_str().as_bytes();
    if path.is_absolute()
        || (!allow_empty && raw.is_empty())
        || raw.len() > MAX_PATH_BYTES
        || (!raw.is_empty()
            && raw
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || matches!(component, b"." | b"..")))
    {
        return Err(ProviderFileError::InvalidRelativePath);
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(ProviderFileError::InvalidRelativePath);
        };
        if name.is_empty() || name.as_bytes().len() > MAX_COMPONENT_BYTES {
            return Err(ProviderFileError::InvalidRelativePath);
        }
    }
    Ok(())
}

fn open_directory_chain(
    root: &File,
    relative: &Path,
    owner: u32,
    cancellation: &CancellationToken,
) -> Result<DirectoryChain, ProviderFileError> {
    let root = root
        .try_clone()
        .map_err(|_| ProviderFileError::UnsafeLayout)?;
    let root_stat = fstat(&root).map_err(|_| ProviderFileError::UnsafeLayout)?;
    validate_directory(&root_stat, owner)?;
    let mut chain = DirectoryChain {
        directories: vec![root],
        names: Vec::new(),
        identities: vec![FileKey::from_stat(&root_stat)],
    };
    for component in relative.components() {
        check_cancelled(cancellation)?;
        let Component::Normal(name) = component else {
            return Err(ProviderFileError::InvalidRelativePath);
        };
        let parent = chain.last();
        let expected =
            fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(map_relative_stat_error)?;
        validate_directory(&expected, owner)?;
        let descriptor = openat(
            parent,
            name,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(map_relative_open_error)?;
        let directory = File::from(descriptor);
        let opened = fstat(&directory).map_err(|_| ProviderFileError::Changed)?;
        if FileSnapshot::from_stat(&opened) != FileSnapshot::from_stat(&expected) {
            return Err(ProviderFileError::Changed);
        }
        chain.names.push(name.to_os_string());
        chain.identities.push(FileKey::from_stat(&opened));
        chain.directories.push(directory);
    }
    Ok(chain)
}

fn read_relative_file(
    root: &File,
    relative: &Path,
    maximum_bytes: usize,
    owner: u32,
    expected: Option<FileSnapshot>,
    cancellation: &CancellationToken,
) -> Result<ProviderFileContents, ProviderFileError> {
    inspect_relative_file(
        root,
        relative,
        maximum_bytes,
        owner,
        expected,
        cancellation,
        |file, expected_size, cancellation| {
            read_bounded(file, expected_size, maximum_bytes, cancellation)
                .map(|bytes| ProviderFileContents { bytes })
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "security-sensitive file validation inputs remain explicit"
)]
fn inspect_relative_file<T>(
    root: &File,
    relative: &Path,
    maximum_bytes: usize,
    owner: u32,
    expected: Option<FileSnapshot>,
    cancellation: &CancellationToken,
    operation: impl FnOnce(&mut File, usize, &CancellationToken) -> Result<T, ProviderFileError>,
) -> Result<T, ProviderFileError> {
    check_cancelled(cancellation)?;
    let parent_path = relative.parent().unwrap_or_else(|| Path::new(""));
    let name = relative
        .file_name()
        .ok_or(ProviderFileError::InvalidRelativePath)?;
    let chain = open_directory_chain(root, parent_path, owner, cancellation)?;
    let parent = chain.last();
    let path_stat =
        fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(map_relative_stat_error)?;
    let snapshot = FileSnapshot::from_stat(&path_stat);
    if expected.is_some_and(|candidate| candidate != snapshot) {
        return Err(ProviderFileError::Changed);
    }
    validate_regular_file(&path_stat, owner, maximum_bytes)?;

    let descriptor = openat(
        parent,
        name,
        OFlag::O_RDONLY
            | OFlag::O_CLOEXEC
            | OFlag::O_NOATIME
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(map_relative_open_error)?;
    let mut file = File::from(descriptor);
    let opened = fstat(&file).map_err(|_| ProviderFileError::Changed)?;
    if FileSnapshot::from_stat(&opened) != snapshot {
        return Err(ProviderFileError::Changed);
    }
    let size = usize::try_from(opened.st_size).map_err(|_| ProviderFileError::TooLarge)?;
    let output = operation(&mut file, size, cancellation)?;
    let closed_over = fstat(&file).map_err(|_| ProviderFileError::Changed)?;
    if FileSnapshot::from_stat(&closed_over) != snapshot {
        return Err(ProviderFileError::Changed);
    }
    let final_path = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| ProviderFileError::Changed)?;
    if FileSnapshot::from_stat(&final_path) != snapshot {
        return Err(ProviderFileError::Changed);
    }
    chain.verify(owner)?;
    check_cancelled(cancellation)?;
    Ok(output)
}

fn read_bounded(
    file: &mut File,
    expected_size: usize,
    maximum_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<Zeroizing<Vec<u8>>, ProviderFileError> {
    if expected_size > maximum_bytes {
        return Err(ProviderFileError::TooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected_size));
    let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES]);
    loop {
        check_cancelled(cancellation)?;
        let read = file
            .read(&mut *chunk)
            .map_err(|_| ProviderFileError::Read)?;
        if read == 0 {
            break;
        }
        let next = bytes
            .len()
            .checked_add(read)
            .ok_or(ProviderFileError::TooLarge)?;
        if next > maximum_bytes || next > expected_size {
            return Err(ProviderFileError::Changed);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if bytes.len() != expected_size {
        return Err(ProviderFileError::Changed);
    }
    Ok(bytes)
}

fn visit_bounded_lines(
    file: &mut File,
    expected_size: usize,
    maximum_line_bytes: usize,
    cancellation: &CancellationToken,
    mut visitor: impl FnMut(&[u8]),
) -> Result<(), ProviderFileError> {
    let _ = posix_fadvise(&*file, 0, 0, PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL);
    let mut total = 0_usize;
    let mut line = Zeroizing::new(Vec::with_capacity(maximum_line_bytes.min(64 * 1024)));
    let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES]);
    let mut oversized = false;
    loop {
        check_cancelled(cancellation)?;
        let read = file
            .read(&mut *chunk)
            .map_err(|_| ProviderFileError::Read)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or(ProviderFileError::TooLarge)?;
        if total > expected_size {
            return Err(ProviderFileError::Changed);
        }
        for byte in &chunk[..read] {
            if *byte == b'\n' {
                if !oversized && !line.is_empty() {
                    visitor(&line);
                }
                line.clear();
                oversized = false;
            } else if !oversized {
                if line.len() == maximum_line_bytes {
                    line.clear();
                    oversized = true;
                } else {
                    line.push(*byte);
                }
            }
        }
    }
    if total != expected_size {
        return Err(ProviderFileError::Changed);
    }
    if !oversized && !line.is_empty() {
        visitor(&line);
    }
    let _ = posix_fadvise(&*file, 0, 0, PosixFadviseAdvice::POSIX_FADV_DONTNEED);
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "recursive scan state is explicit and security-sensitive"
)]
fn scan_directory(
    directory: &File,
    relative: &Path,
    depth: usize,
    root: FileKey,
    owner: u32,
    budget: &mut ScanBudget,
    candidates: &mut Vec<ProviderFileCandidate>,
    cancellation: &CancellationToken,
) -> Result<(), ProviderFileError> {
    check_cancelled(cancellation)?;
    let before = fstat(directory).map_err(|_| ProviderFileError::Changed)?;
    validate_directory(&before, owner)?;
    let before = FileSnapshot::from_stat(&before);
    let descriptor = openat(
        directory,
        Path::new("."),
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_CLOEXEC
            | OFlag::O_NOATIME
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ProviderFileError::UnsafeLayout)?;
    let mut stream = Dir::from_fd(descriptor).map_err(|_| ProviderFileError::UnsafeLayout)?;
    let mut names = Vec::<OsString>::new();
    for result in stream.iter() {
        check_cancelled(cancellation)?;
        let entry = result.map_err(|_| ProviderFileError::Changed)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        budget.observe_entry()?;
        if name.is_empty() || name.len() > MAX_COMPONENT_BYTES {
            return Err(ProviderFileError::UnsafeLayout);
        }
        names.push(OsStr::from_bytes(name).to_os_string());
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    for name in names {
        check_cancelled(cancellation)?;
        let stat = fstatat(directory, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| ProviderFileError::Changed)?;
        if stat.st_uid != owner {
            return Err(ProviderFileError::WrongOwner);
        }
        let mut path = relative.to_path_buf();
        path.push(&name);
        if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
            return Err(ProviderFileError::UnsafeLayout);
        }
        match file_type(&stat) {
            SFlag::S_IFREG => {
                validate_regular_file(&stat, owner, budget.limits.file_bytes)?;
                let size =
                    usize::try_from(stat.st_size).map_err(|_| ProviderFileError::TooLarge)?;
                budget.observe_file(size)?;
                candidates.push(ProviderFileCandidate {
                    relative_path: path,
                    size,
                    snapshot: FileSnapshot::from_stat(&stat),
                    root,
                });
            }
            SFlag::S_IFDIR => {
                if depth >= budget.limits.depth {
                    return Err(ProviderFileError::TooDeep);
                }
                let descriptor = openat(
                    directory,
                    name.as_os_str(),
                    OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| ProviderFileError::Changed)?;
                let child = File::from(descriptor);
                let opened = fstat(&child).map_err(|_| ProviderFileError::Changed)?;
                if FileSnapshot::from_stat(&opened) != FileSnapshot::from_stat(&stat) {
                    return Err(ProviderFileError::Changed);
                }
                scan_directory(
                    &child,
                    &path,
                    depth + 1,
                    root,
                    owner,
                    budget,
                    candidates,
                    cancellation,
                )?;
                let linked = fstatat(directory, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|_| ProviderFileError::Changed)?;
                if FileKey::from_stat(&linked) != FileKey::from_stat(&opened) {
                    return Err(ProviderFileError::Changed);
                }
            }
            _ => return Err(ProviderFileError::UnsafeLayout),
        }
    }
    let after = fstat(directory).map_err(|_| ProviderFileError::Changed)?;
    if FileSnapshot::from_stat(&after) != before {
        return Err(ProviderFileError::Changed);
    }
    Ok(())
}

fn validate_directory(stat: &nix::libc::stat, owner: u32) -> Result<(), ProviderFileError> {
    if file_type(stat) != SFlag::S_IFDIR {
        return Err(ProviderFileError::UnsafeLayout);
    }
    if stat.st_uid != owner {
        return Err(ProviderFileError::WrongOwner);
    }
    Ok(())
}

fn validate_regular_file(
    stat: &nix::libc::stat,
    owner: u32,
    maximum_bytes: usize,
) -> Result<(), ProviderFileError> {
    if file_type(stat) != SFlag::S_IFREG {
        return Err(ProviderFileError::UnsafeLayout);
    }
    if stat.st_uid != owner {
        return Err(ProviderFileError::WrongOwner);
    }
    if stat.st_nlink != 1 {
        return Err(ProviderFileError::UnsafeLayout);
    }
    let size = usize::try_from(stat.st_size).map_err(|_| ProviderFileError::TooLarge)?;
    if size > maximum_bytes {
        return Err(ProviderFileError::TooLarge);
    }
    Ok(())
}

fn file_type(stat: &nix::libc::stat) -> SFlag {
    SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT
}

fn map_relative_stat_error(error: nix::errno::Errno) -> ProviderFileError {
    if error == nix::errno::Errno::ENOENT {
        ProviderFileError::Missing
    } else {
        ProviderFileError::UnsafeLayout
    }
}

fn map_relative_open_error(error: nix::errno::Errno) -> ProviderFileError {
    if error == nix::errno::Errno::ENOENT {
        ProviderFileError::Missing
    } else {
        ProviderFileError::UnsafeLayout
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), ProviderFileError> {
    if cancellation.is_cancelled() {
        Err(ProviderFileError::Cancelled)
    } else {
        Ok(())
    }
}
