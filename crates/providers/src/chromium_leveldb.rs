//! Bounded, read-only Chromium `LevelDB` and local-storage inspection.
//!
//! The reader accepts one already validated [`BrowserProfile`] and one normal
//! relative directory. It never opens `LevelDB` through its library API, never
//! creates `LOCK`, and never writes beneath the browser profile. Source files
//! are acquired through held `O_NOFOLLOW` descriptors into zeroizing memory and
//! accepted only when the directory and every entry retain the same identity
//! across a complete bounded acquisition attempt.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path};

use nix::dir::Dir;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fstat, fstatat};
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::browser_profile::{BrowserKind, BrowserProfile};

const LEVELDB_LOG_BLOCK_BYTES: usize = 32 * 1024;
const LEVELDB_LOG_HEADER_BYTES: usize = 7;
const LEVELDB_TABLE_FOOTER_BYTES: usize = 48;
const LEVELDB_TABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const LEVELDB_BLOCK_TRAILER_BYTES: usize = 5;
const LEVELDB_MAX_SEQUENCE: u64 = (1_u64 << 56) - 1;
const SNAPSHOT_ATTEMPTS: usize = 3;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_FILE_NAME_BYTES: usize = 255;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const MAX_LEVELDB_FILES: usize = 256;
const MAX_LEVELDB_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LEVELDB_AGGREGATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LOGICAL_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_TABLE_BLOCK_BYTES: usize = 8 * 1024 * 1024;
const MAX_TABLE_BLOCKS: usize = 4 * 1024;
const MAX_LEVELDB_ENTRIES: usize = 65_536;
const MAX_LEVELDB_FIELD_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECONSTRUCTED_ENTRY_BYTES: usize = 64 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 256 * 1024;
const MAX_ORIGIN_BYTES: usize = 2 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_TOKEN_CANDIDATES: usize = 256;
const DEFAULT_TOKEN_MINIMUM_BYTES: usize = 60;

/// A validated exact HTTPS origin used for local-storage selection.
///
/// Default port 443 is canonicalized away. User information, paths other than
/// `/`, queries, and fragments are rejected.
#[derive(Clone, PartialEq, Eq)]
pub struct ChromiumHttpsOrigin {
    canonical: String,
    host: String,
    port: u16,
}

impl ChromiumHttpsOrigin {
    /// Parses and canonicalizes one exact HTTPS origin.
    ///
    /// # Errors
    ///
    /// Returns [`ChromiumLevelDbError::InvalidOrigin`] for non-HTTPS or
    /// non-origin input.
    pub fn parse(value: &str) -> Result<Self, ChromiumLevelDbError> {
        parse_https_origin(value).ok_or(ChromiumLevelDbError::InvalidOrigin)
    }

    /// Canonical serialization of this origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Effective HTTPS port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl Debug for ChromiumHttpsOrigin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChromiumHttpsOrigin(<redacted>)")
    }
}

/// One decoded live local-storage value for an exact origin.
pub struct ChromiumLocalStorageEntry {
    origin: ChromiumHttpsOrigin,
    key: Zeroizing<String>,
    value: Zeroizing<String>,
    raw_value_length: usize,
    sequence: u64,
}

impl ChromiumLocalStorageEntry {
    /// Exact canonical origin selected by the caller.
    #[must_use]
    pub const fn origin(&self) -> &ChromiumHttpsOrigin {
        &self.origin
    }

    /// Decoded local-storage key. Keep the borrow short-lived.
    #[must_use]
    pub fn expose_key(&self) -> &str {
        self.key.as_str()
    }

    /// Decoded local-storage value. Keep the borrow short-lived.
    #[must_use]
    pub fn expose_value(&self) -> &str {
        self.value.as_str()
    }

    /// Encoded `LevelDB` value length before text decoding.
    #[must_use]
    pub const fn raw_value_length(&self) -> usize {
        self.raw_value_length
    }

    /// `LevelDB` sequence number that selected this value.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl Debug for ChromiumLocalStorageEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChromiumLocalStorageEntry")
            .field("origin", &"<redacted>")
            .field("key", &"<redacted>")
            .field("value", &"<redacted>")
            .field("raw_value_length", &self.raw_value_length)
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// One best-effort decoded live `LevelDB` key/value pair.
pub struct ChromiumLevelDbTextEntry {
    key: Zeroizing<String>,
    value: Zeroizing<String>,
    sequence: u64,
}

impl ChromiumLevelDbTextEntry {
    /// Decoded key. Keep the borrow short-lived.
    #[must_use]
    pub fn expose_key(&self) -> &str {
        self.key.as_str()
    }

    /// Decoded value. Keep the borrow short-lived.
    #[must_use]
    pub fn expose_value(&self) -> &str {
        self.value.as_str()
    }

    /// `LevelDB` sequence number that selected this value.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl Debug for ChromiumLevelDbTextEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChromiumLevelDbTextEntry")
            .field("key", &"<redacted>")
            .field("value", &"<redacted>")
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// One bounded ASCII token-like candidate found in live `LevelDB` data.
pub struct ChromiumTokenCandidate(Zeroizing<String>);

impl ChromiumTokenCandidate {
    /// Borrows the candidate. Never log or serialize it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl Debug for ChromiumTokenCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChromiumTokenCandidate([REDACTED])")
    }
}

/// Stable, path- and content-free `LevelDB` reader failures.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ChromiumLevelDbError {
    /// The supplied profile was not a usable Chromium profile directory.
    #[error("Chromium LevelDB profile is invalid")]
    InvalidProfile,
    /// Firefox and Zen do not use the supported Chromium store format.
    #[error("browser does not support Chromium LevelDB")]
    UnsupportedBrowser,
    /// The `LevelDB` directory was not a bounded normal relative path.
    #[error("Chromium LevelDB relative directory is invalid")]
    InvalidRelativePath,
    /// The selected `LevelDB` directory does not exist.
    #[error("Chromium LevelDB directory is missing")]
    Missing,
    /// A symlink, special file, non-UTF-8 name, or path escape was found.
    #[error("Chromium LevelDB file layout is unsafe")]
    UnsafeLayout,
    /// A file, aggregate, block, field, or text value exceeded its byte bound.
    #[error("Chromium LevelDB data exceeds its size bound")]
    TooLarge,
    /// A directory, file, block, entry, or token-result count exceeded its cap.
    #[error("Chromium LevelDB data exceeds its count bound")]
    TooManyEntries,
    /// Source identities kept changing during bounded acquisition retries.
    #[error("Chromium LevelDB changed during acquisition")]
    Changed,
    /// A log, table, Snappy stream, checksum, key, or value was malformed.
    #[error("Chromium LevelDB data is malformed")]
    Malformed,
    /// The requested origin was not an exact HTTPS origin.
    #[error("Chromium local-storage origin is invalid")]
    InvalidOrigin,
    /// The token scan minimum was outside its fixed accepted range.
    #[error("Chromium token scan policy is invalid")]
    InvalidTokenPolicy,
}

/// A stable, in-memory view of one Chromium `LevelDB` directory.
///
/// All retained raw keys and values are zeroized on drop. Construct a reader
/// only for the shortest scope needed to project local-storage or token data.
pub struct ChromiumLevelDbReader {
    records: BTreeMap<SecretBytes, VersionedValue>,
    source_file_count: usize,
}

impl ChromiumLevelDbReader {
    /// Acquires and parses one `LevelDB` directory beneath `profile`.
    ///
    /// # Errors
    ///
    /// Rejects unsupported browsers, unsafe relative paths, symlinks, special
    /// files, non-UTF-8 names, changing source identities, excessive input, and
    /// malformed `LevelDB` data.
    pub fn open(
        profile: &BrowserProfile,
        relative_directory: impl AsRef<Path>,
    ) -> Result<Self, ChromiumLevelDbError> {
        ensure_chromium(profile.browser())?;
        let relative = relative_directory.as_ref();
        validate_relative_directory(relative)?;
        let images = acquire_stable_images(profile, relative)?;
        let source_file_count = images.len();
        let records = parse_images(images)?;
        Ok(Self {
            records,
            source_file_count,
        })
    }

    /// Number of `.log` and `.ldb` files included in this view.
    #[must_use]
    pub const fn source_file_count(&self) -> usize {
        self.source_file_count
    }

    /// Projects newest live local-storage values for one exact HTTPS origin.
    ///
    /// # Errors
    ///
    /// Returns a stable size/count/malformed error when decoded fields violate
    /// their fixed output bounds.
    pub fn local_storage_entries(
        &self,
        origin: &ChromiumHttpsOrigin,
    ) -> Result<Vec<ChromiumLocalStorageEntry>, ChromiumLevelDbError> {
        project_local_storage(&self.records, origin)
    }

    /// Decodes bounded text pairs from newest live records.
    ///
    /// Binary records that cannot be decoded conservatively are skipped.
    ///
    /// # Errors
    ///
    /// Returns a stable count/size error if projected output exceeds a bound.
    pub fn text_entries(&self) -> Result<Vec<ChromiumLevelDbTextEntry>, ChromiumLevelDbError> {
        project_text_entries(&self.records)
    }

    /// Scans newest live keys and values for bounded ASCII token candidates.
    ///
    /// # Errors
    ///
    /// Rejects a minimum outside `1..=16384` and result sets larger than 256.
    pub fn token_candidates(
        &self,
        minimum_bytes: usize,
    ) -> Result<Vec<ChromiumTokenCandidate>, ChromiumLevelDbError> {
        project_token_candidates(&self.records, minimum_bytes)
    }

    /// Uses the pinned reader's default 60-byte token threshold.
    ///
    /// # Errors
    ///
    /// Returns a stable count error if more than 256 candidates are found.
    pub fn default_token_candidates(
        &self,
    ) -> Result<Vec<ChromiumTokenCandidate>, ChromiumLevelDbError> {
        self.token_candidates(DEFAULT_TOKEN_MINIMUM_BYTES)
    }
}

impl Debug for ChromiumLevelDbReader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChromiumLevelDbReader")
            .field("live_record_count", &self.records.len())
            .field("source_file_count", &self.source_file_count)
            .field("contents", &"<redacted>")
            .finish()
    }
}

struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Borrow<[u8]> for SecretBytes {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SecretBytes {}

impl PartialOrd for SecretBytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecretBytes {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Debug for SecretBytes {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

struct VersionedValue {
    sequence: u64,
    value: Option<Zeroizing<Vec<u8>>>,
}

struct ParsedRecord {
    key: SecretBytes,
    sequence: u64,
    value: Option<Zeroizing<Vec<u8>>>,
}

struct FileImage {
    kind: LevelDbFileKind,
    bytes: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LevelDbFileKind {
    Log,
    Table,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_stat(stat: &nix::libc::stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            links: stat.st_nlink,
            uid: stat.st_uid,
            gid: stat.st_gid,
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DirectoryEntryIdentity {
    name: String,
    identity: FileIdentity,
    kind: Option<LevelDbFileKind>,
}

struct DirectoryInspection {
    directory: FileIdentity,
    entries: Vec<DirectoryEntryIdentity>,
}

enum AcquisitionError {
    Changed,
    Fatal(ChromiumLevelDbError),
}

impl From<ChromiumLevelDbError> for AcquisitionError {
    fn from(error: ChromiumLevelDbError) -> Self {
        Self::Fatal(error)
    }
}

fn ensure_chromium(browser: BrowserKind) -> Result<(), ChromiumLevelDbError> {
    match browser {
        BrowserKind::Chromium
        | BrowserKind::GoogleChrome
        | BrowserKind::Brave
        | BrowserKind::BraveOrigin
        | BrowserKind::MicrosoftEdge => Ok(()),
        BrowserKind::Firefox | BrowserKind::Zen => Err(ChromiumLevelDbError::UnsupportedBrowser),
    }
}

fn validate_relative_directory(relative: &Path) -> Result<(), ChromiumLevelDbError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || relative.components().any(|component| match component {
            Component::Normal(name) => {
                name.to_str().is_none()
                    || name.as_encoded_bytes().len() > MAX_FILE_NAME_BYTES
                    || name.as_encoded_bytes().contains(&0)
            }
            _ => true,
        })
    {
        return Err(ChromiumLevelDbError::InvalidRelativePath);
    }
    Ok(())
}

fn acquire_stable_images(
    profile: &BrowserProfile,
    relative: &Path,
) -> Result<Vec<FileImage>, ChromiumLevelDbError> {
    for _ in 0..SNAPSHOT_ATTEMPTS {
        match acquire_images_once(profile, relative) {
            Ok(images) => return Ok(images),
            Err(AcquisitionError::Changed) => {}
            Err(AcquisitionError::Fatal(error)) => return Err(error),
        }
    }
    Err(ChromiumLevelDbError::Changed)
}

fn acquire_images_once(
    profile: &BrowserProfile,
    relative: &Path,
) -> Result<Vec<FileImage>, AcquisitionError> {
    let profile_directory = open_profile_directory(profile.path())?;
    let profile_stat = fstat(&profile_directory)
        .map_err(|_| AcquisitionError::Fatal(ChromiumLevelDbError::InvalidProfile))?;
    if file_type(&profile_stat) != SFlag::S_IFDIR {
        return Err(AcquisitionError::Fatal(
            ChromiumLevelDbError::InvalidProfile,
        ));
    }

    let leveldb_directory = open_relative_directory(&profile_directory, relative)?;
    let before = inspect_directory(&leveldb_directory)?;
    let relevant_count = before
        .entries
        .iter()
        .filter(|entry| entry.kind.is_some())
        .count();
    if relevant_count > MAX_LEVELDB_FILES {
        return Err(ChromiumLevelDbError::TooManyEntries.into());
    }
    let aggregate = before
        .entries
        .iter()
        .filter(|entry| entry.kind.is_some())
        .try_fold(0_u64, |total, entry| {
            let size = u64::try_from(entry.identity.size)
                .map_err(|_| ChromiumLevelDbError::UnsafeLayout)?;
            if size > MAX_LEVELDB_FILE_BYTES {
                return Err(ChromiumLevelDbError::TooLarge);
            }
            total
                .checked_add(size)
                .filter(|sum| *sum <= MAX_LEVELDB_AGGREGATE_BYTES)
                .ok_or(ChromiumLevelDbError::TooLarge)
        })?;
    let mut images = Vec::with_capacity(relevant_count);
    let mut read_total = 0_u64;
    for entry in before.entries.iter().filter(|entry| entry.kind.is_some()) {
        let image = read_file_image(&leveldb_directory, entry)?;
        read_total = read_total
            .checked_add(
                u64::try_from(image.bytes.len())
                    .map_err(|_| AcquisitionError::Fatal(ChromiumLevelDbError::TooLarge))?,
            )
            .ok_or(AcquisitionError::Fatal(ChromiumLevelDbError::TooLarge))?;
        images.push(image);
    }
    if read_total != aggregate {
        return Err(AcquisitionError::Changed);
    }
    let after = inspect_directory(&leveldb_directory).map_err(|_| AcquisitionError::Changed)?;
    if before.directory != after.directory || before.entries != after.entries {
        return Err(AcquisitionError::Changed);
    }
    Ok(images)
}

fn open_profile_directory(path: &Path) -> Result<File, AcquisitionError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(AcquisitionError::Fatal(
            ChromiumLevelDbError::InvalidProfile,
        ));
    }
    let root_descriptor = open(
        Path::new("/"),
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| AcquisitionError::Fatal(ChromiumLevelDbError::InvalidProfile))?;
    let mut directory = File::from(root_descriptor);
    let mut opened_component = false;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(AcquisitionError::Fatal(
                ChromiumLevelDbError::InvalidProfile,
            ));
        };
        let descriptor = openat(
            &directory,
            name,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| AcquisitionError::Fatal(ChromiumLevelDbError::InvalidProfile))?;
        directory = File::from(descriptor);
        let stat = fstat(&directory)
            .map_err(|_| AcquisitionError::Fatal(ChromiumLevelDbError::InvalidProfile))?;
        if file_type(&stat) != SFlag::S_IFDIR {
            return Err(AcquisitionError::Fatal(
                ChromiumLevelDbError::InvalidProfile,
            ));
        }
        opened_component = true;
    }
    if !opened_component {
        return Err(AcquisitionError::Fatal(
            ChromiumLevelDbError::InvalidProfile,
        ));
    }
    Ok(directory)
}

fn open_relative_directory(
    profile_directory: &File,
    relative: &Path,
) -> Result<File, AcquisitionError> {
    let mut directory = profile_directory
        .try_clone()
        .map_err(|_| AcquisitionError::Fatal(ChromiumLevelDbError::InvalidProfile))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(AcquisitionError::Fatal(
                ChromiumLevelDbError::InvalidRelativePath,
            ));
        };
        let descriptor = match openat(
            &directory,
            name,
            OFlag::O_RDONLY
                | OFlag::O_DIRECTORY
                | OFlag::O_CLOEXEC
                | OFlag::O_NOATIME
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(nix::errno::Errno::ENOENT) => {
                return Err(AcquisitionError::Fatal(ChromiumLevelDbError::Missing));
            }
            Err(_) => {
                return Err(AcquisitionError::Fatal(ChromiumLevelDbError::UnsafeLayout));
            }
        };
        directory = File::from(descriptor);
        let stat = fstat(&directory).map_err(|_| AcquisitionError::Changed)?;
        if file_type(&stat) != SFlag::S_IFDIR {
            return Err(AcquisitionError::Fatal(ChromiumLevelDbError::UnsafeLayout));
        }
    }
    Ok(directory)
}

fn inspect_directory(directory: &File) -> Result<DirectoryInspection, ChromiumLevelDbError> {
    let stat = fstat(directory).map_err(|_| ChromiumLevelDbError::UnsafeLayout)?;
    if file_type(&stat) != SFlag::S_IFDIR {
        return Err(ChromiumLevelDbError::UnsafeLayout);
    }
    let cloned = directory
        .try_clone()
        .map_err(|_| ChromiumLevelDbError::UnsafeLayout)?;
    let mut stream = Dir::from_fd(cloned.into()).map_err(|_| ChromiumLevelDbError::UnsafeLayout)?;
    let mut entries = Vec::new();
    for result in stream.iter() {
        if entries.len() >= MAX_DIRECTORY_ENTRIES {
            return Err(ChromiumLevelDbError::TooManyEntries);
        }
        let entry = result.map_err(|_| ChromiumLevelDbError::UnsafeLayout)?;
        let name_bytes = entry.file_name().to_bytes();
        if matches!(name_bytes, b"." | b"..") {
            continue;
        }
        let name =
            std::str::from_utf8(name_bytes).map_err(|_| ChromiumLevelDbError::UnsafeLayout)?;
        if name.is_empty() || name.len() > MAX_FILE_NAME_BYTES {
            return Err(ChromiumLevelDbError::UnsafeLayout);
        }
        let entry_stat = fstatat(directory, entry.file_name(), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| ChromiumLevelDbError::UnsafeLayout)?;
        if file_type(&entry_stat) != SFlag::S_IFREG {
            return Err(ChromiumLevelDbError::UnsafeLayout);
        }
        entries.push(DirectoryEntryIdentity {
            kind: classify_leveldb_file(name),
            name: name.to_owned(),
            identity: FileIdentity::from_stat(&entry_stat),
        });
    }
    entries.sort();
    Ok(DirectoryInspection {
        directory: FileIdentity::from_stat(&stat),
        entries,
    })
}

fn read_file_image(
    directory: &File,
    expected: &DirectoryEntryIdentity,
) -> Result<FileImage, AcquisitionError> {
    let kind = expected
        .kind
        .ok_or(AcquisitionError::Fatal(ChromiumLevelDbError::Malformed))?;
    let descriptor = openat(
        directory,
        OsStr::new(&expected.name),
        OFlag::O_RDONLY
            | OFlag::O_CLOEXEC
            | OFlag::O_NOATIME
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| AcquisitionError::Changed)?;
    let mut file = File::from(descriptor);
    let opened = fstat(&file).map_err(|_| AcquisitionError::Changed)?;
    if file_type(&opened) != SFlag::S_IFREG || FileIdentity::from_stat(&opened) != expected.identity
    {
        return Err(AcquisitionError::Changed);
    }
    let expected_size = usize::try_from(opened.st_size)
        .map_err(|_| AcquisitionError::Fatal(ChromiumLevelDbError::TooLarge))?;
    let read_limit = MAX_LEVELDB_FILE_BYTES
        .checked_add(1)
        .ok_or(AcquisitionError::Fatal(ChromiumLevelDbError::TooLarge))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected_size));
    let mut limited: Take<&mut File> = (&mut file).take(read_limit);
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| AcquisitionError::Changed)?;
    if bytes.len() != expected_size {
        return Err(AcquisitionError::Changed);
    }
    let closed_over = fstat(&file).map_err(|_| AcquisitionError::Changed)?;
    if FileIdentity::from_stat(&closed_over) != expected.identity {
        return Err(AcquisitionError::Changed);
    }
    Ok(FileImage { kind, bytes })
}

fn file_type(stat: &nix::libc::stat) -> SFlag {
    SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT
}

fn classify_leveldb_file(name: &str) -> Option<LevelDbFileKind> {
    let (stem, kind) = if let Some(stem) = name.strip_suffix(".log") {
        (stem, LevelDbFileKind::Log)
    } else {
        let stem = name.strip_suffix(".ldb")?;
        (stem, LevelDbFileKind::Table)
    };
    (!stem.is_empty() && stem.bytes().all(|byte| byte.is_ascii_digit())).then_some(kind)
}

#[derive(Default)]
struct ParseBudget {
    entries: usize,
    table_blocks: usize,
    reconstructed_entry_bytes: usize,
}

fn parse_images(
    images: Vec<FileImage>,
) -> Result<BTreeMap<SecretBytes, VersionedValue>, ChromiumLevelDbError> {
    let mut budget = ParseBudget::default();
    let mut records = BTreeMap::new();
    for image in images {
        let parsed = match image.kind {
            LevelDbFileKind::Log => parse_log(&image.bytes, &mut budget)?,
            LevelDbFileKind::Table => parse_table(&image.bytes, &mut budget)?,
        };
        for record in parsed {
            merge_record(&mut records, record)?;
        }
    }
    Ok(records)
}

fn merge_record(
    records: &mut BTreeMap<SecretBytes, VersionedValue>,
    record: ParsedRecord,
) -> Result<(), ChromiumLevelDbError> {
    let decision = records
        .get(record.key.as_slice())
        .map_or(Ordering::Greater, |existing| {
            record.sequence.cmp(&existing.sequence)
        });
    match decision {
        Ordering::Greater => {
            records.insert(
                record.key,
                VersionedValue {
                    sequence: record.sequence,
                    value: record.value,
                },
            );
            Ok(())
        }
        Ordering::Less => Ok(()),
        Ordering::Equal => {
            let existing = records
                .get(record.key.as_slice())
                .ok_or(ChromiumLevelDbError::Malformed)?;
            if existing.value.as_deref() == record.value.as_deref() {
                Ok(())
            } else {
                Err(ChromiumLevelDbError::Malformed)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogRecordType {
    Full,
    First,
    Middle,
    Last,
}

impl LogRecordType {
    fn parse(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Full),
            2 => Some(Self::First),
            3 => Some(Self::Middle),
            4 => Some(Self::Last),
            _ => None,
        }
    }
}

fn parse_log(
    bytes: &[u8],
    budget: &mut ParseBudget,
) -> Result<Vec<ParsedRecord>, ChromiumLevelDbError> {
    let mut records = Vec::new();
    let mut fragmented: Option<Zeroizing<Vec<u8>>> = None;
    for block_start in (0..bytes.len()).step_by(LEVELDB_LOG_BLOCK_BYTES) {
        let block_end = block_start
            .checked_add(LEVELDB_LOG_BLOCK_BYTES)
            .map_or(bytes.len(), |end| end.min(bytes.len()));
        let mut offset = block_start;
        while offset < block_end {
            let remaining = block_end - offset;
            if remaining < LEVELDB_LOG_HEADER_BYTES {
                if bytes[offset..block_end].iter().any(|byte| *byte != 0) {
                    return Err(ChromiumLevelDbError::Malformed);
                }
                break;
            }
            let checksum = read_u32_le(bytes, offset)?;
            let length = usize::from(read_u16_le(bytes, offset + 4)?);
            let raw_type = bytes[offset + 6];
            offset += LEVELDB_LOG_HEADER_BYTES;
            if checksum == 0 && length == 0 && raw_type == 0 {
                if bytes[offset..block_end].iter().any(|byte| *byte != 0) {
                    return Err(ChromiumLevelDbError::Malformed);
                }
                break;
            }
            let payload_end = offset
                .checked_add(length)
                .filter(|end| *end <= block_end)
                .ok_or(ChromiumLevelDbError::Malformed)?;
            let record_type =
                LogRecordType::parse(raw_type).ok_or(ChromiumLevelDbError::Malformed)?;
            let payload = &bytes[offset..payload_end];
            if masked_crc32c_parts(raw_type, payload) != checksum {
                return Err(ChromiumLevelDbError::Malformed);
            }
            offset = payload_end;
            match record_type {
                LogRecordType::Full => {
                    if fragmented.is_some() {
                        return Err(ChromiumLevelDbError::Malformed);
                    }
                    records.extend(parse_write_batch(payload, budget)?);
                }
                LogRecordType::First => {
                    if fragmented.is_some() {
                        return Err(ChromiumLevelDbError::Malformed);
                    }
                    if payload.len() > MAX_LOGICAL_RECORD_BYTES {
                        return Err(ChromiumLevelDbError::TooLarge);
                    }
                    fragmented = Some(Zeroizing::new(payload.to_vec()));
                }
                LogRecordType::Middle => {
                    let buffer = fragmented.as_mut().ok_or(ChromiumLevelDbError::Malformed)?;
                    append_bounded(buffer, payload, MAX_LOGICAL_RECORD_BYTES)?;
                }
                LogRecordType::Last => {
                    let mut buffer = fragmented.take().ok_or(ChromiumLevelDbError::Malformed)?;
                    append_bounded(&mut buffer, payload, MAX_LOGICAL_RECORD_BYTES)?;
                    records.extend(parse_write_batch(&buffer, budget)?);
                }
            }
        }
    }
    if fragmented.is_some() {
        return Err(ChromiumLevelDbError::Malformed);
    }
    Ok(records)
}

fn append_bounded(
    destination: &mut Vec<u8>,
    source: &[u8],
    maximum: usize,
) -> Result<(), ChromiumLevelDbError> {
    let new_length = destination
        .len()
        .checked_add(source.len())
        .filter(|length| *length <= maximum)
        .ok_or(ChromiumLevelDbError::TooLarge)?;
    destination.reserve(new_length - destination.len());
    destination.extend_from_slice(source);
    Ok(())
}

fn parse_write_batch(
    bytes: &[u8],
    budget: &mut ParseBudget,
) -> Result<Vec<ParsedRecord>, ChromiumLevelDbError> {
    if bytes.len() < 12 || bytes.len() > MAX_LOGICAL_RECORD_BYTES {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let base_sequence = read_u64_le(bytes, 0)?;
    if base_sequence > LEVELDB_MAX_SEQUENCE {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let count = usize::try_from(read_u32_le(bytes, 8)?)
        .map_err(|_| ChromiumLevelDbError::TooManyEntries)?;
    reserve_entries(budget, count)?;
    let mut records = Vec::with_capacity(count);
    let mut reader = SliceReader::new(&bytes[12..]);
    for index in 0..count {
        let sequence = base_sequence
            .checked_add(u64::try_from(index).map_err(|_| ChromiumLevelDbError::Malformed)?)
            .filter(|sequence| *sequence <= LEVELDB_MAX_SEQUENCE)
            .ok_or(ChromiumLevelDbError::Malformed)?;
        let tag = reader.read_u8().ok_or(ChromiumLevelDbError::Malformed)?;
        let key = reader.read_length_prefixed(MAX_LEVELDB_FIELD_BYTES)?;
        let value = match tag {
            0 => None,
            1 => Some(reader.read_length_prefixed(MAX_LEVELDB_FIELD_BYTES)?),
            _ => return Err(ChromiumLevelDbError::Malformed),
        };
        reserve_reconstructed_entry_bytes(budget, key.len(), value.map_or(0, <[u8]>::len))?;
        records.push(ParsedRecord {
            key: SecretBytes::new(key.to_vec()),
            sequence,
            value: value.map(|bytes| Zeroizing::new(bytes.to_vec())),
        });
    }
    if !reader.is_empty() {
        return Err(ChromiumLevelDbError::Malformed);
    }
    Ok(records)
}

fn reserve_entries(
    budget: &mut ParseBudget,
    additional: usize,
) -> Result<(), ChromiumLevelDbError> {
    budget.entries = budget
        .entries
        .checked_add(additional)
        .filter(|count| *count <= MAX_LEVELDB_ENTRIES)
        .ok_or(ChromiumLevelDbError::TooManyEntries)?;
    Ok(())
}

fn reserve_reconstructed_entry_bytes(
    budget: &mut ParseBudget,
    key_bytes: usize,
    value_bytes: usize,
) -> Result<(), ChromiumLevelDbError> {
    let additional = key_bytes
        .checked_add(value_bytes)
        .ok_or(ChromiumLevelDbError::TooLarge)?;
    budget.reconstructed_entry_bytes = budget
        .reconstructed_entry_bytes
        .checked_add(additional)
        .filter(|total| *total <= MAX_RECONSTRUCTED_ENTRY_BYTES)
        .ok_or(ChromiumLevelDbError::TooLarge)?;
    Ok(())
}

fn masked_crc32c_parts(record_type: u8, payload: &[u8]) -> u32 {
    let crc = crc32c_extend(crc32c_extend(!0_u32, &[record_type]), payload);
    mask_crc32c(!crc)
}

fn masked_crc32c_block(block: &[u8], compression: u8) -> u32 {
    let crc = crc32c_extend(crc32c_extend(!0_u32, block), &[compression]);
    mask_crc32c(!crc)
}

fn crc32c_extend(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0x82f6_3b78
            };
        }
    }
    crc
}

const fn mask_crc32c(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BlockHandle {
    offset: usize,
    size: usize,
}

struct BlockEntry {
    key: SecretBytes,
    value: Zeroizing<Vec<u8>>,
}

fn parse_table(
    bytes: &[u8],
    budget: &mut ParseBudget,
) -> Result<Vec<ParsedRecord>, ChromiumLevelDbError> {
    if bytes.len() < LEVELDB_TABLE_FOOTER_BYTES {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let footer_start = bytes.len() - LEVELDB_TABLE_FOOTER_BYTES;
    let magic = read_u64_le(bytes, bytes.len() - 8)?;
    if magic != LEVELDB_TABLE_MAGIC {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let mut footer = SliceReader::new(&bytes[footer_start..bytes.len() - 8]);
    let metaindex = footer.read_block_handle()?;
    let index = footer.read_block_handle()?;
    if footer.remaining().iter().any(|byte| *byte != 0) {
        return Err(ChromiumLevelDbError::Malformed);
    }
    validate_block_handle(metaindex, footer_start)?;
    validate_block_handle(index, footer_start)?;

    let mut handles = BTreeSet::from([metaindex]);
    if !handles.insert(index) {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let metaindex_bytes = read_table_block(bytes, metaindex, footer_start, budget)?;
    let _metaindex_entries = parse_prefix_block(&metaindex_bytes, MAX_TABLE_BLOCKS, budget)?;
    let index_bytes = read_table_block(bytes, index, footer_start, budget)?;
    let index_entries = parse_prefix_block(&index_bytes, MAX_TABLE_BLOCKS, budget)?;
    if index_entries.len() > MAX_TABLE_BLOCKS {
        return Err(ChromiumLevelDbError::TooManyEntries);
    }
    let mut parsed = Vec::new();
    for index_entry in index_entries {
        let handle = decode_block_handle(&index_entry.value)?;
        validate_block_handle(handle, footer_start)?;
        if !handles.insert(handle) {
            return Err(ChromiumLevelDbError::Malformed);
        }
        let block = read_table_block(bytes, handle, footer_start, budget)?;
        let entries = parse_prefix_block(&block, MAX_LEVELDB_ENTRIES, budget)?;
        reserve_entries(budget, entries.len())?;
        for entry in entries {
            parsed.push(decode_internal_entry(entry)?);
        }
    }
    let mut ranges = handles
        .into_iter()
        .map(|handle| {
            let end = handle
                .offset
                .checked_add(handle.size)
                .and_then(|value| value.checked_add(LEVELDB_BLOCK_TRAILER_BYTES))
                .ok_or(ChromiumLevelDbError::Malformed)?;
            Ok((handle.offset, end))
        })
        .collect::<Result<Vec<_>, ChromiumLevelDbError>>()?;
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(ChromiumLevelDbError::Malformed);
    }
    Ok(parsed)
}

fn validate_block_handle(
    handle: BlockHandle,
    footer_start: usize,
) -> Result<(), ChromiumLevelDbError> {
    if handle.size > MAX_TABLE_BLOCK_BYTES {
        return Err(ChromiumLevelDbError::TooLarge);
    }
    let trailer_end = handle
        .offset
        .checked_add(handle.size)
        .and_then(|end| end.checked_add(LEVELDB_BLOCK_TRAILER_BYTES))
        .filter(|end| *end <= footer_start)
        .ok_or(ChromiumLevelDbError::Malformed)?;
    let _ = trailer_end;
    Ok(())
}

fn read_table_block(
    table: &[u8],
    handle: BlockHandle,
    footer_start: usize,
    budget: &mut ParseBudget,
) -> Result<Zeroizing<Vec<u8>>, ChromiumLevelDbError> {
    budget.table_blocks = budget
        .table_blocks
        .checked_add(1)
        .filter(|count| *count <= MAX_TABLE_BLOCKS)
        .ok_or(ChromiumLevelDbError::TooManyEntries)?;
    validate_block_handle(handle, footer_start)?;
    let block_end = handle
        .offset
        .checked_add(handle.size)
        .ok_or(ChromiumLevelDbError::Malformed)?;
    let compression = *table
        .get(block_end)
        .ok_or(ChromiumLevelDbError::Malformed)?;
    let checksum = read_u32_le(table, block_end + 1)?;
    let raw = table
        .get(handle.offset..block_end)
        .ok_or(ChromiumLevelDbError::Malformed)?;
    if masked_crc32c_block(raw, compression) != checksum {
        return Err(ChromiumLevelDbError::Malformed);
    }
    match compression {
        0 => Ok(Zeroizing::new(raw.to_vec())),
        1 => snappy_decompress(raw),
        _ => Err(ChromiumLevelDbError::Malformed),
    }
}

fn parse_prefix_block(
    bytes: &[u8],
    maximum_entries: usize,
    budget: &mut ParseBudget,
) -> Result<Vec<BlockEntry>, ChromiumLevelDbError> {
    if bytes.len() < 8 || bytes.len() > MAX_TABLE_BLOCK_BYTES {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let restart_count = usize::try_from(read_u32_le(bytes, bytes.len() - 4)?)
        .map_err(|_| ChromiumLevelDbError::TooManyEntries)?;
    if restart_count == 0 || restart_count > maximum_entries.saturating_add(1) {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let restart_bytes = restart_count
        .checked_mul(4)
        .and_then(|value| value.checked_add(4))
        .filter(|value| *value <= bytes.len())
        .ok_or(ChromiumLevelDbError::Malformed)?;
    let entries_end = bytes.len() - restart_bytes;
    let restarts = parse_restart_offsets(bytes, entries_end, restart_count)?;
    let mut entries = Vec::new();
    let mut starts = BTreeMap::new();
    let mut offset = 0_usize;
    let mut last_key = Zeroizing::new(Vec::new());
    while offset < entries_end {
        if entries.len() >= maximum_entries {
            return Err(ChromiumLevelDbError::TooManyEntries);
        }
        let entry_start = offset;
        let mut reader = SliceReader::new(&bytes[offset..entries_end]);
        let shared = usize::try_from(
            reader
                .read_varint32()
                .ok_or(ChromiumLevelDbError::Malformed)?,
        )
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
        let non_shared = usize::try_from(
            reader
                .read_varint32()
                .ok_or(ChromiumLevelDbError::Malformed)?,
        )
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
        let value_length = usize::try_from(
            reader
                .read_varint32()
                .ok_or(ChromiumLevelDbError::Malformed)?,
        )
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
        let key_length = shared
            .checked_add(non_shared)
            .ok_or(ChromiumLevelDbError::TooLarge)?;
        if shared > last_key.len()
            || key_length > MAX_LEVELDB_FIELD_BYTES
            || value_length > MAX_LEVELDB_FIELD_BYTES
        {
            return Err(ChromiumLevelDbError::TooLarge);
        }
        let suffix = reader
            .read_exact(non_shared)
            .ok_or(ChromiumLevelDbError::Malformed)?;
        let value = reader
            .read_exact(value_length)
            .ok_or(ChromiumLevelDbError::Malformed)?;
        let consumed = reader.position();
        offset = offset
            .checked_add(consumed)
            .filter(|position| *position <= entries_end)
            .ok_or(ChromiumLevelDbError::Malformed)?;
        reserve_reconstructed_entry_bytes(budget, key_length, value_length)?;
        let mut key = Zeroizing::new(Vec::with_capacity(key_length));
        key.extend_from_slice(&last_key[..shared]);
        key.extend_from_slice(suffix);
        last_key = Zeroizing::new(key.to_vec());
        starts.insert(entry_start, shared);
        entries.push(BlockEntry {
            key: SecretBytes(key),
            value: Zeroizing::new(value.to_vec()),
        });
    }
    if offset != entries_end {
        return Err(ChromiumLevelDbError::Malformed);
    }
    if entries_end == 0 {
        return if restarts == [0] {
            Ok(entries)
        } else {
            Err(ChromiumLevelDbError::Malformed)
        };
    }
    for restart in restarts {
        if starts.get(&restart) != Some(&0) {
            return Err(ChromiumLevelDbError::Malformed);
        }
    }
    Ok(entries)
}

fn parse_restart_offsets(
    bytes: &[u8],
    entries_end: usize,
    restart_count: usize,
) -> Result<Vec<usize>, ChromiumLevelDbError> {
    let mut restarts = Vec::with_capacity(restart_count);
    for index in 0..restart_count {
        let offset = usize::try_from(read_u32_le(bytes, entries_end + index * 4)?)
            .map_err(|_| ChromiumLevelDbError::Malformed)?;
        if offset > entries_end || (index == 0 && offset != 0) {
            return Err(ChromiumLevelDbError::Malformed);
        }
        if index != 0 && restarts.last().is_some_and(|previous| *previous >= offset) {
            return Err(ChromiumLevelDbError::Malformed);
        }
        restarts.push(offset);
    }
    Ok(restarts)
}

fn decode_internal_entry(entry: BlockEntry) -> Result<ParsedRecord, ChromiumLevelDbError> {
    let key = entry.key.0;
    if key.len() < 8 {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let tag_offset = key.len() - 8;
    let tag = read_u64_le(&key, tag_offset)?;
    let sequence = tag >> 8;
    if sequence > LEVELDB_MAX_SEQUENCE {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let value_type = u8::try_from(tag & 0xff).map_err(|_| ChromiumLevelDbError::Malformed)?;
    let user_key = key[..tag_offset].to_vec();
    let value = if value_type == 1 {
        Some(entry.value)
    } else if value_type == 0 && entry.value.is_empty() {
        None
    } else {
        return Err(ChromiumLevelDbError::Malformed);
    };
    Ok(ParsedRecord {
        key: SecretBytes::new(user_key),
        sequence,
        value,
    })
}

fn decode_block_handle(bytes: &[u8]) -> Result<BlockHandle, ChromiumLevelDbError> {
    let mut reader = SliceReader::new(bytes);
    let handle = reader.read_block_handle()?;
    if !reader.is_empty() {
        return Err(ChromiumLevelDbError::Malformed);
    }
    Ok(handle)
}

fn snappy_decompress(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ChromiumLevelDbError> {
    let mut reader = SliceReader::new(bytes);
    let expected_length = usize::try_from(
        reader
            .read_varint32()
            .ok_or(ChromiumLevelDbError::Malformed)?,
    )
    .map_err(|_| ChromiumLevelDbError::TooLarge)?;
    if expected_length > MAX_TABLE_BLOCK_BYTES {
        return Err(ChromiumLevelDbError::TooLarge);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(expected_length));
    while !reader.is_empty() {
        let tag = reader.read_u8().ok_or(ChromiumLevelDbError::Malformed)?;
        match tag & 0x03 {
            0 => {
                let literal_length = snappy_literal_length(tag, &mut reader)?;
                let literal = reader
                    .read_exact(literal_length)
                    .ok_or(ChromiumLevelDbError::Malformed)?;
                append_bounded(&mut output, literal, expected_length)?;
            }
            1 => {
                let length = usize::from((tag >> 2) & 0x07) + 4;
                let low = usize::from(reader.read_u8().ok_or(ChromiumLevelDbError::Malformed)?);
                let offset = (usize::from(tag >> 5) << 8) | low;
                snappy_copy(&mut output, offset, length, expected_length)?;
            }
            2 => {
                let length = usize::from(tag >> 2) + 1;
                let offset = usize::from(reader.read_u16_le()?);
                snappy_copy(&mut output, offset, length, expected_length)?;
            }
            3 => {
                let length = usize::from(tag >> 2) + 1;
                let offset = usize::try_from(reader.read_u32_le()?)
                    .map_err(|_| ChromiumLevelDbError::Malformed)?;
                snappy_copy(&mut output, offset, length, expected_length)?;
            }
            _ => return Err(ChromiumLevelDbError::Malformed),
        }
    }
    if output.len() != expected_length {
        return Err(ChromiumLevelDbError::Malformed);
    }
    Ok(output)
}

fn snappy_literal_length(
    tag: u8,
    reader: &mut SliceReader<'_>,
) -> Result<usize, ChromiumLevelDbError> {
    let encoded = usize::from(tag >> 2);
    if encoded < 60 {
        return Ok(encoded + 1);
    }
    let extra_bytes = encoded - 59;
    let raw = reader
        .read_exact(extra_bytes)
        .ok_or(ChromiumLevelDbError::Malformed)?;
    let mut length_minus_one = 0_usize;
    for (index, byte) in raw.iter().enumerate() {
        let shift = index
            .checked_mul(8)
            .ok_or(ChromiumLevelDbError::Malformed)?;
        length_minus_one |= usize::from(*byte)
            .checked_shl(u32::try_from(shift).map_err(|_| ChromiumLevelDbError::Malformed)?)
            .ok_or(ChromiumLevelDbError::Malformed)?;
    }
    length_minus_one
        .checked_add(1)
        .filter(|length| *length <= MAX_TABLE_BLOCK_BYTES)
        .ok_or(ChromiumLevelDbError::TooLarge)
}

fn snappy_copy(
    output: &mut Vec<u8>,
    offset: usize,
    length: usize,
    expected_length: usize,
) -> Result<(), ChromiumLevelDbError> {
    if offset == 0
        || offset > output.len()
        || output
            .len()
            .checked_add(length)
            .is_none_or(|value| value > expected_length)
    {
        return Err(ChromiumLevelDbError::Malformed);
    }
    let start = output.len() - offset;
    output.reserve(length);
    for index in 0..length {
        let byte = output[start + index % offset];
        output.push(byte);
    }
    Ok(())
}

struct LogicalLocalValue {
    sequence: u64,
    raw_value_length: usize,
    value: Option<Zeroizing<String>>,
}

fn project_local_storage(
    records: &BTreeMap<SecretBytes, VersionedValue>,
    origin: &ChromiumHttpsOrigin,
) -> Result<Vec<ChromiumLocalStorageEntry>, ChromiumLevelDbError> {
    let mut logical = BTreeMap::<SecretBytes, LogicalLocalValue>::new();
    for (raw_key, version) in records {
        let Some((serialized_origin, local_key)) = decode_local_storage_key(raw_key.as_slice())?
        else {
            continue;
        };
        if !storage_origin_matches(&serialized_origin, origin) {
            continue;
        }
        let logical_key = SecretBytes::new(local_key.as_bytes().to_vec());
        let raw_value_length = version.value.as_ref().map_or(0, |value| value.len());
        let decoded = version
            .value
            .as_ref()
            .map(|value| decode_required_text(value.as_slice()))
            .transpose()?;
        match logical.get(logical_key.as_slice()) {
            None => {
                logical.insert(
                    logical_key,
                    LogicalLocalValue {
                        sequence: version.sequence,
                        raw_value_length,
                        value: decoded,
                    },
                );
            }
            Some(existing) if version.sequence > existing.sequence => {
                logical.insert(
                    logical_key,
                    LogicalLocalValue {
                        sequence: version.sequence,
                        raw_value_length,
                        value: decoded,
                    },
                );
            }
            Some(existing) if version.sequence == existing.sequence => {
                if existing.value.as_ref().map(|value| value.as_bytes())
                    != decoded.as_ref().map(|value| value.as_bytes())
                {
                    return Err(ChromiumLevelDbError::Malformed);
                }
            }
            Some(_) => {}
        }
    }
    logical
        .into_iter()
        .filter_map(|(key, selected)| {
            selected.value.map(|value| {
                String::from_utf8(key.0.to_vec())
                    .map_err(|_| ChromiumLevelDbError::Malformed)
                    .map(|key| ChromiumLocalStorageEntry {
                        origin: origin.clone(),
                        key: Zeroizing::new(key),
                        value,
                        raw_value_length: selected.raw_value_length,
                        sequence: selected.sequence,
                    })
            })
        })
        .collect()
}

fn project_text_entries(
    records: &BTreeMap<SecretBytes, VersionedValue>,
) -> Result<Vec<ChromiumLevelDbTextEntry>, ChromiumLevelDbError> {
    let mut output = Vec::new();
    for (key, version) in records {
        let Some(value) = version.value.as_deref() else {
            continue;
        };
        let Some(key) = decode_optional_text(key.as_slice())? else {
            continue;
        };
        let Some(value) = decode_optional_text(value)? else {
            continue;
        };
        if output.len() >= MAX_LEVELDB_ENTRIES {
            return Err(ChromiumLevelDbError::TooManyEntries);
        }
        output.push(ChromiumLevelDbTextEntry {
            key,
            value,
            sequence: version.sequence,
        });
    }
    Ok(output)
}

fn project_token_candidates(
    records: &BTreeMap<SecretBytes, VersionedValue>,
    minimum_bytes: usize,
) -> Result<Vec<ChromiumTokenCandidate>, ChromiumLevelDbError> {
    if minimum_bytes == 0 || minimum_bytes > MAX_TOKEN_BYTES {
        return Err(ChromiumLevelDbError::InvalidTokenPolicy);
    }
    let mut tokens = BTreeSet::<SecretBytes>::new();
    for (key, version) in records {
        scan_tokens(key.as_slice(), minimum_bytes, &mut tokens)?;
        if let Some(value) = version.value.as_deref() {
            scan_tokens(value, minimum_bytes, &mut tokens)?;
        }
    }
    tokens
        .into_iter()
        .map(|token| {
            String::from_utf8(token.0.to_vec())
                .map(Zeroizing::new)
                .map(ChromiumTokenCandidate)
                .map_err(|_| ChromiumLevelDbError::Malformed)
        })
        .collect()
}

fn scan_tokens(
    bytes: &[u8],
    minimum_bytes: usize,
    tokens: &mut BTreeSet<SecretBytes>,
) -> Result<(), ChromiumLevelDbError> {
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if token_byte(byte) {
            start.get_or_insert(index);
            continue;
        }
        if let Some(run_start) = start.take() {
            insert_token_run(&bytes[run_start..index], minimum_bytes, tokens)?;
        }
    }
    if let Some(run_start) = start {
        insert_token_run(&bytes[run_start..], minimum_bytes, tokens)?;
    }
    Ok(())
}

fn insert_token_run(
    run: &[u8],
    minimum_bytes: usize,
    tokens: &mut BTreeSet<SecretBytes>,
) -> Result<(), ChromiumLevelDbError> {
    if run.len() < minimum_bytes || run.len() > MAX_TOKEN_BYTES {
        return Ok(());
    }
    tokens.insert(SecretBytes::new(run.to_vec()));
    if tokens.len() > MAX_TOKEN_CANDIDATES {
        return Err(ChromiumLevelDbError::TooManyEntries);
    }
    Ok(())
}

const fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'/' | b'=')
}

type DecodedLocalStorageKey = (Zeroizing<String>, Zeroizing<String>);

fn decode_local_storage_key(
    bytes: &[u8],
) -> Result<Option<DecodedLocalStorageKey>, ChromiumLevelDbError> {
    let (start, modern) = if bytes.first() == Some(&b'_') {
        (1, true)
    } else {
        (0, false)
    };
    let Some(relative_split) = bytes
        .get(start..)
        .and_then(|tail| tail.iter().position(|byte| *byte == 0))
    else {
        return Ok(None);
    };
    let split = start
        .checked_add(relative_split)
        .ok_or(ChromiumLevelDbError::Malformed)?;
    let origin_bytes = &bytes[start..split];
    let key_bytes = bytes
        .get(split + 1..)
        .ok_or(ChromiumLevelDbError::Malformed)?;
    if origin_bytes.is_empty()
        || origin_bytes.len() > MAX_ORIGIN_BYTES
        || key_bytes.len() > MAX_TEXT_BYTES
    {
        return if origin_bytes.len() > MAX_ORIGIN_BYTES || key_bytes.len() > MAX_TEXT_BYTES {
            Err(ChromiumLevelDbError::TooLarge)
        } else {
            Ok(None)
        };
    }
    let origin = std::str::from_utf8(origin_bytes)
        .ok()
        .map(str::to_owned)
        .map(Zeroizing::new);
    let Some(origin) = origin else {
        return Ok(None);
    };
    if !modern && !looks_like_legacy_origin(&origin) {
        return Ok(None);
    }
    let key = if let Some(decoded) = decode_prefixed_text(key_bytes) {
        bounded_exact_text(decoded)?
    } else if let Some(decoded) = decode_optional_text(key_bytes)? {
        decoded
    } else {
        return Ok(None);
    };
    Ok(Some((origin, key)))
}

fn decode_required_text(bytes: &[u8]) -> Result<Zeroizing<String>, ChromiumLevelDbError> {
    if bytes.len() > MAX_TEXT_BYTES {
        return Err(ChromiumLevelDbError::TooLarge);
    }
    if let Some(decoded) = decode_prefixed_text(bytes) {
        return bounded_exact_text(decoded);
    }
    decode_optional_text(bytes)?.ok_or(ChromiumLevelDbError::Malformed)
}

fn decode_optional_text(bytes: &[u8]) -> Result<Option<Zeroizing<String>>, ChromiumLevelDbError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_TEXT_BYTES {
        return Ok(None);
    }
    if let Some(decoded) = decode_prefixed_text(bytes) {
        return bounded_text(decoded).map(Some);
    }
    if looks_like_utf16(bytes)
        && let Some(decoded) = decode_utf16_le(bytes)
    {
        return bounded_text(decoded).map(Some);
    }
    if let Ok(decoded) = std::str::from_utf8(bytes) {
        return bounded_text(Zeroizing::new(decoded.to_owned())).map(Some);
    }
    if bytes.len().is_multiple_of(2)
        && let Some(decoded) = decode_utf16_le(bytes)
    {
        return bounded_text(decoded).map(Some);
    }
    let decoded = Zeroizing::new(bytes.iter().map(|byte| char::from(*byte)).collect());
    bounded_text(decoded).map(Some)
}

fn decode_prefixed_text(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let (&prefix, payload) = bytes.split_first()?;
    match prefix {
        0 => decode_utf16_le(payload),
        1 => Some(Zeroizing::new(
            payload.iter().map(|byte| char::from(*byte)).collect(),
        )),
        _ => None,
    }
}

fn decode_utf16_le(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let (units, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut output = Zeroizing::new(String::with_capacity(bytes.len() / 2));
    for decoded in char::decode_utf16(units.iter().map(|unit| u16::from_le_bytes(*unit))) {
        output.push(decoded.ok()?);
    }
    Some(output)
}

fn looks_like_utf16(bytes: &[u8]) -> bool {
    if bytes.len() < 6 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let sample = &bytes[..bytes.len().min(64)];
    let odd = sample.iter().skip(1).step_by(2);
    let checked = odd.clone().count();
    checked >= 4 && odd.filter(|byte| **byte == 0).count() * 10 > checked * 6
}

fn bounded_text(value: Zeroizing<String>) -> Result<Zeroizing<String>, ChromiumLevelDbError> {
    let trimmed = Zeroizing::new(value.trim_matches(char::is_control).to_owned());
    if trimmed.len() > MAX_TEXT_BYTES {
        return Err(ChromiumLevelDbError::TooLarge);
    }
    drop(value);
    Ok(trimmed)
}

fn bounded_exact_text(value: Zeroizing<String>) -> Result<Zeroizing<String>, ChromiumLevelDbError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(ChromiumLevelDbError::TooLarge);
    }
    Ok(value)
}

fn parse_https_origin(value: &str) -> Option<ChromiumHttpsOrigin> {
    if value.is_empty() || value.len() > MAX_ORIGIN_BYTES || value.chars().any(char::is_whitespace)
    {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    let parsed_host = url.host()?;
    let (host, display_host) = canonical_host(&parsed_host)?;
    let port = url.port_or_known_default()?;
    let canonical = if port == 443 {
        format!("https://{display_host}")
    } else {
        format!("https://{display_host}:{port}")
    };
    Some(ChromiumHttpsOrigin {
        canonical,
        host,
        port,
    })
}

fn canonical_host(host: &Host<&str>) -> Option<(String, String)> {
    match host {
        Host::Domain(domain) if !domain.is_empty() => {
            let canonical = domain.to_ascii_lowercase();
            Some((canonical.clone(), canonical))
        }
        Host::Ipv4(address) => {
            let canonical = address.to_string();
            Some((canonical.clone(), canonical))
        }
        Host::Ipv6(address) => {
            let canonical = address.to_string();
            Some((canonical.clone(), format!("[{canonical}]")))
        }
        Host::Domain(_) => None,
    }
}

fn storage_origin_matches(serialized: &str, requested: &ChromiumHttpsOrigin) -> bool {
    let base = serialized
        .split_once('^')
        .map_or(serialized, |(base, _partition)| base);
    if base.is_empty() || base.len() > MAX_ORIGIN_BYTES {
        return false;
    }
    if base.contains("://") {
        return parse_https_origin(base).is_some_and(|parsed| parsed == *requested);
    }
    if requested.port != 443 || !looks_like_legacy_origin(base) {
        return false;
    }
    let candidate = format!("https://{base}");
    parse_https_origin(&candidate)
        .is_some_and(|parsed| parsed.port == 443 && parsed.host == requested.host)
}

fn looks_like_legacy_origin(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ORIGIN_BYTES
        && !value.contains(['/', '?', '#', '@'])
        && !value.chars().any(char::is_whitespace)
        && (value == "localhost" || value.contains('.') || value.starts_with('['))
}

struct SliceReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SliceReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_u8(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.position)?;
        self.position += 1;
        Some(value)
    }

    fn read_exact(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(count)?;
        let value = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(value)
    }

    fn read_u16_le(&mut self) -> Result<u16, ChromiumLevelDbError> {
        let bytes: [u8; 2] = self
            .read_exact(2)
            .ok_or(ChromiumLevelDbError::Malformed)?
            .try_into()
            .map_err(|_| ChromiumLevelDbError::Malformed)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32_le(&mut self) -> Result<u32, ChromiumLevelDbError> {
        let bytes: [u8; 4] = self
            .read_exact(4)
            .ok_or(ChromiumLevelDbError::Malformed)?
            .try_into()
            .map_err(|_| ChromiumLevelDbError::Malformed)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_varint32(&mut self) -> Option<u32> {
        let value = self.read_varint(5)?;
        u32::try_from(value).ok()
    }

    fn read_varint64(&mut self) -> Option<u64> {
        self.read_varint(10)
    }

    fn read_varint(&mut self, maximum_bytes: usize) -> Option<u64> {
        let mut value = 0_u64;
        for index in 0..maximum_bytes {
            let byte = self.read_u8()?;
            let payload = u64::from(byte & 0x7f);
            let shift = u32::try_from(index.checked_mul(7)?).ok()?;
            if shift >= 64 || payload.checked_shl(shift)? >> shift != payload {
                return None;
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                if index > 0 && payload == 0 {
                    return None;
                }
                return Some(value);
            }
        }
        None
    }

    fn read_length_prefixed(&mut self, maximum: usize) -> Result<&'a [u8], ChromiumLevelDbError> {
        let length = usize::try_from(
            self.read_varint32()
                .ok_or(ChromiumLevelDbError::Malformed)?,
        )
        .map_err(|_| ChromiumLevelDbError::TooLarge)?;
        if length > maximum {
            return Err(ChromiumLevelDbError::TooLarge);
        }
        self.read_exact(length)
            .ok_or(ChromiumLevelDbError::Malformed)
    }

    fn read_block_handle(&mut self) -> Result<BlockHandle, ChromiumLevelDbError> {
        let offset = usize::try_from(
            self.read_varint64()
                .ok_or(ChromiumLevelDbError::Malformed)?,
        )
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
        let size = usize::try_from(
            self.read_varint64()
                .ok_or(ChromiumLevelDbError::Malformed)?,
        )
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
        Ok(BlockHandle { offset, size })
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, ChromiumLevelDbError> {
    let value: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or(ChromiumLevelDbError::Malformed)?
        .try_into()
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, ChromiumLevelDbError> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(ChromiumLevelDbError::Malformed)?
        .try_into()
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, ChromiumLevelDbError> {
    let value: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or(ChromiumLevelDbError::Malformed)?
        .try_into()
        .map_err(|_| ChromiumLevelDbError::Malformed)?;
    Ok(u64::from_le_bytes(value))
}
