//! Short-lived, read-only SQLite snapshots for provider-owned browser data.
//!
//! Source database and sidecar files are copied into bounded private staging
//! only after their identities and metadata remain stable for the entire copy.
//! SQLite opens only that staging copy, enters a read transaction, and keeps
//! the view stable until drop. It never opens or modifies browser files.

use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};
use tempfile::{Builder as TempDirBuilder, TempDir};
use thiserror::Error;

const MAX_DATABASE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SHARED_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROLLBACK_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const COPY_ATTEMPTS: usize = 3;
const BUSY_TIMEOUT: Duration = Duration::from_millis(100);

/// A transaction-pinned, privately staged view of a provider-owned SQLite file.
///
/// The contained connection is never shared across threads. Callers should run
/// only fixed application-owned queries with explicit row and value limits and
/// then drop the snapshot promptly to remove the sensitive private copy.
pub struct ReadOnlySqliteSnapshot {
    connection: Connection,
    staging: TempDir,
}

impl ReadOnlySqliteSnapshot {
    /// Opens `relative_database` beneath `profile_root` and pins its current
    /// SQLite/WAL view in a read transaction over a private bounded copy.
    ///
    /// # Errors
    ///
    /// Rejects non-absolute roots, non-normal relative paths, path escapes,
    /// symlinks, special files, oversized database sidecars, replacement races,
    /// malformed SQLite content, and unavailable snapshots.
    pub fn open(
        profile_root: impl AsRef<Path>,
        relative_database: impl AsRef<Path>,
    ) -> Result<Self, SqliteSnapshotError> {
        let root = canonical_profile_root(profile_root.as_ref())?;
        let relative = relative_database.as_ref();
        validate_relative_database(relative)?;
        let source_database = root.join(relative);
        let (staging, database) = stage_consistent_snapshot(&root, &source_database, relative)?;

        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection =
            Connection::open_with_flags(&database, flags).map_err(|_| SqliteSnapshotError::Open)?;
        connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
            .map_err(|_| SqliteSnapshotError::Configure)?;
        configure_connection(&connection)?;
        connection
            .execute_batch("BEGIN DEFERRED; SELECT count(*) FROM sqlite_schema;")
            .map_err(|_| SqliteSnapshotError::Snapshot)?;

        Ok(Self {
            connection,
            staging,
        })
    }

    /// Borrows the pinned read-only connection for a fixed, bounded query.
    ///
    /// This seam is public for provider adapters and fixture tests. Dynamic or
    /// user-supplied SQL must never be passed through it.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl Debug for ReadOnlySqliteSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let _staging_lifetime = self.staging.path();
        formatter
            .debug_struct("ReadOnlySqliteSnapshot")
            .field("database", &"<redacted>")
            .field("connection", &"<private>")
            .field("staging", &"<private>")
            .field("mode", &"read-only transaction")
            .finish()
    }
}

/// Stable, path-free failures from browser SQLite snapshot acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SqliteSnapshotError {
    /// The selected profile root was not an absolute, real directory.
    #[error("browser SQLite profile root is invalid")]
    InvalidRoot,
    /// The database name was empty, absolute, or contained traversal syntax.
    #[error("browser SQLite relative path is invalid")]
    InvalidRelativePath,
    /// The selected database does not exist.
    #[error("browser SQLite database is missing")]
    Missing,
    /// A database component or sidecar was a symlink, special file, or escape.
    #[error("browser SQLite file layout is unsafe")]
    UnsafeFile,
    /// The database or one of its sidecars exceeded a fixed byte ceiling.
    #[error("browser SQLite database exceeds its size bound")]
    TooLarge,
    /// SQLite could not create or open the private staged file read-only.
    #[error("browser SQLite database could not be opened")]
    Open,
    /// The connection could not be restricted to the defensive read-only mode.
    #[error("browser SQLite read-only policy could not be applied")]
    Configure,
    /// A consistent schema/WAL read transaction could not be established.
    #[error("browser SQLite snapshot could not be established")]
    Snapshot,
    /// Source database or sidecar metadata kept changing during bounded retries.
    #[error("browser SQLite database changed identity during acquisition")]
    Replaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileSnapshot {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceSnapshot {
    database: FileSnapshot,
    wal: Option<FileSnapshot>,
    shared_memory: Option<FileSnapshot>,
    rollback_journal: Option<FileSnapshot>,
}

enum StageAttemptError {
    Changed,
    Failure(SqliteSnapshotError),
}

impl From<SqliteSnapshotError> for StageAttemptError {
    fn from(error: SqliteSnapshotError) -> Self {
        Self::Failure(error)
    }
}

fn canonical_profile_root(root: &Path) -> Result<PathBuf, SqliteSnapshotError> {
    if !root.is_absolute() {
        return Err(SqliteSnapshotError::InvalidRoot);
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| SqliteSnapshotError::InvalidRoot)?;
    if !metadata.file_type().is_dir() {
        return Err(SqliteSnapshotError::InvalidRoot);
    }
    root.canonicalize()
        .map_err(|_| SqliteSnapshotError::InvalidRoot)
}

fn validate_relative_database(relative: &Path) -> Result<(), SqliteSnapshotError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SqliteSnapshotError::InvalidRelativePath);
    }
    Ok(())
}

fn stage_consistent_snapshot(
    root: &Path,
    source_database: &Path,
    relative_database: &Path,
) -> Result<(TempDir, PathBuf), SqliteSnapshotError> {
    for _attempt in 0..COPY_ATTEMPTS {
        match stage_snapshot_once(root, source_database, relative_database) {
            Ok(staged) => return Ok(staged),
            Err(StageAttemptError::Changed) => {}
            Err(StageAttemptError::Failure(error)) => return Err(error),
        }
    }
    Err(SqliteSnapshotError::Replaced)
}

fn stage_snapshot_once(
    root: &Path,
    source_database: &Path,
    relative_database: &Path,
) -> Result<(TempDir, PathBuf), StageAttemptError> {
    let before = inspect_source_snapshot(root, source_database)?;
    let staging = TempDirBuilder::new()
        .prefix("omarchy-ai-bar-sqlite-")
        .tempdir()
        .map_err(|_| StageAttemptError::Failure(SqliteSnapshotError::Open))?;
    let staged_database = staging.path().join(relative_database);
    let staged_parent = staged_database.parent().ok_or(StageAttemptError::Failure(
        SqliteSnapshotError::InvalidRelativePath,
    ))?;
    fs::create_dir_all(staged_parent)
        .map_err(|_| StageAttemptError::Failure(SqliteSnapshotError::Open))?;

    copy_source_file(
        source_database,
        &staged_database,
        before.database,
        MAX_DATABASE_BYTES,
    )?;
    copy_optional_sidecar(
        source_database,
        &staged_database,
        "-wal",
        before.wal,
        MAX_WAL_BYTES,
    )?;
    copy_optional_sidecar(
        source_database,
        &staged_database,
        "-journal",
        before.rollback_journal,
        MAX_ROLLBACK_JOURNAL_BYTES,
    )?;

    let after =
        inspect_source_snapshot(root, source_database).map_err(|_| StageAttemptError::Changed)?;
    if before != after {
        return Err(StageAttemptError::Changed);
    }
    Ok((staging, staged_database))
}

fn copy_optional_sidecar(
    source_database: &Path,
    staged_database: &Path,
    suffix: &str,
    expected: Option<FileSnapshot>,
    maximum: u64,
) -> Result<(), StageAttemptError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    copy_source_file(
        &sidecar_path(source_database, suffix)?,
        &sidecar_path(staged_database, suffix)?,
        expected,
        maximum,
    )
}

fn copy_source_file(
    source: &Path,
    destination: &Path,
    expected: FileSnapshot,
    maximum: u64,
) -> Result<(), StageAttemptError> {
    let descriptor = open(
        source,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| StageAttemptError::Changed)?;
    let mut source_file = File::from(descriptor);
    let opened = source_file
        .metadata()
        .map_err(|_| StageAttemptError::Changed)?;
    if !opened.file_type().is_file() || FileSnapshot::from_metadata(&opened) != expected {
        return Err(StageAttemptError::Changed);
    }
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| StageAttemptError::Failure(SqliteSnapshotError::Open))?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut source_file).take(maximum.saturating_add(1)),
        &mut destination_file,
    )
    .map_err(|_| StageAttemptError::Failure(SqliteSnapshotError::Open))?;
    destination_file
        .flush()
        .map_err(|_| StageAttemptError::Failure(SqliteSnapshotError::Open))?;
    if copied != expected.size || copied > maximum {
        return Err(StageAttemptError::Changed);
    }
    let copied_from = source_file
        .metadata()
        .map_err(|_| StageAttemptError::Changed)?;
    if FileSnapshot::from_metadata(&copied_from) != expected {
        return Err(StageAttemptError::Changed);
    }
    Ok(())
}

fn inspect_source_snapshot(
    root: &Path,
    database: &Path,
) -> Result<SourceSnapshot, SqliteSnapshotError> {
    Ok(SourceSnapshot {
        database: inspect_required_file(root, database, MAX_DATABASE_BYTES)?,
        wal: inspect_file(root, &sidecar_path(database, "-wal")?, MAX_WAL_BYTES, false)?,
        shared_memory: inspect_file(
            root,
            &sidecar_path(database, "-shm")?,
            MAX_SHARED_MEMORY_BYTES,
            false,
        )?,
        rollback_journal: inspect_file(
            root,
            &sidecar_path(database, "-journal")?,
            MAX_ROLLBACK_JOURNAL_BYTES,
            false,
        )?,
    })
}

fn inspect_required_file(
    root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Result<FileSnapshot, SqliteSnapshotError> {
    inspect_file(root, path, max_bytes, true)?.ok_or(SqliteSnapshotError::Missing)
}

fn inspect_file(
    root: &Path,
    path: &Path,
    max_bytes: u64,
    required: bool,
) -> Result<Option<FileSnapshot>, SqliteSnapshotError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SqliteSnapshotError::Missing);
        }
        Err(_) => return Err(SqliteSnapshotError::UnsafeFile),
    };
    if !metadata.file_type().is_file() {
        return Err(SqliteSnapshotError::UnsafeFile);
    }
    if metadata.len() > max_bytes {
        return Err(SqliteSnapshotError::TooLarge);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| SqliteSnapshotError::UnsafeFile)?;
    if !canonical.starts_with(root) {
        return Err(SqliteSnapshotError::UnsafeFile);
    }
    Ok(Some(FileSnapshot::from_metadata(&metadata)))
}

fn sidecar_path(database: &Path, suffix: &str) -> Result<PathBuf, SqliteSnapshotError> {
    let name = database
        .file_name()
        .ok_or(SqliteSnapshotError::InvalidRelativePath)?;
    let mut sidecar_name = name.to_os_string();
    sidecar_name.push(suffix);
    Ok(database.with_file_name(sidecar_name))
}

fn configure_connection(connection: &Connection) -> Result<(), SqliteSnapshotError> {
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|_| SqliteSnapshotError::Configure)?;
    for (setting, value) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
        (DbConfig::SQLITE_DBCONFIG_DQS_DML, false),
        (DbConfig::SQLITE_DBCONFIG_DQS_DDL, false),
    ] {
        connection
            .set_db_config(setting, value)
            .map_err(|_| SqliteSnapshotError::Configure)?;
    }
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096;")
        .map_err(|_| SqliteSnapshotError::Configure)
}
