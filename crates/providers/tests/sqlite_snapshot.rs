use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use oab_providers::sqlite_snapshot::{ReadOnlySqliteSnapshot, SqliteSnapshotError};
use rusqlite::Connection;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-sqlite-snapshot-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create fixture directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove fixture directory");
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FileObservation {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn observe_file(path: &Path) -> Option<FileObservation> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("observe fixture file: {error}"),
    };
    let metadata = fs::symlink_metadata(path).expect("fixture metadata");
    Some(FileObservation {
        bytes,
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[test]
fn snapshot_reads_uncheckpointed_wal_and_remains_stable() {
    let temporary = TempDirectory::new();
    let database = temporary.path().join("Cookies");
    let writer = Connection::open(&database).expect("open fixture database");
    writer
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             CREATE TABLE cookies(name TEXT NOT NULL);
             INSERT INTO cookies(name) VALUES ('first');",
        )
        .expect("create WAL fixture");
    let wal = temporary.path().join("Cookies-wal");
    let shared_memory = temporary.path().join("Cookies-shm");
    let database_before = observe_file(&database).expect("live database observation");
    let wal_before = observe_file(&wal).expect("live WAL observation");
    let shared_memory_before =
        observe_file(&shared_memory).expect("live shared-memory observation");

    let snapshot = ReadOnlySqliteSnapshot::open(temporary.path(), "Cookies").expect("snapshot");
    let before: i64 = snapshot
        .connection()
        .query_row("SELECT count(*) FROM cookies", [], |row| row.get(0))
        .expect("snapshot row count");
    assert_eq!(before, 1);
    let query_only: i64 = snapshot
        .connection()
        .query_row("PRAGMA query_only", [], |row| row.get(0))
        .expect("query-only state");
    assert_eq!(query_only, 1);
    assert!(
        snapshot
            .connection()
            .execute("INSERT INTO cookies(name) VALUES ('forbidden')", [])
            .is_err()
    );
    assert_eq!(observe_file(&database), Some(database_before));
    assert_eq!(observe_file(&wal), Some(wal_before));
    assert_eq!(observe_file(&shared_memory), Some(shared_memory_before));

    writer
        .execute("INSERT INTO cookies(name) VALUES ('second')", [])
        .expect("append live row");
    let still_pinned: i64 = snapshot
        .connection()
        .query_row("SELECT count(*) FROM cookies", [], |row| row.get(0))
        .expect("stable row count");
    assert_eq!(still_pinned, 1);

    drop(snapshot);
    let refreshed = ReadOnlySqliteSnapshot::open(temporary.path(), "Cookies").expect("refresh");
    let after: i64 = refreshed
        .connection()
        .query_row("SELECT count(*) FROM cookies", [], |row| row.get(0))
        .expect("refreshed row count");
    assert_eq!(after, 2);
}

#[test]
fn missing_source_shm_is_not_created_and_wal_content_remains_visible() {
    let live = TempDirectory::new();
    let source = TempDirectory::new();
    let live_database = live.path().join("Cookies");
    let writer = Connection::open(&live_database).expect("open live fixture database");
    writer
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             CREATE TABLE cookies(name TEXT NOT NULL);
             INSERT INTO cookies(name) VALUES ('from-wal');",
        )
        .expect("create live WAL fixture");
    let source_database = source.path().join("Cookies");
    let source_wal = source.path().join("Cookies-wal");
    fs::copy(&live_database, &source_database).expect("copy fixture database");
    fs::copy(live.path().join("Cookies-wal"), &source_wal).expect("copy fixture WAL");
    drop(writer);

    let source_shm = source.path().join("Cookies-shm");
    let source_journal = source.path().join("Cookies-journal");
    let database_before = observe_file(&source_database).expect("source database observation");
    let wal_before = observe_file(&source_wal).expect("source WAL observation");
    assert_eq!(observe_file(&source_shm), None);
    assert_eq!(observe_file(&source_journal), None);

    let snapshot = ReadOnlySqliteSnapshot::open(source.path(), "Cookies").expect("snapshot");
    let value: String = snapshot
        .connection()
        .query_row("SELECT name FROM cookies", [], |row| row.get(0))
        .expect("WAL-backed row");
    assert_eq!(value, "from-wal");
    drop(snapshot);

    assert_eq!(observe_file(&source_database), Some(database_before));
    assert_eq!(observe_file(&source_wal), Some(wal_before));
    assert_eq!(observe_file(&source_shm), None);
    assert_eq!(observe_file(&source_journal), None);
}

#[test]
fn paths_symlinks_special_files_and_size_are_rejected() {
    let temporary = TempDirectory::new();
    let outside = TempDirectory::new();
    let outside_database = outside.path().join("outside.sqlite");
    Connection::open(&outside_database).expect("outside fixture");

    assert_eq!(
        ReadOnlySqliteSnapshot::open("relative", "Cookies").expect_err("relative root"),
        SqliteSnapshotError::InvalidRoot
    );
    for relative in ["", "../Cookies", "/tmp/Cookies", "nested/../Cookies"] {
        assert_eq!(
            ReadOnlySqliteSnapshot::open(temporary.path(), relative)
                .expect_err("unsafe relative path"),
            SqliteSnapshotError::InvalidRelativePath
        );
    }
    assert_eq!(
        ReadOnlySqliteSnapshot::open(temporary.path(), "missing").expect_err("missing database"),
        SqliteSnapshotError::Missing
    );

    std::os::unix::fs::symlink(&outside_database, temporary.path().join("linked"))
        .expect("database symlink");
    assert_eq!(
        ReadOnlySqliteSnapshot::open(temporary.path(), "linked").expect_err("symlink database"),
        SqliteSnapshotError::UnsafeFile
    );

    mkfifo(
        &temporary.path().join("fifo"),
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .expect("fixture FIFO");
    assert_eq!(
        ReadOnlySqliteSnapshot::open(temporary.path(), "fifo").expect_err("FIFO database"),
        SqliteSnapshotError::UnsafeFile
    );

    let oversized = temporary.path().join("oversized");
    fs::File::create(&oversized)
        .expect("oversized fixture")
        .set_len(256 * 1024 * 1024 + 1)
        .expect("sparse oversized fixture");
    assert_eq!(
        ReadOnlySqliteSnapshot::open(temporary.path(), "oversized")
            .expect_err("oversized database"),
        SqliteSnapshotError::TooLarge
    );
}

#[test]
fn unsafe_sidecars_are_rejected_and_debug_redacts_the_path() {
    let temporary = TempDirectory::new();
    let outside = TempDirectory::new();
    Connection::open(temporary.path().join("Cookies")).expect("fixture database");
    fs::write(outside.path().join("wal"), b"not a WAL").expect("outside sidecar");
    std::os::unix::fs::symlink(
        outside.path().join("wal"),
        temporary.path().join("Cookies-wal"),
    )
    .expect("sidecar symlink");

    assert_eq!(
        ReadOnlySqliteSnapshot::open(temporary.path(), "Cookies").expect_err("unsafe sidecar"),
        SqliteSnapshotError::UnsafeFile
    );
    fs::remove_file(temporary.path().join("Cookies-wal")).expect("remove sidecar");

    let snapshot = ReadOnlySqliteSnapshot::open(temporary.path(), "Cookies").expect("snapshot");
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains(temporary.path().to_string_lossy().as_ref()));
    assert!(!debug.contains("Cookies"));
}

#[test]
fn oversized_sidecar_is_rejected_before_sqlite_opens_it() {
    let temporary = TempDirectory::new();
    Connection::open(temporary.path().join("Cookies")).expect("fixture database");
    fs::File::create(temporary.path().join("Cookies-wal"))
        .expect("oversized WAL fixture")
        .set_len(256 * 1024 * 1024 + 1)
        .expect("sparse oversized WAL fixture");

    assert_eq!(
        ReadOnlySqliteSnapshot::open(temporary.path(), "Cookies").expect_err("oversized WAL"),
        SqliteSnapshotError::TooLarge
    );
}
