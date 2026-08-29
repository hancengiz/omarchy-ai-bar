use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oab_storage::history::{
    HISTORY_SCHEMA_VERSION, HistoryError, HistoryRecord, HistoryRecordError, HistoryRetention,
    HistoryStore, HistoryStoreOptions, MAX_HISTORY_DATABASE_BYTES, MAX_HISTORY_TIMESTAMP_UNIX_MS,
    MAX_HISTORY_VALUE_MICROS,
};
use rusqlite::Connection;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct PrivateFixture {
    root: PathBuf,
}

impl PrivateFixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let epoch_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-{label}-{}-{epoch_nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create isolated fixture directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("make fixture private");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for PrivateFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn retention(max_records: u32) -> HistoryRetention {
    HistoryRetention::new(max_records).expect("valid retention")
}

fn record(timestamp: i64, metric: &str, value_micros: i64) -> HistoryRecord {
    HistoryRecord::new("openai", timestamp, metric, value_micros).expect("valid record")
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn create_private_empty_file(path: &Path) {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private database file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("enforce private mode");
}

fn create_database_with_sql(path: &Path, sql: &str) {
    create_private_empty_file(path);
    let connection = Connection::open(path).expect("open raw fixture database");
    connection.execute_batch(sql).expect("build fixture schema");
    drop(connection);
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("retain private mode");
}

#[test]
fn wal_thread_ownership_retention_order_and_reopen_are_deterministic() {
    let fixture = PrivateFixture::new("history-lifecycle");
    let database = fixture.path("history.sqlite3");
    let caller_thread = thread::current().id();

    let store = HistoryStore::open(&database, retention(3)).expect("open history store");
    assert_eq!(store.worker_info().thread_name(), "omarchy-ai-history");
    assert_ne!(store.worker_info().thread_id(), caller_thread);

    let status = store.status().expect("read verified status");
    assert_eq!(status.journal_mode(), "wal");
    assert!(status.foreign_keys_enabled());
    assert_eq!(status.busy_timeout_ms(), 5_000);
    assert_eq!(status.schema_version(), HISTORY_SCHEMA_VERSION);
    assert_eq!(status.row_count(), 0);
    assert_eq!(
        status.execution().owner_thread_id(),
        store.worker_info().thread_id()
    );
    assert_ne!(status.execution().owner_thread_id(), caller_thread);

    let first = store
        .insert(record(100, "usage.tokens", 1))
        .expect("insert first");
    let second = store
        .insert(record(300, "usage.tokens", 2))
        .expect("insert second");
    let third = store
        .insert(record(300, "usage.tokens", 3))
        .expect("insert tied timestamp");
    let fourth = store
        .insert(record(200, "usage.tokens", 4))
        .expect("insert and retain");
    assert_eq!(first.pruned_records(), 0);
    assert_eq!(second.pruned_records(), 0);
    assert_eq!(third.pruned_records(), 0);
    assert_eq!(fourth.pruned_records(), 1);

    let owner = store.worker_info().thread_id();
    let sequences = [
        status.execution().operation_sequence(),
        first.execution().operation_sequence(),
        second.execution().operation_sequence(),
        third.execution().operation_sequence(),
        fourth.execution().operation_sequence(),
    ];
    assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        [first, second, third, fourth]
            .into_iter()
            .all(|receipt| receipt.execution().owner_thread_id() == owner)
    );

    let query = store.latest(10).expect("query retained history");
    assert_eq!(query.execution().owner_thread_id(), owner);
    assert_eq!(
        query
            .records()
            .iter()
            .map(HistoryRecord::value_micros)
            .collect::<Vec<_>>(),
        vec![3, 2, 4]
    );
    store.shutdown().expect("checkpoint and join");
    assert!(!sidecar(&database, "-wal").exists());
    assert!(!sidecar(&database, "-shm").exists());

    let reopened = HistoryStore::open(&database, retention(3)).expect("reopen history store");
    let reopened_status = reopened.status().expect("read reopened status");
    assert_eq!(reopened_status.journal_mode(), "wal");
    assert_eq!(reopened_status.row_count(), 3);
    assert_ne!(reopened_status.execution().owner_thread_id(), caller_thread);
    assert_eq!(
        reopened
            .latest(10)
            .expect("read persisted history")
            .into_records(),
        vec![
            record(300, "usage.tokens", 3),
            record(300, "usage.tokens", 2),
            record(200, "usage.tokens", 4),
        ]
    );
    reopened.shutdown().expect("close reopened store");
    assert!(!sidecar(&database, "-wal").exists());
    assert!(!sidecar(&database, "-shm").exists());

    let reduced = HistoryStore::open(&database, retention(2)).expect("lower retention on reopen");
    assert_eq!(reduced.status().expect("read reduced count").row_count(), 2);
    assert_eq!(
        reduced
            .latest(10)
            .expect("read startup-retained history")
            .into_records(),
        vec![
            record(300, "usage.tokens", 3),
            record(300, "usage.tokens", 2),
        ]
    );
    reduced.shutdown().expect("close reduced store");
}

#[test]
fn record_boundaries_preserve_exact_text_integer_and_timestamp_mechanics() {
    let fixture = PrivateFixture::new("history-boundaries");
    let database = fixture.path("history.sqlite3");
    let store = HistoryStore::open(&database, retention(2)).expect("open history store");
    let boundary = HistoryRecord::new(
        "provider-1.test",
        MAX_HISTORY_TIMESTAMP_UNIX_MS,
        "cost.usd_micros",
        -MAX_HISTORY_VALUE_MICROS,
    )
    .expect("boundary record");
    store
        .insert(boundary.clone())
        .expect("store exact boundary");
    assert_eq!(
        store.latest(1).expect("read boundary").records(),
        &[boundary]
    );

    assert!(matches!(
        HistoryRecord::new("OpenAI", 0, "usage", 0),
        Err(HistoryRecordError::InvalidIdentifier { .. })
    ));
    assert!(matches!(
        HistoryRecord::new("openai", -1, "usage", 0),
        Err(HistoryRecordError::TimestampOutOfRange { .. })
    ));
    assert!(matches!(
        HistoryRecord::new("openai", 0, "usage", i64::MAX),
        Err(HistoryRecordError::ValueOutOfRange { .. })
    ));
    assert!(matches!(
        store.latest(0),
        Err(HistoryError::InvalidOptions { .. })
    ));
    assert!(matches!(
        HistoryStoreOptions::default().with_busy_timeout(Duration::from_nanos(1)),
        Err(HistoryError::InvalidOptions { .. })
    ));
    store.shutdown().expect("close boundary store");
}

#[test]
fn bounded_channel_reports_backpressure_without_moving_sqlite_to_callers() {
    let fixture = PrivateFixture::new("history-backpressure");
    let database = fixture.path("history.sqlite3");
    let options = HistoryStoreOptions::new(retention(10))
        .with_command_capacity(1)
        .expect("one-slot queue")
        .with_busy_timeout(Duration::from_secs(2))
        .expect("bounded SQLite wait")
        .with_request_timeout(Duration::from_millis(20))
        .expect("short caller wait");
    assert_eq!(options.command_capacity(), 1);
    let store = HistoryStore::open_with_options(&database, options).expect("open history store");

    let blocker_path = database.clone();
    let (locked_sender, locked_receiver) = mpsc::sync_channel(1);
    let blocker = thread::spawn(move || {
        let connection = Connection::open(blocker_path).expect("open independent lock connection");
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold SQLite writer lock");
        locked_sender.send(()).expect("announce writer lock");
        thread::sleep(Duration::from_millis(150));
        connection
            .execute_batch("ROLLBACK")
            .expect("release writer lock");
    });
    locked_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("writer lock acquired");

    assert!(matches!(
        store.insert(record(1, "queue.first", 1)),
        Err(HistoryError::RequestTimeout)
    ));

    let accepted_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match store.insert(record(2, "queue.second", 2)) {
            Err(HistoryError::QueueFull) if Instant::now() < accepted_deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(HistoryError::RequestTimeout) => break,
            result => panic!("second command should enter the one-slot queue: {result:?}"),
        }
    }
    assert!(matches!(
        store.insert(record(3, "queue.third", 3)),
        Err(HistoryError::QueueFull)
    ));

    let shutdown_started = Instant::now();
    store
        .shutdown()
        .expect("priority shutdown skips queued command and joins");
    assert!(shutdown_started.elapsed() < Duration::from_secs(1));
    blocker.join().expect("lock thread exits");

    let reopened = HistoryStore::open(&database, retention(10)).expect("reopen after shutdown");
    assert_eq!(reopened.status().expect("read row count").row_count(), 1);
    assert_eq!(
        reopened
            .latest(10)
            .expect("read completed command")
            .records(),
        &[record(1, "queue.first", 1)]
    );
    reopened.shutdown().expect("close reopened store");
}

#[test]
fn path_and_file_security_are_enforced_and_shutdown_cleans_sidecars() {
    let fixture = PrivateFixture::new("history-path-security");
    let database = fixture.path("history.sqlite3");
    let store = HistoryStore::open(&database, retention(2)).expect("create secure database");
    assert_eq!(
        fs::symlink_metadata(&database)
            .expect("database metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    store
        .insert(record(1, "security", 1))
        .expect("create WAL activity");
    store.shutdown().expect("close secure database");
    assert!(!sidecar(&database, "-wal").exists());
    assert!(!sidecar(&database, "-shm").exists());

    let public_parent = fixture.path("public-parent");
    fs::create_dir(&public_parent).expect("create public parent");
    fs::set_permissions(&public_parent, fs::Permissions::from_mode(0o755))
        .expect("set public mode");
    assert!(matches!(
        HistoryStore::open(public_parent.join("history.sqlite3"), retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    let permissive = fixture.path("permissive.sqlite3");
    create_database_with_sql(&permissive, "PRAGMA user_version=0");
    fs::set_permissions(&permissive, fs::Permissions::from_mode(0o644))
        .expect("make database unsafe");
    assert!(matches!(
        HistoryStore::open(&permissive, retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    let target = fixture.path("target.sqlite3");
    create_private_empty_file(&target);
    let linked = fixture.path("linked.sqlite3");
    symlink(&target, &linked).expect("create database symlink");
    assert!(matches!(
        HistoryStore::open(&linked, retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    let database_directory = fixture.path("directory.sqlite3");
    fs::create_dir(&database_directory).expect("create non-file database path");
    fs::set_permissions(&database_directory, fs::Permissions::from_mode(0o700))
        .expect("set directory mode");
    assert!(matches!(
        HistoryStore::open(&database_directory, retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    let real_parent = fixture.path("real-parent");
    fs::create_dir(&real_parent).expect("create real private parent");
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))
        .expect("set real parent mode");
    let linked_parent = fixture.path("linked-parent");
    symlink(&real_parent, &linked_parent).expect("create parent symlink");
    assert!(matches!(
        HistoryStore::open(linked_parent.join("history.sqlite3"), retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    assert!(HistoryStore::open(fixture.path("missing/history.sqlite3"), retention(1)).is_err());
    assert!(matches!(
        HistoryStore::open(Path::new("relative-history.sqlite3"), retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    let hardlink_target = fixture.path("hardlink-target.sqlite3");
    create_private_empty_file(&hardlink_target);
    let hardlinked_database = fixture.path("hardlinked.sqlite3");
    fs::hard_link(&hardlink_target, &hardlinked_database).expect("create database hard link");
    assert!(matches!(
        HistoryStore::open(&hardlinked_database, retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    let oversized = fixture.path("oversized.sqlite3");
    let oversized_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&oversized)
        .expect("create oversized sparse database");
    oversized_file
        .set_len(MAX_HISTORY_DATABASE_BYTES + 1)
        .expect("size sparse database above bound");
    assert!(matches!(
        HistoryStore::open(&oversized, retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));
}

#[test]
fn hostile_preexisting_wal_and_rollback_journal_are_rejected() {
    let fixture = PrivateFixture::new("history-sidecar-security");
    let sidecar_database = fixture.path("sidecar.sqlite3");
    HistoryStore::open(&sidecar_database, retention(1))
        .expect("initialize sidecar fixture")
        .shutdown()
        .expect("close sidecar fixture");
    let unsafe_wal = sidecar(&sidecar_database, "-wal");
    create_private_empty_file(&unsafe_wal);
    fs::set_permissions(&unsafe_wal, fs::Permissions::from_mode(0o644))
        .expect("make pre-existing WAL unsafe");
    assert!(matches!(
        HistoryStore::open(&sidecar_database, retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));

    let journal_database = fixture.path("journal.sqlite3");
    HistoryStore::open(&journal_database, retention(1))
        .expect("initialize rollback-journal fixture")
        .shutdown()
        .expect("close rollback-journal fixture");
    let journal_target = fixture.path("hostile-journal-target");
    create_private_empty_file(&journal_target);
    symlink(&journal_target, sidecar(&journal_database, "-journal"))
        .expect("create hostile rollback-journal symlink");
    assert!(matches!(
        HistoryStore::open(&journal_database, retention(1)),
        Err(HistoryError::UnsafePath { .. })
    ));
}

#[test]
fn malformed_and_future_schemas_are_rejected_without_replacement() {
    let fixture = PrivateFixture::new("history-schema-rejection");
    let malformed = fixture.path("malformed.sqlite3");
    create_database_with_sql(
        &malformed,
        "CREATE TABLE history_records (wrong TEXT); PRAGMA user_version=1;",
    );
    assert!(matches!(
        HistoryStore::open(&malformed, retention(1)),
        Err(HistoryError::MalformedSchema { .. })
    ));
    assert!(malformed.is_file());

    let future = fixture.path("future.sqlite3");
    create_database_with_sql(&future, "PRAGMA user_version=2;");
    assert!(matches!(
        HistoryStore::open(&future, retention(1)),
        Err(HistoryError::FutureSchema {
            found: 2,
            supported: HISTORY_SCHEMA_VERSION,
        })
    ));
    assert!(future.is_file());
}
