//! Bounded, non-secret history persisted by one SQLite-owning thread.
//!
//! The connection is constructed and used only by the named worker thread.
//! Callers communicate through a bounded synchronous channel and receive a
//! per-operation execution receipt, so neither a connection mutex nor an
//! unbounded work queue can accidentally be introduced.

use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File, OpenOptions};
use std::num::NonZeroU32;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use thiserror::Error;

use nix::unistd::geteuid;

/// Maximum UTF-8 bytes accepted in a provider or metric identifier.
pub const MAX_HISTORY_IDENTIFIER_BYTES: usize = 64;
/// Maximum retained records supported by one history store.
pub const MAX_HISTORY_RECORDS: u32 = 25_000;
/// Maximum accepted size of the main application-owned history database.
pub const MAX_HISTORY_DATABASE_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum records returned by one query.
pub const MAX_HISTORY_QUERY_RECORDS: u32 = 1_000;
/// Latest Unix timestamp representable by this schema (9999-12-31T23:59:59.999Z).
pub const MAX_HISTORY_TIMESTAMP_UNIX_MS: i64 = 253_402_300_799_999;
/// Largest magnitude accepted for an exact fixed-point history value.
pub const MAX_HISTORY_VALUE_MICROS: i64 = 9_000_000_000_000_000;
/// Current on-disk history schema version.
pub const HISTORY_SCHEMA_VERSION: u32 = 1;

const DATABASE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MASK: u32 = 0o077;
const DEFAULT_COMMAND_CAPACITY: usize = 64;
const MAX_COMMAND_CAPACITY: usize = 1_024;
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONFIGURED_TIMEOUT: Duration = Duration::from_secs(30);
const WORKER_NAME: &str = "omarchy-ai-history";
const WORKER_IDLE_POLL: Duration = Duration::from_millis(10);

const CREATE_TABLE_SQL: &str = "CREATE TABLE history_records (\
\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\
\n    provider_id TEXT NOT NULL,\
\n    observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms >= 0 AND observed_at_unix_ms <= 253402300799999),\
\n    metric_id TEXT NOT NULL,\
\n    value_micros INTEGER NOT NULL CHECK (value_micros >= -9000000000000000 AND value_micros <= 9000000000000000)\
\n) STRICT";
const CREATE_ORDER_INDEX_SQL: &str = "CREATE INDEX history_records_order \
    ON history_records(observed_at_unix_ms DESC, id DESC)";

/// A bounded, canonical, non-secret identifier stored in history.
///
/// Identifiers use lowercase ASCII letters, digits, `.`, `_`, and `-`. The
/// first character must be alphanumeric. Arbitrary labels, account IDs,
/// e-mail addresses, credentials, and provider response text do not belong in
/// this type or in the history schema.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryIdentifier(Box<str>);

impl HistoryIdentifier {
    /// Validates and constructs a history identifier.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryRecordError::InvalidIdentifier`] when the value is
    /// empty, oversized, or not in canonical identifier form.
    pub fn new(value: impl AsRef<str>) -> Result<Self, HistoryRecordError> {
        let value = value.as_ref();
        let valid_length = !value.is_empty() && value.len() <= MAX_HISTORY_IDENTIFIER_BYTES;
        let mut bytes = value.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        let valid_rest = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });

        if !valid_length || !valid_first || !valid_rest {
            return Err(HistoryRecordError::InvalidIdentifier {
                maximum_bytes: MAX_HISTORY_IDENTIFIER_BYTES,
            });
        }

        Ok(Self(value.into()))
    }

    /// Returns the canonical identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for HistoryIdentifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HistoryIdentifier")
            .field(&self.0)
            .finish()
    }
}

/// One exact, bounded history sample.
///
/// Values are fixed-point micro-units rather than floating point, so a value
/// survives SQLite and Rust round trips exactly. Timestamps are Unix
/// milliseconds and text is restricted to non-secret canonical identifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRecord {
    provider_id: HistoryIdentifier,
    observed_at_unix_ms: i64,
    metric_id: HistoryIdentifier,
    value_micros: i64,
}

impl HistoryRecord {
    /// Constructs a validated history sample.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical identifier, an out-of-range
    /// timestamp, or a value outside the exact fixed-point storage bound.
    pub fn new(
        provider_id: impl AsRef<str>,
        observed_at_unix_ms: i64,
        metric_id: impl AsRef<str>,
        value_micros: i64,
    ) -> Result<Self, HistoryRecordError> {
        if !(0..=MAX_HISTORY_TIMESTAMP_UNIX_MS).contains(&observed_at_unix_ms) {
            return Err(HistoryRecordError::TimestampOutOfRange {
                value: observed_at_unix_ms,
            });
        }
        if !(-MAX_HISTORY_VALUE_MICROS..=MAX_HISTORY_VALUE_MICROS).contains(&value_micros) {
            return Err(HistoryRecordError::ValueOutOfRange {
                value: value_micros,
            });
        }

        Ok(Self {
            provider_id: HistoryIdentifier::new(provider_id)?,
            observed_at_unix_ms,
            metric_id: HistoryIdentifier::new(metric_id)?,
            value_micros,
        })
    }

    /// Returns the non-secret provider identifier.
    #[must_use]
    pub const fn provider_id(&self) -> &HistoryIdentifier {
        &self.provider_id
    }

    /// Returns the observation time as exact Unix milliseconds.
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }

    /// Returns the canonical metric identifier.
    #[must_use]
    pub const fn metric_id(&self) -> &HistoryIdentifier {
        &self.metric_id
    }

    /// Returns the exact fixed-point value in micro-units.
    #[must_use]
    pub const fn value_micros(&self) -> i64 {
        self.value_micros
    }
}

/// Validation failure for a history record.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum HistoryRecordError {
    /// An identifier was not in the deliberately narrow safe alphabet.
    #[error("history identifier must be 1..={maximum_bytes} bytes of canonical lowercase ASCII")]
    InvalidIdentifier { maximum_bytes: usize },
    /// A timestamp could not be represented by the stable schema.
    #[error("history timestamp {value} is outside the supported Unix-millisecond range")]
    TimestampOutOfRange { value: i64 },
    /// A fixed-point numeric value exceeded the deliberately bounded range.
    #[error("history micro-unit value {value} is outside the supported range")]
    ValueOutOfRange { value: i64 },
}

/// Deterministic count retention for application-owned history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryRetention(NonZeroU32);

impl HistoryRetention {
    /// Constructs a retention limit.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::InvalidOptions`] for zero or more than
    /// [`MAX_HISTORY_RECORDS`] records.
    pub fn new(max_records: u32) -> Result<Self, HistoryError> {
        let value = NonZeroU32::new(max_records).ok_or(HistoryError::InvalidOptions {
            reason: "history retention must be nonzero",
        })?;
        if max_records > MAX_HISTORY_RECORDS {
            return Err(HistoryError::InvalidOptions {
                reason: "history retention exceeds the supported maximum",
            });
        }
        Ok(Self(value))
    }

    /// Returns the number of records kept after each successful insert.
    #[must_use]
    pub const fn max_records(self) -> u32 {
        self.0.get()
    }
}

impl Default for HistoryRetention {
    fn default() -> Self {
        Self(NonZeroU32::new(MAX_HISTORY_RECORDS).expect("history maximum is nonzero"))
    }
}

/// Validated worker and SQLite timeout configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryStoreOptions {
    retention: HistoryRetention,
    command_capacity: usize,
    busy_timeout: Duration,
    request_timeout: Duration,
}

impl HistoryStoreOptions {
    /// Creates options with bounded production defaults.
    #[must_use]
    pub const fn new(retention: HistoryRetention) -> Self {
        Self {
            retention,
            command_capacity: DEFAULT_COMMAND_CAPACITY,
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// Sets the bounded command-channel capacity.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or more than 1,024 queued commands.
    pub fn with_command_capacity(mut self, capacity: usize) -> Result<Self, HistoryError> {
        if !(1..=MAX_COMMAND_CAPACITY).contains(&capacity) {
            return Err(HistoryError::InvalidOptions {
                reason: "history command capacity must be between 1 and 1024",
            });
        }
        self.command_capacity = capacity;
        Ok(self)
    }

    /// Sets SQLite's lock-contention deadline.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero timeout or one above 30 seconds.
    pub fn with_busy_timeout(mut self, timeout: Duration) -> Result<Self, HistoryError> {
        validate_timeout(timeout, "SQLite busy timeout")?;
        self.busy_timeout = timeout;
        Ok(self)
    }

    /// Sets the caller's request/reply deadline.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero timeout or one above 30 seconds.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Result<Self, HistoryError> {
        validate_timeout(timeout, "history request timeout")?;
        self.request_timeout = timeout;
        Ok(self)
    }

    /// Returns the configured retention limit.
    #[must_use]
    pub const fn retention(self) -> HistoryRetention {
        self.retention
    }

    /// Returns the exact command queue capacity.
    #[must_use]
    pub const fn command_capacity(self) -> usize {
        self.command_capacity
    }
}

impl Default for HistoryStoreOptions {
    fn default() -> Self {
        Self::new(HistoryRetention::default())
    }
}

/// Proof that a database operation ran on the dedicated storage thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageExecution {
    owner_thread_id: ThreadId,
    operation_sequence: u64,
}

impl StorageExecution {
    /// Returns the stable worker thread identity.
    #[must_use]
    pub const fn owner_thread_id(self) -> ThreadId {
        self.owner_thread_id
    }

    /// Returns the monotonically increasing high-level database operation number.
    #[must_use]
    pub const fn operation_sequence(self) -> u64 {
        self.operation_sequence
    }
}

/// Stable worker identity established during database initialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageThreadInfo {
    thread_id: ThreadId,
    thread_name: &'static str,
}

impl StorageThreadInfo {
    /// Returns the worker thread identity.
    #[must_use]
    pub const fn thread_id(&self) -> ThreadId {
        self.thread_id
    }

    /// Returns the fixed worker thread name.
    #[must_use]
    pub const fn thread_name(&self) -> &'static str {
        self.thread_name
    }
}

/// Result of inserting and applying retention in one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsertReceipt {
    execution: StorageExecution,
    pruned_records: u32,
}

impl InsertReceipt {
    /// Returns execution identity and sequence.
    #[must_use]
    pub const fn execution(self) -> StorageExecution {
        self.execution
    }

    /// Returns the number of old rows removed by retention.
    #[must_use]
    pub const fn pruned_records(self) -> u32 {
        self.pruned_records
    }
}

/// A bounded, newest-first history query result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryQuery {
    records: Vec<HistoryRecord>,
    execution: StorageExecution,
}

impl HistoryQuery {
    /// Returns records ordered by timestamp descending and insertion ID descending.
    #[must_use]
    pub fn records(&self) -> &[HistoryRecord] {
        &self.records
    }

    /// Consumes the result and returns its records.
    #[must_use]
    pub fn into_records(self) -> Vec<HistoryRecord> {
        self.records
    }

    /// Returns execution identity and sequence.
    #[must_use]
    pub const fn execution(&self) -> StorageExecution {
        self.execution
    }
}

/// Verified connection state and row count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryStatus {
    journal_mode: Box<str>,
    foreign_keys_enabled: bool,
    busy_timeout_ms: u64,
    schema_version: u32,
    row_count: u32,
    execution: StorageExecution,
}

impl HistoryStatus {
    /// Returns SQLite's normalized journal mode.
    #[must_use]
    pub fn journal_mode(&self) -> &str {
        &self.journal_mode
    }

    /// Reports whether foreign-key enforcement is active on the worker connection.
    #[must_use]
    pub const fn foreign_keys_enabled(&self) -> bool {
        self.foreign_keys_enabled
    }

    /// Returns SQLite's effective busy timeout in milliseconds.
    #[must_use]
    pub const fn busy_timeout_ms(&self) -> u64 {
        self.busy_timeout_ms
    }

    /// Returns the accepted schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the exact number of retained rows.
    #[must_use]
    pub const fn row_count(&self) -> u32 {
        self.row_count
    }

    /// Returns execution identity and sequence.
    #[must_use]
    pub const fn execution(&self) -> StorageExecution {
        self.execution
    }
}

/// Typed failure from validation, queueing, SQLite, or worker lifecycle.
#[derive(Debug, Error)]
pub enum HistoryError {
    /// A record failed its public boundary validation.
    #[error(transparent)]
    InvalidRecord(#[from] HistoryRecordError),
    /// Store options were outside their documented bounds.
    #[error("invalid history-store options: {reason}")]
    InvalidOptions { reason: &'static str },
    /// A database path or its private parent was unsafe.
    #[error("unsafe history path {path:?}: {reason}")]
    UnsafePath { path: PathBuf, reason: &'static str },
    /// A filesystem operation failed.
    #[error("could not {operation} history path {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// SQLite rejected an operation.
    #[error("SQLite history operation {operation} failed: {source}")]
    Database {
        operation: &'static str,
        #[source]
        source: rusqlite::Error,
    },
    /// The database belongs to newer software and must not be modified.
    #[error("history schema version {found} is newer than supported version {supported}")]
    FutureSchema { found: u32, supported: u32 },
    /// The declared schema did not match the exact supported schema.
    #[error("malformed history schema: {reason}")]
    MalformedSchema { reason: &'static str },
    /// The bounded command queue had no free slot.
    #[error("history command queue is full")]
    QueueFull,
    /// The worker did not reply before the configured deadline.
    #[error("history worker request timed out")]
    RequestTimeout,
    /// The worker channel closed unexpectedly.
    #[error("history worker stopped unexpectedly")]
    WorkerStopped,
    /// The named worker thread panicked.
    #[error("history worker thread panicked")]
    WorkerPanicked,
    /// The process executed more operations than its stable receipt can represent.
    #[error("history operation sequence is exhausted")]
    OperationSequenceExhausted,
    /// SQLite could not fully checkpoint before shutdown.
    #[error("history WAL checkpoint remained busy")]
    CheckpointBusy,
}

/// Handle for the bounded request/reply history worker.
pub struct HistoryStore {
    sender: Option<SyncSender<Command>>,
    worker: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    shutdown_result: Option<Receiver<Result<(), HistoryError>>>,
    worker_info: StorageThreadInfo,
    request_timeout: Duration,
}

impl Debug for HistoryStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoryStore")
            .field("worker_info", &self.worker_info)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl HistoryStore {
    /// Opens or creates a history database with default worker settings.
    ///
    /// The parent directory must already exist, contain no symlink component,
    /// be a directory, and grant no group or other permissions. A newly
    /// created database is mode `0600`; an existing database must already be a
    /// regular, non-symlink mode-`0600` file.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, an unsupported or malformed
    /// schema, failure to enable WAL, worker startup failure, or I/O failure.
    pub fn open(path: impl AsRef<Path>, retention: HistoryRetention) -> Result<Self, HistoryError> {
        Self::open_with_options(path, HistoryStoreOptions::new(retention))
    }

    /// Opens or creates a history database with explicit bounded settings.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::open`], plus invalid options.
    pub fn open_with_options(
        path: impl AsRef<Path>,
        options: HistoryStoreOptions,
    ) -> Result<Self, HistoryError> {
        validate_options(options)?;
        let prepared = prepare_database_path(path.as_ref())?;
        let (sender, receiver) = mpsc::sync_channel(options.command_capacity);
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let (shutdown_sender, shutdown_receiver) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_prepared = prepared.clone();
        let worker = thread::Builder::new()
            .name(WORKER_NAME.to_owned())
            .spawn(move || {
                worker_main(
                    &worker_prepared,
                    options,
                    &receiver,
                    &startup_sender,
                    worker_stop.as_ref(),
                    &shutdown_sender,
                );
            })
            .map_err(|source| HistoryError::Io {
                operation: "spawn the storage worker for",
                path: prepared.path.clone(),
                source,
            })?;

        let startup_result = startup_receiver.recv_timeout(options.request_timeout);
        match startup_result {
            Ok(Ok(worker_info)) => Ok(Self {
                sender: Some(sender),
                worker: Some(worker),
                stop,
                shutdown_result: Some(shutdown_receiver),
                worker_info,
                request_timeout: options.request_timeout,
            }),
            Ok(Err(error)) => {
                stop.store(true, Ordering::Release);
                drop(sender);
                join_worker(worker)?;
                Err(error)
            }
            Err(RecvTimeoutError::Timeout) => {
                stop.store(true, Ordering::Release);
                drop(sender);
                join_worker(worker)?;
                Err(HistoryError::RequestTimeout)
            }
            Err(RecvTimeoutError::Disconnected) => {
                stop.store(true, Ordering::Release);
                drop(sender);
                join_worker(worker)?;
                Err(HistoryError::WorkerStopped)
            }
        }
    }

    /// Returns the stable identity of the dedicated worker.
    #[must_use]
    pub const fn worker_info(&self) -> &StorageThreadInfo {
        &self.worker_info
    }

    /// Inserts one record and applies deterministic retention atomically.
    ///
    /// Enqueueing is non-blocking. A saturated command channel returns
    /// [`HistoryError::QueueFull`] immediately; an accepted command has the
    /// configured reply deadline. A timed-out insert may still finish on the
    /// worker; callers that require idempotency must supply that policy above
    /// this low-level append-only store.
    ///
    /// # Errors
    ///
    /// Returns a queue, timeout, lifecycle, or SQLite error.
    pub fn insert(&self, record: HistoryRecord) -> Result<InsertReceipt, HistoryError> {
        self.request(|reply| Command::Insert { record, reply })
    }

    /// Reads a bounded number of records in deterministic newest-first order.
    ///
    /// # Errors
    ///
    /// Returns an option error for a zero or oversized limit, or a queue,
    /// timeout, lifecycle, validation, or SQLite error.
    pub fn latest(&self, limit: u32) -> Result<HistoryQuery, HistoryError> {
        if !(1..=MAX_HISTORY_QUERY_RECORDS).contains(&limit) {
            return Err(HistoryError::InvalidOptions {
                reason: "history query limit must be between 1 and 1000",
            });
        }
        self.request(|reply| Command::Latest { limit, reply })
    }

    /// Reads and re-verifies connection pragmas, schema version, and row count.
    ///
    /// # Errors
    ///
    /// Returns a queue, timeout, lifecycle, or SQLite error.
    pub fn status(&self) -> Result<HistoryStatus, HistoryError> {
        self.request(|reply| Command::Status { reply })
    }

    /// Checkpoints WAL, closes SQLite, and joins the owning thread.
    ///
    /// # Errors
    ///
    /// Returns a checkpoint error or reports a worker panic. Shutdown uses an
    /// out-of-band stop flag, so queued work is abandoned rather than drained;
    /// only an operation already executing can delay the join, and that
    /// operation remains bounded by SQLite's configured busy timeout.
    pub fn shutdown(mut self) -> Result<(), HistoryError> {
        self.shutdown_inner()
    }

    fn request<T>(
        &self,
        make_command: impl FnOnce(SyncSender<Result<T, HistoryError>>) -> Command,
    ) -> Result<T, HistoryError> {
        let sender = self.sender.as_ref().ok_or(HistoryError::WorkerStopped)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        match sender.try_send(make_command(reply)) {
            Ok(()) => receive_reply(&receiver, self.request_timeout),
            Err(TrySendError::Full(_)) => Err(HistoryError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(HistoryError::WorkerStopped),
        }
    }

    fn shutdown_inner(&mut self) -> Result<(), HistoryError> {
        if self.worker.is_none() {
            return Ok(());
        }
        self.stop.store(true, Ordering::Release);
        drop(self.sender.take());
        let join_result = self.worker.take().map_or(Ok(()), join_worker);
        let shutdown_result = self
            .shutdown_result
            .take()
            .ok_or(HistoryError::WorkerStopped)
            .and_then(|receiver| receiver.recv().map_err(|_| HistoryError::WorkerStopped))
            .and_then(|result| result);
        match join_result {
            Ok(()) => shutdown_result,
            Err(error) => Err(error),
        }
    }
}

impl Drop for HistoryStore {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

#[derive(Clone)]
struct PreparedDatabase {
    path: PathBuf,
    identity: FileIdentity,
    created: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

enum Command {
    Insert {
        record: HistoryRecord,
        reply: SyncSender<Result<InsertReceipt, HistoryError>>,
    },
    Latest {
        limit: u32,
        reply: SyncSender<Result<HistoryQuery, HistoryError>>,
    },
    Status {
        reply: SyncSender<Result<HistoryStatus, HistoryError>>,
    },
}

struct WorkerState {
    connection: Connection,
    retention: HistoryRetention,
    owner_thread_id: ThreadId,
    operation_sequence: u64,
}

impl WorkerState {
    fn next_execution(&mut self) -> Result<StorageExecution, HistoryError> {
        self.operation_sequence = self
            .operation_sequence
            .checked_add(1)
            .ok_or(HistoryError::OperationSequenceExhausted)?;
        Ok(StorageExecution {
            owner_thread_id: self.owner_thread_id,
            operation_sequence: self.operation_sequence,
        })
    }

    fn insert(&mut self, record: &HistoryRecord) -> Result<InsertReceipt, HistoryError> {
        let execution = self.next_execution()?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|source| database_error("begin insert transaction", source))?;
        insert_record(&transaction, record)?;
        let pruned_records = prune_records(&transaction, self.retention)?;
        transaction
            .commit()
            .map_err(|source| database_error("commit insert transaction", source))?;
        Ok(InsertReceipt {
            execution,
            pruned_records,
        })
    }

    fn latest(&mut self, limit: u32) -> Result<HistoryQuery, HistoryError> {
        let execution = self.next_execution()?;
        let records = query_latest(&self.connection, limit)?;
        Ok(HistoryQuery { records, execution })
    }

    fn status(&mut self) -> Result<HistoryStatus, HistoryError> {
        let execution = self.next_execution()?;
        read_status(&self.connection, execution)
    }
}

fn worker_main(
    prepared: &PreparedDatabase,
    options: HistoryStoreOptions,
    receiver: &Receiver<Command>,
    startup: &SyncSender<Result<StorageThreadInfo, HistoryError>>,
    stop: &AtomicBool,
    shutdown_result: &SyncSender<Result<(), HistoryError>>,
) {
    let owner_thread_id = thread::current().id();
    let connection = match initialize_connection(prepared, options.busy_timeout, options.retention)
    {
        Ok(connection) => connection,
        Err(error) => {
            let _ = startup.send(Err(error));
            if prepared.created {
                cleanup_failed_new_database(prepared);
            }
            return;
        }
    };
    let worker_info = StorageThreadInfo {
        thread_id: owner_thread_id,
        thread_name: WORKER_NAME,
    };
    if startup.send(Ok(worker_info)).is_err() {
        let _ = shutdown_connection(&connection);
        return;
    }

    let mut state = WorkerState {
        connection,
        retention: options.retention,
        owner_thread_id,
        operation_sequence: 0,
    };
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let command = match receiver.recv_timeout(WORKER_IDLE_POLL) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if stop.load(Ordering::Acquire) {
            break;
        }
        match command {
            Command::Insert { record, reply } => {
                let _ = reply.send(state.insert(&record));
            }
            Command::Latest { limit, reply } => {
                let _ = reply.send(state.latest(limit));
            }
            Command::Status { reply } => {
                let _ = reply.send(state.status());
            }
        }
    }
    let result = shutdown_connection(&state.connection);
    drop(state);
    let _ = shutdown_result.send(result);
}

fn initialize_connection(
    prepared: &PreparedDatabase,
    busy_timeout: Duration,
    retention: HistoryRetention,
) -> Result<Connection, HistoryError> {
    validate_prepared_identity(prepared)?;
    validate_sidecars(&prepared.path)?;
    let mut connection = Connection::open_with_flags(
        &prepared.path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|source| database_error("open database", source))?;
    validate_prepared_identity(prepared)?;
    connection
        .busy_timeout(busy_timeout)
        .map_err(|source| database_error("set busy timeout", source))?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON")
        .map_err(|source| database_error("enable foreign keys", source))?;

    let version = read_schema_version(&connection)?;
    if version > HISTORY_SCHEMA_VERSION {
        return Err(HistoryError::FutureSchema {
            found: version,
            supported: HISTORY_SCHEMA_VERSION,
        });
    }
    migrate_schema(&mut connection, version)?;
    verify_schema(&connection)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|source| database_error("enable WAL", source))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(HistoryError::MalformedSchema {
            reason: "SQLite did not accept WAL journal mode",
        });
    }
    enforce_retention(&mut connection, retention)?;
    let status = read_status(
        &connection,
        StorageExecution {
            owner_thread_id: thread::current().id(),
            operation_sequence: 0,
        },
    )?;
    if status.journal_mode() != "wal"
        || !status.foreign_keys_enabled()
        || status.schema_version() != HISTORY_SCHEMA_VERSION
    {
        return Err(HistoryError::MalformedSchema {
            reason: "required SQLite pragmas were not active",
        });
    }
    Ok(connection)
}

fn migrate_schema(connection: &mut Connection, version: u32) -> Result<(), HistoryError> {
    match version {
        0 => {
            let application_objects: u32 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|source| database_error("inspect unversioned schema", source))?;
            if application_objects != 0 {
                return Err(HistoryError::MalformedSchema {
                    reason: "unversioned database contains application objects",
                });
            }
            let transaction = connection
                .transaction()
                .map_err(|source| database_error("begin schema migration", source))?;
            transaction
                .execute(CREATE_TABLE_SQL, [])
                .map_err(|source| database_error("create history table", source))?;
            transaction
                .execute(CREATE_ORDER_INDEX_SQL, [])
                .map_err(|source| database_error("create history index", source))?;
            transaction
                .pragma_update(None, "user_version", HISTORY_SCHEMA_VERSION)
                .map_err(|source| database_error("write schema version", source))?;
            transaction
                .commit()
                .map_err(|source| database_error("commit schema migration", source))?;
            Ok(())
        }
        HISTORY_SCHEMA_VERSION => Ok(()),
        _ => Err(HistoryError::MalformedSchema {
            reason: "no migration exists for the declared schema version",
        }),
    }
}

fn verify_schema(connection: &Connection) -> Result<(), HistoryError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(|source| database_error("check database integrity", source))?;
    if integrity != "ok" {
        return Err(HistoryError::MalformedSchema {
            reason: "SQLite integrity check failed",
        });
    }

    let table_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='history_records'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| database_error("verify history table", source))?;
    if table_sql.as_deref() != Some(CREATE_TABLE_SQL) {
        return Err(HistoryError::MalformedSchema {
            reason: "history table definition differs from the supported schema",
        });
    }
    let index_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='index' AND name='history_records_order'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| database_error("verify history index", source))?;
    if index_sql.as_deref() != Some(CREATE_ORDER_INDEX_SQL) {
        return Err(HistoryError::MalformedSchema {
            reason: "history ordering index differs from the supported schema",
        });
    }

    let unexpected_objects: u32 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' \
             AND name NOT IN ('history_records', 'history_records_order')",
            [],
            |row| row.get(0),
        )
        .map_err(|source| database_error("verify schema objects", source))?;
    if unexpected_objects != 0 {
        return Err(HistoryError::MalformedSchema {
            reason: "history database contains unexpected schema objects",
        });
    }
    Ok(())
}

fn insert_record(
    transaction: &Transaction<'_>,
    record: &HistoryRecord,
) -> Result<(), HistoryError> {
    transaction
        .execute(
            "INSERT INTO history_records \
             (provider_id, observed_at_unix_ms, metric_id, value_micros) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.provider_id().as_str(),
                record.observed_at_unix_ms(),
                record.metric_id().as_str(),
                record.value_micros(),
            ],
        )
        .map_err(|source| database_error("insert history record", source))?;
    Ok(())
}

fn prune_records(
    transaction: &Transaction<'_>,
    retention: HistoryRetention,
) -> Result<u32, HistoryError> {
    let removed = transaction
        .execute(
            "DELETE FROM history_records WHERE id IN (\
             SELECT id FROM history_records \
             ORDER BY observed_at_unix_ms DESC, id DESC \
             LIMIT -1 OFFSET ?1)",
            [retention.max_records()],
        )
        .map_err(|source| database_error("apply history retention", source))?;
    u32::try_from(removed).map_err(|_| HistoryError::MalformedSchema {
        reason: "retention removed an unrepresentable row count",
    })
}

fn enforce_retention(
    connection: &mut Connection,
    retention: HistoryRetention,
) -> Result<(), HistoryError> {
    let transaction = connection
        .transaction()
        .map_err(|source| database_error("begin startup retention transaction", source))?;
    let _ = prune_records(&transaction, retention)?;
    transaction
        .commit()
        .map_err(|source| database_error("commit startup retention transaction", source))
}

fn query_latest(connection: &Connection, limit: u32) -> Result<Vec<HistoryRecord>, HistoryError> {
    let mut statement = connection
        .prepare(
            "SELECT provider_id, observed_at_unix_ms, metric_id, value_micros \
             FROM history_records \
             ORDER BY observed_at_unix_ms DESC, id DESC LIMIT ?1",
        )
        .map_err(|source| database_error("prepare history query", source))?;
    let rows = statement
        .query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|source| database_error("query history", source))?;
    let mut records = Vec::with_capacity(limit as usize);
    for row in rows {
        let (provider_id, observed_at_unix_ms, metric_id, value_micros) =
            row.map_err(|source| database_error("read history row", source))?;
        records.push(HistoryRecord::new(
            provider_id,
            observed_at_unix_ms,
            metric_id,
            value_micros,
        )?);
    }
    Ok(records)
}

fn read_status(
    connection: &Connection,
    execution: StorageExecution,
) -> Result<HistoryStatus, HistoryError> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|source| database_error("read journal mode", source))?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|source| database_error("read foreign-key setting", source))?;
    let busy_timeout_ms: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|source| database_error("read busy timeout", source))?;
    let row_count: i64 = connection
        .query_row("SELECT count(*) FROM history_records", [], |row| row.get(0))
        .map_err(|source| database_error("count history records", source))?;
    Ok(HistoryStatus {
        journal_mode: journal_mode.to_ascii_lowercase().into(),
        foreign_keys_enabled: foreign_keys == 1,
        busy_timeout_ms: u64::try_from(busy_timeout_ms).map_err(|_| {
            HistoryError::MalformedSchema {
                reason: "SQLite returned a negative busy timeout",
            }
        })?,
        schema_version: read_schema_version(connection)?,
        row_count: u32::try_from(row_count).map_err(|_| HistoryError::MalformedSchema {
            reason: "history row count exceeds the supported bound",
        })?,
        execution,
    })
}

fn read_schema_version(connection: &Connection) -> Result<u32, HistoryError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|source| database_error("read schema version", source))?;
    u32::try_from(version).map_err(|_| HistoryError::MalformedSchema {
        reason: "history schema version is not an unsigned 32-bit integer",
    })
}

fn shutdown_connection(connection: &Connection) -> Result<(), HistoryError> {
    let (busy, _log_frames, _checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|source| database_error("checkpoint WAL during shutdown", source))?;
    if busy == 0 {
        Ok(())
    } else {
        Err(HistoryError::CheckpointBusy)
    }
}

fn prepare_database_path(path: &Path) -> Result<PreparedDatabase, HistoryError> {
    if !path.is_absolute() {
        return Err(unsafe_path(path, "database path must be absolute"));
    }
    if path.file_name().is_none() {
        return Err(unsafe_path(path, "database path has no file name"));
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    reject_symlink_components(parent)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|source| HistoryError::Io {
        operation: "inspect parent directory for",
        path: path.to_path_buf(),
        source,
    })?;
    if !parent_metadata.file_type().is_dir() {
        return Err(unsafe_path(path, "database parent is not a directory"));
    }
    if parent_metadata.uid() != effective_uid() {
        return Err(unsafe_path(
            path,
            "database parent is not owned by the effective user",
        ));
    }
    if parent_metadata.permissions().mode() & PRIVATE_DIRECTORY_MASK != 0 {
        return Err(unsafe_path(
            path,
            "database parent grants group or other permissions",
        ));
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_database_metadata(path, &metadata)?;
            Ok(PreparedDatabase {
                path: path.to_path_buf(),
                identity: metadata_identity(&metadata),
                created: false,
            })
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let file = create_private_database_file(path)?;
            let metadata = file.metadata().map_err(|source| HistoryError::Io {
                operation: "inspect newly created database",
                path: path.to_path_buf(),
                source,
            })?;
            validate_database_metadata(path, &metadata)?;
            Ok(PreparedDatabase {
                path: path.to_path_buf(),
                identity: metadata_identity(&metadata),
                created: true,
            })
        }
        Err(source) => Err(HistoryError::Io {
            operation: "inspect database",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn create_private_database_file(path: &Path) -> Result<File, HistoryError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(DATABASE_MODE)
        .open(path)
        .map_err(|source| HistoryError::Io {
            operation: "create private database",
            path: path.to_path_buf(),
            source,
        })?;
    file.set_permissions(fs::Permissions::from_mode(DATABASE_MODE))
        .map_err(|source| HistoryError::Io {
            operation: "set private database permissions on",
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| HistoryError::Io {
        operation: "sync newly created database",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file)
}

fn reject_symlink_components(path: &Path) -> Result<(), HistoryError> {
    let mut traversed = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(unsafe_path(path, "unsupported path prefix"));
            }
            Component::ParentDir => {
                return Err(unsafe_path(
                    path,
                    "parent-directory traversal is not allowed",
                ));
            }
            Component::RootDir | Component::CurDir | Component::Normal(_) => {
                traversed.push(component.as_os_str());
            }
        }
        if traversed.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(&traversed).map_err(|source| HistoryError::Io {
            operation: "inspect path component for",
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(unsafe_path(path, "path contains a symbolic link"));
        }
    }
    Ok(())
}

fn validate_database_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), HistoryError> {
    if !metadata.file_type().is_file() {
        return Err(unsafe_path(path, "database is not a regular file"));
    }
    if metadata.permissions().mode() & 0o7777 != DATABASE_MODE {
        return Err(unsafe_path(path, "database permissions are not mode 0600"));
    }
    if metadata.uid() != effective_uid() {
        return Err(unsafe_path(
            path,
            "database is not owned by the effective user",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(unsafe_path(
            path,
            "database must have exactly one hard link",
        ));
    }
    if metadata.len() > MAX_HISTORY_DATABASE_BYTES {
        return Err(unsafe_path(
            path,
            "database exceeds the supported size bound",
        ));
    }
    Ok(())
}

fn validate_prepared_identity(prepared: &PreparedDatabase) -> Result<(), HistoryError> {
    let metadata = fs::symlink_metadata(&prepared.path).map_err(|source| HistoryError::Io {
        operation: "reinspect database",
        path: prepared.path.clone(),
        source,
    })?;
    validate_database_metadata(&prepared.path, &metadata)?;
    if metadata_identity(&metadata) != prepared.identity {
        return Err(unsafe_path(
            &prepared.path,
            "database changed while it was being opened",
        ));
    }
    Ok(())
}

fn validate_sidecars(path: &Path) -> Result<(), HistoryError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && metadata.permissions().mode() & 0o7777 == DATABASE_MODE
                    && metadata.uid() == effective_uid()
                    && metadata.nlink() == 1
                    && metadata.len() <= MAX_HISTORY_DATABASE_BYTES => {}
            Ok(_) => {
                return Err(unsafe_path(
                    &sidecar,
                    "SQLite sidecar must be an owner-mode-0600 regular file",
                ));
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(HistoryError::Io {
                    operation: "inspect SQLite sidecar for",
                    path: sidecar,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn cleanup_failed_new_database(prepared: &PreparedDatabase) {
    if validate_prepared_identity(prepared).is_ok() {
        let _ = fs::remove_file(&prepared.path);
        for suffix in ["-journal", "-wal", "-shm"] {
            let sidecar = sidecar_path(&prepared.path, suffix);
            if fs::symlink_metadata(&sidecar).is_ok_and(|metadata| metadata.file_type().is_file()) {
                let _ = fs::remove_file(sidecar);
            }
        }
    }
}

fn metadata_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn effective_uid() -> u32 {
    geteuid().as_raw()
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn unsafe_path(path: &Path, reason: &'static str) -> HistoryError {
    HistoryError::UnsafePath {
        path: path.to_path_buf(),
        reason,
    }
}

fn validate_options(options: HistoryStoreOptions) -> Result<(), HistoryError> {
    if !(1..=MAX_COMMAND_CAPACITY).contains(&options.command_capacity) {
        return Err(HistoryError::InvalidOptions {
            reason: "history command capacity must be between 1 and 1024",
        });
    }
    validate_timeout(options.busy_timeout, "SQLite busy timeout")?;
    validate_timeout(options.request_timeout, "history request timeout")
}

fn validate_timeout(timeout: Duration, label: &'static str) -> Result<(), HistoryError> {
    if timeout < Duration::from_millis(1) || timeout > MAX_CONFIGURED_TIMEOUT {
        return Err(HistoryError::InvalidOptions { reason: label });
    }
    Ok(())
}

fn database_error(operation: &'static str, source: rusqlite::Error) -> HistoryError {
    HistoryError::Database { operation, source }
}

fn receive_reply<T>(
    receiver: &Receiver<Result<T, HistoryError>>,
    timeout: Duration,
) -> Result<T, HistoryError> {
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(HistoryError::RequestTimeout),
        Err(RecvTimeoutError::Disconnected) => Err(HistoryError::WorkerStopped),
    }
}

fn join_worker(worker: JoinHandle<()>) -> Result<(), HistoryError> {
    worker.join().map_err(|_| HistoryError::WorkerPanicked)
}
