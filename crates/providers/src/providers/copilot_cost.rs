//! Local GitHub Copilot CLI token history.
//!
//! The Copilot CLI stores per-response token telemetry in its session SQLite
//! database. This reader uses the shared private read-only snapshot mechanism,
//! never modifies the CLI database, and reports tokens without inventing spend.

use std::collections::BTreeMap;
use std::path::Path;

use oab_domain::{
    ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage, CostUsageDailyBucket,
    CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot, CostUsageTokenMix, ErrorKind,
    Timestamp,
};
use time::{Date, Duration};

use crate::sqlite_snapshot::{ReadOnlySqliteSnapshot, SqliteSnapshotError};

const DATABASE_NAME: &str = "session-store.db";
const HISTORY_DAYS: u16 = 30;
const MAX_ROWS: usize = 100_000;

#[derive(Clone, Copy, Default)]
struct Tokens {
    input: u64,
    cached: u64,
    cache_write: u64,
    output: u64,
    reasoning: u64,
}

impl Tokens {
    fn total(self) -> u64 {
        self.input
            .saturating_add(self.cached)
            .saturating_add(self.cache_write)
            .saturating_add(self.output)
    }

    fn add(&mut self, other: Self) {
        self.input = self.input.saturating_add(other.input);
        self.cached = self.cached.saturating_add(other.cached);
        self.cache_write = self.cache_write.saturating_add(other.cache_write);
        self.output = self.output.saturating_add(other.output);
        self.reasoning = self.reasoning.saturating_add(other.reasoning);
    }
}

#[derive(Default)]
struct Aggregate {
    tokens: Tokens,
    requests: u64,
}

impl Aggregate {
    fn add(&mut self, tokens: Tokens) {
        self.tokens.add(tokens);
        self.requests = self.requests.saturating_add(1);
    }

    fn merge(&mut self, other: &Self) {
        self.tokens.add(other.tokens);
        self.requests = self.requests.saturating_add(other.requests);
    }
}

#[derive(Default)]
struct DayAggregate {
    total: Aggregate,
    models: BTreeMap<String, Aggregate>,
}

/// Reads up to 100,000 recent Copilot CLI usage events from the last 30 days.
///
/// # Errors
///
/// Returns a classified safe-file, SQLite, cancellation, or normalization
/// error. A missing database is a supported empty result.
pub fn scan_copilot_token_history(
    copilot_home: &Path,
    updated_at: Timestamp,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    let snapshot = match ReadOnlySqliteSnapshot::open(copilot_home, DATABASE_NAME) {
        Ok(snapshot) => snapshot,
        Err(SqliteSnapshotError::Missing | SqliteSnapshotError::InvalidRoot) => return Ok(None),
        Err(error) => return Err(classify_sqlite(error)),
    };
    let end = updated_at.as_offset_date_time().date();
    let start = end - Duration::days(i64::from(HISTORY_DAYS - 1));
    let mut statement = snapshot
        .connection()
        .prepare(
            "SELECT created_at, model, input_tokens, output_tokens, \
                    cache_read_tokens, cache_write_tokens, reasoning_tokens \
             FROM assistant_usage_events ORDER BY id DESC LIMIT ?1",
        )
        .map_err(|_| parse_error())?;
    let row_limit = i64::try_from(MAX_ROWS).map_err(|_| parse_error())?;
    let mut rows = statement.query([row_limit]).map_err(|_| parse_error())?;
    let mut days = BTreeMap::<String, DayAggregate>::new();
    let mut observed = 0_usize;
    while let Some(row) = rows.next().map_err(|_| parse_error())? {
        observed = observed.saturating_add(1);
        if observed > MAX_ROWS {
            return Err(parse_error());
        }
        let timestamp: String = row.get(0).map_err(|_| parse_error())?;
        let model: String = row.get(1).map_err(|_| parse_error())?;
        if model.is_empty() || model.len() > 160 {
            continue;
        }
        let Some(date) = parse_date(&timestamp) else {
            continue;
        };
        if date < start || date > end {
            continue;
        }
        let raw_input = unsigned(row.get::<_, Option<i64>>(2).map_err(|_| parse_error())?);
        let output = unsigned(row.get::<_, Option<i64>>(3).map_err(|_| parse_error())?);
        let cached = unsigned(row.get::<_, Option<i64>>(4).map_err(|_| parse_error())?);
        let cache_write = unsigned(row.get::<_, Option<i64>>(5).map_err(|_| parse_error())?);
        let reasoning = unsigned(row.get::<_, Option<i64>>(6).map_err(|_| parse_error())?);
        let tokens = Tokens {
            input: raw_input.saturating_sub(cached),
            cached: cached.min(raw_input),
            cache_write,
            output,
            reasoning: reasoning.min(output),
        };
        if tokens.total() == 0 {
            continue;
        }
        let day = days.entry(day_label(date)).or_default();
        day.total.add(tokens);
        day.models.entry(model).or_default().add(tokens);
    }

    if days.is_empty() {
        return Ok(None);
    }
    build_snapshot(days, start, end, updated_at).map(Some)
}

fn build_snapshot(
    days: BTreeMap<String, DayAggregate>,
    start: Date,
    end: Date,
    updated_at: Timestamp,
) -> Result<CostUsageSnapshot, ClassifiedError> {
    let today = day_label(end);
    let mut history = Aggregate::default();
    let mut session = Aggregate::default();
    let mut buckets = Vec::with_capacity(days.len());
    for (day, aggregate) in days {
        history.merge(&aggregate.total);
        if day == today {
            session.merge(&aggregate.total);
        }
        let models_used = aggregate.models.keys().cloned().collect::<Vec<_>>();
        let models = aggregate
            .models
            .into_iter()
            .map(|(name, metrics)| {
                CostUsageModelBreakdown::new(
                    name,
                    metrics_from(&metrics)?,
                    None,
                    None,
                    Some(metrics.tokens.total()),
                    None,
                )
                .map_err(|_| parse_error())
            })
            .collect::<Result<Vec<_>, _>>()?;
        buckets.push(
            CostUsageDailyBucket::new(
                day,
                None,
                metrics_from(&aggregate.total)?,
                models_used,
                models,
                Vec::new(),
            )
            .map_err(|_| parse_error())?,
        );
    }
    CostUsageSnapshot::new(
        CostUnit::provider("tokens").expect("fixed provider unit"),
        metrics_from(&session)?,
        metrics_from(&history)?,
        None,
        HISTORY_DAYS,
        true,
        Some(format!("{} through {}", day_label(start), day_label(end))),
        None,
        buckets,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        updated_at,
        CostProvenance::Unknown,
    )
    .map_err(|_| parse_error())
}

fn metrics_from(aggregate: &Aggregate) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::new(
            Some(aggregate.tokens.input),
            Some(aggregate.tokens.output),
            Some(aggregate.tokens.cached),
            Some(aggregate.tokens.cache_write),
            Some(aggregate.tokens.reasoning),
        ),
        Some(aggregate.tokens.total()),
        Some(aggregate.requests),
        None,
        CostUsageCoverage::new(0, 0, aggregate.requests, 0).map_err(|_| parse_error())?,
    )
    .map_err(|_| parse_error())
}

fn parse_date(raw: &str) -> Option<Date> {
    let normalized = if raw.ends_with('Z') || raw.contains('+') {
        raw.to_owned()
    } else {
        format!("{}Z", raw.replace(' ', "T"))
    };
    Timestamp::parse(&normalized)
        .ok()
        .map(|timestamp| timestamp.as_offset_date_time().date())
}

fn unsigned(value: Option<i64>) -> u64 {
    value
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0)
}

fn day_label(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn classify_sqlite(error: SqliteSnapshotError) -> ClassifiedError {
    ClassifiedError::new(match error {
        SqliteSnapshotError::Missing | SqliteSnapshotError::InvalidRoot => {
            ErrorKind::MissingCredential
        }
        SqliteSnapshotError::Replaced => ErrorKind::ProviderUnavailable,
        SqliteSnapshotError::InvalidRelativePath
        | SqliteSnapshotError::UnsafeFile
        | SqliteSnapshotError::TooLarge
        | SqliteSnapshotError::Open
        | SqliteSnapshotError::Configure
        | SqliteSnapshotError::Snapshot => ErrorKind::Parse,
    })
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rusqlite::Connection;

    use super::*;

    #[test]
    fn local_events_build_token_only_history() {
        let root = tempfile::tempdir().expect("temporary Copilot home");
        let database = root.path().join(DATABASE_NAME);
        let cli_config = root.path().join("config.json");
        let cli_auth_database = root.path().join("data.db");
        fs::write(&cli_config, b"copilot-cli-config-decoy").expect("CLI config decoy");
        fs::write(&cli_auth_database, b"copilot-cli-auth-database-decoy")
            .expect("CLI auth database decoy");
        let connection = Connection::open(&database).expect("database");
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA wal_autocheckpoint=0;
                 CREATE TABLE assistant_usage_events (
                    id INTEGER PRIMARY KEY,
                    model TEXT NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    cache_read_tokens INTEGER,
                    cache_write_tokens INTEGER,
                    reasoning_tokens INTEGER,
                    created_at TEXT
                );
                INSERT INTO assistant_usage_events VALUES
                    (1, 'gpt-5.6-sol', 100, 20, 30, 10, 5, '2026-08-31T08:00:00Z');",
            )
            .expect("fixture");

        let source_before = fs::read(&database).expect("source database before scan");
        let wal = root.path().join(format!("{DATABASE_NAME}-wal"));
        let shared_memory = root.path().join(format!("{DATABASE_NAME}-shm"));
        let wal_before = fs::read(&wal).expect("source WAL before scan");
        let shared_memory_before =
            fs::read(&shared_memory).expect("source shared memory before scan");
        let metadata_before = fs::metadata(&database).expect("source metadata before scan");
        let config_before = fs::read(&cli_config).expect("CLI config before scan");
        let auth_database_before =
            fs::read(&cli_auth_database).expect("CLI auth database before scan");
        let files_before = directory_entries(root.path());

        let snapshot = scan_copilot_token_history(
            root.path(),
            Timestamp::parse("2026-08-31T10:00:00Z").expect("timestamp"),
        )
        .expect("scan")
        .expect("history");
        assert_eq!(snapshot.history().total_tokens(), Some(130));
        assert_eq!(snapshot.history().request_count(), Some(1));
        assert!(snapshot.history().amount().is_none());
        assert_eq!(snapshot.history().coverage().unmetered(), 1);

        let source_after = fs::read(&database).expect("source database after scan");
        let metadata_after = fs::metadata(&database).expect("source metadata after scan");
        assert_eq!(source_after, source_before);
        assert_eq!(fs::read(&wal).expect("source WAL after scan"), wal_before);
        assert_eq!(
            fs::read(&shared_memory).expect("source shared memory after scan"),
            shared_memory_before
        );
        assert_eq!(metadata_after.len(), metadata_before.len());
        assert_eq!(
            metadata_after.modified().ok(),
            metadata_before.modified().ok()
        );
        assert_eq!(
            fs::read(&cli_config).expect("CLI config after scan"),
            config_before
        );
        assert_eq!(
            fs::read(&cli_auth_database).expect("CLI auth database after scan"),
            auth_database_before
        );
        assert_eq!(directory_entries(root.path()), files_before);
    }

    fn directory_entries(root: &Path) -> Vec<String> {
        let mut entries = fs::read_dir(root)
            .expect("Copilot home listing")
            .map(|entry| {
                entry
                    .expect("Copilot home entry")
                    .file_name()
                    .into_string()
                    .expect("fixture file name")
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }
}
