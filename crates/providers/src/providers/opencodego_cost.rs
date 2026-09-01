//! `OpenCode` Go local quota and spend history.
//!
//! `OpenCode` stores provider messages in `~/.local/share/opencode/opencode.db`.
//! This reader uses the shared private SQLite snapshot and only selects
//! `opencode-go` assistant cost rows. It never opens the live database writable.

use std::collections::BTreeMap;
use std::path::Path;

use oab_domain::{
    AccountScope, ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage,
    CostUsageDailyBucket, CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot,
    CostUsageTokenMix, CurrencyCode, ErrorKind, ExactDecimal, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use time::{Date, Duration, Month, OffsetDateTime};

use crate::normalize::UsageSampleBuilder;
use crate::sqlite_snapshot::{ReadOnlySqliteSnapshot, SqliteSnapshotError};

const DATABASE_NAME: &str = "opencode.db";
const HISTORY_DAYS: u16 = 30;
const MAX_ROWS: usize = 100_000;
const FIVE_HOURS_MS: i64 = 5 * 60 * 60 * 1_000;
const SESSION_LIMIT_USD: f64 = 12.0;
const WEEKLY_LIMIT_USD: f64 = 30.0;
const MONTHLY_LIMIT_USD: f64 = 60.0;

/// One immutable local `OpenCode` Go read, shared by quota and history views.
pub struct OpenCodeGoLocalUsage {
    /// Normalized rolling/weekly/monthly plan windows.
    pub sample: UsageSample,
    /// Per-day and per-model local spend history.
    pub cost: CostUsageSnapshot,
}

#[derive(Clone)]
struct UsageRow {
    created_ms: i64,
    cost: Decimal,
    model: String,
}

#[derive(Default)]
struct Aggregate {
    cost: Decimal,
    requests: u64,
}

impl Aggregate {
    fn add(&mut self, cost: Decimal) {
        self.cost += cost;
        self.requests = self.requests.saturating_add(1);
    }

    fn merge(&mut self, other: &Self) {
        self.cost += other.cost;
        self.requests = self.requests.saturating_add(other.requests);
    }
}

#[derive(Default)]
struct DayAggregate {
    total: Aggregate,
    models: BTreeMap<String, Aggregate>,
}

/// Reads `OpenCode` Go quota and history from a bounded private SQLite snapshot.
///
/// A missing database or an existing database with no `OpenCode` Go rows is a
/// supported empty result.
///
/// # Errors
///
/// Returns a stable classified SQLite or normalization failure.
pub fn scan_opencodego_local_usage(
    opencode_root: &Path,
    scope: AccountScope,
    updated_at: Timestamp,
) -> Result<Option<OpenCodeGoLocalUsage>, ClassifiedError> {
    let snapshot = match ReadOnlySqliteSnapshot::open(opencode_root, DATABASE_NAME) {
        Ok(snapshot) => snapshot,
        Err(SqliteSnapshotError::Missing | SqliteSnapshotError::InvalidRoot) => return Ok(None),
        Err(error) => return Err(classify_sqlite(error)),
    };
    let has_part = snapshot
        .connection()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='part')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| parse_error())?;
    let sql = if has_part {
        MESSAGE_AND_PART_USAGE_SQL
    } else {
        MESSAGE_USAGE_SQL
    };
    let mut statement = snapshot
        .connection()
        .prepare(sql)
        .map_err(|_| parse_error())?;
    let row_limit = i64::try_from(MAX_ROWS).map_err(|_| parse_error())?;
    let mut query = statement.query([row_limit]).map_err(|_| parse_error())?;
    let mut rows = Vec::new();
    while let Some(row) = query.next().map_err(|_| parse_error())? {
        let created_ms = row.get::<_, i64>(0).map_err(|_| parse_error())?;
        let raw_cost = row.get::<_, f64>(1).map_err(|_| parse_error())?;
        let model = row.get::<_, String>(2).map_err(|_| parse_error())?;
        if created_ms <= 0 || !raw_cost.is_finite() || raw_cost < 0.0 || model.len() > 160 {
            continue;
        }
        let Some(cost) = Decimal::from_f64(raw_cost) else {
            continue;
        };
        rows.push(UsageRow {
            created_ms,
            cost,
            model: if model.trim().is_empty() {
                "unknown".to_owned()
            } else {
                model
            },
        });
    }
    if rows.is_empty() {
        return Ok(None);
    }

    let sample = build_sample(scope, updated_at, &rows)?;
    let cost = build_cost(updated_at, &rows)?;
    Ok(Some(OpenCodeGoLocalUsage { sample, cost }))
}

/// Reports whether the local database contains at least one `OpenCode` Go row.
///
/// This uses the same private, read-only snapshot policy as the full scanner.
#[must_use]
pub fn has_opencodego_local_usage(opencode_root: &Path) -> bool {
    let Ok(snapshot) = ReadOnlySqliteSnapshot::open(opencode_root, DATABASE_NAME) else {
        return false;
    };
    snapshot
        .connection()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM message WHERE json_valid(data) AND json_extract(data, '$.providerID') = 'opencode-go' LIMIT 1)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
}

fn build_sample(
    scope: AccountScope,
    updated_at: Timestamp,
    rows: &[UsageRow],
) -> Result<UsageSample, ClassifiedError> {
    let now_ms = updated_at.as_offset_date_time().unix_timestamp_nanos() / 1_000_000;
    let now_ms = i64::try_from(now_ms).map_err(|_| parse_error())?;
    let session_start = now_ms.saturating_sub(FIVE_HOURS_MS);
    let (week_start, week_end) = utc_week_bounds(updated_at.as_offset_date_time())?;
    let (month_start, month_end) = anchored_month_bounds(
        updated_at.as_offset_date_time(),
        rows.iter().map(|row| row.created_ms).min(),
    )?;
    let mut session_cost = Decimal::ZERO;
    let mut weekly_cost = Decimal::ZERO;
    let mut monthly_cost = Decimal::ZERO;
    let mut oldest_session = None::<i64>;
    for row in rows {
        if row.created_ms >= session_start && row.created_ms < now_ms {
            session_cost += row.cost;
            oldest_session =
                Some(oldest_session.map_or(row.created_ms, |oldest| oldest.min(row.created_ms)));
        }
        if row.created_ms >= week_start && row.created_ms < week_end {
            weekly_cost += row.cost;
        }
        if row.created_ms >= month_start && row.created_ms < month_end {
            monthly_cost += row.cost;
        }
    }
    let session_reset = oldest_session
        .unwrap_or(now_ms)
        .saturating_add(FIVE_HOURS_MS);
    UsageSampleBuilder::new(scope, updated_at)
        .primary(local_window(
            session_cost,
            SESSION_LIMIT_USD,
            session_reset,
            300,
        )?)
        .secondary(local_window(
            weekly_cost,
            WEEKLY_LIMIT_USD,
            week_end,
            7 * 24 * 60,
        )?)
        .tertiary(local_window(
            monthly_cost,
            MONTHLY_LIMIT_USD,
            month_end,
            31 * 24 * 60,
        )?)
        .login_method(Some("OpenCode local history".to_owned()))?
        .provenance("opencodego", "local")?
        .build()
}

fn local_window(
    used: Decimal,
    limit: f64,
    reset_ms: i64,
    duration_minutes: i64,
) -> Result<RateWindow, ClassifiedError> {
    let limit_decimal = Decimal::from_f64(limit).ok_or_else(parse_error)?;
    let percent = ((used / limit_decimal) * Decimal::from(100_u8))
        .to_string()
        .parse::<f64>()
        .map_err(|_| parse_error())?
        .clamp(0.0, 100.0);
    let reset = OffsetDateTime::from_unix_timestamp_nanos(i128::from(reset_ms) * 1_000_000)
        .map_err(|_| parse_error())?;
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
        Some(WindowDuration::from_provider_minutes(duration_minutes).map_err(|_| parse_error())?),
        Some(Timestamp::new(reset).map_err(|_| parse_error())?),
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn build_cost(
    updated_at: Timestamp,
    rows: &[UsageRow],
) -> Result<CostUsageSnapshot, ClassifiedError> {
    let end = updated_at.as_offset_date_time().date();
    let start = end - Duration::days(i64::from(HISTORY_DAYS - 1));
    let local_offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let mut days = BTreeMap::<String, DayAggregate>::new();
    for row in rows {
        let timestamp =
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(row.created_ms) * 1_000_000)
                .map_err(|_| parse_error())?
                .to_offset(local_offset);
        let date = timestamp.date();
        if date < start || date > end {
            continue;
        }
        let day = days.entry(day_label(date)).or_default();
        day.total.add(row.cost);
        day.models
            .entry(row.model.clone())
            .or_default()
            .add(row.cost);
    }
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
                    Some(ExactDecimal::new(metrics.cost)),
                    None,
                    None,
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
        CostUnit::currency(CurrencyCode::new("USD").expect("fixed currency")),
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
        CostProvenance::VendorMetered,
    )
    .map_err(|_| parse_error())
}

fn metrics_from(aggregate: &Aggregate) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::default(),
        None,
        Some(aggregate.requests),
        Some(ExactDecimal::new(aggregate.cost)),
        CostUsageCoverage::new(aggregate.requests, 0, 0, 0).map_err(|_| parse_error())?,
    )
    .map_err(|_| parse_error())
}

fn utc_week_bounds(now: OffsetDateTime) -> Result<(i64, i64), ClassifiedError> {
    let days_from_monday = i64::from(now.weekday().number_days_from_monday());
    let start_date = now.date() - Duration::days(days_from_monday);
    let start = start_date.midnight().assume_utc();
    let end = start + Duration::days(7);
    Ok((unix_ms(start)?, unix_ms(end)?))
}

fn anchored_month_bounds(
    now: OffsetDateTime,
    anchor_ms: Option<i64>,
) -> Result<(i64, i64), ClassifiedError> {
    let anchor = anchor_ms
        .and_then(|millis| {
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000).ok()
        })
        .unwrap_or(now);
    let mut year = now.year();
    let mut month = now.month();
    let mut start = anchored_date_time(year, month, anchor)?;
    if start > now {
        (year, month) = previous_month(year, month);
        start = anchored_date_time(year, month, anchor)?;
    }
    let (next_year, next_month) = next_month(year, month);
    let end = anchored_date_time(next_year, next_month, anchor)?;
    Ok((unix_ms(start)?, unix_ms(end)?))
}

fn anchored_date_time(
    year: i32,
    month: Month,
    anchor: OffsetDateTime,
) -> Result<OffsetDateTime, ClassifiedError> {
    let last_day = days_in_month(year, month);
    let day = anchor.day().min(last_day);
    let date = Date::from_calendar_date(year, month, day).map_err(|_| parse_error())?;
    Ok(date.with_time(anchor.time()).assume_utc())
}

const fn next_month(year: i32, month: Month) -> (i32, Month) {
    match month.next() {
        Month::January => (year + 1, Month::January),
        next => (year, next),
    }
}

const fn previous_month(year: i32, month: Month) -> (i32, Month) {
    match month.previous() {
        Month::December => (year - 1, Month::December),
        previous => (year, previous),
    }
}

fn days_in_month(year: i32, month: Month) -> u8 {
    let (next_year, next_month) = next_month(year, month);
    let first = Date::from_calendar_date(year, month, 1).expect("valid year and month");
    let next = Date::from_calendar_date(next_year, next_month, 1).expect("valid year and month");
    u8::try_from((next - first).whole_days()).expect("month length")
}

fn unix_ms(value: OffsetDateTime) -> Result<i64, ClassifiedError> {
    i64::try_from(value.unix_timestamp_nanos() / 1_000_000).map_err(|_| parse_error())
}

fn day_label(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn classify_sqlite(error: SqliteSnapshotError) -> ClassifiedError {
    let kind = match error {
        SqliteSnapshotError::Missing | SqliteSnapshotError::InvalidRoot => {
            ErrorKind::MissingCredential
        }
        SqliteSnapshotError::InvalidRelativePath
        | SqliteSnapshotError::UnsafeFile
        | SqliteSnapshotError::TooLarge
        | SqliteSnapshotError::Replaced
        | SqliteSnapshotError::Open
        | SqliteSnapshotError::Configure
        | SqliteSnapshotError::Snapshot => ErrorKind::ProviderUnavailable,
    };
    ClassifiedError::new(kind)
}

const MESSAGE_USAGE_SQL: &str = r"
    SELECT
      CAST(COALESCE(json_extract(data, '$.time.created'), time_created) AS INTEGER) AS createdMs,
      CAST(json_extract(data, '$.cost') AS REAL),
      COALESCE(json_extract(data, '$.modelID'), '')
    FROM message
    WHERE json_valid(data)
      AND json_extract(data, '$.providerID') = 'opencode-go'
      AND json_extract(data, '$.role') = 'assistant'
      AND json_type(data, '$.cost') IN ('integer', 'real')
    ORDER BY createdMs DESC
    LIMIT ?1
";

const MESSAGE_AND_PART_USAGE_SQL: &str = r"
    WITH provider_messages AS (
      SELECT id AS messageID,
        CAST(COALESCE(json_extract(data, '$.time.created'), time_created) AS INTEGER) AS createdMs,
        CAST(json_extract(data, '$.cost') AS REAL) AS cost,
        json_type(data, '$.cost') IN ('integer', 'real') AS hasCost,
        COALESCE(json_extract(data, '$.modelID'), '') AS modelID
      FROM message
      WHERE json_valid(data)
        AND json_extract(data, '$.providerID') = 'opencode-go'
        AND json_extract(data, '$.role') = 'assistant'
    ), usage_rows AS (
      SELECT CAST(COALESCE(json_extract(p.data, '$.time.created'), p.time_created, m.createdMs) AS INTEGER) AS createdMs,
        CAST(json_extract(p.data, '$.cost') AS REAL) AS cost,
        m.modelID AS modelID
      FROM part p JOIN provider_messages m ON m.messageID = p.message_id
      WHERE json_valid(p.data)
        AND json_extract(p.data, '$.type') = 'step-finish'
        AND json_type(p.data, '$.cost') IN ('integer', 'real')
      UNION ALL
      SELECT createdMs, cost, modelID FROM provider_messages m
      WHERE hasCost AND NOT EXISTS (
        SELECT 1 FROM part p WHERE p.message_id = m.messageID
          AND json_valid(p.data)
          AND json_extract(p.data, '$.type') = 'step-finish'
          AND json_type(p.data, '$.cost') IN ('integer', 'real')
      )
    )
    SELECT createdMs, cost, modelID FROM usage_rows ORDER BY createdMs DESC LIMIT ?1
";

#[cfg(test)]
mod tests {
    use oab_domain::{AccountKey, ProviderId, ProviderInstanceId};
    use rusqlite::Connection;
    use tempfile::TempDir;
    use time::{Date, Month};

    use super::*;

    #[test]
    fn reads_part_costs_and_builds_local_windows() {
        let root = TempDir::new().expect("tempdir");
        let database = root.path().join(DATABASE_NAME);
        let connection = Connection::open(&database).expect("database");
        connection
            .execute_batch(
                "CREATE TABLE message(id TEXT PRIMARY KEY, time_created INTEGER, data TEXT);\
                 CREATE TABLE part(id TEXT PRIMARY KEY, message_id TEXT, time_created INTEGER, data TEXT);",
            )
            .expect("schema");
        let now = Date::from_calendar_date(2026, Month::August, 31)
            .expect("date")
            .with_hms(12, 0, 0)
            .expect("time")
            .assume_utc();
        let created = (now - Duration::hours(2)).unix_timestamp() * 1_000;
        connection
            .execute(
                "INSERT INTO message VALUES(?1, ?2, ?3)",
                ("m1", created, r#"{"role":"assistant","providerID":"opencode-go","modelID":"claude-sonnet-4"}"#),
            )
            .expect("message");
        connection
            .execute(
                "INSERT INTO part VALUES(?1, ?2, ?3, ?4)",
                ("p1", "m1", created, r#"{"type":"step-finish","cost":1.5}"#),
            )
            .expect("part");
        drop(connection);
        let scope = AccountScope::new(
            ProviderId::OpenCodeGo,
            ProviderInstanceId::new("default").expect("instance"),
            AccountKey::new("ambient").expect("account"),
        );
        let usage = scan_opencodego_local_usage(
            root.path(),
            scope,
            Timestamp::new(now).expect("timestamp"),
        )
        .expect("scan")
        .expect("usage");
        assert_eq!(
            usage.cost.history().amount().expect("amount").to_string(),
            "1.5"
        );
        assert_eq!(usage.cost.daily().len(), 1);
        let used_percent = usage
            .sample
            .primary()
            .expect("primary")
            .usage()
            .used_percent()
            .expect("percent")
            .get();
        assert!((used_percent - 12.5).abs() < f64::EPSILON);
    }
}
