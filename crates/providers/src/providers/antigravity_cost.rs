//! Antigravity local token history from CLI/app conversations and tokscale.
//!
//! Native Antigravity conversations store protobuf generation metadata in
//! SQLite. Tokscale can export the same counters as JSONL. This module reads
//! either source with fixed bounds and never modifies provider-owned files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oab_domain::{
    ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage, CostUsageDailyBucket,
    CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot, CostUsageTokenMix, ErrorKind,
    Timestamp,
};
use rusqlite::types::ValueRef;
use serde_json::Value;
use time::{Date, Duration, OffsetDateTime, UtcOffset};
use tokio_util::sync::CancellationToken;

use crate::provider_files::{ProviderFileError, ProviderFileRoot, ProviderFileScanLimits};
use crate::sqlite_snapshot::{ReadOnlySqliteSnapshot, SqliteSnapshotError};

const HISTORY_DAYS: u16 = 30;
const MAX_DATABASES: usize = 500;
const MAX_ROWS_PER_DATABASE: usize = 10_000;
const MAX_ROWS: usize = 50_000;
const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_JSONL_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

/// Resolved Linux Antigravity history locations.
#[derive(Clone)]
pub struct AntigravityHistoryRoots {
    /// Candidate directories containing native conversation databases.
    pub database_roots: Vec<PathBuf>,
    /// Tokscale JSONL fallback directory.
    pub cache_root: PathBuf,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Tokens {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
    reasoning: u64,
}

impl Tokens {
    fn total(self) -> u64 {
        self.input
            .saturating_add(self.output)
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_write)
            .saturating_add(self.reasoning)
    }

    fn add(&mut self, other: Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.cache_write = self.cache_write.saturating_add(other.cache_write);
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

#[derive(Clone, PartialEq, Eq)]
struct Event {
    session: String,
    row: i64,
    timestamp_ms: i64,
    model: Option<String>,
    label: Option<String>,
    response_id: Option<String>,
    tokens: Tokens,
}

/// Scans native databases, falling back to tokscale JSONL only when no native
/// databases exist.
///
/// Missing history is a supported empty result. Incomplete or malformed
/// history fails closed so the runtime can keep its last good cached snapshot.
///
/// # Errors
///
/// Returns a stable cancellation, SQLite, unsafe-file, or parse failure.
pub fn scan_antigravity_token_history(
    roots: &AntigravityHistoryRoots,
    updated_at: Timestamp,
    cancellation: &CancellationToken,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    let (events, found_databases) = read_databases(&roots.database_roots, cancellation)?;
    let events = if found_databases {
        events
    } else {
        read_jsonl(&roots.cache_root, cancellation)?
    };
    if events.is_empty() {
        return Ok(None);
    }
    aggregate(events, updated_at).map(Some)
}

#[allow(clippy::too_many_lines)]
fn read_databases(
    roots: &[PathBuf],
    cancellation: &CancellationToken,
) -> Result<(Vec<Event>, bool), ClassifiedError> {
    let mut events = Vec::new();
    let mut found = false;
    let mut database_count = 0_usize;
    let mut row_count = 0_usize;
    let mut byte_count = 0_usize;
    for path in roots {
        let root = match ProviderFileRoot::open(path) {
            Ok(root) => root,
            Err(ProviderFileError::Missing) => continue,
            Err(error) => return Err(map_file_error(error)),
        };
        let limits = ProviderFileScanLimits::new(
            0,
            MAX_DATABASES,
            MAX_DATABASES,
            MAX_DATABASE_BYTES,
            MAX_TOTAL_BYTES,
        )
        .map_err(map_file_error)?;
        for candidate in root
            .scan("", limits, cancellation)
            .map_err(map_file_error)?
        {
            if candidate
                .relative_path()
                .extension()
                .and_then(|value| value.to_str())
                != Some("db")
            {
                continue;
            }
            found = true;
            database_count = database_count.saturating_add(1);
            if database_count > MAX_DATABASES {
                return Err(parse_error());
            }
            byte_count = byte_count.saturating_add(candidate.len());
            if byte_count > MAX_TOTAL_BYTES {
                return Err(parse_error());
            }
            let database = ReadOnlySqliteSnapshot::open(path, candidate.relative_path())
                .map_err(classify_sqlite)?;
            let has_table = database
                .connection()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='gen_metadata')",
                    [],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| parse_error())?;
            if !has_table {
                return Err(parse_error());
            }
            let mut statement = database
                .connection()
                .prepare(
                    "SELECT idx, data FROM gen_metadata WHERE typeof(idx)='integer' AND typeof(data)='blob' LIMIT ?1",
                )
                .map_err(|_| parse_error())?;
            let mut rows = statement
                .query([i64::try_from(MAX_ROWS_PER_DATABASE + 1).expect("fixed limit")])
                .map_err(|_| parse_error())?;
            let session = candidate
                .relative_path()
                .file_stem()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty() && value.len() <= 160)
                .ok_or_else(parse_error)?
                .to_owned();
            let mut database_rows = 0_usize;
            while let Some(row) = rows.next().map_err(|_| parse_error())? {
                if cancellation.is_cancelled() {
                    return Err(ClassifiedError::new(ErrorKind::Network));
                }
                database_rows = database_rows.saturating_add(1);
                row_count = row_count.saturating_add(1);
                if database_rows > MAX_ROWS_PER_DATABASE || row_count > MAX_ROWS {
                    return Err(parse_error());
                }
                let index = row.get::<_, i64>(0).map_err(|_| parse_error())?;
                if index < 0 {
                    return Err(parse_error());
                }
                let bytes = match row.get_ref(1).map_err(|_| parse_error())? {
                    ValueRef::Blob(bytes) if !bytes.is_empty() && bytes.len() <= MAX_BLOB_BYTES => {
                        bytes
                    }
                    _ => return Err(parse_error()),
                };
                if let Some(turn) = parse_turn(bytes)? {
                    let Some(timestamp_ms) = turn.timestamp_ms else {
                        return Err(parse_error());
                    };
                    let Some(usage) = turn.usage else {
                        return Err(parse_error());
                    };
                    events.push(Event {
                        session: session.clone(),
                        row: index,
                        timestamp_ms,
                        model: turn.model,
                        label: turn.label,
                        response_id: usage.response_id,
                        tokens: Tokens {
                            input: usage.system_prompt.saturating_add(usage.new_input),
                            output: usage.output,
                            cache_read: usage.cache_read,
                            cache_write: 0,
                            reasoning: usage.reasoning,
                        },
                    });
                }
            }
        }
    }
    Ok((events, found))
}

fn read_jsonl(
    path: &Path,
    cancellation: &CancellationToken,
) -> Result<Vec<Event>, ClassifiedError> {
    let root = match ProviderFileRoot::open(path) {
        Ok(root) => root,
        Err(ProviderFileError::Missing) => return Ok(Vec::new()),
        Err(error) => return Err(map_file_error(error)),
    };
    let limits = ProviderFileScanLimits::new(
        0,
        MAX_DATABASES,
        MAX_DATABASES,
        MAX_DATABASE_BYTES,
        MAX_TOTAL_BYTES,
    )
    .map_err(map_file_error)?;
    let mut events = Vec::new();
    let mut total_rows = 0_usize;
    for candidate in root
        .scan("", limits, cancellation)
        .map_err(map_file_error)?
    {
        if candidate
            .relative_path()
            .extension()
            .and_then(|value| value.to_str())
            != Some("jsonl")
        {
            continue;
        }
        let mut session_id = None::<String>;
        let mut session_model = None::<String>;
        let mut line_number = 0_usize;
        root.visit_candidate_lines(&candidate, MAX_JSONL_LINE_BYTES, cancellation, |line| {
            line_number = line_number.saturating_add(1);
            total_rows = total_rows.saturating_add(1);
            if total_rows > MAX_ROWS || line_number > MAX_ROWS_PER_DATABASE {
                return;
            }
            let Ok(row_number) = i64::try_from(line_number) else {
                return;
            };
            let Ok(value) = serde_json::from_slice::<Value>(line) else {
                return;
            };
            let Some(kind) = value.get("type").and_then(Value::as_str) else {
                return;
            };
            if kind == "session_meta" {
                session_id = json_string(&value, &["sessionId"]);
                session_model = json_string(&value, &["modelId", "model_id"]);
                return;
            }
            if kind != "usage" {
                return;
            }
            let Some(session) = json_string(&value, &["sessionId"]).or_else(|| session_id.clone())
            else {
                return;
            };
            let Some(timestamp_ms) = value
                .get("timestamp")
                .and_then(Value::as_i64)
                .filter(|v| *v > 0)
            else {
                return;
            };
            let input = json_counter(&value, &["input"]);
            let output = json_counter(&value, &["output"]);
            let cache_read = json_counter(&value, &["cacheRead", "cache_read"]);
            let cache_write = json_counter(&value, &["cacheWrite", "cache_write"]);
            let reasoning = json_counter(&value, &["reasoning"]);
            if reasoning > 0 {
                return;
            }
            let tokens = Tokens {
                input,
                output,
                cache_read,
                cache_write,
                reasoning,
            };
            if tokens.total() == 0 {
                return;
            }
            events.push(Event {
                session,
                row: row_number,
                timestamp_ms,
                model: json_string(&value, &["modelId", "model_id"])
                    .or_else(|| session_model.clone()),
                label: None,
                response_id: json_string(&value, &["responseId", "response_id"]),
                tokens,
            });
        })
        .map_err(map_file_error)?;
        if total_rows > MAX_ROWS || line_number > MAX_ROWS_PER_DATABASE {
            return Err(parse_error());
        }
    }
    Ok(events)
}

fn aggregate(
    events: Vec<Event>,
    updated_at: Timestamp,
) -> Result<CostUsageSnapshot, ClassifiedError> {
    let mut labels = BTreeMap::<(String, String), String>::new();
    let mut conflicts = BTreeSet::<(String, String)>::new();
    for event in &events {
        let (Some(label), Some(model)) = (&event.label, &event.model) else {
            continue;
        };
        let key = (event.session.clone(), label.clone());
        if labels.get(&key).is_some_and(|prior| prior != model) {
            conflicts.insert(key);
        } else {
            labels.insert(key, model.clone());
        }
    }
    let end = updated_at.as_offset_date_time().date();
    let start = end - Duration::days(i64::from(HISTORY_DAYS - 1));
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let mut row_ids = BTreeMap::<(String, i64), Event>::new();
    let mut responses = BTreeMap::<(String, String), Event>::new();
    let mut days = BTreeMap::<String, DayAggregate>::new();
    for event in events {
        let row_key = (event.session.clone(), event.row);
        if let Some(prior) = row_ids.get(&row_key) {
            if prior != &event {
                return Err(parse_error());
            }
            continue;
        }
        if let Some(response) = &event.response_id {
            let key = (event.session.clone(), response.clone());
            if let Some(prior) = responses.get(&key) {
                if prior.tokens != event.tokens {
                    return Err(parse_error());
                }
                row_ids.insert(row_key, event);
                continue;
            }
        }
        let timestamp =
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(event.timestamp_ms) * 1_000_000)
                .map_err(|_| parse_error())?
                .to_offset(local_offset);
        let date = timestamp.date();
        if date >= start && date <= end {
            let inherited = event.label.as_ref().and_then(|label| {
                let key = (event.session.clone(), label.clone());
                (!conflicts.contains(&key))
                    .then(|| labels.get(&key))
                    .flatten()
                    .cloned()
            });
            let model = event
                .model
                .clone()
                .or(inherited)
                .filter(|model| !model.trim().is_empty() && model.len() <= 160)
                .unwrap_or_else(|| "unknown".to_owned());
            let day = days.entry(day_label(date)).or_default();
            day.total.add(event.tokens);
            day.models.entry(model).or_default().add(event.tokens);
        }
        row_ids.insert(row_key, event.clone());
        if let Some(response) = &event.response_id {
            responses.insert((event.session.clone(), response.clone()), event);
        }
    }
    build_snapshot(days, start, end, updated_at)
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
            Some(aggregate.tokens.cache_read),
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

#[derive(Default)]
struct ParsedUsage {
    system_prompt: u64,
    new_input: u64,
    cache_read: u64,
    output: u64,
    reasoning: u64,
    response_id: Option<String>,
}

#[derive(Default)]
struct ParsedTurn {
    usage: Option<ParsedUsage>,
    timestamp_ms: Option<i64>,
    model: Option<String>,
    label: Option<String>,
}

fn parse_turn(bytes: &[u8]) -> Result<Option<ParsedTurn>, ClassifiedError> {
    let mut turn = ParsedTurn::default();
    let mut found = false;
    visit_fields(bytes, |number, wire, data, _| {
        if number == 1 {
            found = true;
            parse_chat(require_message(wire, data)?, &mut turn)?;
        }
        Ok(())
    })?;
    Ok(found.then_some(turn))
}

fn parse_chat(bytes: &[u8], turn: &mut ParsedTurn) -> Result<(), ClassifiedError> {
    visit_fields(bytes, |number, wire, data, _| {
        match number {
            4 => {
                let mut usage = turn.usage.take().unwrap_or_default();
                parse_usage(require_message(wire, data)?, &mut usage)?;
                turn.usage = Some(usage);
            }
            9 => turn.timestamp_ms = parse_generation(require_message(wire, data)?)?,
            19 => turn.model = parse_string(wire, data)?,
            21 => turn.label = parse_string(wire, data)?,
            _ => {}
        }
        Ok(())
    })
}

fn parse_usage(bytes: &[u8], usage: &mut ParsedUsage) -> Result<(), ClassifiedError> {
    visit_fields(bytes, |number, wire, data, value| {
        match number {
            1 => usage.system_prompt = require_counter(wire, value)?,
            2 => usage.new_input = require_counter(wire, value)?,
            5 => usage.cache_read = require_counter(wire, value)?,
            9 => usage.output = require_counter(wire, value)?,
            10 => usage.reasoning = require_counter(wire, value)?,
            11 => usage.response_id = parse_string(wire, data)?,
            _ => {}
        }
        Ok(())
    })
}

fn parse_generation(bytes: &[u8]) -> Result<Option<i64>, ClassifiedError> {
    let mut seconds = None::<u64>;
    let mut nanos = 0_u64;
    visit_fields(bytes, |number, wire, data, _| {
        if number != 4 {
            return Ok(());
        }
        visit_fields(require_message(wire, data)?, |field, wire, _, value| {
            match field {
                1 => seconds = Some(require_counter(wire, value)?),
                2 => nanos = require_counter(wire, value)?,
                _ => {}
            }
            Ok(())
        })
    })?;
    let Some(seconds) = seconds else {
        return Ok(None);
    };
    if seconds == 0 || seconds > 253_402_300_799 || nanos > 999_999_999 {
        return Err(parse_error());
    }
    let millis = seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(nanos / 1_000_000))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(parse_error)?;
    Ok(Some(millis))
}

fn visit_fields(
    bytes: &[u8],
    mut visitor: impl FnMut(u64, u8, Option<&[u8]>, Option<u64>) -> Result<(), ClassifiedError>,
) -> Result<(), ClassifiedError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let tag = read_varint(bytes, &mut offset)?;
        let number = tag >> 3;
        let wire = u8::try_from(tag & 7).map_err(|_| parse_error())?;
        if number == 0 || number > 536_870_911 {
            return Err(parse_error());
        }
        match wire {
            0 => visitor(number, wire, None, Some(read_varint(bytes, &mut offset)?))?,
            1 => {
                let data = take(bytes, &mut offset, 8)?;
                visitor(number, wire, Some(data), None)?;
            }
            2 => {
                let length =
                    usize::try_from(read_varint(bytes, &mut offset)?).map_err(|_| parse_error())?;
                let data = take(bytes, &mut offset, length)?;
                visitor(number, wire, Some(data), None)?;
            }
            5 => {
                let data = take(bytes, &mut offset, 4)?;
                visitor(number, wire, Some(data), None)?;
            }
            _ => return Err(parse_error()),
        }
    }
    Ok(())
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, ClassifiedError> {
    let mut result = 0_u64;
    for index in 0..10 {
        let byte = *bytes.get(*offset).ok_or_else(parse_error)?;
        *offset = offset.saturating_add(1);
        if index == 9 && byte > 1 {
            return Err(parse_error());
        }
        result |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(parse_error())
}

fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ClassifiedError> {
    let end = offset.checked_add(length).ok_or_else(parse_error)?;
    let value = bytes.get(*offset..end).ok_or_else(parse_error)?;
    *offset = end;
    Ok(value)
}

fn require_message(wire: u8, data: Option<&[u8]>) -> Result<&[u8], ClassifiedError> {
    (wire == 2)
        .then_some(data)
        .flatten()
        .ok_or_else(parse_error)
}

fn require_counter(wire: u8, value: Option<u64>) -> Result<u64, ClassifiedError> {
    (wire == 0)
        .then_some(value)
        .flatten()
        .ok_or_else(parse_error)
}

fn parse_string(wire: u8, data: Option<&[u8]>) -> Result<Option<String>, ClassifiedError> {
    let value = std::str::from_utf8(require_message(wire, data)?)
        .map_err(|_| parse_error())?
        .trim();
    if value.len() > 160 {
        return Err(parse_error());
    }
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

fn json_counter(value: &Value, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
        .unwrap_or(0)
}

fn json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 160)
        .map(str::to_owned)
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

fn map_file_error(error: ProviderFileError) -> ClassifiedError {
    match error {
        ProviderFileError::Cancelled => ClassifiedError::new(ErrorKind::Network),
        ProviderFileError::Missing => ClassifiedError::new(ErrorKind::ProviderUnavailable),
        _ => ClassifiedError::new(ErrorKind::Parse),
    }
}

fn classify_sqlite(error: SqliteSnapshotError) -> ClassifiedError {
    match error {
        SqliteSnapshotError::Missing | SqliteSnapshotError::InvalidRoot => {
            ClassifiedError::new(ErrorKind::MissingCredential)
        }
        _ => ClassifiedError::new(ErrorKind::ProviderUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn reads_tokscale_jsonl_history() {
        let database_root = tempfile::tempdir().expect("databases");
        let cache_root = tempfile::tempdir().expect("cache");
        fs::write(
            cache_root.path().join("usage.jsonl"),
            "{\"type\":\"session_meta\",\"sessionId\":\"s1\",\"modelId\":\"gemini-3\"}\n{\"type\":\"usage\",\"timestamp\":1788163200000,\"input\":100,\"output\":20,\"cacheRead\":10,\"cacheWrite\":5}\n",
        )
        .expect("fixture");
        let roots = AntigravityHistoryRoots {
            database_roots: vec![database_root.path().to_path_buf()],
            cache_root: cache_root.path().to_path_buf(),
        };
        let snapshot = scan_antigravity_token_history(
            &roots,
            Timestamp::parse("2026-08-31T12:00:00Z").expect("timestamp"),
            &CancellationToken::new(),
        )
        .expect("scan")
        .expect("history");
        assert_eq!(snapshot.history().total_tokens(), Some(135));
        assert_eq!(snapshot.daily()[0].models()[0].name(), "gemini-3");
    }
}
