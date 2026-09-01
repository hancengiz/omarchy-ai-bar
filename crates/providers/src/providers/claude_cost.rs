//! Bounded local Claude token and list-price history.
//!
//! Claude Code records cumulative streaming assistant rows in project JSONL
//! files. This scanner keeps the final row for each message/request pair,
//! excludes Vertex AI traffic, and never reads message content beyond the
//! bounded line currently being normalized.

use std::collections::BTreeMap;
use std::path::Path;

use oab_domain::{
    ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage, CostUsageDailyBucket,
    CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot, CostUsageTokenMix, CurrencyCode,
    ErrorKind, ExactDecimal, Timestamp,
};
use rust_decimal::Decimal;
use serde_json::Value;
use time::{Date, Duration};
use tokio_util::sync::CancellationToken;

use crate::provider_files::{ProviderFileError, ProviderFileRoot, ProviderFileScanLimits};

const HISTORY_DAYS: u16 = 30;
const MAX_LINE_BYTES: usize = 512 * 1024;
const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Default)]
struct Tokens {
    input: u64,
    cache_read: u64,
    cache_write: u64,
    cache_write_1h: u64,
    output: u64,
}

impl Tokens {
    fn total(self) -> u64 {
        self.input
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_write)
            .saturating_add(self.output)
    }

    fn add(&mut self, other: Self) {
        self.input = self.input.saturating_add(other.input);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.cache_write = self.cache_write.saturating_add(other.cache_write);
        self.cache_write_1h = self.cache_write_1h.saturating_add(other.cache_write_1h);
        self.output = self.output.saturating_add(other.output);
    }
}

#[derive(Default)]
struct Aggregate {
    tokens: Tokens,
    requests: u64,
    estimated_requests: u64,
    unpriced_requests: u64,
    amount: Decimal,
}

impl Aggregate {
    fn add(&mut self, tokens: Tokens, model: &str) {
        if tokens.total() == 0 {
            return;
        }
        self.tokens.add(tokens);
        self.requests = self.requests.saturating_add(1);
        if let Some(cost) = estimate_cost(model, tokens) {
            self.amount += cost;
            self.estimated_requests = self.estimated_requests.saturating_add(1);
        } else {
            self.unpriced_requests = self.unpriced_requests.saturating_add(1);
        }
    }

    fn merge(&mut self, other: &Self) {
        self.tokens.add(other.tokens);
        self.requests = self.requests.saturating_add(other.requests);
        self.estimated_requests = self
            .estimated_requests
            .saturating_add(other.estimated_requests);
        self.unpriced_requests = self
            .unpriced_requests
            .saturating_add(other.unpriced_requests);
        self.amount += other.amount;
    }
}

#[derive(Default)]
struct DayAggregate {
    total: Aggregate,
    models: BTreeMap<String, Aggregate>,
}

struct UsageRow {
    day: String,
    model: String,
    tokens: Tokens,
}

/// Scans the last 30 local days of Claude Code project history.
///
/// Missing history is a supported empty result. Unsafe or incomplete provider
/// file acquisition fails only this optional enrichment.
///
/// # Errors
///
/// Returns a classified cancellation, unsafe-file, or normalized-data error.
pub fn scan_claude_cost_history(
    claude_home: &Path,
    updated_at: Timestamp,
    cancellation: &CancellationToken,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    scan_history(claude_home, updated_at, cancellation, VertexFilter::Exclude)
}

/// Scans Vertex AI Claude traffic recorded in the local Claude Code history.
///
/// The same bounded reader is used as Claude, but only rows with Vertex IDs,
/// model versions, or explicit Google/Vertex provider metadata are retained.
///
/// # Errors
///
/// Returns a classified cancellation, unsafe-file, or normalized-data error.
pub fn scan_vertexai_cost_history(
    claude_home: &Path,
    updated_at: Timestamp,
    cancellation: &CancellationToken,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    scan_history(claude_home, updated_at, cancellation, VertexFilter::Only)
}

#[derive(Clone, Copy)]
enum VertexFilter {
    Exclude,
    Only,
}

fn scan_history(
    claude_home: &Path,
    updated_at: Timestamp,
    cancellation: &CancellationToken,
    vertex_filter: VertexFilter,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    let root = match ProviderFileRoot::open(claude_home) {
        Ok(root) => root,
        Err(ProviderFileError::Missing) => return Ok(None),
        Err(error) => return Err(map_file_error(error)),
    };
    let limits = ProviderFileScanLimits::new(8, 25_000, 25_000, MAX_FILE_BYTES, MAX_TOTAL_BYTES)
        .map_err(map_file_error)?;
    let candidates = match root.scan("projects", limits, cancellation) {
        Ok(candidates) => candidates,
        Err(ProviderFileError::Missing) => return Ok(None),
        Err(error) => return Err(map_file_error(error)),
    };
    let end = updated_at.as_offset_date_time().date();
    let start = end - Duration::days(i64::from(HISTORY_DAYS - 1));
    let mut days = BTreeMap::<String, DayAggregate>::new();

    for candidate in candidates {
        if candidate
            .relative_path()
            .extension()
            .and_then(|value| value.to_str())
            != Some("jsonl")
        {
            continue;
        }
        let mut keyed = BTreeMap::<String, UsageRow>::new();
        let mut unkeyed = Vec::<UsageRow>::new();
        root.visit_candidate_lines(&candidate, MAX_LINE_BYTES, cancellation, |line| {
            if !contains(line, b"\"assistant\"") || !contains(line, b"\"usage\"") {
                return;
            }
            let Ok(value) = serde_json::from_slice::<Value>(line) else {
                return;
            };
            let Some(row) = parse_row(&value, start, end, vertex_filter) else {
                return;
            };
            let key = value
                .get("message")
                .and_then(|message| message.get("id"))
                .and_then(Value::as_str)
                .zip(value.get("requestId").and_then(Value::as_str))
                .map(|(message, request)| format!("{message}:{request}"));
            if let Some(key) = key {
                // Claude writes cumulative streaming chunks. The final row wins.
                keyed.insert(key, row);
            } else {
                unkeyed.push(row);
            }
        })
        .map_err(map_file_error)?;

        for row in keyed.into_values().chain(unkeyed) {
            let day = days.entry(row.day).or_default();
            day.total.add(row.tokens, &row.model);
            day.models
                .entry(row.model.clone())
                .or_default()
                .add(row.tokens, &row.model);
        }
    }

    if days.is_empty() {
        return Ok(None);
    }
    build_snapshot(days, start, end, updated_at).map(Some)
}

fn parse_row(
    value: &Value,
    start: Date,
    end: Date,
    vertex_filter: VertexFilter,
) -> Option<UsageRow> {
    if value.get("type").and_then(Value::as_str) != Some("assistant") {
        return None;
    }
    let vertex = is_vertex(value);
    if matches!(vertex_filter, VertexFilter::Exclude) == vertex {
        return None;
    }
    let date = value
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|raw| Timestamp::parse(raw).ok())?
        .as_offset_date_time()
        .date();
    if date < start || date > end {
        return None;
    }
    let message = value.get("message")?;
    let model = message
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty() && model.len() <= 160)?;
    let usage = message.get("usage")?;
    let cache_write = unsigned(usage.get("cache_creation_input_tokens"));
    let cache_write_1h = usage
        .get("cache_creation")
        .and_then(|cache| cache.get("ephemeral_1h_input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(cache_write);
    let tokens = Tokens {
        input: unsigned(usage.get("input_tokens")),
        cache_read: unsigned(usage.get("cache_read_input_tokens")),
        cache_write,
        cache_write_1h,
        output: unsigned(usage.get("output_tokens")),
    };
    (tokens.total() > 0).then(|| UsageRow {
        day: day_label(date),
        model: normalize_model(model),
        tokens,
    })
}

fn is_vertex(value: &Value) -> bool {
    let message_id = value
        .get("message")
        .and_then(|message| message.get("id"))
        .and_then(Value::as_str);
    let request_id = value.get("requestId").and_then(Value::as_str);
    let model = value
        .get("message")
        .and_then(|message| message.get("model"))
        .and_then(Value::as_str);
    message_id.is_some_and(|id| id.contains("_vrtx_"))
        || request_id.is_some_and(|id| id.contains("_vrtx_"))
        || model.is_some_and(|model| model.starts_with("claude-") && model.contains('@'))
        || contains_vertex_metadata(value, None)
}

fn contains_vertex_metadata(value: &Value, key: Option<&str>) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(field, nested)| {
            let lower = field.to_ascii_lowercase();
            lower.contains("vertex")
                || lower.contains("gcp")
                || contains_vertex_metadata(nested, Some(&lower))
        }),
        Value::Array(items) => items
            .iter()
            .any(|nested| contains_vertex_metadata(nested, key)),
        Value::String(text) => {
            key.is_some_and(is_provider_key) && text.to_ascii_lowercase().contains("vertex")
        }
        _ => false,
    }
}

fn is_provider_key(key: &str) -> bool {
    matches!(
        key,
        "provider"
            | "platform"
            | "backend"
            | "api_provider"
            | "apiprovider"
            | "api_type"
            | "apitype"
            | "source"
            | "vendor"
            | "client"
    )
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
                    amount(&metrics),
                    None,
                    Some(metrics.tokens.total()),
                    None,
                )
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
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
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
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
        CostProvenance::ListPriceEstimate,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn metrics_from(aggregate: &Aggregate) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::new(
            Some(aggregate.tokens.input),
            Some(aggregate.tokens.output),
            Some(aggregate.tokens.cache_read),
            Some(aggregate.tokens.cache_write),
            None,
        ),
        Some(aggregate.tokens.total()),
        Some(aggregate.requests),
        amount(aggregate),
        CostUsageCoverage::new(
            0,
            aggregate.unpriced_requests,
            0,
            aggregate.estimated_requests,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn amount(aggregate: &Aggregate) -> Option<ExactDecimal> {
    (aggregate.estimated_requests > 0).then(|| ExactDecimal::new(aggregate.amount))
}

struct Pricing {
    input: Decimal,
    output: Decimal,
    cache_write: Decimal,
    cache_read: Decimal,
    long_context: bool,
}

fn estimate_cost(model: &str, tokens: Tokens) -> Option<Decimal> {
    let pricing = match model {
        "claude-fable-5" => pricing((10, 6), (50, 6), (125, 7), (1, 6), false),
        "claude-haiku-4-5" => pricing((1, 6), (5, 6), (125, 8), (1, 7), false),
        "claude-opus-5" | "claude-opus-4-5" | "claude-opus-4-6" | "claude-opus-4-7"
        | "claude-opus-4-8" => pricing((5, 6), (25, 6), (625, 8), (5, 7), false),
        "claude-opus-4" | "claude-opus-4-1" => pricing((15, 6), (75, 6), (1875, 8), (15, 7), false),
        "claude-sonnet-4" | "claude-sonnet-4-5" => pricing((3, 6), (15, 6), (375, 8), (3, 7), true),
        "claude-sonnet-4-6" => pricing((3, 6), (15, 6), (375, 8), (3, 7), false),
        _ => return None,
    };
    let context = tokens
        .input
        .saturating_add(tokens.cache_read)
        .saturating_add(tokens.cache_write);
    let long = pricing.long_context && context > 200_000;
    let input_rate = if long {
        pricing.input * Decimal::from(2)
    } else {
        pricing.input
    };
    let output_rate = if long {
        pricing.output * Decimal::new(15, 1)
    } else {
        pricing.output
    };
    let cache_write_rate = if long {
        pricing.cache_write * Decimal::from(2)
    } else {
        pricing.cache_write
    };
    let cache_read_rate = if long {
        pricing.cache_read * Decimal::from(2)
    } else {
        pricing.cache_read
    };
    let one_hour_cache_write = tokens.cache_write_1h.min(tokens.cache_write);
    let five_minute_cache_write = tokens.cache_write.saturating_sub(one_hour_cache_write);
    Some(
        Decimal::from(tokens.input) * input_rate
            + Decimal::from(tokens.cache_read) * cache_read_rate
            + Decimal::from(five_minute_cache_write) * cache_write_rate
            + Decimal::from(one_hour_cache_write) * input_rate * Decimal::from(2)
            + Decimal::from(tokens.output) * output_rate,
    )
}

fn pricing(
    input: (i64, u32),
    output: (i64, u32),
    cache_write: (i64, u32),
    cache_read: (i64, u32),
    long_context: bool,
) -> Pricing {
    Pricing {
        input: Decimal::new(input.0, input.1),
        output: Decimal::new(output.0, output.1),
        cache_write: Decimal::new(cache_write.0, cache_write.1),
        cache_read: Decimal::new(cache_read.0, cache_read.1),
        long_context,
    }
}

fn normalize_model(model: &str) -> String {
    let mut normalized = model.trim().to_ascii_lowercase().replace('_', "-");
    if let Some((base, version)) = normalized.rsplit_once('@')
        && !base.is_empty()
        && version.len() == 8
        && version.bytes().all(|byte| byte.is_ascii_digit())
    {
        normalized = base.to_owned();
    }
    if let Some((base, suffix)) = normalized.rsplit_once('-')
        && suffix.len() == 8
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        normalized = base.to_owned();
    }
    normalized
}

fn unsigned(value: Option<&Value>) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(0)
}

fn day_label(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn map_file_error(error: ProviderFileError) -> ClassifiedError {
    match error {
        ProviderFileError::Cancelled => ClassifiedError::new(ErrorKind::Network),
        ProviderFileError::Missing => ClassifiedError::new(ErrorKind::ProviderUnavailable),
        _ => ClassifiedError::new(ErrorKind::Parse),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn streaming_rows_are_deduplicated_and_priced() {
        let root = tempfile::tempdir().expect("temporary Claude home");
        let project = root.path().join("projects/example");
        fs::create_dir_all(&project).expect("project directory");
        let row = |output| {
            format!(
                "{{\"type\":\"assistant\",\"timestamp\":\"2026-08-31T08:00:00Z\",\"requestId\":\"req-a\",\"message\":{{\"id\":\"msg-a\",\"model\":\"claude-fable-5\",\"usage\":{{\"input_tokens\":2,\"cache_creation_input_tokens\":100,\"cache_read_input_tokens\":20,\"output_tokens\":{output},\"cache_creation\":{{\"ephemeral_1h_input_tokens\":100}}}}}}}}\n"
            )
        };
        fs::write(project.join("session.jsonl"), row(5) + &row(10)).expect("fixture");

        let snapshot = scan_claude_cost_history(
            root.path(),
            Timestamp::parse("2026-08-31T10:00:00Z").expect("timestamp"),
            &CancellationToken::new(),
        )
        .expect("scan")
        .expect("history");

        assert_eq!(snapshot.history().request_count(), Some(1));
        assert_eq!(snapshot.history().total_tokens(), Some(132));
        assert!(snapshot.history().amount().is_some());
        assert_eq!(snapshot.daily()[0].models()[0].name(), "claude-fable-5");
    }

    #[test]
    fn vertex_rows_are_excluded() {
        let value: Value = serde_json::from_str(
            r#"{"type":"assistant","timestamp":"2026-08-31T08:00:00Z","requestId":"req_vrtx_a","message":{"id":"msg_vrtx_a","model":"claude-opus-4-5@20251101","usage":{"output_tokens":10}}}"#,
        )
        .expect("fixture");
        assert!(
            parse_row(
                &value,
                Date::from_calendar_date(2026, time::Month::August, 1).expect("date"),
                Date::from_calendar_date(2026, time::Month::August, 31).expect("date"),
                VertexFilter::Exclude,
            )
            .is_none()
        );
        assert!(
            parse_row(
                &value,
                Date::from_calendar_date(2026, time::Month::August, 1).expect("date"),
                Date::from_calendar_date(2026, time::Month::August, 31).expect("date"),
                VertexFilter::Only,
            )
            .is_some()
        );
    }
}
