//! Bounded local Codex token and list-price history.
//!
//! Codex writes cumulative token snapshots to daily JSONL rollout files.  This
//! reader follows the same source-of-truth strategy as `CodexBar`: it derives
//! history locally, never sends session contents anywhere, and treats prices as
//! estimates rather than vendor-metered spend.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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
const MAX_DAY_BYTES: usize = 1024 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;
const UNKNOWN_MODEL: &str = "unknown";

#[derive(Clone, Copy, Default)]
struct Totals {
    input: u64,
    cached: u64,
    cache_write: u64,
    output: u64,
    reasoning: u64,
}

impl Totals {
    fn total(self) -> u64 {
        self.input.saturating_add(self.output)
    }

    fn add(&mut self, other: Self) {
        self.input = self.input.saturating_add(other.input);
        self.cached = self.cached.saturating_add(other.cached);
        self.cache_write = self.cache_write.saturating_add(other.cache_write);
        self.output = self.output.saturating_add(other.output);
        self.reasoning = self.reasoning.saturating_add(other.reasoning);
    }

    fn growth_from(self, previous: Option<Self>) -> Self {
        let previous = previous.unwrap_or_default();
        Self {
            input: self.input.saturating_sub(previous.input),
            cached: self.cached.saturating_sub(previous.cached),
            cache_write: self.cache_write.saturating_sub(previous.cache_write),
            output: self.output.saturating_sub(previous.output),
            reasoning: self.reasoning.saturating_sub(previous.reasoning),
        }
    }

    fn clamp_to(self, maximum: Self) -> Self {
        Self {
            input: self.input.min(maximum.input),
            cached: self.cached.min(maximum.cached),
            cache_write: self.cache_write.min(maximum.cache_write),
            output: self.output.min(maximum.output),
            reasoning: self.reasoning.min(maximum.reasoning),
        }
    }
}

#[derive(Default)]
struct Aggregate {
    tokens: Totals,
    requests: u64,
    estimated_requests: u64,
    unpriced_requests: u64,
    amount: Decimal,
}

impl Aggregate {
    fn add(&mut self, tokens: Totals, model: &str) {
        if tokens.total() == 0 {
            return;
        }
        self.tokens.add(tokens);
        self.requests = self.requests.saturating_add(1);
        if let Some(amount) = estimate_cost(model, tokens) {
            self.amount += amount;
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

/// Scans the last 30 local days of Codex rollout history.
///
/// Missing history is a supported empty result. Unsafe, incomplete, or
/// malformed provider-file acquisition fails the optional enrichment without
/// invalidating live quota data.
///
/// # Errors
///
/// Returns a classified cancellation, unsafe-file, or normalized-data error.
pub fn scan_codex_cost_history(
    codex_home: &Path,
    updated_at: Timestamp,
    cancellation: &CancellationToken,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    let root = match ProviderFileRoot::open(codex_home) {
        Ok(root) => root,
        Err(ProviderFileError::Missing) => return Ok(None),
        Err(error) => return Err(map_file_error(error)),
    };
    let end = updated_at.as_offset_date_time().date();
    let start = end - Duration::days(i64::from(HISTORY_DAYS - 1));
    let limits = ProviderFileScanLimits::new(2, 25_000, 25_000, MAX_FILE_BYTES, MAX_DAY_BYTES)
        .map_err(map_file_error)?;
    let mut days = BTreeMap::<String, DayAggregate>::new();
    let mut saw_rollout = false;

    for offset in 0..HISTORY_DAYS {
        if cancellation.is_cancelled() {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }
        let date = start + Duration::days(i64::from(offset));
        let relative = day_directory(date);
        let candidates = match root.scan(&relative, limits, cancellation) {
            Ok(candidates) => candidates,
            Err(ProviderFileError::Missing) => continue,
            Err(error) => return Err(map_file_error(error)),
        };
        for candidate in candidates {
            if candidate
                .relative_path()
                .extension()
                .and_then(|value| value.to_str())
                != Some("jsonl")
            {
                continue;
            }
            saw_rollout = true;
            parse_rollout(&root, &candidate, start, end, &mut days, cancellation)?;
        }
    }

    if !saw_rollout || days.is_empty() {
        return Ok(None);
    }
    build_snapshot(days, start, end, updated_at).map(Some)
}

fn parse_rollout(
    root: &ProviderFileRoot,
    candidate: &crate::provider_files::ProviderFileCandidate,
    start: Date,
    end: Date,
    days: &mut BTreeMap<String, DayAggregate>,
    cancellation: &CancellationToken,
) -> Result<(), ClassifiedError> {
    let mut current_model = String::from(UNKNOWN_MODEL);
    let mut watermark: Option<Totals> = None;
    let mut seen = BTreeSet::<(u64, u64, u64, u64, u64)>::new();

    root.visit_candidate_lines(candidate, MAX_LINE_BYTES, cancellation, |line| {
        let might_be_context = contains(line, b"\"turn_context\"");
        let might_be_usage = contains(line, b"\"token_count\"");
        if !might_be_context && !might_be_usage {
            return;
        }
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            return;
        };
        if value.get("type").and_then(Value::as_str) == Some("turn_context") {
            if let Some(model) = model_from(value.get("payload")) {
                model.clone_into(&mut current_model);
            }
            return;
        }
        let Some(payload) = value.get("payload") else {
            return;
        };
        if value.get("type").and_then(Value::as_str) != Some("event_msg")
            || payload.get("type").and_then(Value::as_str) != Some("token_count")
        {
            return;
        }
        let Some(info) = payload.get("info") else {
            return;
        };
        if let Some(model) = model_from(Some(info)).or_else(|| model_from(Some(payload))) {
            model.clone_into(&mut current_model);
        }
        let total = info.get("total_token_usage").map(parse_totals);
        let last = info.get("last_token_usage").map(parse_totals);
        let delta = match (total, last) {
            (Some(total), last) => {
                let key = (
                    total.input,
                    total.cached,
                    total.cache_write,
                    total.output,
                    total.reasoning,
                );
                if !seen.insert(key) {
                    return;
                }
                let growth = total.growth_from(watermark);
                watermark = Some(match watermark {
                    Some(previous) => Totals {
                        input: previous.input.max(total.input),
                        cached: previous.cached.max(total.cached),
                        cache_write: previous.cache_write.max(total.cache_write),
                        output: previous.output.max(total.output),
                        reasoning: previous.reasoning.max(total.reasoning),
                    },
                    None => total,
                });
                last.map_or(growth, |last| {
                    if growth.total() == 0 {
                        growth
                    } else {
                        growth.clamp_to(last)
                    }
                })
            }
            (None, Some(last)) => last,
            (None, None) => return,
        };
        if delta.total() == 0 {
            return;
        }
        let Some(date) = value
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(|raw| Timestamp::parse(raw).ok())
            .map(|timestamp| timestamp.as_offset_date_time().date())
        else {
            return;
        };
        if date < start || date > end {
            return;
        }
        let day = day_label(date);
        let aggregate = days.entry(day).or_default();
        aggregate.total.add(delta, &current_model);
        aggregate
            .models
            .entry(current_model.clone())
            .or_default()
            .add(delta, &current_model);
    })
    .map_err(map_file_error)
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
                let amount = amount(&metrics);
                CostUsageModelBreakdown::new(
                    name,
                    metrics_from(&metrics)?,
                    amount,
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
            Some(aggregate.tokens.cached),
            Some(aggregate.tokens.cache_write),
            Some(aggregate.tokens.reasoning),
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

fn parse_totals(value: &Value) -> Totals {
    let input = unsigned(value.get("input_tokens"));
    let cached = unsigned(value.get("cached_input_tokens"))
        .max(unsigned(value.get("cache_read_input_tokens")));
    let output = unsigned(value.get("output_tokens"));
    let reasoning = unsigned(value.get("reasoning_output_tokens")).min(output);
    Totals {
        input,
        cached: cached.min(input),
        cache_write: unsigned(value.get("cache_write_input_tokens")),
        output,
        reasoning,
    }
}

fn unsigned(value: Option<&Value>) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(0)
}

fn model_from(value: Option<&Value>) -> Option<&str> {
    let value = value?;
    value
        .get("model")
        .or_else(|| value.get("model_name"))
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty() && model.len() <= 160)
}

fn estimate_cost(model: &str, tokens: Totals) -> Option<Decimal> {
    let (input, output, cached, cache_write) = match model {
        "gpt-5" | "gpt-5-codex" | "gpt-5.1" | "gpt-5.1-codex" | "gpt-5.1-codex-max" => (
            Decimal::new(125, 8),
            Decimal::new(1, 5),
            Decimal::new(125, 9),
            Decimal::new(125, 8),
        ),
        "gpt-5-mini" | "gpt-5.1-codex-mini" => (
            Decimal::new(25, 8),
            Decimal::new(2, 6),
            Decimal::new(25, 9),
            Decimal::new(25, 8),
        ),
        "gpt-5.2" | "gpt-5.2-codex" | "gpt-5.3-codex" | "gpt-5.4" => (
            Decimal::new(175, 8),
            Decimal::new(14, 6),
            Decimal::new(175, 9),
            Decimal::new(175, 8),
        ),
        "gpt-5.5" => (
            Decimal::new(5, 6),
            Decimal::new(3, 5),
            Decimal::new(5, 7),
            Decimal::new(5, 6),
        ),
        "gpt-5.6-sol" => (
            Decimal::new(5, 6),
            Decimal::new(3, 5),
            Decimal::new(5, 7),
            Decimal::new(625, 8),
        ),
        "gpt-5.6-terra" => (
            Decimal::new(2, 6),
            Decimal::new(12, 6),
            Decimal::new(2, 7),
            Decimal::new(25, 7),
        ),
        "gpt-5.6-luna" => (
            Decimal::new(2, 7),
            Decimal::new(12, 7),
            Decimal::new(2, 8),
            Decimal::new(25, 8),
        ),
        _ => return None,
    };
    let uncached = tokens
        .input
        .saturating_sub(tokens.cached)
        .saturating_sub(tokens.cache_write);
    Some(
        Decimal::from(uncached) * input
            + Decimal::from(tokens.cached) * cached
            + Decimal::from(tokens.cache_write) * cache_write
            + Decimal::from(tokens.output) * output,
    )
}

fn day_directory(date: Date) -> PathBuf {
    PathBuf::from(format!(
        "sessions/{:04}/{:02}/{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    ))
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
    fn local_rollout_builds_daily_tokens_and_estimated_cost() {
        let root = tempfile::tempdir().expect("temporary Codex home");
        let day = root.path().join("sessions/2026/08/31");
        fs::create_dir_all(&day).expect("daily directory");
        let rollout = concat!(
            "{\"timestamp\":\"2026-08-31T08:00:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.6-sol\"}}\n",
            "{\"timestamp\":\"2026-08-31T08:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":20,\"output_tokens\":20},\"last_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":20,\"output_tokens\":20}}}}\n",
            "{\"timestamp\":\"2026-08-31T08:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":150,\"cached_input_tokens\":30,\"output_tokens\":30},\"last_token_usage\":{\"input_tokens\":50,\"cached_input_tokens\":10,\"output_tokens\":10}}}}\n"
        );
        fs::write(day.join("rollout.jsonl"), rollout).expect("rollout fixture");

        let snapshot = scan_codex_cost_history(
            root.path(),
            Timestamp::parse("2026-08-31T10:00:00Z").expect("timestamp"),
            &CancellationToken::new(),
        )
        .expect("scan succeeds")
        .expect("history exists");

        assert_eq!(snapshot.daily().len(), 1);
        assert_eq!(snapshot.daily()[0].day(), "2026-08-31");
        assert_eq!(snapshot.session().total_tokens(), Some(180));
        assert_eq!(snapshot.history().request_count(), Some(2));
        assert!(snapshot.history().amount().is_some());
        assert_eq!(
            snapshot.history().coverage().estimated(),
            snapshot.history().request_count().unwrap_or(0)
        );
        assert_eq!(snapshot.daily()[0].models()[0].name(), "gpt-5.6-sol");
    }
}
