//! Cursor token and spend history from the cross-platform tokscale cache.
//!
//! Tokscale writes Cursor usage exports under
//! `~/.config/tokscale/cursor-cache/usage*.csv`. The reader is bounded,
//! race-resistant, and uses the same column layouts supported by `CodexBar`.

use std::collections::BTreeMap;
use std::path::Path;

use oab_domain::{
    ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage, CostUsageDailyBucket,
    CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot, CostUsageTokenMix, CurrencyCode,
    ErrorKind, ExactDecimal, Timestamp,
};
use rust_decimal::Decimal;
use time::{Date, Duration, PrimitiveDateTime, UtcOffset};
use tokio_util::sync::CancellationToken;

use crate::provider_files::{ProviderFileError, ProviderFileRoot, ProviderFileScanLimits};

const HISTORY_DAYS: u16 = 30;
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Default)]
struct Tokens {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
    total: u64,
}

impl Tokens {
    fn add(&mut self, other: Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.cache_write = self.cache_write.saturating_add(other.cache_write);
        self.total = self.total.saturating_add(other.total);
    }
}

#[derive(Default)]
struct Aggregate {
    tokens: Tokens,
    requests: u64,
    amount: Decimal,
}

impl Aggregate {
    fn add(&mut self, tokens: Tokens, amount: Decimal) {
        self.tokens.add(tokens);
        self.requests = self.requests.saturating_add(1);
        self.amount += amount;
    }

    fn merge(&mut self, other: &Self) {
        self.tokens.add(other.tokens);
        self.requests = self.requests.saturating_add(other.requests);
        self.amount += other.amount;
    }
}

#[derive(Default)]
struct DayAggregate {
    total: Aggregate,
    models: BTreeMap<String, Aggregate>,
}

struct CsvLayout {
    model: usize,
    input_with_cache: usize,
    input_without_cache: usize,
    cache_read: usize,
    output: usize,
    total: Option<usize>,
    cost: usize,
}

/// Reads all current tokscale Cursor CSV exports for the last 30 local days.
///
/// Missing cache data is a supported empty result.
///
/// # Errors
///
/// Returns a classified cancellation, unsafe-file, or normalization failure.
pub fn scan_cursor_cost_history(
    cursor_cache_root: &Path,
    updated_at: Timestamp,
    cancellation: &CancellationToken,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    let root = match ProviderFileRoot::open(cursor_cache_root) {
        Ok(root) => root,
        Err(ProviderFileError::Missing) => return Ok(None),
        Err(error) => return Err(map_file_error(error)),
    };
    let limits = ProviderFileScanLimits::new(1, 512, 256, MAX_FILE_BYTES, MAX_TOTAL_BYTES)
        .map_err(map_file_error)?;
    let candidates = root
        .scan("", limits, cancellation)
        .map_err(map_file_error)?;
    let end = updated_at.as_offset_date_time().date();
    let start = end - Duration::days(i64::from(HISTORY_DAYS - 1));
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let mut days = BTreeMap::<String, DayAggregate>::new();

    for candidate in candidates {
        let relative = candidate.relative_path();
        if relative.components().count() != 1 {
            continue;
        }
        let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let is_csv = Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("csv"));
        if !name.starts_with("usage") || !is_csv || name.starts_with("usage.backup") {
            continue;
        }
        let contents = root
            .read_candidate(&candidate, cancellation)
            .map_err(map_file_error)?;
        parse_csv(contents.as_bytes(), start, end, local_offset, &mut days)?;
    }

    if days.is_empty() {
        return Ok(None);
    }
    build_snapshot(days, start, end, updated_at).map(Some)
}

#[allow(clippy::too_many_lines)]
fn parse_csv(
    bytes: &[u8],
    start: Date,
    end: Date,
    local_offset: UtcOffset,
    days: &mut BTreeMap<String, DayAggregate>,
) -> Result<(), ClassifiedError> {
    let text = std::str::from_utf8(bytes).map_err(|_| parse_error())?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let Some(header) = lines.next() else {
        return Ok(());
    };
    let header = parse_csv_line(header);
    let has_kind = header
        .iter()
        .any(|column| column.eq_ignore_ascii_case("kind"));
    let layout = if has_kind && header.len() >= 12 {
        CsvLayout {
            model: 4,
            input_with_cache: 6,
            input_without_cache: 7,
            cache_read: 8,
            output: 9,
            total: header
                .get(10)
                .is_some_and(|value| contains_total(value))
                .then_some(10),
            cost: 11,
        }
    } else if has_kind {
        CsvLayout {
            model: 2,
            input_with_cache: 4,
            input_without_cache: 5,
            cache_read: 6,
            output: 7,
            total: header
                .get(8)
                .is_some_and(|value| contains_total(value))
                .then_some(8),
            cost: 9,
        }
    } else {
        CsvLayout {
            model: 1,
            input_with_cache: 2,
            input_without_cache: 3,
            cache_read: 4,
            output: 5,
            total: header
                .get(6)
                .is_some_and(|value| contains_total(value))
                .then_some(6),
            cost: 7,
        }
    };
    for line in lines.take(100_000) {
        let columns = parse_csv_line(line);
        let required = [
            layout.model,
            layout.input_with_cache,
            layout.input_without_cache,
            layout.cache_read,
            layout.output,
            layout.cost,
        ];
        if required.iter().any(|index| *index >= columns.len()) {
            continue;
        }
        let model = columns[layout.model].trim();
        if model.is_empty() || model.len() > 160 {
            continue;
        }
        let Some(date) = parse_date(&columns[0], local_offset) else {
            continue;
        };
        if date < start || date > end {
            continue;
        }
        let input_with_cache = parse_integer(&columns[layout.input_with_cache]);
        let input = parse_integer(&columns[layout.input_without_cache]);
        let cache_read = parse_integer(&columns[layout.cache_read]);
        let output = parse_integer(&columns[layout.output]);
        let cache_write = input_with_cache.saturating_sub(input);
        let derived = input
            .saturating_add(output)
            .saturating_add(cache_read)
            .saturating_add(cache_write);
        if derived == 0 {
            continue;
        }
        let total = layout
            .total
            .and_then(|index| columns.get(index))
            .map_or(derived, |value| parse_integer(value));
        let amount = parse_cost(&columns[layout.cost]);
        let tokens = Tokens {
            input,
            output,
            cache_read,
            cache_write,
            total,
        };
        let day = days.entry(day_label(date)).or_default();
        day.total.add(tokens, amount);
        day.models
            .entry(model.to_owned())
            .or_default()
            .add(tokens, amount);
    }
    Ok(())
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
                    Some(ExactDecimal::new(metrics.amount)),
                    None,
                    Some(metrics.tokens.total),
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
        CostUsageTokenMix::new(
            Some(aggregate.tokens.input),
            Some(aggregate.tokens.output),
            Some(aggregate.tokens.cache_read),
            Some(aggregate.tokens.cache_write),
            None,
        ),
        Some(aggregate.tokens.total),
        Some(aggregate.requests),
        Some(ExactDecimal::new(aggregate.amount)),
        CostUsageCoverage::new(aggregate.requests, 0, 0, 0).map_err(|_| parse_error())?,
    )
    .map_err(|_| parse_error())
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut columns = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                current.push('"');
                characters.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => columns.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    columns.push(current);
    columns
}

fn parse_integer(value: &str) -> u64 {
    value.trim().replace(',', "").parse::<u64>().unwrap_or(0)
}

fn parse_cost(value: &str) -> Decimal {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "-" || normalized == "included" || normalized == "nan"
    {
        return Decimal::ZERO;
    }
    normalized
        .replace(['$', ','], "")
        .parse::<Decimal>()
        .unwrap_or(Decimal::ZERO)
        .max(Decimal::ZERO)
}

fn parse_date(value: &str, local_offset: UtcOffset) -> Option<Date> {
    let value = value.trim();
    if let Ok(timestamp) = Timestamp::parse(value) {
        return Some(
            timestamp
                .as_offset_date_time()
                .to_offset(local_offset)
                .date(),
        );
    }
    if let Ok(format) = time::format_description::parse_borrowed::<3>("[year]-[month]-[day]")
        && let Ok(date) = Date::parse(value, &format)
    {
        return Some(date);
    }
    for pattern in [
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]",
        "[year]-[month]-[day]T[hour]:[minute]:[second]",
        "[year]-[month]-[day] [hour]:[minute]:[second]",
    ] {
        let Ok(format) = time::format_description::parse_borrowed::<3>(pattern) else {
            continue;
        };
        if let Ok(timestamp) = PrimitiveDateTime::parse(value, &format) {
            return Some(timestamp.assume_offset(local_offset).date());
        }
    }
    None
}

fn contains_total(value: &str) -> bool {
    value.to_ascii_lowercase().contains("total")
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn reads_tokscale_csv_with_authoritative_total() {
        let root = tempfile::tempdir().expect("cache");
        fs::write(
            root.path().join("usage.csv"),
            "Date,Model,Input with cache,Input without cache,Cache read,Output,Total Tokens,Cost\n2026-08-31T08:00:00Z,claude-sonnet,120,100,20,10,150,$1.25\n",
        )
        .expect("fixture");
        let snapshot = scan_cursor_cost_history(
            root.path(),
            Timestamp::parse("2026-08-31T10:00:00Z").expect("timestamp"),
            &CancellationToken::new(),
        )
        .expect("scan")
        .expect("history");
        assert_eq!(snapshot.history().total_tokens(), Some(150));
        assert_eq!(snapshot.history().request_count(), Some(1));
        assert_eq!(
            snapshot.history().amount().expect("amount").to_string(),
            "1.25"
        );
        assert_eq!(snapshot.daily()[0].models()[0].name(), "claude-sonnet");
    }
}
