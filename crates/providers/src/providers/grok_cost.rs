//! Local Grok CLI session-token history.
//!
//! Grok records one bounded `signals.json` summary per CLI session. Subscription
//! credits are quota units rather than dollars, so this source reports session
//! counts and tokens without inventing spend.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use oab_domain::{
    ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage, CostUsageDailyBucket,
    CostUsageMetrics, CostUsageSnapshot, CostUsageTokenMix, ErrorKind, Timestamp,
};
use serde_json::Value;
use time::{Date, Duration, OffsetDateTime, UtcOffset};
use tokio_util::sync::CancellationToken;

use crate::provider_files::{ProviderFileError, ProviderFileRoot, ProviderFileScanLimits};

const HISTORY_DAYS: u16 = 30;
const MAX_SIGNAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

#[derive(Default)]
struct DayAggregate {
    tokens: u64,
    sessions: u64,
    models: BTreeSet<String>,
}

/// Scans the last 30 days of `~/.grok/sessions/**/signals.json` summaries.
///
/// # Errors
///
/// Returns a classified cancellation, unsafe-file, or normalization error.
pub fn scan_grok_token_history(
    grok_home: &Path,
    updated_at: Timestamp,
    cancellation: &CancellationToken,
) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
    let root = match ProviderFileRoot::open(grok_home) {
        Ok(root) => root,
        Err(ProviderFileError::Missing) => return Ok(None),
        Err(error) => return Err(map_file_error(error)),
    };
    let limits = ProviderFileScanLimits::new(4, 25_000, 25_000, MAX_SIGNAL_BYTES, MAX_TOTAL_BYTES)
        .map_err(map_file_error)?;
    let candidates = match root.scan("sessions", limits, cancellation) {
        Ok(candidates) => candidates,
        Err(ProviderFileError::Missing) => return Ok(None),
        Err(error) => return Err(map_file_error(error)),
    };
    let end = updated_at.as_offset_date_time().date();
    let start = end - Duration::days(i64::from(HISTORY_DAYS - 1));
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let mut days = BTreeMap::<String, DayAggregate>::new();

    for candidate in candidates {
        if candidate
            .relative_path()
            .file_name()
            .and_then(|name| name.to_str())
            != Some("signals.json")
        {
            continue;
        }
        let (modified_seconds, _) = candidate.modified_unix_time();
        let Ok(modified) = OffsetDateTime::from_unix_timestamp(modified_seconds) else {
            continue;
        };
        let date = modified.to_offset(local_offset).date();
        if date < start || date > end {
            continue;
        }
        let contents = root
            .read_candidate(&candidate, cancellation)
            .map_err(map_file_error)?;
        let Ok(value) = serde_json::from_slice::<Value>(contents.as_bytes()) else {
            continue;
        };
        let before_compaction = unsigned(value.get("totalTokensBeforeCompaction"));
        let context_used = unsigned(value.get("contextTokensUsed"));
        let session_tokens = before_compaction.saturating_add(context_used);
        let mut models = BTreeSet::new();
        if let Some(model) = bounded_model(value.get("primaryModelId")) {
            models.insert(model.to_owned());
        }
        if let Some(items) = value.get("modelsUsed").and_then(Value::as_array) {
            for item in items.iter().take(64) {
                if let Some(model) = bounded_model(Some(item)) {
                    models.insert(model.to_owned());
                }
            }
        }
        let aggregate = days.entry(day_label(date)).or_default();
        aggregate.tokens = aggregate.tokens.saturating_add(session_tokens);
        aggregate.sessions = aggregate.sessions.saturating_add(1);
        aggregate.models.extend(models);
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
    let mut history_tokens = 0_u64;
    let mut history_sessions = 0_u64;
    let mut today_tokens = 0_u64;
    let mut today_sessions = 0_u64;
    let mut buckets = Vec::with_capacity(days.len());
    for (day, aggregate) in days {
        history_tokens = history_tokens.saturating_add(aggregate.tokens);
        history_sessions = history_sessions.saturating_add(aggregate.sessions);
        if day == today {
            today_tokens = aggregate.tokens;
            today_sessions = aggregate.sessions;
        }
        buckets.push(
            CostUsageDailyBucket::new(
                day,
                None,
                metrics(aggregate.tokens, aggregate.sessions)?,
                aggregate.models.into_iter().collect(),
                Vec::new(),
                Vec::new(),
            )
            .map_err(|_| parse_error())?,
        );
    }
    CostUsageSnapshot::new(
        CostUnit::provider("tokens").expect("fixed provider unit"),
        metrics(today_tokens, today_sessions)?,
        metrics(history_tokens, history_sessions)?,
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

fn metrics(tokens: u64, sessions: u64) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::new(None, None, None, None, None),
        Some(tokens),
        Some(sessions),
        None,
        CostUsageCoverage::new(0, 0, sessions, 0).map_err(|_| parse_error())?,
    )
    .map_err(|_| parse_error())
}

fn bounded_model(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty() && model.len() <= 160)
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

fn map_file_error(error: ProviderFileError) -> ClassifiedError {
    match error {
        ProviderFileError::Cancelled => ClassifiedError::new(ErrorKind::Network),
        ProviderFileError::Missing => ClassifiedError::new(ErrorKind::ProviderUnavailable),
        _ => ClassifiedError::new(ErrorKind::Parse),
    }
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn session_signals_build_token_only_history() {
        let root = tempfile::tempdir().expect("temporary Grok home");
        let session = root.path().join("sessions/project/session-a");
        fs::create_dir_all(&session).expect("session directory");
        fs::write(
            session.join("signals.json"),
            br#"{"totalTokensBeforeCompaction":100,"contextTokensUsed":50,"primaryModelId":"grok-4.6","modelsUsed":["grok-4.6"]}"#,
        )
        .expect("fixture");

        let now = Timestamp::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .expect("timestamp");
        let snapshot = scan_grok_token_history(root.path(), now, &CancellationToken::new())
            .expect("scan")
            .expect("history");
        assert_eq!(snapshot.history().total_tokens(), Some(150));
        assert_eq!(snapshot.history().request_count(), Some(1));
        assert!(snapshot.history().amount().is_none());
        assert_eq!(snapshot.daily()[0].models_used().next(), Some("grok-4.6"));
    }
}
