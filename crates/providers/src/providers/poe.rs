//! Poe fixed-origin point balance and best-effort usage history.

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, DataConfidence, DetailChart, DetailChartKind, DetailChartPoint,
    DetailRow, DetailSection, DetailSensitivity, ErrorKind, FiniteNumber, ProviderId, Timestamp,
    UsageSample,
};
use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc2822;
use time::{Duration as TimeDuration, OffsetDateTime};
use unicode_normalization::UnicodeNormalization;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.poe.com/";
const KEY_NAMES: [&str; 1] = ["POE_API_KEY"];
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const MAX_HISTORY_PAGES: usize = 5;
const MAX_ROWS_PER_PAGE: usize = 100;
const MAX_HISTORY_ENTRIES: usize = MAX_HISTORY_PAGES * MAX_ROWS_PER_PAGE;
const MAX_CURSOR_BYTES: usize = 8 * 1024;
const HISTORY_SECONDS: i64 = 30 * 86_400;
const JS_DATE_LIMIT_MILLIS: f64 = 8_640_000_000_000_000.0;

/// Native Poe usage adapter.
pub struct PoeProvider {
    client: FixedApiClient,
}

impl PoeProvider {
    /// Resolves the Poe API key from its pinned environment name.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for an unusable key.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &KEY_NAMES)
    }

    /// Creates the production fixed-origin client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, credential: ApiKeyCredential) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            credential,
            transport_config()?,
        )?;
        Self::from_client(client)
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Poe {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches the required balance and optional recent point history.
    ///
    /// Every history failure is intentionally non-fatal. Entries accepted
    /// before a later page fails remain available, matching the pinned plugin
    /// contract without allowing optional data to hide a valid balance.
    ///
    /// # Errors
    ///
    /// Returns stable classified credential, transport, status, or balance
    /// parse errors without exposing provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let balance_url = self.client.url("usage/current_balance")?;
        let response = self
            .client
            .get_json_with_status_map(context, balance_url, poe_balance_status)
            .await?;
        let payload: Value = response.json()?;
        let balance = parse_balance(&payload)?;
        let entries = self.fetch_history(context, fetched_at).await;
        normalize(context.scope().clone(), fetched_at, balance, &entries)
    }

    async fn fetch_history(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Vec<HistoryEntry> {
        let Some(now) = clip_to_js_millis(fetched_at.as_offset_date_time()) else {
            return Vec::new();
        };
        let cutoff = now - TimeDuration::seconds(HISTORY_SECONDS);
        let mut entries = Vec::new();
        let mut cursor = None;

        'pages: for _ in 0..MAX_HISTORY_PAGES {
            let Ok(url) = self.history_url(cursor.as_deref()) else {
                break;
            };
            let Ok(response) = self.client.get_json(context, url).await else {
                break;
            };
            let Ok(payload) = response.json::<Value>() else {
                break;
            };
            let Some(root) = payload.as_object() else {
                break;
            };
            let rows = history_rows(root);
            if rows.len() > MAX_ROWS_PER_PAGE {
                break;
            }

            for row in rows {
                let Some(row) = row.as_object() else {
                    continue;
                };
                let Some(created_at) = entry_date(first_nullish(
                    row,
                    &["creation_time", "timestamp", "created_at"],
                )) else {
                    continue;
                };
                if created_at < cutoff {
                    continue;
                }
                let points = match optional_number(first_nullish(
                    row,
                    &["cost_points", "points", "point_cost"],
                )) {
                    Ok(value) => value.unwrap_or(0.0).max(0.0),
                    Err(()) => break 'pages,
                };
                let Ok(cost) = optional_number(first_nullish(row, &["cost_usd", "usd"])) else {
                    break 'pages;
                };
                let model =
                    trimmed_string(row.get("bot_name")).unwrap_or_else(|| "unknown".to_owned());
                let usage_type =
                    trimmed_string(row.get("usage_type")).unwrap_or_else(|| "unknown".to_owned());
                if entries.len() >= MAX_HISTORY_ENTRIES {
                    break 'pages;
                }
                entries.push(HistoryEntry {
                    created_at,
                    points,
                    cost,
                    model,
                    usage_type,
                });
            }

            let Ok(next) = next_cursor(root, rows) else {
                break;
            };
            let Some(next) = next else {
                break;
            };
            if next.len() > MAX_CURSOR_BYTES {
                break;
            }
            cursor = Some(next);

            match last_entry_date(rows) {
                Ok(Some(last)) if last < cutoff => break,
                Ok(_) => {}
                Err(()) => break,
            }
        }
        entries
    }

    fn history_url(&self, cursor: Option<&str>) -> Result<Url, ClassifiedError> {
        let mut url = self.client.url("usage/points_history")?;
        let query = cursor.map_or_else(
            || "limit=100".to_owned(),
            |cursor| format!("limit=100&starting_after={}", encode_uri_component(cursor)),
        );
        url.set_query(Some(&query));
        Ok(url)
    }
}

impl ProviderAdapter for PoeProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Poe)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Clone)]
struct HistoryEntry {
    created_at: OffsetDateTime,
    points: f64,
    cost: Option<f64>,
    model: String,
    usage_type: String,
}

#[derive(Clone, Default)]
struct Summary {
    points: f64,
    requests: usize,
    cost: f64,
    has_cost: bool,
}

struct GroupTotal {
    name: String,
    points: f64,
}

impl Summary {
    fn add_entry(&mut self, entry: &HistoryEntry) -> Result<(), ClassifiedError> {
        self.points = checked_sum(self.points, entry.points)?;
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        if let Some(cost) = entry.cost {
            self.cost = checked_sum(self.cost, cost.max(0.0))?;
            self.has_cost = true;
        }
        Ok(())
    }

    fn add_summary(&mut self, other: &Self) -> Result<(), ClassifiedError> {
        self.points = checked_sum(self.points, other.points)?;
        self.requests = self
            .requests
            .checked_add(other.requests)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        if other.has_cost {
            self.cost = checked_sum(self.cost, other.cost)?;
            self.has_cost = true;
        }
        Ok(())
    }
}

fn parse_balance(payload: &Value) -> Result<Option<f64>, ClassifiedError> {
    let root = payload
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    optional_number(root.get("current_point_balance"))
        .map_err(|()| ClassifiedError::new(ErrorKind::Parse))
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    balance: Option<f64>,
    entries: &[HistoryEntry],
) -> Result<UsageSample, ClassifiedError> {
    let mut daily = BTreeMap::<String, Summary>::new();
    let mut models = Vec::<GroupTotal>::new();
    let mut usage_types = Vec::<GroupTotal>::new();
    for entry in entries {
        let day = day_string(entry.created_at);
        daily.entry(day).or_default().add_entry(entry)?;
        add_group(&mut models, &entry.model, entry.points)?;
        add_group(&mut usage_types, &entry.usage_type, entry.points)?;
    }

    let seven = summarize_days(&daily, 7)?;
    let thirty = summarize_days(&daily, 30)?;
    let today_key = day_string(fetched_at.as_offset_date_time());
    let mut today = Summary::default();
    for entry in entries
        .iter()
        .filter(|entry| day_string(entry.created_at) == today_key)
    {
        today.add_entry(entry)?;
    }

    let mut rows = Vec::new();
    if let Some(balance) = balance {
        rows.push(detail_row(
            "Current balance",
            format!("{} points", compact(balance)?),
            None,
        )?);
    }
    if !entries.is_empty() {
        rows.push(summary_row("Today", &today)?);
        rows.push(summary_row("Last 7 days", &seven)?);
        rows.push(summary_row("Last 30 days", &thirty)?);

        models.sort_by(descending_total_then_name);
        if let Some(total) = models.first() {
            rows.push(detail_row(
                "Top model",
                total.name.clone(),
                Some(format!("{} points", compact(total.points)?)),
            )?);
        }

        usage_types.sort_by(descending_total_then_name);
        if !usage_types.is_empty() {
            let value = usage_types
                .iter()
                .take(2)
                .map(|total| {
                    compact(total.points).map(|points| format!("{}: {points} points", total.name))
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(" · ");
            rows.push(detail_row("Usage mix", value, None)?);
        }

        let mut recent = entries.iter().collect::<Vec<_>>();
        recent.sort_by_key(|entry| Reverse(entry.created_at));
        for (index, entry) in recent.into_iter().take(3).enumerate() {
            let time = time_string(entry.created_at);
            let (label, value) = if index == 0 {
                (
                    "Recent activity".to_owned(),
                    format!("{time} · {}", entry.model),
                )
            } else {
                (time, entry.model.clone())
            };
            rows.push(detail_row(
                &label,
                value,
                Some(format!("{} points", compact(entry.points)?)),
            )?);
        }
    }

    let chart = daily_chart(&daily)?;
    let section = DetailSection::new(Some("Points".to_owned()), rows, chart)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let login_method = balance
        .map(compact)
        .transpose()?
        .map(|balance| format!("Balance: {balance} points"));

    UsageSampleBuilder::new(scope, fetched_at)
        .confidence(DataConfidence::Unknown)
        .login_method(login_method)?
        .detail_sections(vec![section])
        .provenance("poe", "api")?
        .build()
}

fn daily_chart(daily: &BTreeMap<String, Summary>) -> Result<Option<DetailChart>, ClassifiedError> {
    if daily.is_empty() {
        return Ok(None);
    }
    let points = daily
        .iter()
        .map(|(day, summary)| {
            let value = FiniteNumber::new(summary.points)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            DetailChartPoint::new(day.clone(), value)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
        })
        .collect::<Result<Vec<_>, _>>()?;
    DetailChart::new(
        DetailChartKind::Bars,
        Some("Daily points".to_owned()),
        Some("points".to_owned()),
        points,
    )
    .map(Some)
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn history_rows(root: &Map<String, Value>) -> &[Value] {
    for key in ["data", "items", "results"] {
        if let Some(rows) = root.get(key).and_then(Value::as_array) {
            return rows;
        }
    }
    &[]
}

fn first_nullish<'a>(root: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .find_map(|key| root.get(*key).filter(|value| !value.is_null()))
}

fn trimmed_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn encode_uri_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len().saturating_mul(3));
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn optional_number(value: Option<&Value>) -> Result<Option<f64>, ()> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let number = match value {
        Value::Number(value) => value.as_f64().ok_or(())?,
        Value::String(value) => javascript_number(value.trim()).ok_or(())?,
        _ => return Err(()),
    };
    number.is_finite().then_some(Some(number)).ok_or(())
}

fn javascript_number(value: &str) -> Option<f64> {
    if value.is_empty() {
        return Some(0.0);
    }
    let unsigned = value.strip_prefix('+').unwrap_or(value);
    let radix = if let Some(digits) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        Some((digits, 16))
    } else if let Some(digits) = unsigned
        .strip_prefix("0b")
        .or_else(|| unsigned.strip_prefix("0B"))
    {
        Some((digits, 2))
    } else {
        unsigned
            .strip_prefix("0o")
            .or_else(|| unsigned.strip_prefix("0O"))
            .map(|digits| (digits, 8))
    };
    if let Some((digits, base)) = radix {
        if value.starts_with('+') || digits.is_empty() {
            return None;
        }
        let mut number = 0.0_f64;
        for digit in digits.chars() {
            let digit = digit.to_digit(base)?;
            number = number.mul_add(f64::from(base), f64::from(digit));
            if !number.is_finite() {
                return None;
            }
        }
        return Some(number);
    }
    value.parse().ok()
}

fn entry_date(value: Option<&Value>) -> Option<OffsetDateTime> {
    match value? {
        Value::Number(value) => numeric_date(value.as_f64()?),
        Value::String(value) => {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            javascript_number(value)
                .filter(|value| value.is_finite())
                .and_then(numeric_date)
                .or_else(|| textual_date(value))
        }
        _ => None,
    }
}

fn numeric_date(value: f64) -> Option<OffsetDateTime> {
    if !value.is_finite() {
        return None;
    }
    let milliseconds = if value > 100_000_000_000_000.0 {
        value / 1_000.0
    } else if value > 1_000_000_000_000.0 {
        value
    } else {
        value * 1_000.0
    };
    if !milliseconds.is_finite() || milliseconds.abs() > JS_DATE_LIMIT_MILLIS {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    let milliseconds = milliseconds.trunc() as i128;
    OffsetDateTime::from_unix_timestamp_nanos(milliseconds.checked_mul(1_000_000)?).ok()
}

fn textual_date(value: &str) -> Option<OffsetDateTime> {
    if let Ok(timestamp) = Timestamp::parse(value) {
        return clip_to_js_millis(timestamp.as_offset_date_time());
    }
    if value.len() == 10 {
        return Timestamp::parse(&format!("{value}T00:00:00Z"))
            .ok()
            .and_then(|timestamp| clip_to_js_millis(timestamp.as_offset_date_time()));
    }
    if let Some((date, clock)) = value.split_once(' ')
        && date.len() == 10
        && (clock.ends_with('Z') || clock.rfind(['+', '-']).is_some())
        && let Ok(timestamp) = Timestamp::parse(&format!("{date}T{clock}"))
    {
        return clip_to_js_millis(timestamp.as_offset_date_time());
    }
    OffsetDateTime::parse(value, &Rfc2822)
        .ok()
        .and_then(clip_to_js_millis)
}

fn clip_to_js_millis(value: OffsetDateTime) -> Option<OffsetDateTime> {
    // ISO component parsing floors sub-milliseconds before the Unix epoch;
    // this differs intentionally from numeric Date TimeClip truncation.
    let milliseconds = value.unix_timestamp_nanos().div_euclid(1_000_000);
    OffsetDateTime::from_unix_timestamp_nanos(milliseconds.checked_mul(1_000_000)?).ok()
}

fn next_cursor(root: &Map<String, Value>, rows: &[Value]) -> Result<Option<String>, ()> {
    if let Some(cursor) = trimmed_string(root.get("next_cursor")) {
        return Ok(Some(cursor));
    }
    if root.get("has_more") != Some(&Value::Bool(true)) || rows.is_empty() {
        return Ok(None);
    }
    let last = rows.last().ok_or(())?;
    if last.is_null() {
        return Err(());
    }
    Ok(last
        .as_object()
        .and_then(|row| trimmed_string(row.get("query_id"))))
}

fn last_entry_date(rows: &[Value]) -> Result<Option<OffsetDateTime>, ()> {
    let Some(last) = rows.last() else {
        return Ok(None);
    };
    if last.is_null() {
        return Err(());
    }
    Ok(last.as_object().and_then(|row| {
        entry_date(first_nullish(
            row,
            &["creation_time", "timestamp", "created_at"],
        ))
    }))
}

fn summarize_days(
    daily: &BTreeMap<String, Summary>,
    count: usize,
) -> Result<Summary, ClassifiedError> {
    let mut total = Summary::default();
    for summary in daily.values().skip(daily.len().saturating_sub(count)) {
        total.add_summary(summary)?;
    }
    Ok(total)
}

fn add_group(totals: &mut Vec<GroupTotal>, name: &str, points: f64) -> Result<(), ClassifiedError> {
    if let Some(total) = totals.iter_mut().find(|total| total.name == name) {
        total.points = checked_sum(total.points, points)?;
    } else {
        totals.push(GroupTotal {
            name: name.to_owned(),
            points,
        });
    }
    Ok(())
}

fn checked_sum(left: f64, right: f64) -> Result<f64, ClassifiedError> {
    let sum = left + right;
    sum.is_finite()
        .then_some(sum)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn descending_total_then_name(left: &GroupTotal, right: &GroupTotal) -> Ordering {
    right
        .points
        .total_cmp(&left.points)
        .then_with(|| left.name.nfc().cmp(right.name.nfc()))
}

fn summary_row(label: &str, summary: &Summary) -> Result<DetailRow, ClassifiedError> {
    let mut secondary = vec![format!("{} requests", summary.requests)];
    if summary.has_cost {
        secondary.push(format!("${}", fixed(summary.cost, 2)?));
    }
    detail_row(
        label,
        format!("{} points", compact(summary.points)?),
        Some(secondary.join(" · ")),
    )
}

fn detail_row(
    label: &str,
    value: String,
    secondary: Option<String>,
) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, secondary, DetailSensitivity::Public)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn compact(value: f64) -> Result<String, ClassifiedError> {
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let digits = usize::from(value < 1_000.0);
    let raw = fixed(value, digits)?;
    if raw.contains('e') {
        return Ok(raw);
    }
    let (sign, raw) = raw
        .strip_prefix('-')
        .map_or(("", raw.as_str()), |raw| ("-", raw));
    let (integer, fraction) = raw
        .split_once('.')
        .map_or((raw, None), |(integer, fraction)| (integer, Some(fraction)));
    let mut grouped = String::with_capacity(raw.len() + raw.len() / 3 + sign.len());
    grouped.push_str(sign);
    for (index, byte) in integer.bytes().enumerate() {
        if index > 0 && (integer.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    if let Some(fraction) = fraction {
        let fraction = fraction.trim_end_matches('0');
        if !fraction.is_empty() {
            grouped.push('.');
            grouped.push_str(fraction);
        }
    }
    Ok(grouped)
}

fn fixed(value: f64, digits: usize) -> Result<String, ClassifiedError> {
    if !value.is_finite() || digits > 20 {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let value = if value == 0.0 { 0.0 } else { value };
    if value.abs() >= 1e21 {
        let scientific = format!("{value:e}");
        let (mantissa, exponent) = scientific
            .split_once('e')
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let exponent = exponent
            .parse::<i32>()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        return Ok(format!("{mantissa}e{exponent:+}"));
    }
    let Some(decimal) = Decimal::from_f64_retain(value) else {
        return Ok(format!("{:.digits$}", 0.0));
    };
    let decimal = decimal.round_dp_with_strategy(
        u32::try_from(digits).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        RoundingStrategy::MidpointAwayFromZero,
    );
    Ok(format!("{decimal:.digits$}"))
}

fn day_string(value: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        value.year(),
        u8::from(value.month()),
        value.day()
    )
}

fn time_string(value: OffsetDateTime) -> String {
    format!(
        "{:02}-{:02} {:02}:{:02}",
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute()
    )
}

const fn poe_balance_status(status: u16) -> Option<ErrorKind> {
    match status {
        403 => Some(ErrorKind::AuthenticationExpired),
        408 | 429 | 500..=599 => Some(ErrorKind::Api),
        _ => None,
    }
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
