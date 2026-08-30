//! Synthetic fixed-origin quota adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::{Date, Month, OffsetDateTime, Time};
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.synthetic.new/";
const KEY_NAMES: [&str; 1] = ["SYNTHETIC_API_KEY"];
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const MAX_TRAVERSAL_DEPTH: usize = 128;
const MAX_JS_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
const JS_DATE_LIMIT_MILLIS: f64 = 8_640_000_000_000_000.0;

const PERCENT_USED_KEYS: &[&str] = &[
    "percentUsed",
    "usedPercent",
    "usagePercent",
    "usage_percent",
    "used_percent",
    "percent_used",
    "percent",
];
const PERCENT_REMAINING_KEYS: &[&str] = &[
    "percentRemaining",
    "remainingPercent",
    "remaining_percent",
    "percent_remaining",
];
const LIMIT_KEYS: &[&str] = &[
    "limit",
    "messageLimit",
    "message_limit",
    "messages",
    "maxRequests",
    "max_requests",
    "requestLimit",
    "request_limit",
    "quota",
    "max",
    "total",
    "capacity",
    "allowance",
];
const USED_KEYS: &[&str] = &[
    "used",
    "usage",
    "usedMessages",
    "used_messages",
    "messagesUsed",
    "messages_used",
    "requests",
    "requestCount",
    "request_count",
    "consumed",
    "spent",
];
const REMAINING_KEYS: &[&str] = &["remaining", "left", "available", "balance"];
const RESET_KEYS: &[&str] = &[
    "resetAt",
    "reset_at",
    "resetsAt",
    "resets_at",
    "renewAt",
    "renew_at",
    "renewsAt",
    "renews_at",
    "nextTickAt",
    "next_tick_at",
    "nextRegenAt",
    "next_regen_at",
    "periodEnd",
    "period_end",
    "expiresAt",
    "expires_at",
    "endAt",
    "end_at",
];
const PLAN_KEYS: &[&str] = &[
    "plan",
    "planName",
    "plan_name",
    "subscription",
    "subscriptionPlan",
    "tier",
    "package",
    "packageName",
];
const GENERIC_CONTAINER_KEYS: &[&str] = &[
    "quotas",
    "quota",
    "limits",
    "usage",
    "entries",
    "subscription",
];

/// Native Synthetic quota adapter.
pub struct SyntheticProvider {
    client: FixedApiClient,
}

impl SyntheticProvider {
    /// Resolves the Synthetic API key from its pinned environment name.
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
        if client.scope().provider() != ProviderId::Synthetic {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches and normalizes one deterministic sample timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable classified transport or parse errors without provider
    /// response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("v2/quotas")?;
        let response = self
            .client
            .get_json_with_status_map(context, url, synthetic_status)
            .await?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let payload: Value = response.json()?;
        normalize(context.scope().clone(), fetched_at, &payload)
    }
}

impl ProviderAdapter for SyntheticProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Synthetic)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

struct ParsedQuota {
    used_percent: f64,
    window_minutes: Option<f64>,
    resets_at: Option<Timestamp>,
    next_regen_percent: Option<f64>,
    cost: Option<ParsedCost>,
}

struct ParsedCost {
    used: f64,
    limit: f64,
    resets_at: Option<Timestamp>,
    next_regen_amount: Option<f64>,
}

impl ParsedQuota {
    fn rate_window(&self) -> Result<RateWindow, ClassifiedError> {
        let minutes = self.window_minutes.map(validated_minutes).transpose()?;
        let duration = minutes
            .map(WindowDuration::from_provider_minutes)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let reset_description = if self.resets_at.is_none() {
            minutes
                .and_then(window_description)
                .map(BoundedText::new)
                .transpose()
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        } else {
            None
        };
        let next_regen_percent = self
            .next_regen_percent
            .map(|percent| {
                if !percent.is_finite() {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                UsagePercent::new(percent.clamp(0.0, 100.0))
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
            })
            .transpose()?;
        RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(self.used_percent)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            duration,
            self.resets_at,
            reset_description,
            next_regen_percent,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
    }
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: &Value,
) -> Result<UsageSample, ClassifiedError> {
    let owned_root;
    let root = match payload {
        Value::Object(root) => root,
        Value::Array(items) => {
            owned_root = Map::from_iter([("quotas".to_owned(), Value::Array(items.clone()))]);
            &owned_root
        }
        _ => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let data = root
        .get("data")
        .filter(|value| value.is_object() || value.is_array());
    let data_object = data.and_then(Value::as_object);

    let known = [
        quota_property(root, "rollingFiveHourLimit")
            .or_else(|| data_object.and_then(|data| quota_property(data, "rollingFiveHourLimit"))),
        quota_property(root, "weeklyTokenLimit")
            .or_else(|| data_object.and_then(|data| quota_property(data, "weeklyTokenLimit"))),
        nested_quota_property(root, "search", "hourly").or_else(|| {
            data_object.and_then(|data| nested_quota_property(data, "search", "hourly"))
        }),
    ];

    let parsed = if known.iter().any(Option::is_some) {
        known
            .into_iter()
            .map(|quota| quota.map_or(Ok(None), parse_quota))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut candidates = GENERIC_CONTAINER_KEYS
            .iter()
            .map(|key| root.get(*key))
            .collect::<Vec<_>>();
        candidates.push(root.get("data"));
        if let Some(data) = data_object {
            candidates.extend(GENERIC_CONTAINER_KEYS.iter().map(|key| data.get(*key)));
        }

        let mut quotas = Vec::new();
        for candidate in candidates.into_iter().flatten() {
            collect_quotas(candidate, 0, &mut quotas)?;
            if !quotas.is_empty() {
                break;
            }
        }
        quotas
            .into_iter()
            .map(parse_quota)
            .filter_map(Result::transpose)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(Some)
            .collect()
    };

    if !parsed.iter().any(Option::is_some) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let plan = first_string(root, PLAN_KEYS)
        .or_else(|| data_object.and_then(|data| first_string(data, PLAN_KEYS)));
    let cost = parsed
        .iter()
        .flatten()
        .find_map(|quota| quota.cost.as_ref())
        .map(|cost| cost_summary(cost, fetched_at))
        .transpose()?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(primary) = parsed
        .first()
        .and_then(Option::as_ref)
        .map(ParsedQuota::rate_window)
        .transpose()?
    {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = parsed
        .get(1)
        .and_then(Option::as_ref)
        .map(ParsedQuota::rate_window)
        .transpose()?
    {
        builder = builder.secondary(secondary);
    }
    if let Some(tertiary) = parsed
        .get(2)
        .and_then(Option::as_ref)
        .map(ParsedQuota::rate_window)
        .transpose()?
    {
        builder = builder.tertiary(tertiary);
    }
    if let Some(cost) = cost {
        builder = builder.cost(cost);
    }
    builder
        .login_method(plan)?
        .provenance("synthetic", "api")?
        .build()
}

fn quota_property<'a>(root: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    root.get(key)
        .and_then(Value::as_object)
        .filter(|quota| is_quota(quota))
}

fn nested_quota_property<'a>(
    root: &'a Map<String, Value>,
    parent: &str,
    child: &str,
) -> Option<&'a Map<String, Value>> {
    root.get(parent)
        .and_then(Value::as_object)
        .and_then(|value| quota_property(value, child))
}

fn collect_quotas<'a>(
    value: &'a Value,
    depth: usize,
    output: &mut Vec<&'a Map<String, Value>>,
) -> Result<(), ClassifiedError> {
    if depth > MAX_TRAVERSAL_DEPTH {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    match value {
        Value::Array(items) => {
            for item in items {
                collect_quotas(item, depth + 1, output)?;
            }
        }
        Value::Object(object) if is_quota(object) => output.push(object),
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for key in keys {
                collect_quotas(&object[key], depth + 1, output)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn is_quota(payload: &Map<String, Value>) -> bool {
    [
        LIMIT_KEYS,
        USED_KEYS,
        REMAINING_KEYS,
        PERCENT_USED_KEYS,
        PERCENT_REMAINING_KEYS,
    ]
    .into_iter()
    .any(|keys| first_number(payload, keys).is_some())
}

fn parse_quota(payload: &Map<String, Value>) -> Result<Option<ParsedQuota>, ClassifiedError> {
    let mut used_percent = first_number(payload, PERCENT_USED_KEYS).map(normalized_percent);
    let percent_remaining = first_number(payload, PERCENT_REMAINING_KEYS).map(normalized_percent);
    if used_percent.is_none() {
        used_percent = percent_remaining.map(|remaining| 100.0 - remaining);
    }

    if used_percent.is_none() {
        let mut limit = first_number(payload, LIMIT_KEYS);
        let mut used = first_number(payload, USED_KEYS);
        let remaining = first_number(payload, REMAINING_KEYS);
        if limit.is_none()
            && let (Some(used), Some(remaining)) = (used, remaining)
        {
            limit = Some(used + remaining);
        }
        if used.is_none()
            && let (Some(limit), Some(remaining)) = (limit, remaining)
        {
            used = Some(limit - remaining);
        }
        if let (Some(used), Some(limit)) = (used, limit)
            && limit > 0.0
        {
            used_percent = Some(host_percentage(used, limit));
        }
    }
    let Some(used_percent) = used_percent else {
        return Ok(None);
    };
    let used_percent = used_percent.clamp(0.0, 100.0);

    let window_minutes = window_minutes(payload);
    let resets_at = first_date(payload, RESET_KEYS)?;
    let next_regen_percent = first_number(
        payload,
        &[
            "tickPercent",
            "tick_percent",
            "nextTickPercent",
            "next_tick_percent",
        ],
    )
    .map(normalized_percent);
    let cost = parse_cost(payload, used_percent, resets_at);
    Ok(Some(ParsedQuota {
        used_percent,
        window_minutes,
        resets_at,
        next_regen_percent,
        cost,
    }))
}

fn parse_cost(
    payload: &Map<String, Value>,
    used_percent: f64,
    resets_at: Option<Timestamp>,
) -> Option<ParsedCost> {
    let limit = first_currency(payload, &["maxCredits", "max_credits"])?;
    let remaining = first_currency(payload, &["remainingCredits", "remaining_credits"]);
    let explicit_used = first_currency(payload, &["usedCredits", "used_credits"]);
    let used = explicit_used.unwrap_or_else(|| {
        remaining.map_or(used_percent / 100.0 * limit, |remaining| {
            (limit - remaining).max(0.0)
        })
    });
    let next_regen_amount = first_currency(payload, &["nextRegenCredits", "next_regen_credits"]);
    Some(ParsedCost {
        used,
        limit,
        resets_at,
        next_regen_amount,
    })
}

fn cost_summary(cost: &ParsedCost, fetched_at: Timestamp) -> Result<CostSummary, ClassifiedError> {
    let currency = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    CostSummary::new(
        CostAmount::money(exact_decimal(cost.used)?, currency),
        exact_decimal(cost.limit)?,
        Some("Weekly".to_owned()),
        cost.resets_at,
        cost.next_regen_amount.map(exact_decimal).transpose()?,
        None,
        None,
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn first_string(payload: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        payload.get(*key).and_then(|value| match value {
            Value::String(value) => {
                let value = value.trim();
                (!value.is_empty()).then(|| value.to_owned())
            }
            _ => None,
        })
    })
}

fn first_number(payload: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| payload.get(*key).and_then(number_value))
}

fn number_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(value) => {
            let value = value.trim();
            (!value.is_empty()).then(|| js_number(value)).flatten()
        }
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

fn js_number(value: &str) -> Option<f64> {
    let radix = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|digits| (16, digits))
        .or_else(|| {
            value
                .strip_prefix("0b")
                .or_else(|| value.strip_prefix("0B"))
                .map(|digits| (2, digits))
        })
        .or_else(|| {
            value
                .strip_prefix("0o")
                .or_else(|| value.strip_prefix("0O"))
                .map(|digits| (8, digits))
        });
    let parsed = if let Some((radix, digits)) = radix {
        (!digits.is_empty())
            .then(|| u128::from_str_radix(digits, radix).ok())
            .flatten()
            .and_then(|value| value.to_string().parse::<f64>().ok())
    } else {
        value.parse::<f64>().ok()
    }?;
    parsed.is_finite().then_some(parsed)
}

fn normalized_percent(value: f64) -> f64 {
    if value <= 1.0 { value * 100.0 } else { value }
}

fn host_percentage(used: f64, limit: f64) -> f64 {
    if used.is_finite() && limit.is_finite() && limit > 0.0 {
        (used / limit * 100.0).clamp(0.0, 100.0)
    } else {
        100.0
    }
}

fn first_currency(payload: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| payload.get(*key).and_then(currency_value))
}

fn currency_value(value: &Value) -> Option<f64> {
    match value {
        Value::String(value) => {
            let cleaned = value.trim().replace(['$', ','], "");
            let cleaned = cleaned.trim();
            if cleaned.is_empty() {
                Some(0.0)
            } else {
                js_number(cleaned)
            }
        }
        _ => number_value(value),
    }
}

fn window_minutes(payload: &Map<String, Value>) -> Option<f64> {
    if let Some(value) = first_number(
        payload,
        &[
            "windowMinutes",
            "window_minutes",
            "periodMinutes",
            "period_minutes",
        ],
    ) {
        return Some(js_round(value));
    }
    if let Some(value) = first_number(
        payload,
        &["windowHours", "window_hours", "periodHours", "period_hours"],
    ) {
        return Some(js_round(value * 60.0));
    }
    if let Some(value) = first_number(
        payload,
        &["windowDays", "window_days", "periodDays", "period_days"],
    ) {
        return Some(js_round(value * 1440.0));
    }
    if let Some(value) = first_number(
        payload,
        &[
            "windowSeconds",
            "window_seconds",
            "periodSeconds",
            "period_seconds",
        ],
    ) {
        return Some(js_round(value / 60.0));
    }
    let text = first_string(
        payload,
        &[
            "window",
            "windowLabel",
            "window_label",
            "period",
            "periodLabel",
            "period_label",
        ],
    );
    text.as_deref().and_then(window_minutes_text)
}

fn window_minutes_text(raw: &str) -> Option<f64> {
    let compact = raw
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let split = compact
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(compact.len());
    let (number, suffix) = compact.split_at(split);
    let valid_number = !number.is_empty()
        && number.bytes().any(|byte| byte.is_ascii_digit())
        && number.bytes().filter(|byte| *byte == b'.').count() <= 1
        && !number.ends_with('.');
    let multiplier = match suffix {
        "m" | "min" | "mins" | "minute" | "minutes" => 1.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60.0,
        "d" | "day" | "days" => 1440.0,
        _ => return None,
    };
    if !valid_number {
        return None;
    }
    let value = number.parse::<f64>().ok()?;
    Some(js_round(value * multiplier))
}

fn js_round(value: f64) -> f64 {
    if value >= 0.0 {
        value.round()
    } else {
        (value + 0.5).floor()
    }
}

fn validated_minutes(value: f64) -> Result<i64, ClassifiedError> {
    if !value.is_finite() || value <= 0.0 || value > MAX_JS_SAFE_INTEGER || value.fract() != 0.0 {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    decimal_from_f64(value)?
        .to_i64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn window_description(minutes: i64) -> Option<String> {
    if minutes <= 0 {
        return None;
    }
    if minutes % 1440 == 0 {
        let days = minutes / 1440;
        return Some(format!(
            "{days} day{} window",
            if days == 1 { "" } else { "s" }
        ));
    }
    if minutes % 60 == 0 {
        let hours = minutes / 60;
        return Some(format!(
            "{hours} hour{} window",
            if hours == 1 { "" } else { "s" }
        ));
    }
    Some(format!(
        "{minutes} minute{} window",
        if minutes == 1 { "" } else { "s" }
    ))
}

fn first_date(
    payload: &Map<String, Value>,
    keys: &[&str],
) -> Result<Option<Timestamp>, ClassifiedError> {
    for key in keys {
        let Some(value) = payload.get(*key).filter(|value| !value.is_null()) else {
            continue;
        };
        if let Some(date) = parse_date(value)? {
            return Ok(Some(date));
        }
    }
    Ok(None)
}

fn parse_date(value: &Value) -> Result<Option<Timestamp>, ClassifiedError> {
    if let Some(number) = number_value(value) {
        if number > 1_000_000_000_000.0 {
            return unix_millis(number).map(Some);
        }
        if number > 1_000_000_000.0 {
            return unix_millis(number * 1000.0).map(Some);
        }
    }
    if let Value::String(value) = value {
        return Ok(js_iso_date(value.trim()));
    }
    Ok(None)
}

fn js_iso_date(value: &str) -> Option<Timestamp> {
    if let Ok(timestamp) = Timestamp::parse(value) {
        return truncate_to_millis(timestamp.as_offset_date_time());
    }
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = value[..4].parse::<i32>().ok()?;
    let month = Month::try_from(value[5..7].parse::<u8>().ok()?).ok()?;
    let day = value[8..10].parse::<u8>().ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Timestamp::new(date.with_time(Time::MIDNIGHT).assume_utc()).ok()
}

fn truncate_to_millis(value: OffsetDateTime) -> Option<Timestamp> {
    let millis = value.unix_timestamp_nanos().div_euclid(1_000_000);
    let value = OffsetDateTime::from_unix_timestamp_nanos(millis * 1_000_000).ok()?;
    Timestamp::new(value).ok()
}

fn unix_millis(value: f64) -> Result<Timestamp, ClassifiedError> {
    let value = value.trunc();
    if !value.is_finite() || value.abs() > JS_DATE_LIMIT_MILLIS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let millis = decimal_from_f64(value)?
        .to_i128()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let date = OffsetDateTime::from_unix_timestamp_nanos(millis * 1_000_000)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::new(date).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn exact_decimal(value: f64) -> Result<ExactDecimal, ClassifiedError> {
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(ExactDecimal::new(decimal_from_f64(value)?))
}

fn decimal_from_f64(value: f64) -> Result<Decimal, ClassifiedError> {
    let raw = value.to_string();
    Decimal::from_scientific(&raw)
        .or_else(|_| raw.parse())
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn synthetic_status(status: u16) -> Option<ErrorKind> {
    matches!(status, 401 | 403).then_some(ErrorKind::AuthenticationExpired)
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
