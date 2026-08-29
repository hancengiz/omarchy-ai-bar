//! Native adapter for sub2api group-key usage responses.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, NamedRateWindow, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample,
    WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, format_integer, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "SUB2API_API_KEY";
const BASE_URL: &str = "SUB2API_BASE_URL";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RATE_LIMITS: usize = 16;
const DEFAULT_TIME_ZONE: &str = "UTC";

/// Validated sub2api endpoint and group-key credential.
pub struct Sub2ApiSettings {
    credential: ApiKeyCredential,
    endpoint: ConfiguredEndpoint,
    time_zone: String,
}

impl Sub2ApiSettings {
    /// Resolves the baseline endpoint, key, and request time zone.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or endpoint configuration error.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let raw = environment
            .get(BASE_URL)
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::LoopbackHttp)?;
        let time_zone = environment
            .get("TZ")
            .and_then(|value| clean_setting(value))
            .map(str::to_owned)
            .or_else(system_time_zone)
            .unwrap_or_else(|| DEFAULT_TIME_ZONE.to_owned());
        Ok(Self {
            credential,
            endpoint,
            time_zone: validate_time_zone(&time_zone)?,
        })
    }
}

impl Debug for Sub2ApiSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Sub2ApiSettings")
            .field("credential", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("time_zone", &self.time_zone)
            .finish()
    }
}

/// Native sub2api provider adapter.
pub struct Sub2ApiProvider {
    client: FixedApiClient,
    endpoint: ConfiguredEndpoint,
    time_zone: String,
}

impl Sub2ApiProvider {
    /// Creates one exact configured-endpoint production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: Sub2ApiSettings) -> Result<Self, ClassifiedError> {
        let Sub2ApiSettings {
            credential,
            endpoint,
            time_zone,
        } = settings;
        let client = FixedApiClient::new_bearer(
            scope,
            endpoint.url().clone(),
            endpoint.class(),
            credential,
            transport_config()?,
        )?;
        Self::from_client(client, endpoint, time_zone)
    }

    /// Wraps an already validated account-scoped client and matching endpoint.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for another provider, a mismatched base, or
    /// an invalid request time-zone identifier.
    pub fn from_client(
        client: FixedApiClient,
        endpoint: ConfiguredEndpoint,
        time_zone: impl AsRef<str>,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Sub2Api || client.base_url() != endpoint.url() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            client,
            endpoint,
            time_zone: validate_time_zone(time_zone.as_ref())?,
        })
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
        let mut url = usage_url(&self.endpoint)?;
        url.query_pairs_mut()
            .append_pair("days", "30")
            .append_pair("timezone", &self.time_zone);
        let response: UsageResponse = self
            .client
            .get_json(context, url)
            .await
            .map_err(|error| {
                if error.kind() == ErrorKind::PermissionDenied {
                    ClassifiedError::new(ErrorKind::AuthenticationExpired)
                } else {
                    error
                }
            })?
            .json()?;
        normalize(context.scope().clone(), fetched_at, &response)
    }
}

impl ProviderAdapter for Sub2ApiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Sub2Api)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageResponse {
    #[serde(rename = "mode")]
    _mode: Option<String>,
    is_valid: Option<bool>,
    #[serde(rename = "status")]
    _status: Option<String>,
    plan_name: Option<String>,
    #[serde(rename = "remaining")]
    _remaining: Option<JsonDecimal>,
    balance: Option<JsonDecimal>,
    unit: Option<String>,
    quota: Option<Quota>,
    subscription: Option<Subscription>,
    #[serde(rename = "rate_limits")]
    rate_limits: Option<Vec<RateLimit>>,
    usage: Option<UsageTotals>,
    #[serde(rename = "expires_at")]
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct Quota {
    limit: JsonDecimal,
    used: JsonDecimal,
    #[serde(rename = "remaining")]
    _remaining: JsonDecimal,
    unit: Option<String>,
}

#[derive(Deserialize)]
struct Subscription {
    daily_usage_usd: Option<JsonDecimal>,
    weekly_usage_usd: Option<JsonDecimal>,
    monthly_usage_usd: Option<JsonDecimal>,
    daily_limit_usd: Option<JsonDecimal>,
    weekly_limit_usd: Option<JsonDecimal>,
    monthly_limit_usd: Option<JsonDecimal>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct RateLimit {
    window: String,
    limit: JsonDecimal,
    used: JsonDecimal,
    #[serde(rename = "remaining")]
    _remaining: JsonDecimal,
    reset_at: Option<String>,
}

#[derive(Deserialize)]
struct UsageTotals {
    today: Option<Totals>,
    total: Option<Totals>,
}

#[derive(Deserialize)]
struct Totals {
    requests: Option<JsonDecimal>,
    total_tokens: Option<JsonDecimal>,
    actual_cost: Option<JsonDecimal>,
}

#[derive(Clone, Copy)]
struct JsonDecimal(Decimal);

impl<'de> Deserialize<'de> for JsonDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        let raw = number.to_string();
        Decimal::from_scientific(&raw)
            .or_else(|_| raw.parse())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid decimal"))
    }
}

struct WindowSet {
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
    tertiary: Option<RateWindow>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: &UsageResponse,
) -> Result<UsageSample, ClassifiedError> {
    if response.is_valid == Some(false) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let unit = preferred_unit(response);
    let windows = quota_windows(response, &unit)?;
    let extra_windows = rate_windows(response.rate_limits.as_deref().unwrap_or_default())?;
    let expires_at = response
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.expires_at.as_deref())
        .map(parse_date)
        .transpose()?
        .or(response.expires_at.as_deref().map(parse_date).transpose()?);
    let details = detail_sections(response, &unit)?;
    let plan = clean_optional(response.plan_name.as_deref());

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .extra_windows(extra_windows)
        .detail_sections(details)
        .subscription_expires_at(expires_at);
    if let Some(primary) = windows.primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = windows.secondary {
        builder = builder.secondary(secondary);
    }
    if let Some(tertiary) = windows.tertiary {
        builder = builder.tertiary(tertiary);
    }
    builder
        .organization(plan.clone())?
        .login_method(plan)?
        .provenance("sub2api", "api")?
        .build()
}

fn quota_windows(response: &UsageResponse, unit: &str) -> Result<WindowSet, ClassifiedError> {
    if let Some(subscription) = response.subscription.as_ref() {
        let daily = optional_window(
            decimal(subscription.daily_usage_usd),
            subscription.daily_limit_usd.map(|value| value.0),
            Some(1440),
            "USD",
        )?;
        let weekly = optional_window(
            decimal(subscription.weekly_usage_usd),
            subscription.weekly_limit_usd.map(|value| value.0),
            Some(10080),
            "USD",
        )?;
        let monthly = optional_window(
            decimal(subscription.monthly_usage_usd),
            subscription.monthly_limit_usd.map(|value| value.0),
            Some(43200),
            "USD",
        )?;
        return Ok(WindowSet {
            primary: daily,
            secondary: weekly,
            tertiary: monthly,
        });
    }
    let primary = response
        .quota
        .as_ref()
        .map(|quota| {
            optional_window(
                quota.used.0,
                Some(quota.limit.0),
                None,
                clean_non_empty(quota.unit.as_deref()).unwrap_or(unit),
            )
        })
        .transpose()?
        .flatten();
    Ok(WindowSet {
        primary,
        secondary: None,
        tertiary: None,
    })
}

fn optional_window(
    used: Decimal,
    limit: Option<Decimal>,
    minutes: Option<i64>,
    unit: &str,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let Some(limit) = limit.filter(|value| *value > Decimal::ZERO) else {
        return Ok(None);
    };
    window(used, limit, minutes, None, unit).map(Some)
}

fn window(
    used: Decimal,
    limit: Decimal,
    minutes: Option<i64>,
    resets_at: Option<Timestamp>,
    unit: &str,
) -> Result<RateWindow, ClassifiedError> {
    let percent = percentage(used, limit)?;
    let duration = minutes
        .map(WindowDuration::from_provider_minutes)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        duration,
        resets_at,
        Some(
            BoundedText::new(format!(
                "{} / {}",
                format_money(used, unit),
                format_money(limit, unit)
            ))
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn rate_windows(rates: &[RateLimit]) -> Result<Vec<NamedRateWindow>, ClassifiedError> {
    if rates.len() > MAX_RATE_LIMITS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    rates
        .iter()
        .map(|rate| {
            let id = clean_required(&rate.window)?;
            let normalized = id.to_ascii_lowercase();
            let (title, minutes) = match normalized.as_str() {
                "5h" => ("5 hour limit".to_owned(), Some(300)),
                "1d" => ("Daily limit".to_owned(), Some(1440)),
                "7d" => ("7 day limit".to_owned(), Some(10080)),
                _ => (format!("{id} limit"), None),
            };
            let reset = rate.reset_at.as_deref().map(parse_date).transpose()?;
            let window = window(rate.used.0, rate.limit.0, minutes, reset, "USD")?;
            Ok(NamedRateWindow::new(
                BoundedText::new(id).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                BoundedText::new(title).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                window,
            ))
        })
        .collect()
}

fn detail_sections(
    response: &UsageResponse,
    unit: &str,
) -> Result<Vec<DetailSection>, ClassifiedError> {
    let mut rows = Vec::new();
    if let Some(balance) = response.balance {
        rows.push(detail_row("Balance", format_money(balance.0, unit), None)?);
    }
    if let Some(usage) = response.usage.as_ref() {
        push_totals(&mut rows, "Today", usage.today.as_ref())?;
        push_totals(&mut rows, "All time", usage.total.as_ref())?;
    }
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let section = DetailSection::new(Some("Usage summary".to_owned()), rows, None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(vec![section])
}

fn push_totals(
    rows: &mut Vec<DetailRow>,
    title: &str,
    totals: Option<&Totals>,
) -> Result<(), ClassifiedError> {
    let Some(totals) = totals else {
        return Ok(());
    };
    let requests = integer(totals.requests)?;
    let tokens = integer(totals.total_tokens)?;
    let cost = decimal(totals.actual_cost);
    rows.push(detail_row(
        &format!("{title} requests"),
        format_integer(requests),
        None,
    )?);
    rows.push(detail_row(
        &format!("{title} tokens"),
        format_integer(tokens),
        Some(format_money(cost, "USD")),
    )?);
    Ok(())
}

fn detail_row(
    label: &str,
    value: String,
    secondary: Option<String>,
) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, secondary, DetailSensitivity::Personal)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn usage_url(endpoint: &ConfiguredEndpoint) -> Result<Url, ClassifiedError> {
    let segments = endpoint
        .url()
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>()
        })
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if segments.ends_with(&["v1", "usage"]) {
        return Ok(endpoint.url().clone());
    }
    if segments.last() == Some(&"v1") {
        endpoint.path(None, &["usage"])
    } else {
        endpoint.path(None, &["v1", "usage"])
    }
}

fn preferred_unit(response: &UsageResponse) -> String {
    clean_non_empty(response.unit.as_deref())
        .or_else(|| {
            response
                .quota
                .as_ref()
                .and_then(|quota| clean_non_empty(quota.unit.as_deref()))
        })
        .unwrap_or("USD")
        .to_owned()
}

fn percentage(used: Decimal, limit: Decimal) -> Result<f64, ClassifiedError> {
    if limit <= Decimal::ZERO {
        return Ok(100.0);
    }
    used.checked_mul(Decimal::from(100_u8))
        .and_then(|value| value.checked_div(limit))
        .and_then(|value| value.to_f64())
        .map(|value| value.clamp(0.0, 100.0))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn integer(value: Option<JsonDecimal>) -> Result<i64, ClassifiedError> {
    let value = decimal(value);
    if !value.fract().is_zero() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    value
        .try_into()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn decimal(value: Option<JsonDecimal>) -> Decimal {
    value.map_or(Decimal::ZERO, |value| value.0)
}

fn parse_date(value: &str) -> Result<Timestamp, ClassifiedError> {
    Timestamp::parse(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn clean_optional(value: Option<&str>) -> Option<String> {
    clean_non_empty(value).map(str::to_owned)
}

fn clean_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn clean_required(value: &str) -> Result<String, ClassifiedError> {
    clean_non_empty(Some(value))
        .map(str::to_owned)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn validate_time_zone(value: &str) -> Result<String, ClassifiedError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 256
        || value.contains(char::is_control)
        || value.contains(['?', '#', '&', '='])
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(value.to_owned())
}

fn system_time_zone() -> Option<String> {
    std::fs::read_link("/etc/localtime")
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .and_then(|path| {
            path.split_once("/zoneinfo/")
                .map(|(_, identifier)| identifier.to_owned())
        })
        .filter(|identifier| validate_time_zone(identifier).is_ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/timezone")
                .ok()
                .and_then(|value| clean_setting(&value).map(str::to_owned))
                .filter(|identifier| validate_time_zone(identifier).is_ok())
        })
}

fn format_money(value: Decimal, unit: &str) -> String {
    if unit.eq_ignore_ascii_case("USD") {
        format!("${}", format_decimal_grouped(value))
    } else {
        format!("{value:.2} {unit}")
    }
}

fn format_decimal_grouped(value: Decimal) -> String {
    let raw = format!("{value:.2}");
    let (whole, fraction) = raw.split_once('.').unwrap_or((raw.as_str(), "00"));
    let (sign, digits) = whole
        .strip_prefix('-')
        .map_or(("", whole), |digits| ("-", digits));
    let mut grouped = String::with_capacity(raw.len() + raw.len() / 3);
    grouped.push_str(sign);
    for (index, byte) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    grouped.push('.');
    grouped.push_str(fraction);
    grouped
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(15)),
    )
    .map_err(|error| error.classified())
}
