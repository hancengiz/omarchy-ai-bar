//! Native `ClawRouter` monthly budget and routed-provider usage adapter.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, CostAmount, CostProvenance, CostSummary, CurrencyCode,
    DetailChart, DetailChartKind, DetailChartPoint, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, ExactDecimal, FiniteNumber, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};
use time::{Date, Month, Time};
use url::Url;

use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "CLAWROUTER_API_KEY";
const BASE_URL: &str = "CLAWROUTER_BASE_URL";
const DEFAULT_BASE_URL: &str = "https://clawrouter.openclaw.ai";
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const MAX_PROVIDER_ROWS: usize = 50_000;
// The script checks `Number.isInteger`, which can accept already-rounded JSON
// numbers above this boundary. The native adapter deliberately rejects those
// literals instead of treating lossy JavaScript accounting values as exact.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_CHART_PROVIDERS: usize = 119;
const MAX_DETAIL_PROVIDERS: usize = 20;
const MICROS_PER_DOLLAR: i64 = 1_000_000;

/// Validated `ClawRouter` endpoint and policy-key credential.
pub struct ClawRouterSettings {
    credential: ApiKeyCredential,
    endpoint: ConfiguredEndpoint,
}

impl ClawRouterSettings {
    /// Resolves the pinned API key and optional HTTPS deployment override.
    ///
    /// A bare host is promoted to HTTPS. URL credentials, query strings,
    /// fragments, explicit HTTP, and malformed authorities fail closed.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API-configuration error.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let raw = environment
            .get(BASE_URL)
            .and_then(|value| clean_setting(value))
            .unwrap_or(DEFAULT_BASE_URL);
        let endpoint = normalize_endpoint(raw)?;
        Ok(Self {
            credential,
            endpoint,
        })
    }

    /// Validated, credential-free deployment root.
    #[must_use]
    pub const fn endpoint(&self) -> &Url {
        self.endpoint.url()
    }
}

impl Debug for ClawRouterSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClawRouterSettings")
            .field("credential", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Native `ClawRouter` provider adapter.
pub struct ClawRouterProvider {
    client: FixedApiClient,
    endpoint: ConfiguredEndpoint,
}

impl ClawRouterProvider {
    /// Creates the exact-origin production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed transport configuration.
    pub fn new(scope: AccountScope, settings: ClawRouterSettings) -> Result<Self, ClassifiedError> {
        let ClawRouterSettings {
            credential,
            endpoint,
        } = settings;
        let client = FixedApiClient::new_bearer(
            scope,
            endpoint.url().clone(),
            endpoint.class(),
            credential,
            transport_config()?,
        )?;
        Self::from_client(client, endpoint)
    }

    /// Wraps an already validated account-scoped client and matching endpoint.
    ///
    /// # Errors
    ///
    /// Rejects another provider, account scope, or endpoint binding.
    pub fn from_client(
        client: FixedApiClient,
        endpoint: ConfiguredEndpoint,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::ClawRouter
            || client.base_url() != endpoint.url()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client, endpoint })
    }

    /// Fetches one deterministic monthly usage sample.
    ///
    /// # Errors
    ///
    /// Returns stable classified configuration, transport, status, or parse
    /// failures without retaining provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.endpoint.path(Some("v1"), &["v1", "usage"])?;
        let response = self
            .client
            .get_json_with_status_map(context, url, clawrouter_status)
            .await?;
        let payload: UsageResponse = response.json()?;
        normalize(context.scope().clone(), fetched_at, payload)
    }
}

impl ProviderAdapter for ClawRouterProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::ClawRouter)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct UsageResponse {
    budget: Budget,
    usage: Usage,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Budget {
    configured: bool,
    ledger: String,
    window_key: Option<Value>,
    limit_micros: Option<JsonInteger>,
    spent_micros: Option<JsonInteger>,
    remaining_micros: Option<JsonInteger>,
}

#[derive(Deserialize)]
struct Usage {
    summary: Summary,
    #[serde(deserialize_with = "deserialize_providers")]
    providers: Vec<ProviderUsage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    request_count: JsonInteger,
    success_count: JsonInteger,
    error_count: JsonInteger,
    input_tokens: JsonInteger,
    output_tokens: JsonInteger,
    total_tokens: JsonInteger,
    actual_cost_micros: JsonInteger,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderUsage {
    provider: String,
    request_count: JsonInteger,
    success_count: JsonInteger,
    error_count: JsonInteger,
    total_tokens: JsonInteger,
    actual_cost_micros: JsonInteger,
}

#[derive(Clone, Copy)]
struct JsonInteger(i64);

impl<'de> Deserialize<'de> for JsonInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let number = Number::deserialize(deserializer)?;
        let raw = number.to_string();
        let value = Decimal::from_scientific(&raw)
            .or_else(|_| raw.parse())
            .map_err(|_| serde::de::Error::custom("invalid integer"))?;
        if !value.fract().is_zero() {
            return Err(serde::de::Error::custom("value must be an integer"));
        }
        let value = value
            .to_i64()
            .filter(|value| value.unsigned_abs() <= MAX_SAFE_INTEGER as u64)
            .ok_or_else(|| serde::de::Error::custom("integer exceeds JavaScript safe range"))?;
        Ok(Self(value))
    }
}

struct RoutedProvider {
    name: String,
    requests: i64,
    #[allow(dead_code)]
    success: i64,
    #[allow(dead_code)]
    errors: i64,
    tokens: i64,
    cost: Decimal,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: UsageResponse,
) -> Result<UsageSample, ClassifiedError> {
    let Budget {
        configured,
        ledger,
        window_key,
        limit_micros,
        spent_micros,
        remaining_micros,
    } = payload.budget;
    let limit = limit_micros.map(micros);
    let spent = spent_micros.map(micros);
    let remaining = remaining_micros.map(micros);
    let resets_at = monthly_reset(window_key.as_ref())?;

    let Summary {
        request_count,
        success_count,
        error_count,
        input_tokens,
        output_tokens,
        total_tokens,
        actual_cost_micros,
    } = payload.usage.summary;
    let actual_cost = micros(actual_cost_micros);
    let mut providers = payload
        .usage
        .providers
        .into_iter()
        .map(|provider| RoutedProvider {
            name: nonempty_provider_name(&provider.provider),
            requests: provider.request_count.0,
            success: provider.success_count.0,
            errors: provider.error_count.0,
            tokens: provider.total_tokens.0,
            cost: micros(provider.actual_cost_micros),
        })
        .collect::<Vec<_>>();
    providers.sort_by(compare_provider);

    let mut usage_rows = vec![
        detail_row(
            "Requests",
            request_count.0.to_string(),
            Some(format!(
                "{} succeeded · {} failed",
                success_count.0, error_count.0
            )),
        )?,
        detail_row(
            "Tokens",
            total_tokens.0.to_string(),
            Some(format!(
                "{} input · {} output",
                input_tokens.0, output_tokens.0
            )),
        )?,
        detail_row("Actual cost", format_usd_six(actual_cost), None)?,
        detail_row("Budget ledger", ledger, None)?,
    ];

    if let (Some(spent), Some(limit)) = (spent, limit) {
        usage_rows.push(detail_row(
            "Monthly budget",
            format!("{} / {}", format_usd_six(spent), format_usd_two(limit)),
            remaining.map(|value| format!("{} remaining", format_usd_six(value))),
        )?);
    }

    let mut sections =
        vec![DetailSection::new(Some("Usage".to_owned()), usage_rows, None).map_err(parse_error)?];
    if !providers.is_empty() {
        sections.push(provider_section(&providers)?);
    }

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .organization(Some(format!("{} routed providers", providers.len())))?
        .login_method(Some(if configured {
            "Managed monthly budget".to_owned()
        } else {
            "Unmetered".to_owned()
        }))?
        .detail_sections(sections);

    if let (Some(spent), Some(limit)) = (spent, limit) {
        if limit > Decimal::ZERO {
            builder = builder.primary(primary_window(spent, limit, resets_at)?);
        }
        builder = builder.cost(cost_summary(spent, limit, resets_at, fetched_at)?);
    } else if actual_cost > Decimal::ZERO {
        builder = builder.cost(cost_summary(
            actual_cost,
            Decimal::ZERO,
            resets_at,
            fetched_at,
        )?);
    }

    builder.provenance("clawrouter", "api")?.build()
}

fn provider_section(providers: &[RoutedProvider]) -> Result<DetailSection, ClassifiedError> {
    let rows = providers
        .iter()
        .take(MAX_DETAIL_PROVIDERS)
        .map(|provider| {
            detail_row(
                &provider.name,
                format!("{} requests", provider.requests),
                Some(format!(
                    "{} · {} tokens",
                    format_usd_six(provider.cost),
                    provider.tokens
                )),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut points = providers
        .iter()
        .take(MAX_CHART_PROVIDERS)
        .map(|provider| chart_point(&provider.name, provider.cost))
        .collect::<Result<Vec<_>, _>>()?;
    if providers.len() > MAX_CHART_PROVIDERS {
        let other = providers[MAX_CHART_PROVIDERS..].iter().try_fold(
            Decimal::ZERO,
            |total, provider| {
                total
                    .checked_add(provider.cost)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
            },
        )?;
        points.push(chart_point("Other", other)?);
    }
    let chart = DetailChart::new(
        DetailChartKind::Bars,
        Some("Provider cost".to_owned()),
        Some("USD".to_owned()),
        points,
    )
    .map_err(parse_error)?;
    DetailSection::new(Some("Routed providers".to_owned()), rows, Some(chart)).map_err(parse_error)
}

fn primary_window(
    spent: Decimal,
    limit: Decimal,
    resets_at: Option<Timestamp>,
) -> Result<RateWindow, ClassifiedError> {
    let percent = spent
        .checked_mul(Decimal::from(100_u8))
        .and_then(|value| value.checked_div(limit))
        .and_then(|value| value.to_f64())
        .filter(|value| value.is_finite())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .clamp(0.0, 100.0);
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        resets_at,
        None,
        None,
        false,
    )
    .map_err(parse_error)
}

fn cost_summary(
    used: Decimal,
    limit: Decimal,
    resets_at: Option<Timestamp>,
    fetched_at: Timestamp,
) -> Result<CostSummary, ClassifiedError> {
    let currency = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    CostSummary::new(
        CostAmount::money(ExactDecimal::new(used), currency),
        ExactDecimal::new(limit),
        Some("This month".to_owned()),
        resets_at,
        None,
        None,
        None,
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map_err(parse_error)
}

fn monthly_reset(window_key: Option<&Value>) -> Result<Option<Timestamp>, ClassifiedError> {
    let Some(window_key) = window_key.and_then(Value::as_str) else {
        return Ok(None);
    };
    let bytes = window_key.as_bytes();
    if bytes.len() < 7 {
        return Ok(None);
    }
    let suffix = &bytes[bytes.len() - 7..];
    if suffix[4] != b'-'
        || !suffix[..4].iter().all(u8::is_ascii_digit)
        || !suffix[5..].iter().all(u8::is_ascii_digit)
    {
        return Ok(None);
    }
    let year = decimal_digits(&suffix[..4]);
    let raw_month = (suffix[5] - b'0') * 10 + (suffix[6] - b'0');
    let (year, month) = if raw_month == 12 {
        (
            year.checked_add(1)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
            1,
        )
    } else {
        (year, raw_month.saturating_add(1))
    };
    // The script interpolates the numeric year without zero-padding before
    // constructing a JavaScript Date. Its ISO parser therefore rejects the
    // rebuilt value outside the four-digit 1000...9999 range.
    if !(1000..=9999).contains(&year) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let month = Month::try_from(month).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let date = Date::from_calendar_date(year, month, 1)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::new(date.with_time(Time::MIDNIGHT).assume_utc())
        .map(Some)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn normalize_endpoint(raw: &str) -> Result<ConfiguredEndpoint, ClassifiedError> {
    if raw.contains('\\') || raw.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let candidate = if has_explicit_scheme(raw) {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    ConfiguredEndpoint::parse(&candidate, ConfiguredHttpPolicy::HttpsOnly)
}

fn has_explicit_scheme(raw: &str) -> bool {
    let Some(colon) = raw.find(':') else {
        return false;
    };
    if raw[colon..].starts_with("://") {
        return true;
    }
    if raw
        .find(['/', '?', '#'])
        .is_some_and(|authority_end| colon > authority_end)
    {
        return false;
    }
    let suffix_start = colon + 1;
    if suffix_start >= raw.len() {
        return true;
    }
    let suffix_end = raw[suffix_start..]
        .find(['/', '?', '#'])
        .map_or(raw.len(), |offset| suffix_start + offset);
    let suffix = &raw[suffix_start..suffix_end];
    if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    raw[..colon].bytes().enumerate().all(|(index, byte)| {
        if index == 0 {
            byte.is_ascii_alphabetic()
        } else {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        }
    })
}

fn deserialize_providers<'de, D>(deserializer: D) -> Result<Vec<ProviderUsage>, D::Error>
where
    D: Deserializer<'de>,
{
    let providers = Vec::<ProviderUsage>::deserialize(deserializer)?;
    if providers.len() > MAX_PROVIDER_ROWS {
        return Err(serde::de::Error::custom("too many routed providers"));
    }
    Ok(providers)
}

fn compare_provider(left: &RoutedProvider, right: &RoutedProvider) -> Ordering {
    right
        .cost
        .cmp(&left.cost)
        .then_with(|| right.requests.cmp(&left.requests))
        .then_with(|| left.name.cmp(&right.name))
}

fn nonempty_provider_name(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "Unknown".to_owned()
    } else {
        value.to_owned()
    }
}

fn micros(value: JsonInteger) -> Decimal {
    Decimal::from(value.0) / Decimal::from(MICROS_PER_DOLLAR)
}

fn decimal_digits(bytes: &[u8]) -> i32 {
    bytes
        .iter()
        .fold(0_i32, |value, byte| value * 10 + i32::from(byte - b'0'))
}

fn detail_row(
    label: impl Into<String>,
    value: impl Into<String>,
    secondary: Option<String>,
) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, secondary, DetailSensitivity::Public).map_err(parse_error)
}

fn chart_point(label: &str, value: Decimal) -> Result<DetailChartPoint, ClassifiedError> {
    let value = value
        .to_f64()
        .and_then(|value| FiniteNumber::new(value).ok())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    DetailChartPoint::new(label.to_owned(), value).map_err(parse_error)
}

fn format_usd_six(value: Decimal) -> String {
    format!("${value:.6}")
}

fn format_usd_two(value: Decimal) -> String {
    format!("${value:.2}")
}

fn parse_error<T>(_: T) -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

const fn clawrouter_status(status: u16) -> Option<ErrorKind> {
    match status {
        401 | 403 => Some(ErrorKind::AuthenticationExpired),
        429 => Some(ErrorKind::RateLimited),
        500..=599 => Some(ErrorKind::ProviderUnavailable),
        200..=299 => None,
        _ => Some(ErrorKind::Api),
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
