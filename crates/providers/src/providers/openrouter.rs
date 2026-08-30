//! Native `OpenRouter` credits, API-key quota, and management Activity adapter.

use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage,
    CostUsageDailyBucket, CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot,
    CostUsageTokenMix, CurrencyCode, DetailChart, DetailChartKind, DetailChartPoint, DetailRow,
    DetailSection, DetailSensitivity, ErrorKind, ExactDecimal, FiniteNumber, ProviderId,
    RateWindow, Timestamp, UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::{Date, Duration as TimeDuration, Month, Time};
use url::Url;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::{EndpointClass, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient, OptionalRequestError};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const DEFAULT_API_BASE: &str = "https://openrouter.ai/api/v1";
const ACTIVITY_API_BASE: &str = "https://openrouter.ai/api/v1";
const DEFAULT_CLIENT_TITLE: &str = "Omarchy AI Bar";
const API_KEY_ENV: &str = "OPENROUTER_API_KEY";
const MANAGEMENT_KEY_ENV: &str = "OPENROUTER_MANAGEMENT_API_KEY";
const API_URL_ENV: &str = "OPENROUTER_API_URL";
const HTTP_REFERER_ENV: &str = "OPENROUTER_HTTP_REFERER";
const CLIENT_TITLE_ENV: &str = "OPENROUTER_X_TITLE";
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const MAX_ACTIVITY_ROWS: usize = 20_000;
const MAX_DISTINCT_ACTIVITY_ROWS: usize = 10_000;
const MAX_MODEL_UTF16_UNITS: usize = 64;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const HISTORY_DAYS: u16 = 30;

/// Validated standard and management credentials plus public request metadata.
pub struct OpenRouterSettings {
    credential: ApiKeyCredential,
    management_credential: Option<ApiKeyCredential>,
    api_base: Url,
    api_class: EndpointClass,
    client_title: String,
    http_referer: Option<String>,
}

impl OpenRouterSettings {
    /// Resolves the complete `OpenRouter` configuration from environment-style values.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or endpoint-configuration error.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY_ENV])?;
        let management_credential = environment
            .get(MANAGEMENT_KEY_ENV)
            .and_then(|value| clean_setting(value))
            .map(ApiKeyCredential::new)
            .transpose()?;
        let api_base = environment
            .get(API_URL_ENV)
            .and_then(|value| clean_setting(value))
            .map_or_else(|| normalize_api_base(DEFAULT_API_BASE), normalize_api_base)?;
        let api_class = endpoint_class(&api_base)?;
        let client_title = environment
            .get(CLIENT_TITLE_ENV)
            .and_then(|value| clean_setting(value))
            .unwrap_or(DEFAULT_CLIENT_TITLE)
            .to_owned();
        let http_referer = environment
            .get(HTTP_REFERER_ENV)
            .and_then(|value| clean_setting(value))
            .map(str::to_owned);
        validate_public_header_value(&client_title)?;
        if let Some(referer) = http_referer.as_deref() {
            validate_public_header_value(referer)?;
        }
        Ok(Self {
            credential,
            management_credential,
            api_base,
            api_class,
            client_title,
            http_referer,
        })
    }

    /// Validated API base after HTTPS and trailing-slash normalization.
    #[must_use]
    pub const fn api_base(&self) -> &Url {
        &self.api_base
    }

    /// Public client title sent only to the credits endpoint.
    #[must_use]
    pub fn client_title(&self) -> &str {
        &self.client_title
    }

    /// Optional public referer sent only to the credits endpoint.
    #[must_use]
    pub fn http_referer(&self) -> Option<&str> {
        self.http_referer.as_deref()
    }

    /// Whether exact 30-day management Activity is configured.
    #[must_use]
    pub const fn has_management_credential(&self) -> bool {
        self.management_credential.is_some()
    }
}

impl Debug for OpenRouterSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenRouterSettings")
            .field("credential", &"<redacted>")
            .field(
                "management_credential",
                &self.management_credential.as_ref().map(|_| "<redacted>"),
            )
            .field("api_base", &"<redacted>")
            .field("api_class", &self.api_class)
            .field("client_title", &"<redacted>")
            .field(
                "http_referer",
                &self.http_referer.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Native `OpenRouter` provider adapter.
pub struct OpenRouterProvider {
    credits_client: FixedApiClient,
    key_client: FixedApiClient,
    activity_client: Option<FixedApiClient>,
    client_title: String,
    http_referer: Option<String>,
}

impl OpenRouterProvider {
    /// Creates isolated exact-origin clients for required and optional requests.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed transport configuration.
    pub fn new(scope: AccountScope, settings: OpenRouterSettings) -> Result<Self, ClassifiedError> {
        let credits_client = FixedApiClient::new_bearer(
            scope.clone(),
            settings.api_base.clone(),
            settings.api_class,
            settings.credential.clone(),
            transport_config(Duration::from_secs(15))?,
        )?;
        let key_client = FixedApiClient::new_bearer(
            scope.clone(),
            settings.api_base,
            settings.api_class,
            settings.credential,
            transport_config(Duration::from_secs(1))?,
        )?;
        let activity_client = settings
            .management_credential
            .map(|credential| {
                let base = normalize_api_base(ACTIVITY_API_BASE)?;
                FixedApiClient::new_bearer(
                    scope,
                    base,
                    EndpointClass::PublicHttps,
                    credential,
                    transport_config(Duration::from_secs(1))?,
                )
            })
            .transpose()?;
        Self::from_clients(
            credits_client,
            key_client,
            activity_client,
            settings.client_title,
            settings.http_referer,
        )
    }

    /// Wraps validated account-scoped clients for deterministic fixtures.
    ///
    /// # Errors
    ///
    /// Rejects provider/account scope mismatches or unsafe public metadata.
    pub fn from_clients(
        credits_client: FixedApiClient,
        key_client: FixedApiClient,
        activity_client: Option<FixedApiClient>,
        client_title: String,
        http_referer: Option<String>,
    ) -> Result<Self, ClassifiedError> {
        let scope = credits_client.scope();
        if scope.provider() != ProviderId::OpenRouter
            || key_client.scope() != scope
            || activity_client
                .as_ref()
                .is_some_and(|client| client.scope() != scope)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_public_header_value(&client_title)?;
        if let Some(referer) = http_referer.as_deref() {
            validate_public_header_value(referer)?;
        }
        Ok(Self {
            credits_client,
            key_client,
            activity_client,
            client_title,
            http_referer,
        })
    }

    /// Fetches required credits and bounded best-effort quota and Activity data.
    ///
    /// # Errors
    ///
    /// Returns only required credits/configuration failures. Optional requests
    /// become observable degradation rows on an otherwise valid sample.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let credits_url = self.credits_client.url("credits")?;
        let mut public_headers = vec![("X-Title", self.client_title.as_str())];
        if let Some(referer) = self.http_referer.as_deref() {
            public_headers.push(("HTTP-Referer", referer));
        }
        let credits_response = self
            .credits_client
            .get_json_with_public_headers_and_status_map(
                context,
                credits_url,
                &public_headers,
                |_| Some(ErrorKind::Api),
            )
            .await?;
        if credits_response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let credits = parse_credits(credits_response.body())?;
        let key = self.fetch_key(context).await;
        let activity = self.fetch_activity(context, fetched_at).await;
        normalize(context.scope().clone(), fetched_at, &credits, key, activity)
    }

    async fn fetch_key(&self, context: &ProviderContext) -> KeyOutcome {
        let url = match self.key_client.url("key") {
            Ok(url) => url,
            Err(error) => return KeyOutcome::degraded(degradation_from_kind(error.kind())),
        };
        let response = match self
            .key_client
            .get_json_optional_diagnostic(context, url)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return KeyOutcome::degraded(degradation_from_request_error(error, false));
            }
        };
        if response.status() != 200 {
            return KeyOutcome::degraded(format!("Request returned HTTP {}", response.status()));
        }
        match parse_key(response.body()) {
            Ok(Some(data)) => KeyOutcome::available(data),
            Ok(None) => KeyOutcome::degraded("Response was unavailable".to_owned()),
            Err(_) => KeyOutcome::degraded("Response was invalid".to_owned()),
        }
    }

    async fn fetch_activity(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> ActivityOutcome {
        let Some(client) = self.activity_client.as_ref() else {
            return ActivityOutcome::degraded("Management API key not configured".to_owned());
        };
        let Ok((latest_completed, cutoff)) = activity_window(fetched_at) else {
            return ActivityOutcome::degraded("Response was invalid".to_owned());
        };
        let history_url = match client.url("activity") {
            Ok(url) => url,
            Err(error) => {
                return ActivityOutcome::degraded(degradation_from_kind(error.kind()));
            }
        };
        let mut dated_url = history_url.clone();
        dated_url
            .query_pairs_mut()
            .append_pair("date", &latest_completed.to_string());
        let (history, dated) = tokio::join!(
            client.get_json_optional_diagnostic(context, history_url),
            client.get_json_optional_diagnostic(context, dated_url),
        );
        let history = match history {
            Ok(response) => response,
            Err(error) => {
                return ActivityOutcome::degraded(degradation_from_request_error(error, true));
            }
        };
        if history.status() != 200 {
            return ActivityOutcome::degraded(activity_status_degradation(history.status()));
        }
        let dated = match dated {
            Ok(response) => response,
            Err(error) => {
                return ActivityOutcome::degraded(degradation_from_request_error(error, true));
            }
        };
        if dated.status() != 200 {
            return ActivityOutcome::degraded(activity_status_degradation(dated.status()));
        }
        match parse_activity(history.body(), dated.body(), latest_completed, cutoff) {
            Ok(cost_usage) => ActivityOutcome::available(cost_usage),
            Err(_) => ActivityOutcome::degraded("Response was invalid".to_owned()),
        }
    }
}

impl ProviderAdapter for OpenRouterProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::OpenRouter)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

struct Credits {
    granted: Decimal,
    used: Decimal,
    balance: Decimal,
}

struct KeyData {
    limit: Option<Decimal>,
    limit_remaining: Option<Decimal>,
    usage: Option<Decimal>,
    usage_daily: Option<Decimal>,
    usage_weekly: Option<Decimal>,
    usage_monthly: Option<Decimal>,
    limit_reset: Option<String>,
    rate_limit: Option<RateLimit>,
}

struct RateLimit {
    requests: String,
    interval: String,
}

struct KeyOutcome {
    data: Option<KeyData>,
    degradation: Option<String>,
}

impl KeyOutcome {
    fn available(data: KeyData) -> Self {
        Self {
            data: Some(data),
            degradation: None,
        }
    }

    fn degraded(reason: String) -> Self {
        Self {
            data: None,
            degradation: Some(reason),
        }
    }
}

struct ActivityOutcome {
    cost_usage: Option<CostUsageSnapshot>,
    degradation: Option<String>,
}

impl ActivityOutcome {
    fn available(cost_usage: CostUsageSnapshot) -> Self {
        Self {
            cost_usage: Some(cost_usage),
            degradation: None,
        }
    }

    fn degraded(reason: String) -> Self {
        Self {
            cost_usage: None,
            degradation: Some(reason),
        }
    }
}

fn parse_credits(body: &[u8]) -> Result<Credits, ClassifiedError> {
    let root: Value =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let total_credits = required_decimal(data, "total_credits")?;
    let total_usage = required_decimal(data, "total_usage")?;
    let balance = total_credits
        .checked_sub(total_usage)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .max(Decimal::ZERO);
    Ok(Credits {
        granted: total_credits,
        used: total_usage,
        balance,
    })
}

fn parse_key(body: &[u8]) -> Result<Option<KeyData>, ClassifiedError> {
    let root: Value =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let Some(data) = root.get("data").and_then(Value::as_object) else {
        return Ok(None);
    };
    let limit_reset = match data.get("limit_reset") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let rate_limit = match data.get("rate_limit") {
        None | Some(Value::Null) => None,
        Some(Value::Object(value)) => {
            let requests = value
                .get("requests")
                .and_then(json_integer_text)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            let interval = value
                .get("interval")
                .and_then(Value::as_str)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
                .to_owned();
            Some(RateLimit { requests, interval })
        }
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    Ok(Some(KeyData {
        limit: optional_decimal(data, "limit")?,
        limit_remaining: optional_decimal(data, "limit_remaining")?,
        usage: optional_decimal(data, "usage")?,
        usage_daily: optional_decimal(data, "usage_daily")?,
        usage_weekly: optional_decimal(data, "usage_weekly")?,
        usage_monthly: optional_decimal(data, "usage_monthly")?,
        limit_reset,
        rate_limit,
    }))
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    credits: &Credits,
    key: KeyOutcome,
    activity: ActivityOutcome,
) -> Result<UsageSample, ClassifiedError> {
    let mut details = vec![
        DetailSection::new(
            Some("Credits".to_owned()),
            vec![
                detail_row("Remaining", format_usd(credits.balance), None)?,
                detail_row("Used", format_usd(credits.used), None)?,
                detail_row("Total added", format_usd(credits.granted), None)?,
            ],
            None,
        )
        .map_err(parse_error)?,
    ];

    let mut primary = None;
    match key.data.as_ref() {
        Some(data) => {
            let (window, remaining) = key_window(data)?;
            primary = window;
            details.push(key_details(data, remaining)?);
        }
        None => {
            details.push(
                DetailSection::new(
                    Some("API key".to_owned()),
                    vec![detail_row(
                        "API key limit",
                        "Unavailable right now".to_owned(),
                        Some(
                            key.degradation
                                .unwrap_or_else(|| "Response was unavailable".to_owned()),
                        ),
                    )?],
                    None,
                )
                .map_err(parse_error)?,
            );
        }
    }

    if activity.cost_usage.is_none() {
        details.push(
            DetailSection::new(
                Some("Spend history".to_owned()),
                vec![detail_row(
                    "Last 30 days",
                    "Unavailable right now".to_owned(),
                    Some(
                        activity
                            .degradation
                            .unwrap_or_else(|| "Response was unavailable".to_owned()),
                    ),
                )?],
                None,
            )
            .map_err(parse_error)?,
        );
    }

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(Some(format!("Balance: {}", format_usd(credits.balance))))?
        .detail_sections(details);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(cost_usage) = activity.cost_usage {
        builder = builder.cost_usage(cost_usage);
    }
    builder.provenance("openrouter", "api")?.build()
}

fn key_window(data: &KeyData) -> Result<(Option<RateWindow>, Option<Decimal>), ClassifiedError> {
    let Some(limit) = data.limit.filter(|limit| *limit > Decimal::ZERO) else {
        return Ok((None, None));
    };
    let used = if let Some(remaining) = data.limit_remaining {
        limit
            .checked_sub(remaining.max(Decimal::ZERO).min(limit))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .into()
    } else {
        match data.limit_reset.as_deref() {
            Some("daily") => data.usage_daily,
            Some("weekly") => data.usage_weekly,
            Some("monthly") => data.usage_monthly,
            _ => data.usage,
        }
    };
    let Some(used) = used.filter(|used| *used >= Decimal::ZERO) else {
        return Ok((None, None));
    };
    let percent = used
        .to_f64()
        .zip(limit.to_f64())
        .map(|(used, limit)| (used / limit * 100.0).clamp(0.0, 100.0))
        .filter(|value| value.is_finite())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let window = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        None,
        None,
        false,
    )
    .map_err(parse_error)?;
    let remaining = limit
        .checked_sub(used)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .max(Decimal::ZERO);
    Ok((Some(window), Some(remaining)))
}

fn key_details(
    data: &KeyData,
    key_remaining: Option<Decimal>,
) -> Result<DetailSection, ClassifiedError> {
    let mut rows = Vec::new();
    if let Some(limit) = data.limit.filter(|limit| *limit > Decimal::ZERO) {
        rows.push(detail_row(
            "API key limit",
            format_usd(limit),
            Some("Spending cap, not balance".to_owned()),
        )?);
        if let Some(remaining) = key_remaining {
            rows.push(detail_row(
                "API key remaining",
                format_usd(remaining),
                None,
            )?);
        }
        if let Some(usage) = data.usage {
            rows.push(detail_row("API key used", format_usd(usage), None)?);
        }
    } else {
        rows.push(detail_row(
            "API key limit",
            "No limit configured".to_owned(),
            None,
        )?);
    }
    if let Some(reset) = data
        .limit_reset
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        rows.push(detail_row("Reset window", reset.to_owned(), None)?);
    }

    let mut points = Vec::new();
    for (label, value) in [
        ("Today", data.usage_daily),
        ("This week", data.usage_weekly),
        ("This month", data.usage_monthly),
    ] {
        if let Some(value) = value {
            rows.push(detail_row(label, format_usd(value), None)?);
            let finite = value
                .to_f64()
                .and_then(|value| FiniteNumber::new(value).ok())
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            points.push(DetailChartPoint::new(label.to_owned(), finite).map_err(parse_error)?);
        }
    }
    if let Some(rate) = data.rate_limit.as_ref() {
        rows.push(detail_row(
            "Rate limit",
            format!("{} requests / {}", rate.requests, rate.interval),
            None,
        )?);
    }
    let chart = if points.is_empty() {
        None
    } else {
        Some(
            DetailChart::new(
                DetailChartKind::Bars,
                Some("Key spend".to_owned()),
                Some("USD".to_owned()),
                points,
            )
            .map_err(parse_error)?,
        )
    };
    DetailSection::new(Some("API key".to_owned()), rows, chart).map_err(parse_error)
}

#[derive(Clone)]
struct ActivityRow {
    day: String,
    model: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    reasoning_tokens: Option<u64>,
    requests: u64,
    cost: Decimal,
    estimated_cost: Decimal,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActivityIdentity {
    day: String,
    model: Option<String>,
    endpoint_id: String,
    provider_name: String,
    workspace_id: String,
}

#[derive(Clone, PartialEq, Eq)]
struct ActivitySignature {
    input_tokens: u64,
    output_tokens: u64,
    reasoning_tokens: Option<u64>,
    requests: u64,
    metered_cost: Decimal,
    estimated_cost: Decimal,
}

struct ParsedActivityRow {
    identity: ActivityIdentity,
    signature: ActivitySignature,
    row: ActivityRow,
}

#[derive(Default)]
struct ActivityParseState {
    seen: BTreeMap<ActivityIdentity, ActivitySignature>,
    entries: Vec<ActivityRow>,
    aggregate: UsageAccumulator,
}

impl ActivityParseState {
    fn accept(&mut self, parsed: ParsedActivityRow) -> Result<(), ClassifiedError> {
        match self.seen.entry(parsed.identity) {
            Entry::Occupied(existing) if existing.get() == &parsed.signature => return Ok(()),
            Entry::Occupied(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
            Entry::Vacant(entry) => {
                entry.insert(parsed.signature);
            }
        }
        self.aggregate.add(&parsed.row)?;
        self.entries.push(parsed.row);
        if self.entries.len() > MAX_DISTINCT_ACTIVITY_ROWS {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(())
    }
}

fn parse_activity(
    history_body: &[u8],
    dated_body: &[u8],
    latest_completed: Date,
    cutoff: Date,
) -> Result<CostUsageSnapshot, ClassifiedError> {
    let history = activity_rows(history_body)?;
    let dated = activity_rows(dated_body)?;
    let input_count = history
        .len()
        .checked_add(dated.len())
        .filter(|count| *count <= MAX_ACTIVITY_ROWS)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let mut raw_rows = Vec::with_capacity(input_count);
    raw_rows.extend(history);
    raw_rows.extend(dated);

    let mut state = ActivityParseState::default();
    for value in raw_rows {
        if let Some(parsed) = parse_activity_row(&value, latest_completed, cutoff)? {
            state.accept(parsed)?;
        }
    }
    build_cost_usage(&state.entries, latest_completed, &state.aggregate)
}

fn parse_activity_row(
    value: &Value,
    latest_completed: Date,
    cutoff: Date,
) -> Result<Option<ParsedActivityRow>, ClassifiedError> {
    let object = value
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let raw_date = object
        .get("date")
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let date = parse_activity_date(raw_date)?;
    if date > latest_completed {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if date < cutoff {
        return Ok(None);
    }
    let day = date.to_string();
    let model = activity_model(object)?;
    let input_tokens = required_safe_integer(object, "prompt_tokens")?;
    let output_tokens = required_safe_integer(object, "completion_tokens")?;
    let reasoning_tokens = optional_safe_integer(object, "reasoning_tokens")?;
    if reasoning_tokens.is_some_and(|reasoning| reasoning > output_tokens) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let requests = required_safe_integer(object, "requests")?;
    let metered_cost = required_decimal(object, "usage")?;
    let estimated_cost = optional_decimal(object, "byok_usage_inference")?.unwrap_or(Decimal::ZERO);
    if metered_cost < Decimal::ZERO || estimated_cost < Decimal::ZERO {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let cost = metered_cost
        .checked_add(estimated_cost)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    checked_safe_sum(input_tokens, output_tokens)?;
    Ok(Some(ParsedActivityRow {
        identity: ActivityIdentity {
            day: day.clone(),
            model: model.clone(),
            endpoint_id: identity_component(object.get("endpoint_id"))?,
            provider_name: identity_component(object.get("provider_name"))?,
            workspace_id: identity_component(object.get("workspace_id"))?,
        },
        signature: ActivitySignature {
            input_tokens,
            output_tokens,
            reasoning_tokens,
            requests,
            metered_cost,
            estimated_cost,
        },
        row: ActivityRow {
            day,
            model,
            input_tokens,
            output_tokens,
            reasoning_tokens,
            requests,
            cost,
            estimated_cost,
        },
    }))
}

fn activity_rows(body: &[u8]) -> Result<Vec<Value>, ClassifiedError> {
    let root: Value =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    root.get("data")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

#[derive(Clone, Default)]
struct UsageAccumulator {
    input: u64,
    output: u64,
    reasoning: u64,
    has_reasoning: bool,
    requests: u64,
    estimated_requests: u64,
    cost: Decimal,
    estimated_cost: Decimal,
}

impl UsageAccumulator {
    fn add(&mut self, row: &ActivityRow) -> Result<(), ClassifiedError> {
        self.input = checked_safe_sum(self.input, row.input_tokens)?;
        self.output = checked_safe_sum(self.output, row.output_tokens)?;
        self.reasoning = checked_safe_sum(self.reasoning, row.reasoning_tokens.unwrap_or(0))?;
        self.has_reasoning |= row.reasoning_tokens.is_some();
        self.requests = checked_safe_sum(self.requests, row.requests)?;
        if row.estimated_cost > Decimal::ZERO {
            self.estimated_requests = checked_safe_sum(self.estimated_requests, row.requests)?;
        }
        self.cost = self
            .cost
            .checked_add(row.cost)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        self.estimated_cost = self
            .estimated_cost
            .checked_add(row.estimated_cost)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(())
    }

    fn add_accumulator(&mut self, other: &Self) -> Result<(), ClassifiedError> {
        self.input = checked_safe_sum(self.input, other.input)?;
        self.output = checked_safe_sum(self.output, other.output)?;
        self.reasoning = checked_safe_sum(self.reasoning, other.reasoning)?;
        self.has_reasoning |= other.has_reasoning;
        self.requests = checked_safe_sum(self.requests, other.requests)?;
        self.estimated_requests =
            checked_safe_sum(self.estimated_requests, other.estimated_requests)?;
        self.cost = self
            .cost
            .checked_add(other.cost)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        self.estimated_cost = self
            .estimated_cost
            .checked_add(other.estimated_cost)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(())
    }

    fn metrics(&self) -> Result<CostUsageMetrics, ClassifiedError> {
        let priced = self.requests.saturating_sub(self.estimated_requests);
        let coverage =
            CostUsageCoverage::new(priced, 0, 0, self.estimated_requests).map_err(parse_error)?;
        CostUsageMetrics::new(
            CostUsageTokenMix::new(
                Some(self.input),
                Some(self.output),
                None,
                None,
                self.has_reasoning.then_some(self.reasoning),
            ),
            Some(checked_safe_sum(self.input, self.output)?),
            Some(self.requests),
            Some(ExactDecimal::new(self.cost)),
            coverage,
        )
        .map_err(parse_error)
    }
}

fn build_cost_usage(
    entries: &[ActivityRow],
    latest_completed: Date,
    aggregate: &UsageAccumulator,
) -> Result<CostUsageSnapshot, ClassifiedError> {
    let daily = daily_cost_usage(entries)?;
    let session = CostUsageMetrics::new(
        CostUsageTokenMix::default(),
        None,
        None,
        None,
        CostUsageCoverage::default(),
    )
    .map_err(parse_error)?;
    let metered = aggregate
        .cost
        .checked_sub(aggregate.estimated_cost)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let provenance = if aggregate.estimated_cost > Decimal::ZERO {
        if metered > Decimal::ZERO {
            CostProvenance::Mixed
        } else {
            CostProvenance::ListPriceEstimate
        }
    } else {
        CostProvenance::VendorMetered
    };
    let metered_amount = (aggregate.estimated_cost > Decimal::ZERO && metered > Decimal::ZERO)
        .then(|| ExactDecimal::new(metered));
    let updated_at = Timestamp::new(
        latest_completed
            .with_time(Time::MIDNIGHT + TimeDuration::hours(12))
            .assume_utc(),
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let currency = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    CostUsageSnapshot::new(
        CostUnit::currency(currency),
        session,
        aggregate.metrics()?,
        metered_amount,
        HISTORY_DAYS,
        true,
        Some("Last 30 days (UTC)".to_owned()),
        None,
        daily,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        updated_at,
        provenance,
    )
    .map_err(parse_error)
}

fn daily_cost_usage(entries: &[ActivityRow]) -> Result<Vec<CostUsageDailyBucket>, ClassifiedError> {
    let mut grouped = BTreeMap::<(String, Option<String>), UsageAccumulator>::new();
    for row in entries {
        grouped
            .entry((row.day.clone(), row.model.clone()))
            .or_default()
            .add(row)?;
    }
    let mut daily_accumulators = BTreeMap::<String, UsageAccumulator>::new();
    let mut model_breakdowns = BTreeMap::<String, Vec<CostUsageModelBreakdown>>::new();
    for ((day, model), accumulator) in grouped {
        if let Some(model) = model {
            let breakdown =
                CostUsageModelBreakdown::new(model, accumulator.metrics()?, None, None, None, None)
                    .map_err(parse_error)?;
            model_breakdowns
                .entry(day.clone())
                .or_default()
                .push(breakdown);
        }
        daily_accumulators
            .entry(day)
            .or_default()
            .add_accumulator(&accumulator)?;
    }
    daily_accumulators
        .into_iter()
        .map(|(day, accumulator)| {
            let models = model_breakdowns.remove(&day).unwrap_or_default();
            let names = models.iter().map(|model| model.name().to_owned()).collect();
            CostUsageDailyBucket::new(
                &day,
                None,
                accumulator.metrics()?,
                names,
                models,
                Vec::new(),
            )
            .map_err(parse_error)
        })
        .collect()
}

fn activity_model(row: &Map<String, Value>) -> Result<Option<String>, ClassifiedError> {
    let value = match row.get("model_permaslug") {
        None | Some(Value::Null) => row.get("model"),
        value => value,
    };
    let model = value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if model
        .as_deref()
        .is_some_and(|value| value.encode_utf16().count() > MAX_MODEL_UTF16_UNITS)
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(model)
}

fn identity_component(value: Option<&Value>) -> Result<String, ClassifiedError> {
    let value = value.filter(|value| javascript_truthy(value));
    serde_json::to_string(value.unwrap_or(&Value::Null))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn javascript_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn parse_activity_date(raw: &str) -> Result<Date, ClassifiedError> {
    let bytes = raw.as_bytes();
    let valid_shape = (bytes.len() == 10 || bytes.len() == 19)
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && (bytes.len() == 10
            || (bytes.get(10) == Some(&b' ')
                && bytes.get(13) == Some(&b':')
                && bytes.get(16) == Some(&b':')
                && bytes[11..13].iter().all(u8::is_ascii_digit)
                && bytes[14..16].iter().all(u8::is_ascii_digit)
                && bytes[17..19].iter().all(u8::is_ascii_digit)));
    if !valid_shape {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let year = raw[..4]
        .parse::<i32>()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let month = raw[5..7]
        .parse::<u8>()
        .ok()
        .and_then(|value| Month::try_from(value).ok())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let day = raw[8..10]
        .parse::<u8>()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Date::from_calendar_date(year, month, day).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn activity_window(fetched_at: Timestamp) -> Result<(Date, Date), ClassifiedError> {
    let latest_completed = fetched_at
        .as_offset_date_time()
        .date()
        .checked_sub(TimeDuration::days(1))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let cutoff = latest_completed
        .checked_sub(TimeDuration::days(i64::from(HISTORY_DAYS - 1)))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok((latest_completed, cutoff))
}

fn required_decimal(object: &Map<String, Value>, key: &str) -> Result<Decimal, ClassifiedError> {
    object
        .get(key)
        .and_then(json_decimal)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn optional_decimal(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<Decimal>, ClassifiedError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => json_decimal(value)
            .map(Some)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn json_decimal(value: &Value) -> Option<Decimal> {
    let raw = value.as_number()?.to_string();
    Decimal::from_scientific(&raw).or_else(|_| raw.parse()).ok()
}

fn required_safe_integer(object: &Map<String, Value>, key: &str) -> Result<u64, ClassifiedError> {
    object
        .get(key)
        .and_then(json_safe_integer)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn optional_safe_integer(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, ClassifiedError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => json_safe_integer(value)
            .map(Some)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn json_safe_integer(value: &Value) -> Option<u64> {
    let value = json_decimal(value)?;
    if value < Decimal::ZERO || !value.fract().is_zero() {
        return None;
    }
    value.to_u64().filter(|value| *value <= MAX_SAFE_INTEGER)
}

fn json_integer_text(value: &Value) -> Option<String> {
    let value = json_decimal(value)?;
    value.fract().is_zero().then(|| value.trunc().to_string())
}

fn checked_safe_sum(left: u64, right: u64) -> Result<u64, ClassifiedError> {
    left.checked_add(right)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn detail_row(
    label: &str,
    value: String,
    secondary: Option<String>,
) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(
        label.to_owned(),
        value,
        secondary,
        DetailSensitivity::Public,
    )
    .map_err(parse_error)
}

fn format_usd(value: Decimal) -> String {
    format!("${:.2}", value.max(Decimal::ZERO).round_dp(2))
}

fn degradation_from_request_error(error: OptionalRequestError, activity: bool) -> String {
    match error {
        OptionalRequestError::HttpStatus(403) if activity => {
            "Management API key required".to_owned()
        }
        OptionalRequestError::HttpStatus(status) => format!("Request returned HTTP {status}"),
        OptionalRequestError::Timeout => "Request timed out".to_owned(),
        OptionalRequestError::Other(_) => "Request failed".to_owned(),
    }
}

fn activity_status_degradation(status: u16) -> String {
    if status == 403 {
        "Management API key required".to_owned()
    } else {
        format!("Request returned HTTP {status}")
    }
}

fn degradation_from_kind(kind: ErrorKind) -> String {
    if kind == ErrorKind::Parse {
        "Response was invalid".to_owned()
    } else {
        "Request failed".to_owned()
    }
}

fn normalize_api_base(raw: &str) -> Result<Url, ClassifiedError> {
    let raw = clean_setting(raw).ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if raw.contains('\\') || raw.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let candidate = if has_explicit_scheme(raw) {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let mut url = Url::parse(&candidate).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    endpoint_class(&url)?;
    let mut path = url.path().trim_end_matches('/').to_owned();
    path.push('/');
    url.set_path(&path);
    Ok(url)
}

fn endpoint_class(url: &Url) -> Result<EndpointClass, ClassifiedError> {
    let mut origin = url.clone();
    origin.set_path("/");
    classify_https_endpoint(&origin).map_err(|_| ClassifiedError::new(ErrorKind::Api))
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

fn validate_public_header_value(value: &str) -> Result<(), ClassifiedError> {
    if value.is_empty() || value.len() > 8 * 1024 || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn transport_config(request_timeout: Duration) -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        request_timeout,
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn parse_error<T>(_: T) -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
