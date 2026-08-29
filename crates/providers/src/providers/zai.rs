//! Native z.ai / GLM quota, MCP, balance, and model-token adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::path::Path;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailChart, DetailChartKind, DetailChartPoint,
    DetailRow, DetailSection, DetailSensitivity, ErrorKind, FiniteNumber, NamedRateWindow,
    ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::{Duration as TimeDuration, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};
use url::Url;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::{EndpointClass, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const GLOBAL_ORIGIN: &str = "https://api.z.ai";
const BIGMODEL_CN_ORIGIN: &str = "https://open.bigmodel.cn";
const BIGMODEL_BALANCE_URL: &str =
    "https://www.bigmodel.cn/api/biz/account/query-customer-account-report";
const QUOTA_PATH: &str = "api/monitor/usage/quota/limit";
const MODEL_USAGE_PATH: &str = "api/monitor/usage/model-usage";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_MODEL_POINTS: usize = 120;
const MAX_MODEL_ROWS: usize = 20;
const MAX_MCP_ROWS: usize = 20;
const MAX_SECRET_FILE_BYTES: u64 = 16 * 1024;

const PRIMARY_KEY: &str = "Z_AI_API_KEY";
const CN_KEYS: [&str; 4] = [
    "BIGMODEL_API_KEY",
    "ZHIPU_API_KEY",
    "ZHIPUAI_API_KEY",
    "GLM_API_KEY",
];
const CN_KEY_PATHS: [&str; 3] = [
    ".coding-relay/glm-api-key",
    ".config/bigmodel/api_key",
    ".config/zhipu/api_key",
];

/// z.ai API deployment selected for an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZaiRegion {
    /// Global z.ai service.
    Global,
    /// Mainland-China `BigModel` service.
    BigModelCn,
}

impl ZaiRegion {
    const fn origin(self) -> &'static str {
        match self {
            Self::Global => GLOBAL_ORIGIN,
            Self::BigModelCn => BIGMODEL_CN_ORIGIN,
        }
    }

    const fn host(self) -> &'static str {
        match self {
            Self::Global => "api.z.ai",
            Self::BigModelCn => "open.bigmodel.cn",
        }
    }
}

/// Personal or `BigModel` organization/project quota scope.
#[derive(Clone, PartialEq, Eq)]
pub enum ZaiUsageScope {
    /// Personal coding-plan usage.
    Personal,
    /// Team usage selected by organization and project.
    Team {
        organization: String,
        project: String,
    },
}

impl Debug for ZaiUsageScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Personal => formatter.write_str("Personal"),
            Self::Team { .. } => formatter.write_str("Team(<redacted>)"),
        }
    }
}

/// Validated z.ai credential, routing, and usage-scope configuration.
pub struct ZaiSettings {
    credential: ApiKeyCredential,
    region: ZaiRegion,
    usage_scope: ZaiUsageScope,
    quota_url: Url,
    quota_class: EndpointClass,
    model_usage_url: Url,
    model_usage_class: EndpointClass,
    balance_url: Option<Url>,
    balance_class: Option<EndpointClass>,
    local_offset: UtcOffset,
    use_system_local_offset: bool,
}

impl ZaiSettings {
    /// Resolves the complete fail-closed z.ai configuration from environment
    /// values and the host's current local UTC offset.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API-configuration error.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
        Self::resolve_inner(environment, local_offset, true)
    }

    /// Resolves configuration using an injected local offset for deterministic
    /// model-usage range tests.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API-configuration error.
    pub fn resolve_with_offset(
        environment: &BTreeMap<String, String>,
        local_offset: UtcOffset,
    ) -> Result<Self, ClassifiedError> {
        Self::resolve_inner(environment, local_offset, false)
    }

    fn resolve_inner(
        environment: &BTreeMap<String, String>,
        local_offset: UtcOffset,
        use_system_local_offset: bool,
    ) -> Result<Self, ClassifiedError> {
        let region = resolve_region(environment)?;
        let credential = resolve_credential(environment, region)?;
        let usage_scope = resolve_usage_scope(environment)?;

        let api_host = optional_endpoint(environment, "Z_AI_API_HOST")?;
        if let Some(url) = api_host.as_ref() {
            validate_region_host(url, region)?;
        }

        let quota_url = if let Some(url) = optional_endpoint(environment, "Z_AI_QUOTA_ENDPOINT")? {
            url
        } else if let Some(url) = optional_endpoint(environment, "Z_AI_QUOTA_URL")? {
            url
        } else if let Some(url) = api_host.as_ref() {
            endpoint_from_host(url, QUOTA_PATH)
        } else {
            endpoint_from_origin(region.origin(), QUOTA_PATH)?
        };
        validate_region_host(&quota_url, region)?;

        let model_usage_url =
            if let Some(url) = optional_endpoint(environment, "Z_AI_MODEL_USAGE_ENDPOINT")? {
                url
            } else if let Some(url) = api_host.as_ref() {
                endpoint_from_host(url, MODEL_USAGE_PATH)
            } else {
                endpoint_from_origin(region.origin(), MODEL_USAGE_PATH)?
            };
        validate_region_host(&model_usage_url, region)?;

        // Validate a supplied balance endpoint in every region. A valid global
        // override remains unused because the upstream balance API is CN-only.
        let configured_balance = optional_endpoint(environment, "Z_AI_BALANCE_ENDPOINT")?
            .or(optional_endpoint(environment, "Z_AI_BALANCE_URL")?);
        let balance_url = match region {
            ZaiRegion::Global => None,
            ZaiRegion::BigModelCn => Some(match configured_balance {
                Some(url) => url,
                None => parse_https_endpoint(BIGMODEL_BALANCE_URL)?,
            }),
        };

        let quota_class = endpoint_class(&quota_url)?;
        let model_usage_class = endpoint_class(&model_usage_url)?;
        let balance_class = balance_url.as_ref().map(endpoint_class).transpose()?;
        Ok(Self {
            credential,
            region,
            usage_scope,
            quota_url,
            quota_class,
            model_usage_url,
            model_usage_class,
            balance_url,
            balance_class,
            local_offset,
            use_system_local_offset,
        })
    }

    #[must_use]
    pub const fn region(&self) -> ZaiRegion {
        self.region
    }

    #[must_use]
    pub const fn usage_scope(&self) -> &ZaiUsageScope {
        &self.usage_scope
    }

    #[must_use]
    pub const fn quota_url(&self) -> &Url {
        &self.quota_url
    }

    #[must_use]
    pub const fn model_usage_url(&self) -> &Url {
        &self.model_usage_url
    }

    #[must_use]
    pub const fn balance_url(&self) -> Option<&Url> {
        self.balance_url.as_ref()
    }
}

impl Debug for ZaiSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZaiSettings")
            .field("credential", &"<redacted>")
            .field("region", &self.region)
            .field("usage_scope", &self.usage_scope)
            .field("quota_url", &"<redacted>")
            .field("model_usage_url", &"<redacted>")
            .field(
                "balance_url",
                &self.balance_url.as_ref().map(|_| "<redacted>"),
            )
            .field("local_offset", &self.local_offset)
            .finish_non_exhaustive()
    }
}

/// Native z.ai / GLM provider adapter.
pub struct ZaiProvider {
    quota_client: FixedApiClient,
    model_client: FixedApiClient,
    balance_client: Option<FixedApiClient>,
    region: ZaiRegion,
    usage_scope: ZaiUsageScope,
    local_offset: UtcOffset,
    use_system_local_offset: bool,
}

impl ZaiProvider {
    /// Creates isolated exact-origin production clients for quota, history,
    /// and the optional CN balance lookup.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed transport configuration.
    pub fn new(scope: AccountScope, settings: ZaiSettings) -> Result<Self, ClassifiedError> {
        let quota_client = FixedApiClient::new_bearer(
            scope.clone(),
            settings.quota_url,
            settings.quota_class,
            settings.credential.clone(),
            transport_config(Duration::from_secs(15))?,
        )?;
        let model_client = FixedApiClient::new_bearer(
            scope.clone(),
            settings.model_usage_url,
            settings.model_usage_class,
            settings.credential.clone(),
            transport_config(Duration::from_secs(15))?,
        )?;
        let balance_client = match (settings.balance_url, settings.balance_class) {
            (Some(url), Some(class)) => Some(FixedApiClient::new_bearer(
                scope,
                url,
                class,
                settings.credential,
                transport_config(Duration::from_secs(5))?,
            )?),
            (None, None) => None,
            _ => return Err(ClassifiedError::new(ErrorKind::Api)),
        };
        let mut provider = Self::from_clients(
            quota_client,
            model_client,
            balance_client,
            settings.region,
            settings.usage_scope,
            settings.local_offset,
        )?;
        provider.use_system_local_offset = settings.use_system_local_offset;
        Ok(provider)
    }

    /// Wraps already validated account-scoped clients. This is the deterministic
    /// test seam for custom loopback endpoints.
    ///
    /// # Errors
    ///
    /// Rejects provider or account-scope mismatches.
    pub fn from_clients(
        quota_client: FixedApiClient,
        model_client: FixedApiClient,
        balance_client: Option<FixedApiClient>,
        region: ZaiRegion,
        usage_scope: ZaiUsageScope,
        local_offset: UtcOffset,
    ) -> Result<Self, ClassifiedError> {
        let scope = quota_client.scope();
        if scope.provider() != ProviderId::Zai
            || model_client.scope() != scope
            || balance_client
                .as_ref()
                .is_some_and(|client| client.scope() != scope)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_scope(&usage_scope)?;
        Ok(Self {
            quota_client,
            model_client,
            balance_client,
            region,
            usage_scope,
            local_offset,
            use_system_local_offset: false,
        })
    }

    /// Fetches the mandatory quota and best-effort balance/model enrichments at
    /// one deterministic clock instant.
    ///
    /// # Errors
    ///
    /// Returns stable API, network, or parse classifications without provider
    /// response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let headers = team_headers(&self.usage_scope);
        let quota_url = quota_request_url(self.quota_client.base_url(), &self.usage_scope)?;
        let quota_response = self
            .quota_client
            .get_json_with_public_headers_and_status_map(context, quota_url, &headers, |_| {
                Some(ErrorKind::Api)
            })
            .await?;
        if quota_response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let quota: Value = quota_response.json()?;
        let parsed = ParsedQuota::parse(&quota)?;
        let mut normalized = normalize_quota(&parsed, fetched_at)?;

        if self.region == ZaiRegion::BigModelCn
            && let Some(client) = self.balance_client.as_ref()
            && normalized.rows.len() < 24
            && let Some(row) = optional_balance_row(client, context).await
        {
            normalized.rows.push(row);
        }

        let quota_details =
            DetailSection::new(Some("Quota details".to_owned()), normalized.rows, None)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let mut details = vec![quota_details];
        let local_offset = if self.use_system_local_offset {
            UtcOffset::local_offset_at(fetched_at.as_offset_date_time())
                .unwrap_or(self.local_offset)
        } else {
            self.local_offset
        };
        for (days, title) in [(1, "Hourly tokens"), (30, "Daily tokens")] {
            if let Ok(Some(section)) = self
                .model_usage_section(context, fetched_at, local_offset, days, title, &headers)
                .await
            {
                details.push(section);
            }
        }

        let mut builder = UsageSampleBuilder::new(context.scope().clone(), fetched_at)
            .primary(normalized.primary)
            .extra_windows(normalized.extra_windows)
            .detail_sections(details)
            .login_method(parsed.plan.clone())?;
        if let Some(secondary) = normalized.secondary {
            builder = builder.secondary(secondary);
        }
        builder.provenance("zai", "api")?.build()
    }

    async fn model_usage_section(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        local_offset: UtcOffset,
        days: i64,
        title: &str,
        headers: &[(&str, &str)],
    ) -> Result<Option<DetailSection>, ClassifiedError> {
        let url = model_usage_url(
            self.model_client.base_url(),
            fetched_at,
            local_offset,
            days,
            &self.usage_scope,
        )?;
        let response = self
            .model_client
            .get_json_with_public_headers_and_status_map(context, url, headers, |_| None)
            .await?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let body: Value = response.json()?;
        normalize_model_usage(&body, title)
    }
}

impl ProviderAdapter for ZaiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Zai)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LimitKind {
    Tokens,
    Credit,
    Time,
}

#[derive(Clone)]
struct ParsedLimit {
    kind: LimitKind,
    unit: i64,
    number: i64,
    usage: Option<i64>,
    remaining: Option<i64>,
    percent: f64,
    window_minutes: Option<i64>,
    reset_millis: Option<i64>,
    usage_details: Vec<(String, i64)>,
}

struct ParsedQuota {
    plan: Option<String>,
    limits: Vec<ParsedLimit>,
}

impl ParsedQuota {
    fn parse(root: &Value) -> Result<Self, ClassifiedError> {
        let root = root
            .as_object()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        if root.get("success").and_then(Value::as_bool) != Some(true)
            || !number_is_200(root.get("code"))
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let data = root
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let raw_limits = data
            .get("limits")
            .and_then(Value::as_array)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let mut limits = Vec::with_capacity(raw_limits.len().min(64));
        for raw in raw_limits {
            if let Some(limit) = parse_limit(raw)? {
                limits.push(limit);
            }
        }
        let plan = ["planName", "plan", "plan_type", "packageName", "level"]
            .into_iter()
            .find_map(|key| {
                data.get(key)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            });
        Ok(Self { plan, limits })
    }
}

struct NormalizedQuota {
    primary: RateWindow,
    secondary: Option<RateWindow>,
    extra_windows: Vec<NamedRateWindow>,
    rows: Vec<DetailRow>,
}

fn normalize_quota(
    parsed: &ParsedQuota,
    fetched_at: Timestamp,
) -> Result<NormalizedQuota, ClassifiedError> {
    let mut quota_limits = parsed
        .limits
        .iter()
        .filter(|limit| matches!(limit.kind, LimitKind::Tokens | LimitKind::Credit))
        .cloned()
        .collect::<Vec<_>>();
    quota_limits.sort_by_key(|limit| limit.window_minutes.unwrap_or(i64::MAX));
    let time_limit = parsed
        .limits
        .iter()
        .rev()
        .find(|limit| limit.kind == LimitKind::Time)
        .cloned();
    let token_limit = quota_limits.last().cloned();
    let session_limit = (quota_limits.len() >= 2).then(|| quota_limits[0].clone());

    let primary_limit = session_limit
        .as_ref()
        .or(token_limit.as_ref())
        .or(time_limit.as_ref());
    let primary = primary_limit.map_or_else(empty_window, rate_window)?;
    let secondary = match (session_limit.as_ref(), token_limit.as_ref()) {
        (Some(_), Some(longest)) => Some(rate_window(longest)?),
        _ => None,
    };
    let mut extra_windows = Vec::new();
    if token_limit.is_some()
        && let Some(time) = time_limit.as_ref()
    {
        extra_windows.push(NamedRateWindow::new(
            BoundedText::new("zai-mcp").map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            BoundedText::new("MCP").map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            rate_window(time)?,
        ));
    }

    let mut rows = Vec::new();
    if let Some(longest) = token_limit.as_ref() {
        rows.push(limit_row(
            if longest.kind == LimitKind::Credit {
                "Credit quota"
            } else {
                "Token quota"
            },
            longest,
        )?);
    }
    if let Some(shortest) = session_limit.as_ref() {
        rows.push(limit_row(
            if shortest.kind == LimitKind::Credit {
                "Session credit quota"
            } else {
                "Session token quota"
            },
            shortest,
        )?);
    }
    if [token_limit.as_ref(), session_limit.as_ref()]
        .into_iter()
        .flatten()
        .any(|limit| limit.kind == LimitKind::Credit)
    {
        rows.push(quota_rate_row(fetched_at)?);
    }
    if let Some(time) = time_limit.as_ref() {
        rows.push(limit_row("MCP quota", time)?);
        let available = 24_usize.saturating_sub(rows.len()).min(MAX_MCP_ROWS);
        for (model, usage) in time.usage_details.iter().take(available) {
            rows.push(detail_row(model, usage.to_string(), None)?);
        }
    }
    Ok(NormalizedQuota {
        primary,
        secondary,
        extra_windows,
        rows,
    })
}

fn parse_limit(raw: &Value) -> Result<Option<ParsedLimit>, ClassifiedError> {
    let raw = raw
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let kind = match raw.get("type").and_then(Value::as_str) {
        Some("TOKENS_LIMIT") => Some(LimitKind::Tokens),
        Some("CREDIT_LIMIT") => Some(LimitKind::Credit),
        Some("TIME_LIMIT") => Some(LimitKind::Time),
        Some(_) => None,
        None => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let unit = required_integer(raw, "unit")?;
    let number = required_integer(raw, "number")?;
    let raw_percentage = required_integer(raw, "percentage")?;
    let Some(kind) = kind else {
        return Ok(None);
    };
    let usage = optional_integer(raw, "usage")?;
    let current = optional_integer(raw, "currentValue")?;
    let remaining = optional_integer(raw, "remaining")?;
    let reset_millis = optional_integer(raw, "nextResetTime")?;
    let mut percent = raw_percentage
        .to_f64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if let Some(total) = usage.filter(|value| *value > 0) {
        let used = match (remaining, current) {
            (Some(remaining), current) => {
                let derived = i128::from(total) - i128::from(remaining);
                derived.max(i128::from(current.unwrap_or_else(|| {
                    i64::try_from(derived).unwrap_or(if derived.is_negative() {
                        i64::MIN
                    } else {
                        i64::MAX
                    })
                })))
            }
            (None, Some(current)) => i128::from(current),
            (None, None) => i128::MIN,
        };
        if used != i128::MIN {
            let used = used.clamp(0, i128::from(total));
            percent = used
                .to_f64()
                .zip(total.to_f64())
                .map(|(used, total)| used * 100.0 / total)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        }
    }
    percent = percent.clamp(0.0, 100.0);
    let multiplier = match unit {
        1 => Some(1440_i64),
        3 => Some(60),
        5 => Some(1),
        6 => Some(10080),
        _ => None,
    };
    let window_minutes = if number > 0 {
        multiplier
            .map(|multiplier| {
                number
                    .checked_mul(multiplier)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
            })
            .transpose()?
    } else {
        None
    };
    let details = match raw.get("usageDetails") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(details)) => details.as_slice(),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let usage_details = details
        .iter()
        .filter_map(|detail| {
            let detail = detail.as_object()?;
            let model = detail.get("modelCode")?.as_str()?.to_owned();
            let usage = json_integer(detail.get("usage")?)?;
            Some((model, usage))
        })
        .collect();
    Ok(Some(ParsedLimit {
        kind,
        unit,
        number,
        usage,
        remaining,
        percent,
        window_minutes,
        reset_millis,
        usage_details,
    }))
}

fn rate_window(limit: &ParsedLimit) -> Result<RateWindow, ClassifiedError> {
    let minutes = if limit.kind == LimitKind::Time && limit.unit == 5 && limit.number == 1 {
        Some(30 * 24 * 60)
    } else {
        limit.window_minutes
    };
    let duration = minutes
        .map(WindowDuration::from_provider_minutes)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let resets_at = limit.reset_millis.map(timestamp_from_millis).transpose()?;
    let description = if limit.kind == LimitKind::Time {
        Some("MCP".to_owned())
    } else if limit.window_minutes == Some(300) {
        Some("5-hour".to_owned())
    } else {
        limit.window_minutes.and_then(|_| {
            let unit = match limit.unit {
                1 => "day",
                3 => "hour",
                5 => "minute",
                6 => "week",
                _ => return None,
            };
            Some(format!(
                "{} {}{} window",
                limit.number,
                unit,
                if limit.number == 1 { "" } else { "s" }
            ))
        })
    };
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(limit.percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        duration,
        resets_at,
        description
            .map(BoundedText::new)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn empty_window() -> Result<RateWindow, ClassifiedError> {
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(0.0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        None,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn limit_row(label: &str, limit: &ParsedLimit) -> Result<DetailRow, ClassifiedError> {
    let secondary = [
        limit.usage.map(|value| format!("{value} limit")),
        limit.remaining.map(|value| format!("{value} remaining")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    detail_row(
        label,
        format!("{}% used", format_percent(limit.percent)),
        (!secondary.is_empty()).then(|| secondary.join(" · ")),
    )
}

fn quota_rate_row(fetched_at: Timestamp) -> Result<DetailRow, ClassifiedError> {
    let now = fetched_at.as_offset_date_time().to_offset(UtcOffset::UTC);
    let weekday = now.weekday();
    let is_weekday = matches!(
        weekday,
        Weekday::Monday
            | Weekday::Tuesday
            | Weekday::Wednesday
            | Weekday::Thursday
            | Weekday::Friday
    );
    let is_peak = is_weekday && (6..10).contains(&now.hour());
    let mut boundary_date = now.date();
    let boundary_hour = if is_peak { 10 } else { 6 };
    if !is_peak && now.hour() >= 6 {
        boundary_date = boundary_date
            .checked_add(TimeDuration::days(1))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    }
    if !is_peak {
        while matches!(boundary_date.weekday(), Weekday::Saturday | Weekday::Sunday) {
            boundary_date = boundary_date
                .checked_add(TimeDuration::days(1))
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        }
    }
    let boundary = PrimitiveDateTime::new(
        boundary_date,
        Time::from_hms(boundary_hour, 0, 0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
    )
    .assume_utc();
    let countdown = countdown_text((boundary - now).whole_seconds());
    detail_row(
        "Quota rate",
        if is_peak { "Peak" } else { "Off-peak" }.to_owned(),
        Some(format!(
            "{} {countdown}",
            if is_peak { "off-peak" } else { "peak" }
        )),
    )
}

async fn optional_balance_row(
    client: &FixedApiClient,
    context: &ProviderContext,
) -> Option<DetailRow> {
    let response = client
        .get_json(context, client.base_url().clone())
        .await
        .ok()?;
    if response.status() != 200 {
        return None;
    }
    let body: Value = response.json().ok()?;
    let root = body.as_object()?;
    if root.get("success").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let data = root.get("data")?.as_object()?;
    let available = data.get("availableBalance").and_then(json_finite_number);
    let current = data.get("balance").and_then(json_finite_number);
    let value = available.or(current)?;
    let mut secondary = Vec::new();
    if let Some(value) = data.get("rechargeAmount").and_then(json_finite_number) {
        secondary.push(format!("recharged ¥{value:.2}"));
    }
    if let Some(value) = data
        .get("giveAmount")
        .and_then(json_finite_number)
        .filter(|value| *value > 0.0)
    {
        secondary.push(format!("granted ¥{value:.2}"));
    }
    if let Some(value) = data.get("totalSpendAmount").and_then(json_finite_number) {
        secondary.push(format!("spent ¥{value:.2}"));
    }
    DetailRow::new(
        "Account balance",
        format!("¥{value:.2}"),
        (!secondary.is_empty()).then(|| secondary.join(" · ")),
        DetailSensitivity::Personal,
    )
    .ok()
}

fn normalize_model_usage(
    body: &Value,
    title: &str,
) -> Result<Option<DetailSection>, ClassifiedError> {
    let root = body
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if root.get("success").and_then(Value::as_bool) != Some(true)
        || !number_is_200(root.get("code"))
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let data = root.get("data").and_then(Value::as_object);
    let labels = data
        .and_then(|data| data.get("x_time"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let models = data
        .and_then(|data| data.get("modelDataList"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if labels.len() > MAX_MODEL_POINTS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let mut points = Vec::new();
    for (index, label) in labels.iter().enumerate() {
        let mut total = 0_i64;
        for model in models {
            let value = model
                .as_object()
                .and_then(|model| model.get("tokensUsage"))
                .and_then(Value::as_array)
                .and_then(|values| values.get(index))
                .and_then(json_integer)
                .filter(|value| *value > 0)
                .unwrap_or(0);
            total = total
                .checked_add(value)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        }
        if total > 0 {
            points.push(
                DetailChartPoint::new(
                    js_string(label),
                    FiniteNumber::new(
                        total
                            .to_f64()
                            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
                    )
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                )
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            );
        }
    }
    if points.is_empty() {
        return Ok(None);
    }

    let mut totals = Vec::new();
    for model in models {
        let model = model.as_object();
        let name = model
            .and_then(|model| model.get("modelName"))
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_owned();
        let mut total = 0_i64;
        if let Some(values) = model
            .and_then(|model| model.get("tokensUsage"))
            .and_then(Value::as_array)
        {
            for value in values {
                if let Some(value) = json_integer(value).filter(|value| *value > 0) {
                    total = total
                        .checked_add(value)
                        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                }
            }
        }
        if total > 0 {
            totals.push((name, total));
        }
    }
    totals.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let rows = totals
        .into_iter()
        .take(MAX_MODEL_ROWS)
        .map(|(name, total)| detail_row(&name, total.to_string(), None))
        .collect::<Result<Vec<_>, _>>()?;
    let chart = DetailChart::new(
        DetailChartKind::Bars,
        Some(title.to_owned()),
        Some("tokens".to_owned()),
        points,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    DetailSection::new(Some(title.to_owned()), rows, Some(chart))
        .map(Some)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn model_usage_url(
    base: &Url,
    fetched_at: Timestamp,
    local_offset: UtcOffset,
    days: i64,
    usage_scope: &ZaiUsageScope,
) -> Result<Url, ClassifiedError> {
    let local = fetched_at.as_offset_date_time().to_offset(local_offset);
    let start_date = local
        .date()
        .checked_sub(TimeDuration::days(days.max(1)))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let start = PrimitiveDateTime::new(start_date, Time::MIDNIGHT);
    let end = PrimitiveDateTime::new(
        local.date(),
        Time::from_hms(local.hour(), 59, 59).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
    );
    let mut url = base.clone();
    url.set_query(None);
    let mut query = format!(
        "startTime={}&endTime={}",
        encode_zai_timestamp(start),
        encode_zai_timestamp(end)
    );
    if matches!(usage_scope, ZaiUsageScope::Team { .. }) {
        query.push_str("&type=3");
    }
    url.set_query(Some(&query));
    Ok(url)
}

fn quota_request_url(base: &Url, usage_scope: &ZaiUsageScope) -> Result<Url, ClassifiedError> {
    let mut url = base.clone();
    if !matches!(usage_scope, ZaiUsageScope::Team { .. }) {
        return Ok(url);
    }
    let pairs = url
        .query_pairs()
        .filter(|(key, _)| key != "type")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(&key, &value);
        }
        query.append_pair("type", "2");
    }
    if url.host_str().is_none() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(url)
}

fn team_headers(scope: &ZaiUsageScope) -> Vec<(&str, &str)> {
    match scope {
        ZaiUsageScope::Personal => Vec::new(),
        ZaiUsageScope::Team {
            organization,
            project,
        } => vec![
            ("Bigmodel-Organization", organization.as_str()),
            ("Bigmodel-Project", project.as_str()),
        ],
    }
}

fn resolve_region(environment: &BTreeMap<String, String>) -> Result<ZaiRegion, ClassifiedError> {
    match environment
        .get("Z_AI_REGION")
        .and_then(|value| clean_setting(value))
        .unwrap_or("global")
    {
        "global" => Ok(ZaiRegion::Global),
        "bigmodel-cn" => Ok(ZaiRegion::BigModelCn),
        _ => Err(ClassifiedError::new(ErrorKind::Api)),
    }
}

fn resolve_usage_scope(
    environment: &BTreeMap<String, String>,
) -> Result<ZaiUsageScope, ClassifiedError> {
    match environment
        .get("Z_AI_USAGE_SCOPE")
        .and_then(|value| clean_setting(value))
        .unwrap_or("personal")
    {
        "personal" => Ok(ZaiUsageScope::Personal),
        "team" => {
            let organization = first_clean_setting(
                environment,
                &["Z_AI_ORGANIZATION", "Z_AI_BIGMODEL_ORGANIZATION"],
            )
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
            let project =
                first_clean_setting(environment, &["Z_AI_PROJECT", "Z_AI_BIGMODEL_PROJECT"])
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
            let scope = ZaiUsageScope::Team {
                organization,
                project,
            };
            validate_scope(&scope)?;
            Ok(scope)
        }
        _ => Err(ClassifiedError::new(ErrorKind::Api)),
    }
}

fn validate_scope(scope: &ZaiUsageScope) -> Result<(), ClassifiedError> {
    if let ZaiUsageScope::Team {
        organization,
        project,
    } = scope
        && (organization.trim().is_empty()
            || project.trim().is_empty()
            || organization.len() > 8 * 1024
            || project.len() > 8 * 1024
            || organization.contains(['\r', '\n'])
            || project.contains(['\r', '\n']))
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn resolve_credential(
    environment: &BTreeMap<String, String>,
    region: ZaiRegion,
) -> Result<ApiKeyCredential, ClassifiedError> {
    let mut keys = vec![PRIMARY_KEY];
    if region == ZaiRegion::BigModelCn {
        keys.extend(CN_KEYS);
    }
    if let Ok(credential) = ApiKeyCredential::resolve(environment, &keys) {
        return Ok(credential);
    }
    if region == ZaiRegion::BigModelCn
        && let Some(home) = environment
            .get("HOME")
            .and_then(|value| clean_setting(value))
    {
        for relative in CN_KEY_PATHS {
            let path = Path::new(home).join(relative);
            let readable_size = path
                .metadata()
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map(|metadata| metadata.len())
                .filter(|length| *length <= MAX_SECRET_FILE_BYTES);
            if readable_size.is_none() {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(path) else {
                continue;
            };
            let Some(first_line) = raw
                .split(|character| {
                    matches!(
                        character,
                        '\n' | '\r'
                            | '\u{000B}'
                            | '\u{000C}'
                            | '\u{0085}'
                            | '\u{2028}'
                            | '\u{2029}'
                    )
                })
                .find(|line| !line.is_empty())
            else {
                continue;
            };
            if let Ok(credential) = ApiKeyCredential::new(first_line) {
                return Ok(credential);
            }
        }
    }
    Err(ClassifiedError::new(ErrorKind::MissingCredential))
}

fn optional_endpoint(
    environment: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<Url>, ClassifiedError> {
    environment
        .get(key)
        .and_then(|value| clean_setting(value))
        .map(parse_https_endpoint)
        .transpose()
}

fn parse_https_endpoint(raw: &str) -> Result<Url, ClassifiedError> {
    let value = if has_explicit_scheme(raw) {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&value).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    endpoint_class(&url)?;
    Ok(url)
}

fn endpoint_class(url: &Url) -> Result<EndpointClass, ClassifiedError> {
    let mut origin = url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    classify_https_endpoint(&origin).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn endpoint_from_origin(origin: &str, path: &str) -> Result<Url, ClassifiedError> {
    let origin = parse_https_endpoint(origin)?;
    Ok(endpoint_from_host(&origin, path))
}

fn endpoint_from_host(base: &Url, path: &str) -> Url {
    if base.path().is_empty() || base.path() == "/" {
        let mut result = base.clone();
        result.set_path(&format!("/{path}"));
        result
    } else {
        base.clone()
    }
}

fn validate_region_host(url: &Url, region: ZaiRegion) -> Result<(), ClassifiedError> {
    let Some(host) = url.host_str() else {
        return Err(ClassifiedError::new(ErrorKind::Api));
    };
    if (host.eq_ignore_ascii_case("api.z.ai") || host.eq_ignore_ascii_case("open.bigmodel.cn"))
        && !host.eq_ignore_ascii_case(region.host())
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
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
    let scheme = &raw[..colon];
    scheme.bytes().enumerate().all(|(index, byte)| {
        if index == 0 {
            byte.is_ascii_alphabetic()
        } else {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        }
    })
}

fn first_clean_setting(environment: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| environment.get(*key))
        .find_map(|value| clean_setting(value).map(str::to_owned))
}

fn required_integer(raw: &Map<String, Value>, key: &str) -> Result<i64, ClassifiedError> {
    raw.get(key)
        .and_then(json_integer)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn optional_integer(raw: &Map<String, Value>, key: &str) -> Result<Option<i64>, ClassifiedError> {
    match raw.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => json_integer(value)
            .map(Some)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn json_integer(value: &Value) -> Option<i64> {
    let raw = value.as_number()?.to_string();
    let value = Decimal::from_scientific(&raw)
        .or_else(|_| raw.parse())
        .ok()?;
    if value.fract().is_zero() {
        value.to_i64()
    } else {
        None
    }
}

fn number_is_200(value: Option<&Value>) -> bool {
    value.and_then(json_integer) == Some(200)
}

fn json_finite_number(value: &Value) -> Option<f64> {
    if value.is_null() {
        return None;
    }
    let value = match value {
        Value::Bool(value) => f64::from(u8::from(*value)),
        Value::Number(value) => value.as_f64()?,
        Value::Null => return None,
        value => parse_javascript_number(&javascript_primitive_string(value)?)?,
    };
    value.is_finite().then_some(value)
}

fn javascript_primitive_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_owned()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.clone()),
        Value::Array(values) => Some(
            values
                .iter()
                .map(|value| match value {
                    Value::Null => Some(String::new()),
                    value => javascript_primitive_string(value),
                })
                .collect::<Option<Vec<_>>>()?
                .join(","),
        ),
        Value::Object(_) => None,
    }
}

fn parse_javascript_number(value: &str) -> Option<f64> {
    let value = value.trim();
    if value.is_empty() {
        return Some(0.0);
    }
    let radix = [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ]
    .into_iter()
    .find_map(|(prefix, radix)| value.strip_prefix(prefix).map(|value| (value, radix)));
    if let Some((value, radix)) = radix {
        return u128::from_str_radix(value, radix).ok()?.to_f64();
    }
    value.parse().ok()
}

fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

fn timestamp_from_millis(value: i64) -> Result<Timestamp, ClassifiedError> {
    let nanos = i128::from(value)
        .checked_mul(1_000_000)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let value = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::new(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_percent(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

fn countdown_text(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 1 {
        return "now".to_owned();
    }
    let minutes = (seconds.saturating_add(59) / 60).max(1);
    let days = minutes / 1440;
    let hours = (minutes / 60) % 24;
    let remainder = minutes % 60;
    if days > 0 {
        if hours > 0 {
            return format!("in {days}d {hours}h");
        }
        if remainder > 0 {
            return format!("in {days}d {remainder}m");
        }
        return format!("in {days}d");
    }
    if hours > 0 {
        if remainder > 0 {
            format!("in {hours}h {remainder}m")
        } else {
            format!("in {hours}h")
        }
    } else {
        format!("in {minutes}m")
    }
}

fn encode_zai_timestamp(value: PrimitiveDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}%20{:02}%3A{:02}%3A{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
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

fn transport_config(request_timeout: Duration) -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        request_timeout,
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), request_timeout),
    )
    .map_err(|error| error.classified())
}
