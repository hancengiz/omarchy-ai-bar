//! xAI Management API prepaid balance and best-effort daily spend history.

use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, CostAmount, CostProvenance, CostSummary, CostUnit,
    CostUsageCoverage, CostUsageDailyBucket, CostUsageMetrics, CostUsageSnapshot,
    CostUsageTokenMix, CurrencyCode, DataConfidence, DetailChart, DetailChartKind,
    DetailChartPoint, DetailRow, DetailSection, DetailSensitivity, ErrorKind, ExactDecimal,
    FiniteNumber, ProviderId, Timestamp, UsageSample,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Deserializer, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{HttpResponse, TransportConfig};

const API_ORIGIN: &str = "https://management-api.x.ai/v1/billing/teams/";
const KEY_NAMES: [&str; 1] = ["XAI_MANAGEMENT_API_KEY"];
const TEAM_ID_NAMES: [&str; 1] = ["XAI_TEAM_ID"];
const MAX_TEAM_ID_BYTES: usize = 512;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_DAILY_POINTS: usize = 120;
const HISTORY_DAYS: u16 = 30;

/// Selected xAI Management API key and required team identifier.
pub struct XaiCredential {
    key: ApiKeyCredential,
    team_id: String,
}

impl XaiCredential {
    /// Resolves the baseline environment keys with quote trimming.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when either value is absent
    /// or the team identifier cannot be represented by one URL path segment.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let key = ApiKeyCredential::resolve(environment, &KEY_NAMES)?;
        let team_id = TEAM_ID_NAMES
            .iter()
            .filter_map(|name| environment.get(*name))
            .find_map(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::new(key, &team_id)
    }

    /// Builds an explicitly selected Management key and team identifier.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for an unsafe team ID.
    pub fn new(key: ApiKeyCredential, team_id: &str) -> Result<Self, ClassifiedError> {
        let team_id = clean_setting(team_id)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        validate_team_id(&team_id)?;
        Ok(Self { key, team_id })
    }
}

impl Debug for XaiCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XaiCredential")
            .field("key", &"<redacted>")
            .field("team_id", &"<redacted>")
            .finish()
    }
}

/// Native xAI Management API adapter.
pub struct XaiProvider {
    client: FixedApiClient,
    team_id: String,
}

impl XaiProvider {
    /// Creates the production fixed-origin client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, credential: XaiCredential) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            credential.key,
            transport_config()?,
        )?;
        Self::from_client(client, credential.team_id)
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for another provider or an unsafe team ID.
    pub fn from_client(client: FixedApiClient, team_id: String) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Xai {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_team_id(&team_id)?;
        Ok(Self { client, team_id })
    }

    /// Fetches the authoritative posted prepaid balance and optional history.
    ///
    /// History transport and parse failures preserve the valid balance. A
    /// history authentication failure remains authoritative because it proves
    /// that the selected Management key is unusable.
    ///
    /// # Errors
    ///
    /// Returns stable classified credential, transport, and balance errors
    /// without exposing provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let balance_url = self.team_url(&["prepaid", "balance"])?;
        let balance: BalanceEnvelope =
            self.authenticated_get(context, balance_url).await?.json()?;
        let balance = parse_balance(&balance)?;

        let history = match self.fetch_history(context, fetched_at).await {
            Ok(history) => Some(history),
            Err(error) if error.kind() == ErrorKind::AuthenticationExpired => return Err(error),
            Err(_) => None,
        };
        normalize(
            context.scope().clone(),
            fetched_at,
            balance,
            history.as_ref(),
        )
    }

    async fn fetch_history(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<SpendHistory, ClassifiedError> {
        let usage_url = self.team_url(&["usage"])?;
        let body = usage_request_body(fetched_at)?;
        let response = self
            .client
            .post_json(context, usage_url, body)
            .await
            .map_err(remap_authentication)?;
        parse_history(response.json()?)
    }

    async fn authenticated_get(
        &self,
        context: &ProviderContext,
        url: Url,
    ) -> Result<HttpResponse, ClassifiedError> {
        self.client
            .get_json_with_status_map(context, url, xai_balance_status)
            .await
    }

    fn team_url(&self, suffix: &[&str]) -> Result<Url, ClassifiedError> {
        let mut url = self.client.base_url().clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| ClassifiedError::new(ErrorKind::Api))?;
            segments.pop_if_empty().push(&self.team_id);
            for segment in suffix {
                segments.push(segment);
            }
        }
        Ok(url)
    }
}

impl ProviderAdapter for XaiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Xai)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct BalanceEnvelope {
    total: BalanceTotal,
}

#[derive(Deserialize)]
struct BalanceTotal {
    val: String,
}

#[derive(Deserialize)]
struct UsageEnvelope {
    #[serde(rename = "timeSeries")]
    time_series: Option<Vec<UsageSeries>>,
    #[serde(rename = "limitReached")]
    limit_reached: Option<bool>,
}

#[derive(Deserialize)]
struct UsageSeries {
    #[serde(rename = "dataPoints")]
    data_points: Option<Vec<UsagePoint>>,
}

#[derive(Deserialize)]
struct UsagePoint {
    timestamp: String,
    values: Option<Vec<JsonDecimal>>,
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

#[derive(Serialize)]
struct UsageRequest {
    #[serde(rename = "analyticsRequest")]
    analytics_request: AnalyticsRequest,
}

#[derive(Serialize)]
struct AnalyticsRequest {
    #[serde(rename = "timeRange")]
    time_range: UsageTimeRange,
    #[serde(rename = "timeUnit")]
    time_unit: &'static str,
    values: [AnalyticsValue; 1],
    #[serde(rename = "groupBy")]
    group_by: [String; 0],
    filters: [String; 0],
}

#[derive(Serialize)]
struct UsageTimeRange {
    #[serde(rename = "startTime")]
    start_time: String,
    #[serde(rename = "endTime")]
    end_time: String,
    timezone: &'static str,
}

#[derive(Serialize)]
struct AnalyticsValue {
    name: &'static str,
    aggregation: &'static str,
}

struct SpendHistory {
    daily: BTreeMap<String, Decimal>,
    total: Decimal,
    partial: bool,
}

struct HistoryEnrichment {
    total: Decimal,
    partial: bool,
    chart: DetailChart,
    cost_usage: CostUsageSnapshot,
}

fn parse_balance(response: &BalanceEnvelope) -> Result<Decimal, ClassifiedError> {
    let raw = response.total.val.trim();
    if !is_plain_decimal(raw) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let ledger = raw
        .parse::<Decimal>()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Decimal::ZERO
        .checked_sub(ledger)
        .and_then(|value| value.checked_div(Decimal::from(100_u8)))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn parse_history(response: UsageEnvelope) -> Result<SpendHistory, ClassifiedError> {
    let series = response
        .time_series
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let mut daily = BTreeMap::<String, Decimal>::new();
    for series in series {
        let points = series
            .data_points
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        for point in points {
            let value = point
                .values
                .and_then(|values| values.first().copied())
                .map(|value| value.0)
                .filter(|value| *value >= Decimal::ZERO)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            let at = Timestamp::parse(&point.timestamp)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            let day = utc_day(at.as_offset_date_time());
            match daily.entry(day) {
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
                Entry::Occupied(mut entry) => {
                    let sum = entry
                        .get()
                        .checked_add(value)
                        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                    entry.insert(sum);
                }
            }
        }
    }
    if daily.len() > MAX_DAILY_POINTS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let total = daily
        .values()
        .try_fold(Decimal::ZERO, |total, value| total.checked_add(*value))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(SpendHistory {
        daily,
        total,
        partial: response.limit_reached == Some(true),
    })
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    balance: Decimal,
    history: Option<&SpendHistory>,
) -> Result<UsageSample, ClassifiedError> {
    let currency = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let cost = CostSummary::new(
        CostAmount::money(ExactDecimal::new(balance), currency.clone()),
        ExactDecimal::new(Decimal::ZERO),
        Some("Prepaid credits".to_owned()),
        None,
        None,
        None,
        None,
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;

    // Any domain-level enrichment rejection is still best effort and must not
    // discard the authoritative balance.
    let enrichment = history.and_then(|history| build_history(history, fetched_at, currency).ok());
    let total = enrichment
        .as_ref()
        .map_or(Decimal::ZERO, |history| history.total);
    let partial = enrichment.as_ref().is_some_and(|history| history.partial);
    let rows = vec![
        detail_row("Prepaid balance", format_usd(balance))?,
        detail_row(
            if partial {
                "Last 30 days (partial)"
            } else {
                "Last 30 days"
            },
            format_usd(total),
        )?,
    ];
    let chart = enrichment.as_ref().map(|history| history.chart.clone());
    let details = DetailSection::new(Some("Billing summary".to_owned()), rows, chart)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(Some("Management API".to_owned()))?
        .cost(cost)
        .detail_sections(vec![details])
        .confidence(if partial {
            DataConfidence::Estimated
        } else {
            DataConfidence::Exact
        });
    if let Some(enrichment) = enrichment {
        builder = builder.cost_usage(enrichment.cost_usage);
    }
    builder.provenance("xai", "management-api")?.build()
}

fn build_history(
    history: &SpendHistory,
    fetched_at: Timestamp,
    currency: CurrencyCode,
) -> Result<HistoryEnrichment, ClassifiedError> {
    let chart_points = history
        .daily
        .iter()
        .map(|(day, value)| {
            let value = value
                .to_f64()
                .and_then(|value| FiniteNumber::new(value).ok())
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            DetailChartPoint::new(day.clone(), value)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let chart = DetailChart::new(
        DetailChartKind::Bars,
        Some("Daily spend".to_owned()),
        Some("USD".to_owned()),
        chart_points,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;

    let daily = history
        .daily
        .iter()
        .map(|(day, amount)| {
            CostUsageDailyBucket::new(
                day,
                None,
                cost_metrics(Some(*amount))?,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let today = utc_day(fetched_at.as_offset_date_time());
    let session = cost_metrics(history.daily.get(&today).copied())?;
    let history_metrics = cost_metrics(Some(history.total))?;
    let cost_usage = CostUsageSnapshot::new(
        CostUnit::currency(currency),
        session,
        history_metrics,
        Some(ExactDecimal::new(history.total)),
        HISTORY_DAYS,
        !history.partial,
        history.partial.then(|| "Last 30 days (partial)".to_owned()),
        None,
        daily,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        fetched_at,
        CostProvenance::VendorMetered,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(HistoryEnrichment {
        total: history.total,
        partial: history.partial,
        chart,
        cost_usage,
    })
}

fn cost_metrics(amount: Option<Decimal>) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::default(),
        None,
        None,
        amount.map(ExactDecimal::new),
        CostUsageCoverage::default(),
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn usage_request_body(fetched_at: Timestamp) -> Result<Vec<u8>, ClassifiedError> {
    let now = fetched_at.as_offset_date_time();
    let start_date = now
        .date()
        .checked_sub(TimeDuration::days(i64::from(HISTORY_DAYS - 1)))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let start = start_date.midnight().assume_utc();
    let request = UsageRequest {
        analytics_request: AnalyticsRequest {
            time_range: UsageTimeRange {
                start_time: xai_timestamp(start),
                end_time: xai_timestamp(now),
                timezone: "Etc/GMT",
            },
            time_unit: "TIME_UNIT_DAY",
            values: [AnalyticsValue {
                name: "usd",
                aggregation: "AGGREGATION_SUM",
            }],
            group_by: [],
            filters: [],
        },
    };
    serde_json::to_vec(&request).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn xai_timestamp(value: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

fn utc_day(value: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        value.year(),
        u8::from(value.month()),
        value.day()
    )
}

fn detail_row(label: &str, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Public)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_usd(value: Decimal) -> String {
    let rounded = value.round_dp(2);
    format!("${rounded:.2}")
}

fn remap_authentication(error: ClassifiedError) -> ClassifiedError {
    if error.kind() == ErrorKind::PermissionDenied {
        ClassifiedError::new(ErrorKind::AuthenticationExpired)
    } else {
        error
    }
}

const fn xai_balance_status(status: u16) -> Option<ErrorKind> {
    match status {
        403 => Some(ErrorKind::AuthenticationExpired),
        408 | 500..=599 => Some(ErrorKind::Api),
        _ => None,
    }
}

fn clean_setting(raw: &str) -> Option<String> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = value[1..value.len() - 1].trim();
    }
    (!value.is_empty()).then(|| value.to_owned())
}

fn validate_team_id(team_id: &str) -> Result<(), ClassifiedError> {
    if team_id.is_empty()
        || team_id.len() > MAX_TEAM_ID_BYTES
        || matches!(team_id, "." | "..")
        || team_id.contains('/')
        || team_id.chars().any(char::is_control)
    {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    Ok(())
}

fn is_plain_decimal(value: &str) -> bool {
    let value = value.strip_prefix('-').unwrap_or(value);
    let mut parts = value.split('.');
    let Some(integer) = parts.next() else {
        return false;
    };
    if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(fraction), None) => {
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
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
