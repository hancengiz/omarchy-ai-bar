//! LLM-API-Key-Proxy aggregate quota adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, NamedRateWindow, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Deserializer};

use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, format_integer, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "LLM_PROXY_API_KEY";
const BASE_URL: &str = "LLM_PROXY_BASE_URL";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDERS: usize = 512;
const MAX_QUOTA_GROUPS: usize = 4096;

/// Validated LLM Proxy endpoint and bearer credential.
pub struct LlmProxySettings {
    credential: ApiKeyCredential,
    endpoint: ConfiguredEndpoint,
}

impl LlmProxySettings {
    /// Resolves the baseline environment settings.
    ///
    /// HTTPS is accepted for any valid host. Plain HTTP is accepted only for
    /// loopback, RFC 1918/link-local/IPv6-local addresses, and `.local` hosts.
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
        let endpoint = ConfiguredEndpoint::parse(raw, ConfiguredHttpPolicy::PrivateNetworkHttp)?;
        Ok(Self {
            credential,
            endpoint,
        })
    }
}

impl Debug for LlmProxySettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmProxySettings")
            .field("credential", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Native LLM Proxy provider adapter.
pub struct LlmProxyProvider {
    client: FixedApiClient,
    endpoint: ConfiguredEndpoint,
}

impl LlmProxyProvider {
    /// Creates one exact configured-endpoint production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: LlmProxySettings) -> Result<Self, ClassifiedError> {
        let LlmProxySettings {
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
    /// Returns a stable API error for another provider or a mismatched base.
    pub fn from_client(
        client: FixedApiClient,
        endpoint: ConfiguredEndpoint,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::LlmProxy || client.base_url() != endpoint.url()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client, endpoint })
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
        let url = self.endpoint.path(Some("v1"), &["v1", "quota-stats"])?;
        let response: QuotaStatsResponse = self.client.get_json(context, url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, &response)
    }
}

impl ProviderAdapter for LlmProxyProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::LlmProxy)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct QuotaStatsResponse {
    providers: BTreeMap<String, ProviderStats>,
    summary: Option<Summary>,
}

#[derive(Deserialize)]
struct ProviderStats {
    credential_count: Option<i64>,
    active_count: Option<i64>,
    #[serde(rename = "exhausted_count")]
    _exhausted_count: Option<i64>,
    total_requests: Option<i64>,
    tokens: Option<Tokens>,
    approx_cost: Option<JsonDecimal>,
    #[serde(default, deserialize_with = "deserialize_quota_groups")]
    quota_groups: Option<Vec<QuotaGroup>>,
}

#[derive(Deserialize)]
struct Tokens {
    input_cached: Option<i64>,
    input_uncached: Option<i64>,
    output: Option<i64>,
}

#[derive(Deserialize)]
struct QuotaGroup {
    remaining_percent: Option<JsonDecimal>,
    reset_time: Option<String>,
}

#[derive(Deserialize)]
struct Summary {
    total_requests: Option<i64>,
    approx_cost: Option<JsonDecimal>,
    total_tokens: Option<i64>,
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

fn deserialize_quota_groups<'de, D>(deserializer: D) -> Result<Option<Vec<QuotaGroup>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    if let Ok(groups) = serde_json::from_value::<Vec<QuotaGroup>>(value.clone()) {
        return Ok(Some(groups));
    }
    Ok(
        serde_json::from_value::<BTreeMap<String, QuotaGroup>>(value)
            .ok()
            .map(|groups| groups.into_values().collect()),
    )
}

struct ProviderSummary {
    name: String,
    requests: i64,
    tokens: i64,
    approximate_cost: Option<Decimal>,
}

struct Aggregate {
    summaries: Vec<ProviderSummary>,
    total_requests: i64,
    total_tokens: i64,
    approximate_cost: Option<Decimal>,
    minimum_remaining: Option<f64>,
    next_reset: Option<Timestamp>,
    credential_count: i64,
    active_count: i64,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: &QuotaStatsResponse,
) -> Result<UsageSample, ClassifiedError> {
    let aggregate = aggregate(response, fetched_at)?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .secondary(zero_window(format!(
            "{} requests",
            format_integer(aggregate.total_requests)
        ))?)
        .tertiary(zero_window(format!(
            "{} tokens",
            format_integer(aggregate.total_tokens)
        ))?)
        .extra_windows(top_provider_windows(&aggregate.summaries)?);
    if let Some(remaining) = aggregate.minimum_remaining {
        let used = (100.0 - remaining).clamp(0.0, 100.0);
        builder = builder.primary(
            RateWindow::new(
                WindowUsage::known(
                    UsagePercent::new(used).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                ),
                None,
                aggregate.next_reset,
                None,
                None,
                false,
            )
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        );
    }
    if let Some(cost) = aggregate.approximate_cost {
        builder = builder.cost(cost_summary(cost, aggregate.next_reset, fetched_at)?);
    }
    builder
        .organization(Some(format!(
            "{}/{} active keys",
            aggregate.active_count, aggregate.credential_count
        )))?
        .login_method(Some("quota-stats".to_owned()))?
        .provenance("llmproxy", "api")?
        .build()
}

fn aggregate(
    response: &QuotaStatsResponse,
    fetched_at: Timestamp,
) -> Result<Aggregate, ClassifiedError> {
    let summaries = provider_summaries(response)?;
    let (total_requests, total_tokens, approximate_cost) = aggregate_totals(response, &summaries)?;
    let (minimum_remaining, next_reset) = quota_summary(response, fetched_at)?;
    Ok(Aggregate {
        summaries,
        total_requests,
        total_tokens,
        approximate_cost,
        minimum_remaining,
        next_reset,
        credential_count: provider_count(response, |provider| provider.credential_count)?,
        active_count: provider_count(response, |provider| provider.active_count)?,
    })
}

fn provider_summaries(
    response: &QuotaStatsResponse,
) -> Result<Vec<ProviderSummary>, ClassifiedError> {
    if response.providers.len() > MAX_PROVIDERS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut summaries = response
        .providers
        .iter()
        .map(|(name, stats)| {
            Ok(ProviderSummary {
                name: name.clone(),
                requests: stats.total_requests.unwrap_or(0),
                tokens: token_total(stats.tokens.as_ref())?,
                approximate_cost: stats.approx_cost.map(|value| value.0),
            })
        })
        .collect::<Result<Vec<_>, ClassifiedError>>()?;
    summaries.sort_by(|left, right| {
        right
            .requests
            .cmp(&left.requests)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(summaries)
}

fn aggregate_totals(
    response: &QuotaStatsResponse,
    summaries: &[ProviderSummary],
) -> Result<(i64, i64, Option<Decimal>), ClassifiedError> {
    let requests = response
        .summary
        .as_ref()
        .and_then(|summary| summary.total_requests)
        .map_or_else(
            || checked_sum(summaries.iter().map(|summary| summary.requests)),
            Ok,
        )?;
    let tokens = response
        .summary
        .as_ref()
        .and_then(|summary| summary.total_tokens)
        .map_or_else(
            || checked_sum(summaries.iter().map(|summary| summary.tokens)),
            Ok,
        )?;
    let cost = response
        .summary
        .as_ref()
        .and_then(|summary| summary.approx_cost)
        .map(|value| value.0)
        .or_else(|| {
            let sum = summaries
                .iter()
                .filter_map(|summary| summary.approximate_cost)
                .sum::<Decimal>();
            (sum > Decimal::ZERO).then_some(sum)
        });
    Ok((requests, tokens, cost))
}

fn quota_summary(
    response: &QuotaStatsResponse,
    fetched_at: Timestamp,
) -> Result<(Option<f64>, Option<Timestamp>), ClassifiedError> {
    let groups = response
        .providers
        .values()
        .flat_map(|provider| provider.quota_groups.iter().flatten())
        .collect::<Vec<_>>();
    if groups.len() > MAX_QUOTA_GROUPS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let minimum = groups
        .iter()
        .filter_map(|group| group.remaining_percent)
        .map(|value| {
            value
                .0
                .to_f64()
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .reduce(f64::min);
    let reset = groups
        .iter()
        .filter_map(|group| group.reset_time.as_deref())
        .filter_map(|value| Timestamp::parse(value).ok())
        .filter(|value| *value > fetched_at)
        .min();
    Ok((minimum, reset))
}

fn provider_count(
    response: &QuotaStatsResponse,
    select: impl Fn(&ProviderStats) -> Option<i64>,
) -> Result<i64, ClassifiedError> {
    checked_sum(
        response
            .providers
            .values()
            .map(|provider| select(provider).unwrap_or(0)),
    )
}

fn cost_summary(
    cost: Decimal,
    next_reset: Option<Timestamp>,
    fetched_at: Timestamp,
) -> Result<CostSummary, ClassifiedError> {
    let currency = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    CostSummary::new(
        CostAmount::money(ExactDecimal::new(cost), currency),
        ExactDecimal::new(Decimal::ZERO),
        Some("Approx. spend".to_owned()),
        next_reset,
        None,
        None,
        None,
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn token_total(tokens: Option<&Tokens>) -> Result<i64, ClassifiedError> {
    let Some(tokens) = tokens else {
        return Ok(0);
    };
    checked_sum([
        tokens.input_cached.unwrap_or(0),
        tokens.input_uncached.unwrap_or(0),
        tokens.output.unwrap_or(0),
    ])
}

fn checked_sum(values: impl IntoIterator<Item = i64>) -> Result<i64, ClassifiedError> {
    values.into_iter().try_fold(0_i64, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
    })
}

fn zero_window(description: String) -> Result<RateWindow, ClassifiedError> {
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(0.0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        Some(BoundedText::new(description).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn top_provider_windows(
    summaries: &[ProviderSummary],
) -> Result<Vec<NamedRateWindow>, ClassifiedError> {
    summaries
        .iter()
        .take(3)
        .map(|summary| {
            let mut pieces = vec![
                format!("{} req", format_integer(summary.requests)),
                format!("{} tok", format_integer(summary.tokens)),
            ];
            if let Some(cost) = summary.approximate_cost {
                pieces.push(format_usd(cost));
            }
            let window = zero_window(pieces.join(" · "))?;
            let id = BoundedText::new(summary.name.clone())
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            let title = BoundedText::new(summary.name.clone())
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            Ok(NamedRateWindow::new(id, title, window))
        })
        .collect()
}

fn format_usd(value: Decimal) -> String {
    format!("${:.2}", value.round_dp(2))
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}
