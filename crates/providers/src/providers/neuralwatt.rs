//! Neuralwatt subscription-energy quota, prepaid balance, and key allowance.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, NamedRateWindow, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::{EndpointClass, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "NEURALWATT_API_KEY";
const API_URL: &str = "NEURALWATT_API_URL";
const DEFAULT_API_URL: &str = "https://api.neuralwatt.com";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Validated Neuralwatt endpoint and secret.
pub struct NeuralWattSettings {
    credential: ApiKeyCredential,
    endpoint: Url,
    endpoint_class: EndpointClass,
}

impl NeuralWattSettings {
    /// Resolves the baseline environment settings and HTTPS override.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential or API configuration errors.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let endpoint = match environment
            .get(API_URL)
            .and_then(|value| clean_setting(value))
        {
            Some(value) => normalize_https_endpoint(value)?,
            None => {
                Url::parse(DEFAULT_API_URL).map_err(|_| ClassifiedError::new(ErrorKind::Api))?
            }
        };
        let endpoint_class =
            classify_https_endpoint(&endpoint).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self {
            credential,
            endpoint,
            endpoint_class,
        })
    }
}

impl Debug for NeuralWattSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeuralWattSettings")
            .field("credential", &"<redacted>")
            .field("endpoint", &"<redacted>")
            .field("endpoint_class", &self.endpoint_class)
            .finish()
    }
}

/// Native Neuralwatt provider adapter.
pub struct NeuralWattProvider {
    client: FixedApiClient,
}

impl NeuralWattProvider {
    /// Creates one exact configured-endpoint production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: NeuralWattSettings) -> Result<Self, ClassifiedError> {
        let NeuralWattSettings {
            credential,
            endpoint,
            endpoint_class,
        } = settings;
        let client = FixedApiClient::new_bearer(
            scope,
            endpoint,
            endpoint_class,
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
        if client.scope().provider() != ProviderId::Neuralwatt {
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
        let url = quota_url(self.client.base_url())?;
        let response: QuotaResponse = self.client.get_json(context, url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, &response)
    }
}

impl ProviderAdapter for NeuralWattProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Neuralwatt)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct QuotaResponse {
    #[serde(rename = "snapshot_at")]
    _snapshot_at: Option<String>,
    balance: Option<Balance>,
    usage: Option<Usage>,
    limits: Option<Limits>,
    subscription: Option<Subscription>,
    key: Option<ApiKey>,
}

#[derive(Deserialize)]
struct Balance {
    credits_remaining_usd: Option<JsonDecimal>,
    total_credits_usd: Option<JsonDecimal>,
    credits_used_usd: Option<JsonDecimal>,
    accounting_method: Option<String>,
}

#[derive(Deserialize)]
struct Usage {
    #[serde(rename = "lifetime")]
    _lifetime: Option<UsagePeriod>,
    current_month: Option<UsagePeriod>,
}

#[derive(Deserialize)]
struct UsagePeriod {
    cost_usd: Option<JsonDecimal>,
    #[serde(rename = "requests")]
    _requests: Option<i64>,
    #[serde(rename = "tokens")]
    _tokens: Option<i64>,
    energy_kwh: Option<JsonDecimal>,
}

#[derive(Deserialize)]
struct Limits {
    #[serde(rename = "overage_limit_usd")]
    _overage_limit_usd: Option<JsonDecimal>,
    rate_limit_tier: Option<String>,
}

#[derive(Deserialize)]
struct Subscription {
    plan: Option<String>,
    #[serde(rename = "status")]
    _status: Option<String>,
    #[serde(rename = "billing_interval")]
    _billing_interval: Option<String>,
    current_period_start: Option<Timestamp>,
    current_period_end: Option<Timestamp>,
    auto_renew: Option<bool>,
    kwh_included: Option<JsonDecimal>,
    kwh_used: Option<JsonDecimal>,
    kwh_remaining: Option<JsonDecimal>,
    #[serde(rename = "in_overage")]
    _in_overage: Option<bool>,
}

#[derive(Deserialize)]
struct ApiKey {
    #[serde(rename = "name")]
    _name: Option<String>,
    allowance: Option<KeyAllowance>,
}

#[derive(Deserialize)]
struct KeyAllowance {
    limit_usd: Option<JsonDecimal>,
    period: Option<String>,
    spent_usd: Option<JsonDecimal>,
    #[serde(rename = "remaining_usd")]
    _remaining_usd: Option<JsonDecimal>,
    #[serde(default)]
    blocked: bool,
}

#[derive(Clone, Copy)]
struct JsonDecimal(Decimal);

impl<'de> Deserialize<'de> for JsonDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        let raw = number.to_string();
        Decimal::from_scientific(&raw)
            .or_else(|_| raw.parse())
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid decimal"))
    }
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: &QuotaResponse,
) -> Result<UsageSample, ClassifiedError> {
    let balance = response
        .balance
        .as_ref()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if non_negative(balance.credits_remaining_usd).is_none()
        && non_negative(balance.credits_used_usd).is_none()
        && positive(balance.total_credits_usd).is_none()
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    let primary = subscription_window(response.subscription.as_ref())?;
    if let Some(primary) = primary.clone() {
        builder = builder.primary(primary);
    }
    if let Some(allowance) = response.key.as_ref().and_then(|key| key.allowance.as_ref())
        && let Some(extra) = allowance_window(allowance)?
    {
        builder = builder.extra_windows(vec![extra]);
    }

    if let Some(remaining) = effective_remaining(balance) {
        let currency =
            CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let cost = CostSummary::new(
            CostAmount::money(ExactDecimal::new(remaining), currency),
            ExactDecimal::new(Decimal::ZERO),
            Some("Neuralwatt prepaid balance".to_owned()),
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
        builder = builder.cost(cost);
    }

    let login_method = response
        .subscription
        .as_ref()
        .and_then(|subscription| display_plan(subscription.plan.as_deref()))
        .or_else(|| display_method(balance.accounting_method.as_deref()));
    let renews_at = response.subscription.as_ref().and_then(|subscription| {
        (subscription.auto_renew != Some(false))
            .then_some(primary.as_ref().and_then(RateWindow::resets_at))
            .flatten()
    });

    // These values are intentionally decoded even though the pinned baseline
    // does not expose them as resettable lanes. Keeping the reads explicit
    // documents that omission and preserves strict schema validation.
    let _current_month = response.usage.as_ref().and_then(|usage| {
        usage
            .current_month
            .as_ref()
            .map(|period| (period.cost_usd, period.energy_kwh))
    });
    let _rate_limit_tier = response
        .limits
        .as_ref()
        .and_then(|limits| limits.rate_limit_tier.as_deref());

    builder
        .login_method(login_method)?
        .subscription_renews_at(renews_at)
        .provenance("neuralwatt", "api")?
        .build()
}

fn subscription_window(
    subscription: Option<&Subscription>,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let Some(subscription) = subscription else {
        return Ok(None);
    };
    let Some(total) = effective_subscription_total(subscription) else {
        return Ok(None);
    };
    let Some(used) = effective_subscription_used(subscription, total) else {
        return Ok(None);
    };
    let percent = percentage(used, total)?;
    let duration = match (
        subscription.current_period_start,
        subscription.current_period_end,
    ) {
        (Some(start), Some(end)) if end > start => {
            let seconds = end
                .unix_timestamp()
                .checked_sub(start.unix_timestamp())
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            let minutes = (seconds / 60).max(1);
            Some(
                WindowDuration::from_provider_minutes(minutes)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            )
        }
        _ => None,
    };
    let description = BoundedText::new(format!("{} / {} kWh", format_kwh(used), format_kwh(total)))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        duration,
        subscription.current_period_end,
        Some(description),
        None,
        false,
    )
    .map(Some)
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn allowance_window(allowance: &KeyAllowance) -> Result<Option<NamedRateWindow>, ClassifiedError> {
    let percent = if allowance.blocked {
        Some(100.0)
    } else {
        match (
            non_negative(allowance.spent_usd),
            positive(allowance.limit_usd),
        ) {
            (Some(spent), Some(limit)) => Some(percentage(spent, limit)?),
            _ => None,
        }
    };
    let Some(percent) = percent else {
        return Ok(None);
    };
    let period = allowance
        .period
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("allowance");
    let title = format!("Key {}", title_case(period));
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
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(Some(NamedRateWindow::new(
        BoundedText::new("key-allowance").map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
        BoundedText::new(title).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        window,
    )))
}

fn effective_remaining(balance: &Balance) -> Option<Decimal> {
    non_negative(balance.credits_remaining_usd).or_else(|| {
        Some(
            effective_total(balance)?
                .checked_sub(non_negative(balance.credits_used_usd)?)?
                .max(Decimal::ZERO),
        )
    })
}

fn effective_total(balance: &Balance) -> Option<Decimal> {
    positive(balance.total_credits_usd).or_else(|| {
        let total = non_negative(balance.credits_remaining_usd)?
            .checked_add(non_negative(balance.credits_used_usd)?)?;
        (total > Decimal::ZERO).then_some(total)
    })
}

fn effective_subscription_total(subscription: &Subscription) -> Option<Decimal> {
    positive(subscription.kwh_included).or_else(|| {
        let total = non_negative(subscription.kwh_used)?
            .checked_add(non_negative(subscription.kwh_remaining)?)?;
        (total > Decimal::ZERO).then_some(total)
    })
}

fn effective_subscription_used(subscription: &Subscription, total: Decimal) -> Option<Decimal> {
    non_negative(subscription.kwh_used).or_else(|| {
        Some(
            total
                .checked_sub(non_negative(subscription.kwh_remaining)?)?
                .max(Decimal::ZERO),
        )
    })
}

fn percentage(used: Decimal, total: Decimal) -> Result<f64, ClassifiedError> {
    used.checked_mul(Decimal::from(100_u8))
        .and_then(|value| value.checked_div(total))
        .and_then(|value| value.to_f64())
        .map(|value| value.clamp(0.0, 100.0))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn non_negative(value: Option<JsonDecimal>) -> Option<Decimal> {
    value
        .map(|value| value.0)
        .filter(|value| *value >= Decimal::ZERO)
}

fn positive(value: Option<JsonDecimal>) -> Option<Decimal> {
    value
        .map(|value| value.0)
        .filter(|value| *value > Decimal::ZERO)
}

fn display_plan(plan: Option<&str>) -> Option<String> {
    let plan = plan.map(str::trim).filter(|value| !value.is_empty())?;
    Some(format!("{} plan", title_case(&plan.replace('_', " "))))
}

fn display_method(method: Option<&str>) -> Option<String> {
    let method = method.filter(|value| !value.is_empty())?;
    Some(title_case(method))
}

fn title_case(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            let mut characters = word.chars();
            let Some(first) = characters.next() else {
                return String::new();
            };
            first
                .to_uppercase()
                .chain(characters.flat_map(char::to_lowercase))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_kwh(value: Decimal) -> String {
    if value.fract().is_zero() {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
    }
}

fn quota_url(base: &Url) -> Result<Url, ClassifiedError> {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    let last_is_v1 = url
        .path_segments()
        .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
        .is_some_and(|segment| segment == "v1");
    let mut path = url
        .path_segments_mut()
        .map_err(|()| ClassifiedError::new(ErrorKind::Api))?;
    path.pop_if_empty();
    if last_is_v1 {
        path.push("quota");
    } else {
        path.push("v1");
        path.push("quota");
    }
    drop(path);
    Ok(url)
}

fn normalize_https_endpoint(raw: &str) -> Result<Url, ClassifiedError> {
    let candidate = if has_explicit_scheme(raw) {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(url)
}

fn has_explicit_scheme(raw: &str) -> bool {
    raw.find(':').is_some_and(|colon| {
        let scheme = &raw[..colon];
        !scheme.is_empty()
            && scheme.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic()
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                }
            })
    })
}

fn clean_setting(raw: &str) -> Option<&str> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = &value[1..value.len() - 1];
    }
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}
