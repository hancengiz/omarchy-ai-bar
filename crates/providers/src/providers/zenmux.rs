//! `ZenMux` Management API subscription quota and optional PAYG adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{HttpResponse, TransportConfig};

const API_ORIGIN: &str = "https://zenmux.ai/api/v1/management/";
const KEY_NAMES: [&str; 1] = ["ZENMUX_MANAGEMENT_API_KEY"];
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Native `ZenMux` Management API adapter.
pub struct ZenMuxProvider {
    client: FixedApiClient,
}

impl ZenMuxProvider {
    /// Resolves the Management API key from the pinned environment name.
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
        if client.scope().provider() != ProviderId::ZenMux {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches authoritative subscription quota and best-effort PAYG balance.
    ///
    /// Authentication failure from either endpoint remains authoritative;
    /// other PAYG failures do not discard valid subscription quota.
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
        let subscription_url = self.client.url("subscription/detail")?;
        let subscription_response = self.authenticated_get(context, subscription_url).await?;
        let subscription: SubscriptionEnvelope = subscription_response.json()?;
        let parsed = ParsedSubscription::parse(subscription)?;

        let balance_url = self.client.url("payg/balance")?;
        let balance = match self.authenticated_get(context, balance_url).await {
            Ok(response) => response
                .json::<BalanceEnvelope>()
                .ok()
                .and_then(|response| parse_balance(&response)),
            Err(error) if error.kind() == ErrorKind::AuthenticationExpired => return Err(error),
            Err(_) => None,
        };
        normalize(context.scope().clone(), fetched_at, &parsed, balance)
    }

    async fn authenticated_get(
        &self,
        context: &ProviderContext,
        url: Url,
    ) -> Result<HttpResponse, ClassifiedError> {
        self.client.get_json(context, url).await.map_err(|error| {
            if error.kind() == ErrorKind::PermissionDenied {
                ClassifiedError::new(ErrorKind::AuthenticationExpired)
            } else {
                error
            }
        })
    }
}

impl ProviderAdapter for ZenMuxProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::ZenMux)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct SubscriptionEnvelope {
    success: bool,
    data: SubscriptionData,
}

#[derive(Deserialize)]
struct SubscriptionData {
    plan: Plan,
    account_status: String,
    quota_5_hour: Quota,
    quota_7_day: Quota,
}

#[derive(Deserialize)]
struct Plan {
    tier: String,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct Quota {
    usage_percentage: JsonDecimal,
    resets_at: Option<String>,
    max_flows: JsonDecimal,
    used_flows: JsonDecimal,
    #[serde(rename = "remaining_flows")]
    _remaining_flows: JsonDecimal,
}

#[derive(Deserialize)]
struct BalanceEnvelope {
    success: bool,
    data: BalanceData,
}

#[derive(Deserialize)]
struct BalanceData {
    currency: String,
    total_credits: JsonDecimal,
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

struct ParsedSubscription {
    plan_tier: String,
    expires_at: Option<Timestamp>,
    account_status: String,
    five_hour: ParsedQuota,
    weekly: ParsedQuota,
}

struct ParsedQuota {
    usage_fraction: Decimal,
    resets_at: Option<Timestamp>,
    max_flows: Decimal,
    used_flows: Decimal,
}

impl ParsedSubscription {
    fn parse(response: SubscriptionEnvelope) -> Result<Self, ClassifiedError> {
        if !response.success {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(Self {
            plan_tier: response.data.plan.tier,
            expires_at: parse_optional_date(response.data.plan.expires_at.as_deref()),
            account_status: response.data.account_status,
            five_hour: ParsedQuota::from(response.data.quota_5_hour),
            weekly: ParsedQuota::from(response.data.quota_7_day),
        })
    }
}

impl From<Quota> for ParsedQuota {
    fn from(quota: Quota) -> Self {
        Self {
            usage_fraction: quota.usage_percentage.0,
            resets_at: parse_optional_date(quota.resets_at.as_deref()),
            max_flows: quota.max_flows.0,
            used_flows: quota.used_flows.0,
        }
    }
}

fn parse_balance(response: &BalanceEnvelope) -> Option<Decimal> {
    (response.success && response.data.currency.trim().eq_ignore_ascii_case("usd"))
        .then_some(response.data.total_credits.0)
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    subscription: &ParsedSubscription,
    balance: Option<Decimal>,
) -> Result<UsageSample, ClassifiedError> {
    let primary = quota_window(&subscription.five_hour, 300)?;
    let secondary = quota_window(&subscription.weekly, 10080)?;
    let plan =
        clean_optional(&subscription.plan_tier).map(|tier| format!("{} plan", title_case(&tier)));
    let status = clean_optional(&subscription.account_status);
    let login_method = if status
        .as_deref()
        .is_none_or(|status| status.eq_ignore_ascii_case("healthy"))
    {
        plan
    } else {
        [plan, status.map(|status| title_case(&status))]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ")
            .into()
    };

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .secondary(secondary)
        .subscription_expires_at(subscription.expires_at);
    if let Some(balance) = balance {
        builder = builder.cost(balance_cost(balance, fetched_at)?);
    }
    builder
        .login_method(login_method)?
        .provenance("zenmux", "api")?
        .build()
}

fn quota_window(quota: &ParsedQuota, minutes: i64) -> Result<RateWindow, ClassifiedError> {
    let percent = quota
        .usage_fraction
        .checked_mul(Decimal::from(100_u8))
        .and_then(|value| value.to_f64())
        .map(|value| value.clamp(0.0, 100.0))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let description = format!(
        "{} / {} flows",
        format_flows(quota.used_flows),
        format_flows(quota.max_flows)
    );
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(
            WindowDuration::from_provider_minutes(minutes)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
        ),
        quota.resets_at,
        Some(BoundedText::new(description).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn balance_cost(balance: Decimal, fetched_at: Timestamp) -> Result<CostSummary, ClassifiedError> {
    let currency = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    CostSummary::new(
        CostAmount::money(ExactDecimal::new(balance), currency),
        ExactDecimal::new(Decimal::ZERO),
        Some("ZenMux PAYG balance".to_owned()),
        None,
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

fn parse_optional_date(raw: Option<&str>) -> Option<Timestamp> {
    raw.and_then(|value| Timestamp::parse(value).ok())
}

fn clean_optional(raw: &str) -> Option<String> {
    let value = raw.trim();
    (!value.is_empty()).then(|| value.to_owned())
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

fn format_flows(value: Decimal) -> String {
    if value.fract().is_zero() {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
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
