//! `DeepInfra` balance, current-month usage, and spending-limit API adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, Money, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.deepinfra.com";
const KEY_NAMES: [&str; 2] = ["DEEPINFRA_API_KEY", "DEEPINFRA_TOKEN"];
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Native `DeepInfra` provider adapter.
pub struct DeepInfraProvider {
    client: FixedApiClient,
}

impl DeepInfraProvider {
    /// Resolves the baseline key precedence from an environment snapshot.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when neither key is usable.
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
        if client.scope().provider() != ProviderId::DeepInfra {
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
        let checklist_url = self.client.url("payment/checklist")?;
        let mut checklist_url = checklist_url;
        checklist_url
            .query_pairs_mut()
            .append_pair("compute_owed", "true");
        let checklist: ChecklistResponse =
            self.client.get_json(context, checklist_url).await?.json()?;

        let usage_url = self.client.url("payment/usage")?;
        let mut usage_url = usage_url;
        usage_url.query_pairs_mut().append_pair("from", "current");
        let usage: UsageResponse = self.client.get_json(context, usage_url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, &checklist, &usage)
    }
}

impl ProviderAdapter for DeepInfraProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::DeepInfra)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct ChecklistResponse {
    stripe_balance: JsonDecimal,
    recent: JsonDecimal,
    limit: Option<JsonDecimal>,
    #[serde(default)]
    suspended: bool,
    suspend_reason: Option<String>,
}

#[derive(Deserialize)]
struct UsageResponse {
    months: Vec<UsageMonth>,
    #[serde(rename = "initial_month")]
    _initial_month: Option<String>,
}

#[derive(Deserialize)]
struct UsageMonth {
    #[serde(rename = "period")]
    _period: String,
    #[serde(rename = "total_cost")]
    total_cost_cents: JsonDecimal,
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
    checklist: &ChecklistResponse,
    usage: &UsageResponse,
) -> Result<UsageSample, ClassifiedError> {
    let recent = checklist.recent.0.max(Decimal::ZERO);
    let current_month = usage.months.last().map_or(recent, |month| {
        (month.total_cost_cents.0 / Decimal::from(100_u8)).max(Decimal::ZERO)
    });
    let net_balance = checklist
        .stripe_balance
        .0
        .checked_add(recent)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let available = (-net_balance).max(Decimal::ZERO);
    let owed = net_balance.max(Decimal::ZERO);
    let limit = checklist
        .limit
        .map(|value| value.0)
        .filter(|value| *value > Decimal::ZERO);
    let used_percent = if checklist.suspended || owed > Decimal::ZERO || available <= Decimal::ZERO
    {
        100.0
    } else {
        0.0
    };
    let balance_text = if owed > Decimal::ZERO {
        format!("{} owed", format_usd(owed))
    } else {
        format!("{} available", format_usd(available))
    };
    let spending_text = format!("{} spent this month", format_usd(current_month));
    let detail = if checklist.suspended {
        checklist
            .suspend_reason
            .as_deref()
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
            .map_or_else(
                || format!("Suspended · {balance_text} · {spending_text}"),
                |reason| format!("Suspended: {reason} · {balance_text} · {spending_text}"),
            )
    } else {
        format!("{balance_text} · {spending_text}")
    };
    let primary = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(used_percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        Some(BoundedText::new(detail).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let usd = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .balance(Money::new(ExactDecimal::new(available), usd.clone()));
    if let Some(limit) = limit {
        let cost = CostSummary::new(
            CostAmount::money(ExactDecimal::new(recent), usd),
            ExactDecimal::new(limit),
            Some("Billing cycle".to_owned()),
            None,
            None,
            None,
            Some(ExactDecimal::new(available)),
            fetched_at,
            None,
            None,
            CostProvenance::VendorMetered,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        builder = builder.cost(cost);
    }
    builder.provenance("deepinfra", "api")?.build()
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
