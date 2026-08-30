//! Venice DIEM and USD billing-balance adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use serde_json::{Map, Value};
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.venice.ai";
const KEY_NAMES: [&str; 2] = ["VENICE_API_KEY", "VENICE_KEY"];
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;

/// Native Venice provider adapter.
pub struct VeniceProvider {
    client: FixedApiClient,
}

impl VeniceProvider {
    /// Resolves the pinned environment-key precedence.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when neither key is usable.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &KEY_NAMES)
    }

    /// Creates the production fixed-origin Venice client.
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
        if client.scope().provider() != ProviderId::Venice {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches and normalizes one deterministic sample timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable classified scope, transport, or parse errors without
    /// exposing credentials or response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("api/v1/billing/balance")?;
        let response = self
            .client
            .get_json_with_status_map(context, url, |_| Some(ErrorKind::Api))
            .await?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let payload: Value = response.json()?;
        let response = parse_response(&payload)?;
        normalize(context.scope().clone(), fetched_at, &response)
    }
}

impl ProviderAdapter for VeniceProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Venice)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

struct VeniceResponse {
    can_consume: bool,
    currency: Option<String>,
    diem: Option<f64>,
    usd: Option<f64>,
    allocation: Option<f64>,
}

fn parse_response(payload: &Value) -> Result<VeniceResponse, ClassifiedError> {
    let payload = payload
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let can_consume = payload
        .get("canConsume")
        .and_then(Value::as_bool)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let balances = payload
        .get("balances")
        .and_then(Value::as_object)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let currency = optional_currency(payload)?;
    let diem = optional_number(balances.get("diem"))?;
    let usd = optional_number(balances.get("usd"))?;
    let allocation = optional_number(payload.get("diemEpochAllocation"))?;
    Ok(VeniceResponse {
        can_consume,
        currency,
        diem,
        usd,
        allocation,
    })
}

fn optional_currency(payload: &Map<String, Value>) -> Result<Option<String>, ClassifiedError> {
    match payload.get("consumptionCurrency") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.to_uppercase())),
        Some(_) => Err(ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn optional_number(value: Option<&Value>) -> Result<Option<f64>, ClassifiedError> {
    let number = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(value)) if value.is_empty() => return Ok(None),
        Some(Value::Number(value)) => value.as_f64(),
        Some(Value::String(value)) => parse_javascript_number(value),
        Some(_) => None,
    }
    .filter(|number| number.is_finite())
    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(Some(number))
}

fn parse_javascript_number(value: &str) -> Option<f64> {
    let value = value.trim();
    if value.is_empty() {
        return Some(0.0);
    }
    let (radix, digits) = if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (16_u32, digits)
    } else if let Some(digits) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        (8_u32, digits)
    } else if let Some(digits) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        (2_u32, digits)
    } else {
        return value.parse().ok();
    };
    if digits.is_empty() {
        return None;
    }
    digits.chars().try_fold(0.0_f64, |number, digit| {
        digit
            .to_digit(radix)
            .map(|digit| number.mul_add(f64::from(radix), f64::from(digit)))
            .filter(|number| number.is_finite())
    })
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: &VeniceResponse,
) -> Result<UsageSample, ClassifiedError> {
    let (used_percent, description) = match (
        response.can_consume,
        response.currency.as_deref(),
        response.diem,
        response.usd,
        response.allocation,
    ) {
        (false, _, _, _, _) => (100.0, "Balance unavailable for API calls".to_owned()),
        (true, Some("USD"), _, Some(usd), _) if usd > 0.0 => {
            (0.0, format!("${} USD remaining", fixed_two(usd)))
        }
        (true, currency, Some(diem), _, Some(allocation))
            if currency != Some("USD") && allocation > 0.0 =>
        {
            (
                percentage(allocation - diem, allocation),
                format!(
                    "DIEM {} / {} epoch allocation",
                    fixed_two(diem),
                    fixed_two(allocation)
                ),
            )
        }
        (true, _, Some(diem), _, _) if diem > 0.0 => {
            (0.0, format!("DIEM {} remaining", fixed_two(diem)))
        }
        (true, _, _, Some(usd), _) if usd > 0.0 => {
            (0.0, format!("${} USD remaining", fixed_two(usd)))
        }
        (true, _, _, _, _) => (100.0, "No Venice API balance available".to_owned()),
    };

    let primary = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(used_percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        Some(BoundedText::new(description).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .provenance("venice", "api")?
        .build()
}

fn percentage(used: f64, limit: f64) -> f64 {
    if !used.is_finite() || !limit.is_finite() || limit <= 0.0 {
        return 100.0;
    }
    (used / limit * 100.0).clamp(0.0, 100.0)
}

fn fixed_two(value: f64) -> String {
    if value == 0.0 {
        "0.00".to_owned()
    } else {
        format!("{value:.2}")
    }
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(20),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
