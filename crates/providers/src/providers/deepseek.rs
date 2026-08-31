//! `DeepSeek` API wallet-balance adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CurrencyCode, ErrorKind, ExactDecimal, Money,
    ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowUsage,
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

const API_ORIGIN: &str = "https://api.deepseek.com";
const KEY_NAMES: [&str; 1] = ["DEEPSEEK_API_KEY"];
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Native `DeepSeek` balance adapter.
pub struct DeepSeekProvider {
    client: FixedApiClient,
}

impl DeepSeekProvider {
    /// Resolves the standard `DeepSeek` API key.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for an absent or unsafe key.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &KEY_NAMES)
    }

    /// Creates the fixed-origin production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed transport configuration.
    pub fn new(scope: AccountScope, credential: ApiKeyCredential) -> Result<Self, ClassifiedError> {
        let base = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base,
            EndpointClass::PublicHttps,
            credential,
            transport_config()?,
        )?;
        Self::from_client(client)
    }

    /// Binds a validated client for deterministic loopback tests.
    #[doc(hidden)]
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::DeepSeek {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches the authoritative wallet balance.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("user/balance")?;
        let payload: BalanceEnvelope = self.client.get_json(context, url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, payload)
    }
}

impl ProviderAdapter for DeepSeekProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::DeepSeek)
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
    is_available: bool,
    balance_infos: Vec<BalanceInfo>,
}

#[derive(Deserialize)]
struct BalanceInfo {
    currency: String,
    total_balance: String,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: BalanceEnvelope,
) -> Result<UsageSample, ClassifiedError> {
    let selected = payload
        .balance_infos
        .into_iter()
        .next()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let balance = selected
        .total_balance
        .parse::<Decimal>()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if balance.is_sign_negative() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let currency = CurrencyCode::new(selected.currency.to_ascii_uppercase())
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let status = if payload.is_available {
        format!("{} {} available", currency.as_str(), balance.round_dp(2))
    } else {
        "API balance unavailable".to_owned()
    };
    let primary = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(if payload.is_available && balance > Decimal::ZERO {
                0.0
            } else {
                100.0
            })
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        Some(BoundedText::new(status).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .balance(Money::new(ExactDecimal::new(balance), currency))
        .provenance("deepseek", "api")?
        .build()
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(20),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}
