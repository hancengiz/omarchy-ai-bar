//! Moonshot / Kimi Open Platform regional balance adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{AccountScope, ClassifiedError, ErrorKind, ProviderId, Timestamp, UsageSample};
use serde::Deserialize;
use url::Url;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const KEY_NAMES: [&str; 2] = ["MOONSHOT_API_KEY", "MOONSHOT_KEY"];
const REGION_KEY: &str = "MOONSHOT_REGION";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Closed Moonshot account region and credential-routing boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoonshotRegion {
    /// International account hosted at `api.moonshot.ai`.
    International,
    /// China-mainland account hosted at `api.moonshot.cn`.
    China,
}

impl MoonshotRegion {
    /// Resolves `MOONSHOT_REGION`, defaulting unknown or absent values to the
    /// international region like the pinned baseline.
    #[must_use]
    pub fn from_environment(environment: &BTreeMap<String, String>) -> Self {
        match environment
            .get(REGION_KEY)
            .and_then(|value| clean_setting(value))
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("china") => Self::China,
            _ => Self::International,
        }
    }

    /// Exact public API origin associated with this region.
    #[must_use]
    pub const fn api_origin(self) -> &'static str {
        match self {
            Self::International => "https://api.moonshot.ai",
            Self::China => "https://api.moonshot.cn",
        }
    }
}

/// A virtual key paired with the only Moonshot region it may contact.
pub struct MoonshotSettings {
    region: MoonshotRegion,
    credential: ApiKeyCredential,
}

impl MoonshotSettings {
    /// Resolves an environment key for the environment-selected region.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when no key is usable.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let region = MoonshotRegion::from_environment(environment);
        Self::resolve_for_region(region, environment)
    }

    /// Resolves an environment key only when its selected region matches the
    /// requested destination region.
    ///
    /// This prevents a key selected for one host from crossing to the other
    /// host during account/configuration transitions.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for a region mismatch or no
    /// usable key.
    pub fn resolve_for_region(
        region: MoonshotRegion,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        if MoonshotRegion::from_environment(environment) != region {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        let credential = ApiKeyCredential::resolve(environment, &KEY_NAMES)?;
        Ok(Self { region, credential })
    }

    /// Pairs an already-resolved key with an explicit persisted region.
    #[must_use]
    pub const fn new(region: MoonshotRegion, credential: ApiKeyCredential) -> Self {
        Self { region, credential }
    }
}

impl Debug for MoonshotSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MoonshotSettings")
            .field("region", &self.region)
            .field("credential", &"<redacted>")
            .finish()
    }
}

/// Native Moonshot provider adapter.
pub struct MoonshotProvider {
    client: FixedApiClient,
}

impl MoonshotProvider {
    /// Creates the exact fixed-origin client for the selected account region.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: MoonshotSettings) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(settings.region.api_origin())
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            settings.credential,
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
        if client.scope().provider() != ProviderId::Moonshot {
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
        let url = self.client.url("v1/users/me/balance")?;
        let response: BalanceResponse = self.client.get_json(context, url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, &response)
    }
}

impl ProviderAdapter for MoonshotProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Moonshot)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct BalanceResponse {
    code: i64,
    data: BalanceData,
    #[serde(rename = "scode")]
    _scode: String,
    status: bool,
}

#[derive(Deserialize)]
struct BalanceData {
    #[serde(rename = "available_balance")]
    available: f64,
    #[serde(rename = "voucher_balance")]
    voucher: f64,
    #[serde(rename = "cash_balance")]
    cash: f64,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: &BalanceResponse,
) -> Result<UsageSample, ClassifiedError> {
    if response.code != 0
        || !response.status
        || !response.data.available.is_finite()
        || !response.data.voucher.is_finite()
        || !response.data.cash.is_finite()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let balance = format_usd(response.data.available.abs());
    let balance = if response.data.available < 0.0 {
        format!("-${}", &balance[1..])
    } else {
        balance
    };
    let login_method = if response.data.cash < 0.0 {
        format!(
            "Balance: {balance} · {} in deficit",
            format_usd(response.data.cash.abs())
        )
    } else {
        format!("Balance: {balance}")
    };
    UsageSampleBuilder::new(scope, fetched_at)
        .login_method(Some(login_method))?
        .provenance("moonshot", "api")?
        .build()
}

fn format_usd(value: f64) -> String {
    let rounded = (value * 100.0).round() / 100.0;
    format!("${rounded:.2}")
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
