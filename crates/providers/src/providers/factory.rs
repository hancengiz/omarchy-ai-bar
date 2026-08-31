//! `Factory` (Droid) API-key usage adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.factory.ai";
const API_KEY_ENV: &str = "FACTORY_API_KEY";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Native Factory API-key provider.
pub struct FactoryProvider {
    client: FixedApiClient,
}

impl FactoryProvider {
    /// Resolves `FACTORY_API_KEY`.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when the key is absent.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &[API_KEY_ENV])
    }

    /// Creates the fixed-origin production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid transport configuration.
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
        if client.scope().provider() != ProviderId::Factory {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches authenticated account metadata and subscription usage.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let auth_url = self.client.url("api/app/auth/me")?;
        let auth: AuthResponse = self.client.get_json(context, auth_url).await?.json()?;
        let mut usage_url = self.client.url("api/organization/subscription/usage")?;
        {
            let mut query = usage_url.query_pairs_mut();
            query.append_pair("useCache", "true");
            if let Some(user_id) = auth
                .user_profile
                .as_ref()
                .and_then(|profile| profile.id.as_deref())
            {
                query.append_pair("userId", user_id);
            }
        }
        let usage: UsageResponse = self.client.get_json(context, usage_url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, &auth, usage)
    }
}

impl ProviderAdapter for FactoryProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Factory)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    organization: Option<Organization>,
    user_profile: Option<UserProfile>,
}

#[derive(Deserialize)]
struct UserProfile {
    id: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct Organization {
    name: Option<String>,
    subscription: Option<Subscription>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    factory_tier: Option<String>,
    orb_subscription: Option<OrbSubscription>,
}

#[derive(Deserialize)]
struct OrbSubscription {
    plan: Option<Plan>,
}

#[derive(Deserialize)]
struct Plan {
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageResponse {
    usage: Option<UsageData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageData {
    end_date: Option<i64>,
    standard: Option<TokenUsage>,
    premium: Option<TokenUsage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenUsage {
    user_tokens: Option<i64>,
    total_allowance: Option<i64>,
    used_ratio: Option<f64>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    auth: &AuthResponse,
    usage_response: UsageResponse,
) -> Result<UsageSample, ClassifiedError> {
    let usage = usage_response.usage.ok_or_else(parse_error)?;
    let resets_at = usage.end_date.and_then(timestamp_millis);
    let standard = usage
        .standard
        .as_ref()
        .map(|value| token_window(value, resets_at))
        .transpose()?;
    let premium = usage
        .premium
        .as_ref()
        .map(|value| token_window(value, resets_at))
        .transpose()?;
    if standard.is_none() && premium.is_none() {
        return Err(parse_error());
    }

    let user = auth.user_profile.as_ref();
    let organization = auth.organization.as_ref();
    let subscription = organization.and_then(|value| value.subscription.as_ref());
    let tier = subscription.and_then(|value| value.factory_tier.as_deref());
    let plan = subscription
        .and_then(|value| value.orb_subscription.as_ref())
        .and_then(|value| value.plan.as_ref())
        .and_then(|value| value.name.as_deref());
    let login = [tier, plan]
        .into_iter()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" - ");
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .provider_account_id(user.and_then(|value| value.id.clone()))?
        .email(user.and_then(|value| value.email.clone()))?
        .organization(organization.and_then(|value| value.name.clone()))?
        .login_method((!login.is_empty()).then_some(login))?;
    if let Some(standard) = standard {
        builder = builder.primary(standard);
    }
    if let Some(premium) = premium {
        builder = builder.secondary(premium);
    }
    builder.provenance("factory", "api-key")?.build()
}

fn token_window(
    usage: &TokenUsage,
    resets_at: Option<Timestamp>,
) -> Result<RateWindow, ClassifiedError> {
    let used = usage.user_tokens.unwrap_or(0).max(0);
    let allowance = usage.total_allowance.unwrap_or(0);
    let percent = usage
        .used_ratio
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|value| if value <= 1.001 { value * 100.0 } else { value })
        .or_else(|| ratio_percent(used, allowance))
        .ok_or_else(parse_error)?
        .clamp(0.0, 100.0);
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
        None,
        resets_at,
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn ratio_percent(used: i64, allowance: i64) -> Option<f64> {
    if allowance <= 0 {
        return None;
    }
    (Decimal::from(used) * Decimal::ONE_HUNDRED / Decimal::from(allowance)).to_f64()
}

fn timestamp_millis(value: i64) -> Option<Timestamp> {
    let seconds = if value.unsigned_abs() > 1_000_000_000_000_u64 {
        value / 1_000
    } else {
        value
    };
    Timestamp::from_unix_timestamp(seconds).ok()
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
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
