//! `ClinePass` 5-hour, weekly, and monthly usage-limit adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://api.cline.bot";
const KEY_NAMES: [&str; 2] = ["CLINE_API_KEY", "CLINEPASS_API_KEY"];
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_LIMITS: usize = 1024;

/// Native `ClinePass` provider adapter.
pub struct ClinePassProvider {
    client: FixedApiClient,
}

impl ClinePassProvider {
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
        if client.scope().provider() != ProviderId::ClinePass {
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
        let url = self.client.url("api/v1/users/me/plan/usage-limits")?;
        let response = self.client.get_json(context, url).await.map_err(|error| {
            if error.kind() == ErrorKind::PermissionDenied {
                ClassifiedError::new(ErrorKind::AuthenticationExpired)
            } else {
                error
            }
        })?;
        let payload: UsageLimitsResponse = response.json()?;
        normalize(context.scope().clone(), fetched_at, &payload)
    }
}

impl ProviderAdapter for ClinePassProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::ClinePass)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct UsageLimitsResponse {
    success: bool,
    data: UsageLimitsData,
}

#[derive(Deserialize)]
struct UsageLimitsData {
    limits: Vec<Value>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: &UsageLimitsResponse,
) -> Result<UsageSample, ClassifiedError> {
    if !payload.success || payload.data.limits.len() > MAX_LIMITS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let mut primary = None;
    let mut secondary = None;
    let mut tertiary = None;
    for raw in &payload.data.limits {
        let object = raw
            .as_object()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let (minutes, destination) = match kind {
            "five_hour" => (5 * 60, &mut primary),
            "weekly" => (7 * 24 * 60, &mut secondary),
            "monthly" => (30 * 24 * 60, &mut tertiary),
            _ => continue,
        };
        let percent = object
            .get("percentUsed")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .clamp(0.0, 100.0);
        let resets_at = match object.get("resetsAt") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => {
                Some(Timestamp::parse(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?)
            }
            Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
        };
        *destination = Some(
            RateWindow::new(
                WindowUsage::known(
                    UsagePercent::new(percent)
                        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                ),
                Some(
                    WindowDuration::from_provider_minutes(minutes)
                        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                ),
                resets_at,
                None,
                None,
                false,
            )
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        );
    }

    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    if let Some(tertiary) = tertiary {
        builder = builder.tertiary(tertiary);
    }
    builder
        .login_method(Some("API key".to_owned()))?
        .provenance("clinepass", "api")?
        .build()
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
