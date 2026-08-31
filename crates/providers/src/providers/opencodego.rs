//! `OpenCode Go` public usage API adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use serde_json::{Map, Value};
use time::Duration as TimeDuration;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://opencode.ai";
const API_KEY_ENV: &str = "OPENCODE_API_KEY";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Native `OpenCode Go` API-key provider.
pub struct OpenCodeGoProvider {
    client: FixedApiClient,
}

impl OpenCodeGoProvider {
    /// Resolves the public `OpenCode Go` API key.
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
        if client.scope().provider() != ProviderId::OpenCodeGo {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches the rolling, weekly, and optional monthly usage windows.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("zen/go/v1/usage")?;
        let payload: Value = self.client.get_json(context, url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, &payload)
    }
}

impl ProviderAdapter for OpenCodeGoProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::OpenCodeGo)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: &Value,
) -> Result<UsageSample, ClassifiedError> {
    let usage = payload
        .get("usage")
        .and_then(Value::as_object)
        .ok_or_else(parse_error)?;
    let rolling = required_window(usage, "rolling", fetched_at, 5 * 60)?;
    let weekly = optional_window(usage, "weekly", fetched_at, 7 * 24 * 60)?;
    let monthly = optional_window(usage, "monthly", fetched_at, 30 * 24 * 60)?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at).primary(rolling);
    if let Some(weekly) = weekly {
        builder = builder.secondary(weekly);
    }
    if let Some(monthly) = monthly {
        builder = builder.tertiary(monthly);
    }
    builder
        .login_method(Some("API key".to_owned()))?
        .provenance("opencodego", "api")?
        .build()
}

fn required_window(
    usage: &Map<String, Value>,
    name: &str,
    fetched_at: Timestamp,
    minutes: i64,
) -> Result<RateWindow, ClassifiedError> {
    let value = usage.get(name).ok_or_else(parse_error)?;
    parse_window(value, fetched_at, minutes)
}

fn optional_window(
    usage: &Map<String, Value>,
    name: &str,
    fetched_at: Timestamp,
    minutes: i64,
) -> Result<Option<RateWindow>, ClassifiedError> {
    usage
        .get(name)
        .map(|value| parse_window(value, fetched_at, minutes))
        .transpose()
}

fn parse_window(
    value: &Value,
    fetched_at: Timestamp,
    minutes: i64,
) -> Result<RateWindow, ClassifiedError> {
    let object = value.as_object().ok_or_else(parse_error)?;
    let percent = ["percent", "usagePercent", "usedPercent", "percentUsed"]
        .iter()
        .find_map(|key| object.get(*key).and_then(number_value))
        .filter(|value| value.is_finite())
        .ok_or_else(parse_error)?
        .clamp(0.0, 100.0);
    let resets_at = ["resetsAt", "resetAt", "resets_at", "reset_at"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(Timestamp::parse)
        .transpose()
        .map_err(|_| parse_error())?
        .or_else(|| {
            ["resetInSec", "resetInSeconds", "reset_in_sec"]
                .iter()
                .find_map(|key| object.get(*key).and_then(integer_value))
                .filter(|seconds| *seconds >= 0)
                .and_then(|seconds| {
                    fetched_at
                        .as_offset_date_time()
                        .checked_add(TimeDuration::seconds(seconds))
                        .and_then(|value| Timestamp::new(value).ok())
                })
        });
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
        Some(WindowDuration::from_provider_minutes(minutes).map_err(|_| parse_error())?),
        resets_at,
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn number_value(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str()?.parse::<f64>().ok())
}

fn integer_value(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str()?.parse::<i64>().ok())
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
