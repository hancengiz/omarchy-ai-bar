//! Native `Groq` Prometheus usage-rate adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use serde_json::Value;
use url::Url;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::classify_https_endpoint;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const DEFAULT_API_BASE: &str = "https://api.groq.com/v1";
const API_KEY: &str = "GROQ_API_KEY";
const API_URL: &str = "GROQ_API_URL";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Validated `Groq` endpoint and API credential.
pub struct GroqSettings {
    credential: ApiKeyCredential,
    base_url: Url,
}

impl GroqSettings {
    /// Resolves the standard API key and optional HTTPS endpoint override.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential or endpoint errors.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let base_url = environment
            .get(API_URL)
            .and_then(|value| clean_setting(value))
            .unwrap_or(DEFAULT_API_BASE);
        let mut base_url = if base_url.contains("://") {
            Url::parse(base_url)
        } else {
            Url::parse(&format!("https://{base_url}"))
        }
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        classify_https_endpoint(&base_url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        base_url.set_query(None);
        Ok(Self {
            credential,
            base_url,
        })
    }
}

/// Native `Groq` metrics provider.
pub struct GroqProvider {
    client: FixedApiClient,
}

impl GroqProvider {
    /// Creates the exact-origin production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: GroqSettings) -> Result<Self, ClassifiedError> {
        let class = classify_https_endpoint(&settings.base_url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            settings.base_url,
            class,
            settings.credential,
            transport_config()?,
        )?;
        Self::from_client(client)
    }

    /// Binds a validated client for isolated loopback fixtures.
    #[doc(hidden)]
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Groq {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches five-minute request and token rates.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and response-parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let (requests, input, output, cache) = tokio::try_join!(
            self.query(context, "sum(model_project_id_status_code:requests:rate5m)"),
            self.query(context, "sum(model_project_id:tokens_in:rate5m)"),
            self.query(context, "sum(model_project_id:tokens_out:rate5m)"),
            self.query(context, "sum(model_project_id:prompt_cache_hits:rate5m)"),
        )?;
        normalize(
            context.scope().clone(),
            fetched_at,
            requests,
            input + output,
            cache,
        )
    }

    async fn query(&self, context: &ProviderContext, query: &str) -> Result<f64, ClassifiedError> {
        let mut url = self.client.url("metrics/prometheus/api/v1/query")?;
        url.query_pairs_mut().append_pair("query", query);
        let payload: Value = self.client.get_json(context, url).await?.json()?;
        parse_scalar(&payload)
    }
}

impl ProviderAdapter for GroqProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Groq)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

fn parse_scalar(payload: &Value) -> Result<f64, ClassifiedError> {
    if payload.get("status").and_then(Value::as_str) != Some("success") {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let value = payload
        .pointer("/data/result")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("value"))
        .and_then(Value::as_array)
        .and_then(|values| values.get(1));
    let scalar = match value {
        None => Some(0.0),
        Some(Value::Number(value)) => value.as_f64(),
        Some(Value::String(value)) => value.parse().ok(),
        Some(_) => None,
    }
    .filter(|value| value.is_finite() && *value >= 0.0)
    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(scalar)
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    requests_per_second: f64,
    tokens_per_second: f64,
    cache_per_second: f64,
) -> Result<UsageSample, ClassifiedError> {
    let primary = metric_window(format_rate(requests_per_second * 60.0, "req/min"))?;
    let secondary = metric_window(format_rate(tokens_per_second * 60.0, "tok/min"))?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .secondary(secondary);
    if cache_per_second > 0.0 {
        builder = builder.tertiary(metric_window(format_rate(
            cache_per_second * 60.0,
            "cache/min",
        ))?);
    }
    builder.provenance("groq", "prometheus")?.build()
}

fn metric_window(description: String) -> Result<RateWindow, ClassifiedError> {
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(0.0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(
            WindowDuration::from_provider_minutes(5)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        Some(BoundedText::new(description).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_rate(value: f64, unit: &str) -> String {
    if value >= 100.0 {
        format!("{value:.0} {unit}")
    } else if value >= 10.0 {
        format!("{value:.1} {unit}")
    } else {
        format!("{value:.2} {unit}")
    }
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
