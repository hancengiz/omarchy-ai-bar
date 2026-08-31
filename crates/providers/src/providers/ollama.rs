//! `Ollama` Cloud API-key and model-catalog adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsageSample, WindowUsage,
};
use serde::Deserialize;
use url::Url;

use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const DEFAULT_ORIGIN: &str = "https://ollama.com";
const API_KEY: &str = "OLLAMA_API_KEY";
const API_URL: &str = "OLLAMA_API_URL";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MODELS: usize = 10_000;

/// Validated `Ollama` Cloud account settings.
pub struct OllamaSettings {
    credential: ApiKeyCredential,
    endpoint: ConfiguredEndpoint,
}

impl OllamaSettings {
    /// Resolves the standard API key and an optional HTTPS/loopback endpoint.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential or endpoint errors.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let endpoint = environment
            .get(API_URL)
            .and_then(|value| clean_setting(value))
            .unwrap_or(DEFAULT_ORIGIN);
        let endpoint = normalize_endpoint(endpoint)?;
        Ok(Self {
            credential,
            endpoint,
        })
    }

    /// Exact source selected by the configured endpoint.
    #[must_use]
    pub fn source(&self) -> crate::descriptor::ProviderSource {
        if self.endpoint.url().as_str() == "https://ollama.com/" {
            crate::descriptor::ProviderSource::ApiKey
        } else {
            crate::descriptor::ProviderSource::ConfigurableEndpoint
        }
    }
}

/// Native `Ollama` model-catalog provider.
pub struct OllamaProvider {
    client: FixedApiClient,
}

impl OllamaProvider {
    /// Creates the exact-origin production client.
    ///
    /// # Errors
    ///
    /// Returns stable API errors for invalid fixed configuration.
    pub fn new(scope: AccountScope, settings: OllamaSettings) -> Result<Self, ClassifiedError> {
        let source = settings.source();
        let client = FixedApiClient::new_bearer(
            scope,
            settings.endpoint.url().clone(),
            settings.endpoint.class(),
            settings.credential,
            transport_config()?,
        )?
        .with_source(source)?;
        Self::from_client(client)
    }

    /// Binds a validated client for deterministic loopback fixtures.
    #[doc(hidden)]
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Ollama {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Verifies the selected key and reads the bounded cloud model catalog.
    ///
    /// `Ollama` does not expose quota percentages through this API; the sample
    /// therefore preserves an unknown usage lane instead of inventing a quota.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("api/tags")?;
        let payload: TagsEnvelope = self.client.get_json(context, url).await?.json()?;
        if payload.models.len() > MAX_MODELS {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let description = format!("API key verified · {} models", payload.models.len());
        let primary = RateWindow::new(
            WindowUsage::unknown(),
            None,
            None,
            Some(
                BoundedText::new(description)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        UsageSampleBuilder::new(context.scope().clone(), fetched_at)
            .primary(primary)
            .provenance("ollama", "api")?
            .build()
    }
}

impl ProviderAdapter for OllamaProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Ollama)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct TagsEnvelope {
    models: Vec<serde_json::Value>,
}

fn normalize_endpoint(raw: &str) -> Result<ConfiguredEndpoint, ClassifiedError> {
    let normalized = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&normalized).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if url.path() != "/" && !url.path().is_empty() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    ConfiguredEndpoint::parse(&normalized, ConfiguredHttpPolicy::LoopbackHttp)
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
