//! Azure `OpenAI` deployment validation through a bounded chat-completion probe.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::{EndpointClass, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_KEY: &str = "AZURE_OPENAI_API_KEY";
const ENDPOINT: &str = "AZURE_OPENAI_ENDPOINT";
const DEPLOYMENT: &str = "AZURE_OPENAI_DEPLOYMENT_NAME";
const API_VERSION: &str = "AZURE_OPENAI_API_VERSION";
const DEFAULT_API_VERSION: &str = "2024-10-21";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_DEPLOYMENT_BYTES: usize = 160;
const MAX_API_VERSION_BYTES: usize = 64;

/// Validated Azure `OpenAI` endpoint, deployment, version, and secret.
pub struct AzureOpenAiSettings {
    api_key: ApiKeyCredential,
    endpoint: Url,
    endpoint_class: EndpointClass,
    deployment: String,
    api_version: String,
}

impl AzureOpenAiSettings {
    /// Resolves the four baseline environment settings.
    ///
    /// Bare endpoint hosts are normalized to HTTPS. Endpoint paths are
    /// preserved, while queries, fragments, and user information are rejected.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for incomplete configuration
    /// and an API error for invalid endpoint or bounded text values.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let api_key = ApiKeyCredential::resolve(environment, &[API_KEY])?;
        let raw_endpoint = environment
            .get(ENDPOINT)
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let endpoint = normalize_endpoint(raw_endpoint)?;
        let endpoint_class =
            classify_https_endpoint(&endpoint).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let deployment = environment
            .get(DEPLOYMENT)
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let deployment = bounded_setting::<MAX_DEPLOYMENT_BYTES>(deployment)?;
        let api_version = environment
            .get(API_VERSION)
            .and_then(|value| clean_setting(value))
            .unwrap_or(DEFAULT_API_VERSION);
        let api_version = bounded_setting::<MAX_API_VERSION_BYTES>(api_version)?;
        Ok(Self {
            api_key,
            endpoint,
            endpoint_class,
            deployment,
            api_version,
        })
    }
}

impl Debug for AzureOpenAiSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureOpenAiSettings")
            .field("api_key", &"<redacted>")
            .field("endpoint", &"<redacted>")
            .field("endpoint_class", &self.endpoint_class)
            .field("deployment", &"<redacted>")
            .field("api_version", &self.api_version)
            .finish()
    }
}

/// Native Azure `OpenAI` provider adapter.
pub struct AzureOpenAiProvider {
    client: FixedApiClient,
    deployment: String,
    api_version: String,
}

impl AzureOpenAiProvider {
    /// Creates one exact configured-endpoint production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(
        scope: AccountScope,
        settings: AzureOpenAiSettings,
    ) -> Result<Self, ClassifiedError> {
        let AzureOpenAiSettings {
            api_key,
            endpoint,
            endpoint_class,
            deployment,
            api_version,
        } = settings;
        let client = FixedApiClient::new(
            scope,
            endpoint,
            endpoint_class,
            "api-key",
            api_key,
            transport_config()?,
        )?;
        Self::from_client(client, &deployment, &api_version)
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for another provider or invalid deployment
    /// configuration.
    pub fn from_client(
        client: FixedApiClient,
        deployment: &str,
        api_version: &str,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::AzureOpenAi {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let deployment = bounded_setting::<MAX_DEPLOYMENT_BYTES>(
            clean_setting(deployment)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?,
        )?;
        let api_version = clean_setting(api_version).unwrap_or(DEFAULT_API_VERSION);
        let api_version = bounded_setting::<MAX_API_VERSION_BYTES>(api_version)?;
        Ok(Self {
            client,
            deployment,
            api_version,
        })
    }

    /// Performs the baseline's minimal deployment-validation request at a
    /// deterministic sample time.
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
        let url = validation_url(self.client.base_url(), &self.deployment, &self.api_version)?;
        let body = validation_body(&self.deployment, &self.api_version)?;
        let response = self.client.post_json(context, url, body).await?;
        let completion: CompletionResponse = response.json()?;
        normalize(
            context.scope().clone(),
            self.client.base_url(),
            &self.deployment,
            completion.model.as_deref(),
            fetched_at,
        )
    }
}

impl ProviderAdapter for AzureOpenAiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::AzureOpenAi)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for AzureOpenAiProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureOpenAiProvider")
            .field("client", &self.client)
            .field("deployment", &"<redacted>")
            .field("api_version", &self.api_version)
            .finish()
    }
}

#[derive(Deserialize)]
struct CompletionResponse {
    model: Option<String>,
}

fn validation_url(
    endpoint: &Url,
    deployment: &str,
    api_version: &str,
) -> Result<Url, ClassifiedError> {
    let uses_v1 = uses_v1_api(api_version);
    let expected_root = if uses_v1 {
        &["openai", "v1"][..]
    } else {
        &["openai"][..]
    };
    let existing = endpoint
        .path_segments()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?
        .filter(|component| !component.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let shared = (0..=existing.len().min(expected_root.len()))
        .rev()
        .find(|count| {
            existing[existing.len() - count..]
                .iter()
                .map(String::as_str)
                .eq(expected_root[..*count].iter().copied())
        })
        .unwrap_or(0);
    let mut url = endpoint.clone();
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| ClassifiedError::new(ErrorKind::Api))?;
        segments.pop_if_empty();
        for component in &expected_root[shared..] {
            segments.push(component);
        }
        if uses_v1 {
            segments.push("chat").push("completions");
        } else {
            segments
                .push("deployments")
                .push(deployment)
                .push("chat")
                .push("completions");
        }
    }
    if !uses_v1 {
        url.query_pairs_mut()
            .append_pair("api-version", api_version);
    }
    Ok(url)
}

fn validation_body(deployment: &str, api_version: &str) -> Result<Vec<u8>, ClassifiedError> {
    let payload = if uses_v1_api(api_version) {
        json!({
            "messages": [{"role": "user", "content": "ping"}],
            "model": deployment,
            "max_completion_tokens": 64
        })
    } else {
        json!({
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1
        })
    };
    serde_json::to_vec(&payload).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn normalize(
    scope: AccountScope,
    endpoint: &Url,
    deployment: &str,
    model: Option<&str>,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let model = model
        .and_then(clean_setting)
        .map(bounded_setting::<160>)
        .transpose()?;
    let detail = model.as_ref().map_or_else(
        || format!("Deployment: {deployment}"),
        |model| format!("Deployment: {deployment} · Model: {model}"),
    );
    let primary = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(0.0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        Some(BoundedText::new(detail).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let organization = endpoint
        .host_str()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?
        .to_owned();
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .organization(Some(organization))?
        .login_method(Some(format!("Deployment: {deployment}")))?
        .provenance("azure-openai", "deployment-probe")?
        .build()
}

fn normalize_endpoint(raw: &str) -> Result<Url, ClassifiedError> {
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let mut endpoint = Url::parse(&candidate).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    if !endpoint.path().ends_with('/') {
        let path = format!("{}/", endpoint.path());
        endpoint.set_path(&path);
    }
    Ok(endpoint)
}

fn uses_v1_api(api_version: &str) -> bool {
    api_version.eq_ignore_ascii_case("v1")
}

fn bounded_setting<const N: usize>(value: &str) -> Result<String, ClassifiedError> {
    BoundedText::<N>::new(value)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn clean_setting(raw: &str) -> Option<&str> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = &value[1..value.len() - 1];
    }
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(20),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
