//! `Antigravity` remote quota adapter for an explicit Google OAuth token.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://cloudcode-pa.googleapis.com";
const TOKEN_ENV: &str = "ANTIGRAVITY_OAUTH_ACCESS_TOKEN";
const PROJECT_ENV: &str = "ANTIGRAVITY_PROJECT_ID";
const EMAIL_ENV: &str = "ANTIGRAVITY_ACCOUNT_EMAIL";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Explicit remote Antigravity OAuth settings.
pub struct AntigravitySettings {
    credential: ApiKeyCredential,
    project_id: Option<String>,
    email: Option<String>,
}

impl AntigravitySettings {
    /// Resolves the remote OAuth token and optional public account labels.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential or configuration errors.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        Ok(Self {
            credential: ApiKeyCredential::resolve(environment, &[TOKEN_ENV])?,
            project_id: optional_value(environment, PROJECT_ENV)?,
            email: optional_value(environment, EMAIL_ENV)?,
        })
    }
}

impl std::fmt::Debug for AntigravitySettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AntigravitySettings")
            .field("credential", &"<redacted>")
            .field(
                "project_id",
                &self.project_id.as_ref().map(|_| "<redacted>"),
            )
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Native `Antigravity` remote quota provider.
pub struct AntigravityProvider {
    client: FixedApiClient,
    project_id: Option<String>,
    email: Option<String>,
}

impl AntigravityProvider {
    /// Creates the fixed-origin production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid transport configuration.
    pub fn new(
        scope: AccountScope,
        settings: AntigravitySettings,
    ) -> Result<Self, ClassifiedError> {
        let base = Url::parse(API_ORIGIN).map_err(|_| api_error())?;
        let client = FixedApiClient::new_bearer(
            scope,
            base,
            EndpointClass::PublicHttps,
            settings.credential,
            transport_config()?,
        )?;
        Self::from_client(client, settings.project_id, settings.email)
    }

    /// Binds a validated client for deterministic loopback tests.
    #[doc(hidden)]
    pub fn from_client(
        client: FixedApiClient,
        project_id: Option<String>,
        email: Option<String>,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Antigravity {
            return Err(api_error());
        }
        Ok(Self {
            client: client.with_source(ProviderSource::OAuth)?,
            project_id,
            email,
        })
    }

    /// Fetches and groups Gemini versus Claude/GPT quota families.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("./v1internal:retrieveUserQuota")?;
        let body = self
            .project_id
            .as_ref()
            .map_or_else(|| json!({}), |project| json!({ "project": project }));
        let payload: QuotaResponse = self
            .client
            .post_json(
                context,
                url,
                serde_json::to_vec(&body).map_err(|_| parse_error())?,
            )
            .await?
            .json()?;
        normalize(
            context.scope().clone(),
            fetched_at,
            payload,
            self.email.clone(),
        )
    }
}

impl ProviderAdapter for AntigravityProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Antigravity)
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
struct QuotaResponse {
    buckets: Vec<QuotaBucket>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuotaBucket {
    remaining_fraction: Option<f64>,
    reset_time: Option<String>,
    model_id: Option<String>,
}

#[derive(Clone, Copy)]
struct Quota {
    remaining: f64,
    reset: Option<Timestamp>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: QuotaResponse,
    email: Option<String>,
) -> Result<UsageSample, ClassifiedError> {
    if payload.buckets.is_empty() || payload.buckets.len() > 10_000 {
        return Err(parse_error());
    }
    let mut gemini = None;
    let mut claude_gpt = None;
    for bucket in payload.buckets {
        let Some(model) = bucket.model_id.map(|value| value.to_ascii_lowercase()) else {
            continue;
        };
        let Some(remaining) = bucket.remaining_fraction.filter(|value| value.is_finite()) else {
            continue;
        };
        let target = if model.contains("gemini") {
            &mut gemini
        } else if model.contains("claude") || model.contains("gpt") {
            &mut claude_gpt
        } else {
            continue;
        };
        let candidate = Quota {
            remaining: remaining.clamp(0.0, 1.0),
            reset: bucket
                .reset_time
                .as_deref()
                .map(Timestamp::parse)
                .transpose()
                .map_err(|_| parse_error())?,
        };
        if target
            .as_ref()
            .is_none_or(|current: &Quota| candidate.remaining < current.remaining)
        {
            *target = Some(candidate);
        }
    }
    if gemini.is_none() && claude_gpt.is_none() {
        return Err(parse_error());
    }
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .email(email)?
        .login_method(Some("Antigravity OAuth".to_owned()))?;
    if let Some(quota) = gemini {
        builder = builder.primary(quota_window(quota)?);
    }
    if let Some(quota) = claude_gpt {
        builder = builder.secondary(quota_window(quota)?);
    }
    builder.provenance("antigravity", "remote-quota")?.build()
}

fn quota_window(quota: Quota) -> Result<RateWindow, ClassifiedError> {
    let used = (100.0 - quota.remaining * 100.0).clamp(0.0, 100.0);
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(used).map_err(|_| parse_error())?),
        None,
        quota.reset,
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn optional_value(
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<String>, ClassifiedError> {
    let value = environment.get(name).and_then(|value| clean_setting(value));
    if value.is_some_and(|value| value.len() > 256 || value.contains(['\r', '\n'])) {
        return Err(api_error());
    }
    Ok(value.map(str::to_owned))
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
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
