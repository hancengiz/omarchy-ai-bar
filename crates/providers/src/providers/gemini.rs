//! `Gemini CLI` quota adapter for an explicit OAuth access token.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
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
const ACCESS_TOKEN_ENV: &str = "GEMINI_OAUTH_ACCESS_TOKEN";
const PROJECT_ID_ENV: &str = "GEMINI_PROJECT_ID";
const ACCOUNT_EMAIL_ENV: &str = "GEMINI_ACCOUNT_EMAIL";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Explicit Gemini OAuth configuration suitable for a user service.
pub struct GeminiSettings {
    credential: ApiKeyCredential,
    project_id: Option<String>,
    account_email: Option<String>,
}

impl GeminiSettings {
    /// Resolves an OAuth access token and optional project/account labels.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API error for unsafe values.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let credential = ApiKeyCredential::resolve(environment, &[ACCESS_TOKEN_ENV])?;
        let project_id = optional_value(environment, PROJECT_ID_ENV, 256)?;
        let account_email = optional_value(environment, ACCOUNT_EMAIL_ENV, 256)?;
        Ok(Self {
            credential,
            project_id,
            account_email,
        })
    }
}

impl Debug for GeminiSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeminiSettings")
            .field("credential", &"<redacted>")
            .field(
                "project_id",
                &self.project_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "account_email",
                &self.account_email.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Native `Gemini` quota provider.
pub struct GeminiProvider {
    client: FixedApiClient,
    project_id: Option<String>,
    account_email: Option<String>,
}

impl GeminiProvider {
    /// Creates the fixed-origin production client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid transport configuration.
    pub fn new(scope: AccountScope, settings: GeminiSettings) -> Result<Self, ClassifiedError> {
        let base = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base,
            EndpointClass::PublicHttps,
            settings.credential,
            transport_config()?,
        )?;
        Self::from_client(client, settings.project_id, settings.account_email)
    }

    /// Binds a validated client for deterministic loopback tests.
    #[doc(hidden)]
    pub fn from_client(
        client: FixedApiClient,
        project_id: Option<String>,
        account_email: Option<String>,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Gemini {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let client = client.with_source(ProviderSource::OAuth)?;
        Ok(Self {
            client,
            project_id,
            account_email,
        })
    }

    /// Fetches and groups the lowest quota bucket for each Gemini model tier.
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
            self.account_email.clone(),
        )
    }
}

impl ProviderAdapter for GeminiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Gemini)
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

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: QuotaResponse,
    account_email: Option<String>,
) -> Result<UsageSample, ClassifiedError> {
    if payload.buckets.is_empty() || payload.buckets.len() > 10_000 {
        return Err(parse_error());
    }
    let mut pro = None;
    let mut flash = None;
    let mut flash_lite = None;
    for bucket in payload.buckets {
        let Some(model) = bucket.model_id else {
            continue;
        };
        let Some(remaining) = bucket.remaining_fraction.filter(|value| value.is_finite()) else {
            continue;
        };
        let candidate = ModelQuota {
            remaining: remaining.clamp(0.0, 1.0),
            reset: bucket
                .reset_time
                .as_deref()
                .map(Timestamp::parse)
                .transpose()
                .map_err(|_| parse_error())?,
        };
        let model = model.to_ascii_lowercase();
        let target = if model.contains("flash-lite") {
            &mut flash_lite
        } else if model.contains("flash") {
            &mut flash
        } else if model.contains("pro") {
            &mut pro
        } else {
            continue;
        };
        if target
            .as_ref()
            .is_none_or(|current: &ModelQuota| candidate.remaining < current.remaining)
        {
            *target = Some(candidate);
        }
    }
    if pro.is_none() && flash.is_none() && flash_lite.is_none() {
        return Err(parse_error());
    }
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .email(account_email)?
        .login_method(Some("Gemini OAuth".to_owned()))?;
    if let Some(value) = pro {
        builder = builder.primary(quota_window(&value)?);
    }
    if let Some(value) = flash {
        builder = builder.secondary(quota_window(&value)?);
    }
    if let Some(value) = flash_lite {
        builder = builder.tertiary(quota_window(&value)?);
    }
    builder.provenance("gemini", "quota-api")?.build()
}

struct ModelQuota {
    remaining: f64,
    reset: Option<Timestamp>,
}

fn quota_window(value: &ModelQuota) -> Result<RateWindow, ClassifiedError> {
    let used = (100.0 - value.remaining * 100.0).clamp(0.0, 100.0);
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(used).map_err(|_| parse_error())?),
        Some(WindowDuration::from_provider_minutes(24 * 60).map_err(|_| parse_error())?),
        value.reset,
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn optional_value(
    environment: &BTreeMap<String, String>,
    name: &str,
    maximum: usize,
) -> Result<Option<String>, ClassifiedError> {
    let value = environment.get(name).and_then(|value| clean_setting(value));
    if value.is_some_and(|value| value.len() > maximum || value.contains(['\r', '\n'])) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(value.map(str::to_owned))
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
