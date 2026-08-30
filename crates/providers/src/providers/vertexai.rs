//! Google Vertex AI ADC authentication and Cloud Monitoring quota usage.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use time::Duration as TimeDuration;
use time::format_description::well_known::Rfc3339;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy, classify_https_endpoint};
use crate::executable::{ExecutablePath, resolve_executable};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{StderrClassifier, SubprocessError, SubprocessRequest};
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
};

const ADC_FILE_NAME: &str = "application_default_credentials.json";
const DEFAULT_MONITORING_ORIGIN: &str = "https://monitoring.googleapis.com";
const DEFAULT_OAUTH_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const GCLOUD_OVERRIDE: &str = "OMARCHY_AI_BAR_GCLOUD_PATH";
const MAX_ADC_BYTES: u64 = 1024 * 1024;
const MAX_ADC_BYTES_USIZE: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_PROJECT_BYTES: usize = 256;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAGES: usize = 20;
const MAX_SERIES: usize = 4_096;
const MAX_POINTS_PER_SERIES: usize = 4_096;
const MAX_LABELS_PER_SERIES: usize = 128;
const MAX_LABEL_BYTES: usize = 4 * 1024;
const GCLOUD_OUTPUT_BYTES: usize = 16 * 1024;
const GCLOUD_STDERR_BYTES: usize = 64 * 1024;
const ACCESS_TOKEN_EARLY_REFRESH_SECONDS: i64 = 5 * 60;
const QUOTA_WINDOW_SECONDS: u64 = 24 * 60 * 60;
const QUOTA_WINDOW_SECONDS_I64: i64 = 24 * 60 * 60;

const GCLOUD_ENVIRONMENT_ALLOWLIST: [&str; 18] = [
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "CLOUDSDK_PYTHON",
    "CLOUDSDK_PYTHON_ARGS",
    "CLOUDSDK_PYTHON_SITEPACKAGES",
    "XDG_CACHE_HOME",
];

const USAGE_FILTER: &str = "metric.type=\"serviceruntime.googleapis.com/quota/allocation/usage\" AND resource.type=\"consumer_quota\" AND resource.label.service=\"aiplatform.googleapis.com\"";
const LIMIT_FILTER: &str = "metric.type=\"serviceruntime.googleapis.com/quota/limit\" AND resource.type=\"consumer_quota\" AND resource.label.service=\"aiplatform.googleapis.com\"";

/// Google ADC credential form selected from the credentials document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexCredentialKind {
    /// User ADC refreshed directly through Google's OAuth endpoint.
    User,
    /// Service-account ADC whose token is minted by the bounded `gcloud` helper.
    ServiceAccount,
}

/// Validated immutable Vertex AI account configuration.
pub struct VertexSettings {
    adc_path: PathBuf,
    config_dir: PathBuf,
    project_id: String,
    credentials: AdcCredentials,
}

impl VertexSettings {
    /// Resolves ADC, project configuration, and any required Linux helper path.
    ///
    /// `GOOGLE_APPLICATION_CREDENTIALS` takes precedence over
    /// `CLOUDSDK_CONFIG/application_default_credentials.json`, followed by the
    /// XDG-compatible gcloud default under `$HOME/.config/gcloud`. The service
    /// account's own project wins over gcloud config and project environment
    /// variables. Gcloud-owned files are read only and are never rewritten.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or configuration error for
    /// absent, oversized, malformed, or unsafe inputs.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let home = required_absolute_directory(environment, "HOME")?;
        let config_dir = optional_absolute_directory(environment, "CLOUDSDK_CONFIG")?
            .unwrap_or_else(|| home.join(".config/gcloud"));
        let adc_path = match environment
            .get("GOOGLE_APPLICATION_CREDENTIALS")
            .and_then(|value| clean_setting(value))
        {
            Some(path) => validated_absolute_path(path)?,
            None => config_dir.join(ADC_FILE_NAME),
        };
        validate_path_bound(&adc_path)?;
        let bytes = read_bounded_required(&adc_path, MAX_ADC_BYTES)?;
        let adc_fingerprint = fingerprint(&bytes);
        let document: AdcDocument =
            serde_json::from_slice(&bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let configured_project = load_project_id(&config_dir, environment)?;
        let credentials = parse_adc(document, environment, &home, adc_fingerprint)?;
        let project_id = credentials
            .service_project()
            .map(str::to_owned)
            .or(configured_project)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        validate_project(&project_id)?;
        Ok(Self {
            adc_path,
            config_dir,
            project_id,
            credentials,
        })
    }

    /// Absolute ADC document selected for this account.
    #[must_use]
    pub fn adc_path(&self) -> &Path {
        &self.adc_path
    }

    /// Google Cloud project used for the Monitoring resource path.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Parsed ADC credential form.
    #[must_use]
    pub const fn credential_kind(&self) -> VertexCredentialKind {
        match self.credentials {
            AdcCredentials::User(_) => VertexCredentialKind::User,
            AdcCredentials::ServiceAccount(_) => VertexCredentialKind::ServiceAccount,
        }
    }

    /// Service-account gcloud executable, when this credential form requires it.
    #[must_use]
    pub fn gcloud_path(&self) -> Option<&Path> {
        match &self.credentials {
            AdcCredentials::ServiceAccount(credentials) => Some(credentials.gcloud_path.as_path()),
            AdcCredentials::User(_) => None,
        }
    }
}

impl Debug for VertexSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VertexSettings")
            .field("adc_path", &"<redacted>")
            .field("config_dir", &"<redacted>")
            .field("project_id", &"<redacted>")
            .field("credentials", &self.credentials)
            .finish()
    }
}

enum AdcCredentials {
    User(UserAdc),
    ServiceAccount(ServiceAccountAdc),
}

impl AdcCredentials {
    fn service_project(&self) -> Option<&str> {
        match self {
            Self::ServiceAccount(credentials) => credentials.project_id.as_deref(),
            Self::User(_) => None,
        }
    }

    fn email(&self) -> Option<&str> {
        match self {
            Self::User(credentials) => credentials.email.as_deref(),
            Self::ServiceAccount(credentials) => Some(&credentials.email),
        }
    }
}

impl Debug for AdcCredentials {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(_) => formatter.write_str("AdcCredentials::User(<redacted>)"),
            Self::ServiceAccount(_) => {
                formatter.write_str("AdcCredentials::ServiceAccount(<redacted>)")
            }
        }
    }
}

struct UserAdc {
    client_id: SecretString,
    client_secret: SecretString,
    refresh_token: SecretString,
    access_token: Option<SecretString>,
    expires_at: Option<Timestamp>,
    email: Option<String>,
}

struct ServiceAccountAdc {
    email: String,
    project_id: Option<String>,
    adc_fingerprint: [u8; 32],
    gcloud_path: ExecutablePath,
    gcloud_environment: BTreeMap<String, String>,
}

struct SecretString(Zeroizing<String>);

impl SecretString {
    fn parse(value: &str) -> Result<Self, ClassifiedError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_SECRET_BYTES
            || value.chars().any(char::is_whitespace)
            || value.chars().any(char::is_control)
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl Debug for SecretString {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Zeroizing::new(String::deserialize(deserializer)?);
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

struct DocumentSecret(Zeroizing<String>);

impl DocumentSecret {
    fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl<'de> Deserialize<'de> for DocumentSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Zeroizing::new(String::deserialize(deserializer)?);
        if value.trim().is_empty() || value.len() > MAX_ADC_BYTES_USIZE {
            return Err(serde::de::Error::custom("invalid document secret"));
        }
        Ok(Self(value))
    }
}

impl Debug for DocumentSecret {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("DocumentSecret(<redacted>)")
    }
}

#[derive(Deserialize)]
struct AdcDocument {
    #[serde(rename = "type")]
    credential_type: Option<String>,
    client_id: Option<SecretString>,
    client_secret: Option<SecretString>,
    refresh_token: Option<SecretString>,
    access_token: Option<SecretString>,
    token_expiry: Option<String>,
    id_token: Option<SecretString>,
    client_email: Option<String>,
    private_key: Option<DocumentSecret>,
    project_id: Option<String>,
}

fn parse_adc(
    document: AdcDocument,
    environment: &BTreeMap<String, String>,
    home: &Path,
    adc_fingerprint: [u8; 32],
) -> Result<AdcCredentials, ClassifiedError> {
    let is_service_account = document.client_email.is_some() || document.private_key.is_some();
    if is_service_account {
        if document
            .credential_type
            .as_deref()
            .is_some_and(|kind| kind != "service_account" && kind != "external_account")
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let email = clean_identity(
            document
                .client_email
                .as_deref()
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
        )?;
        let private_key = document
            .private_key
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let _private_key_bytes = private_key.byte_len();
        let project_id = document
            .project_id
            .as_deref()
            .and_then(clean_setting)
            .map(str::to_owned);
        if let Some(project_id) = &project_id {
            validate_project(project_id)?;
        }
        let gcloud_path = find_gcloud(environment, home)?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        return Ok(AdcCredentials::ServiceAccount(ServiceAccountAdc {
            email,
            project_id,
            adc_fingerprint,
            gcloud_path,
            gcloud_environment: gcloud_environment(environment, home),
        }));
    }

    let client_id = document
        .client_id
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let client_secret = document
        .client_secret
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let refresh_token = document
        .refresh_token
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let expires_at = document
        .token_expiry
        .as_deref()
        .and_then(|value| Timestamp::parse(value).ok());
    let email = document
        .id_token
        .as_ref()
        .and_then(|token| email_from_id_token(token.expose()));
    Ok(AdcCredentials::User(UserAdc {
        client_id,
        client_secret,
        refresh_token,
        access_token: document.access_token,
        expires_at,
        email,
    }))
}

fn find_gcloud(
    environment: &BTreeMap<String, String>,
    home: &Path,
) -> Result<Option<ExecutablePath>, ClassifiedError> {
    let override_path = environment.get(GCLOUD_OVERRIDE).map(String::as_str);
    let path = environment.get("PATH").map(OsStr::new);
    let fallbacks = [
        PathBuf::from("/usr/bin/gcloud"),
        PathBuf::from("/usr/local/bin/gcloud"),
        PathBuf::from("/opt/google-cloud-sdk/bin/gcloud"),
        home.join("google-cloud-sdk/bin/gcloud"),
        home.join(".local/bin/gcloud"),
    ];
    resolve_executable("gcloud", override_path, path, &fallbacks)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn gcloud_environment(
    environment: &BTreeMap<String, String>,
    home: &Path,
) -> BTreeMap<String, String> {
    let mut selected = BTreeMap::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);
    for name in GCLOUD_ENVIRONMENT_ALLOWLIST {
        if let Some(value) = environment.get(name) {
            selected.insert(name.to_owned(), value.clone());
        }
    }
    selected
        .entry("PATH".to_owned())
        .or_insert_with(|| "/usr/local/sbin:/usr/local/bin:/usr/bin".to_owned());
    selected
}

/// Native exact-origin Vertex AI provider.
pub struct VertexAiProvider {
    scope: AccountScope,
    settings: VertexSettings,
    oauth_endpoint: Url,
    monitoring_origin: Url,
    oauth_transport: HttpTransport,
    monitoring_transport: HttpTransport,
}

impl VertexAiProvider {
    /// Creates the production Google OAuth and Cloud Monitoring client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for the wrong provider scope or an invalid
    /// fixed transport configuration.
    pub fn new(scope: AccountScope, settings: VertexSettings) -> Result<Self, ClassifiedError> {
        let oauth_endpoint =
            Url::parse(DEFAULT_OAUTH_ENDPOINT).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let monitoring_origin = Url::parse(DEFAULT_MONITORING_ORIGIN)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let oauth_class = classify_https_endpoint(&oauth_endpoint)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let monitoring_class = classify_https_endpoint(&monitoring_origin)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::build(
            scope,
            settings,
            oauth_endpoint,
            oauth_class,
            monitoring_origin,
            monitoring_class,
            transport_config()?,
        )
    }

    /// Creates a client whose two endpoints are restricted to exact loopback
    /// origins. This is the network-real integration-test seam; it cannot
    /// authorize public or private non-loopback credential destinations.
    ///
    /// # Errors
    ///
    /// Returns a stable API error unless both URLs are credential-free HTTP(S)
    /// loopback URLs and the monitoring URL is a bare origin.
    #[doc(hidden)]
    pub fn with_loopback_endpoints(
        scope: AccountScope,
        settings: VertexSettings,
        oauth_endpoint: Url,
        monitoring_origin: Url,
    ) -> Result<Self, ClassifiedError> {
        if monitoring_origin.path() != "/"
            || monitoring_origin.query().is_some()
            || monitoring_origin.fragment().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_loopback_url(&oauth_endpoint)?;
        validate_loopback_url(&monitoring_origin)?;
        Self::build(
            scope,
            settings,
            oauth_endpoint,
            EndpointClass::LoopbackDevelopment,
            monitoring_origin,
            EndpointClass::LoopbackDevelopment,
            transport_config()?,
        )
    }

    fn build(
        scope: AccountScope,
        settings: VertexSettings,
        oauth_endpoint: Url,
        oauth_class: EndpointClass,
        monitoring_origin: Url,
        monitoring_class: EndpointClass,
        config: TransportConfig,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::VertexAi {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let oauth_policy =
            EndpointPolicy::new([(oauth_endpoint.origin().ascii_serialization(), oauth_class)])
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        oauth_policy
            .validate(&oauth_endpoint)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let monitoring_policy = EndpointPolicy::new([(
            monitoring_origin.origin().ascii_serialization(),
            monitoring_class,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        monitoring_policy
            .validate(&monitoring_origin)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let oauth_transport =
            HttpTransport::new(oauth_policy, config).map_err(|error| error.classified())?;
        let monitoring_transport =
            HttpTransport::new(monitoring_policy, config).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            settings,
            oauth_endpoint,
            monitoring_origin,
            oauth_transport,
            monitoring_transport,
        })
    }

    /// Fetches one deterministic timestamp, returning identity-only success
    /// when Cloud Monitoring has no matching recent quota data.
    ///
    /// # Errors
    ///
    /// Returns stable classified authentication, permission, network, API, or
    /// parse errors. Raw OAuth, subprocess, and Monitoring response text is
    /// never copied into the public error.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::CloudCredentials {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let token = self
            .access_token(context.cancellation(), fetched_at)
            .await?;
        let quota = self
            .fetch_quota_percent(&token.access_token, fetched_at, context.cancellation())
            .await?;
        normalize(
            self.scope.clone(),
            fetched_at,
            &self.settings.project_id,
            token
                .email
                .as_deref()
                .or_else(|| self.settings.credentials.email()),
            quota,
        )
    }

    async fn access_token(
        &self,
        cancellation: &CancellationToken,
        fetched_at: Timestamp,
    ) -> Result<TokenIdentity, ClassifiedError> {
        match &self.settings.credentials {
            AdcCredentials::User(credentials) => {
                if token_is_fresh(credentials, fetched_at) {
                    let access_token = AccessToken::parse(
                        credentials
                            .access_token
                            .as_ref()
                            .expect("freshness requires an access token")
                            .expose(),
                    )?;
                    return Ok(TokenIdentity {
                        access_token,
                        email: credentials.email.clone(),
                    });
                }
                self.refresh_user_token(credentials, cancellation).await
            }
            AdcCredentials::ServiceAccount(credentials) => {
                self.gcloud_service_token(credentials, cancellation).await
            }
        }
    }

    async fn refresh_user_token(
        &self,
        credentials: &UserAdc,
        cancellation: &CancellationToken,
    ) -> Result<TokenIdentity, ClassifiedError> {
        let body = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("client_id", credentials.client_id.expose());
            serializer.append_pair("client_secret", credentials.client_secret.expose());
            serializer.append_pair("refresh_token", credentials.refresh_token.expose());
            serializer.append_pair("grant_type", "refresh_token");
            Zeroizing::new(serializer.finish())
        };
        let request = HttpRequest::post(self.oauth_endpoint.clone(), body.as_bytes().to_vec())
            .map_err(|error| error.classified())?
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::FormUrlEncoded)
            .accepted_statuses(&[400, 401])
            .map_err(|error| error.classified())?;
        let response = self
            .oauth_transport
            .send(&request, cancellation)
            .await
            .map_err(|error| error.classified())?;
        if response.status() != 200 {
            let error = serde_json::from_slice::<OAuthErrorResponse>(response.body())
                .ok()
                .and_then(|payload| payload.error);
            let kind = match error.as_deref() {
                Some("invalid_grant" | "unauthorized_client") => ErrorKind::AuthenticationExpired,
                _ if response.status() == 401 => ErrorKind::AuthenticationExpired,
                None => ErrorKind::AuthenticationExpired,
                _ => ErrorKind::Api,
            };
            return Err(ClassifiedError::new(kind));
        }
        let payload: OAuthTokenResponse = response.json()?;
        if payload
            .token_type
            .as_deref()
            .is_some_and(|value| !value.eq_ignore_ascii_case("bearer"))
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let access_token = payload
            .access_token
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let email = payload
            .id_token
            .as_ref()
            .and_then(|token| email_from_id_token(token.expose()))
            .or_else(|| credentials.email.clone());
        Ok(TokenIdentity {
            access_token: AccessToken(access_token.0),
            email,
        })
    }

    async fn gcloud_service_token(
        &self,
        credentials: &ServiceAccountAdc,
        cancellation: &CancellationToken,
    ) -> Result<TokenIdentity, ClassifiedError> {
        self.verify_service_adc(credentials)?;
        let classifier = StderrClassifier::ascii_case_insensitive([
            (1, "application-default login"),
            (1, "reauthentication"),
            (1, "credentials are invalid"),
            (1, "credentials have expired"),
        ])
        .map_err(map_subprocess_error)?;
        let request = SubprocessRequest::new(
            credentials.gcloud_path.as_path(),
            ["auth", "application-default", "print-access-token"],
            Duration::from_secs(20),
            GCLOUD_OUTPUT_BYTES,
            GCLOUD_STDERR_BYTES,
        )
        .map_err(map_subprocess_error)?
        .with_cleared_environment()
        .with_stderr_classifier(classifier)
        .with_environment("GOOGLE_APPLICATION_CREDENTIALS", &self.settings.adc_path)
        .map_err(map_subprocess_error)?
        .with_environment("CLOUDSDK_CONFIG", &self.settings.config_dir)
        .map_err(map_subprocess_error)?
        .with_environment("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .map_err(map_subprocess_error)?;
        let request =
            credentials
                .gcloud_environment
                .iter()
                .try_fold(request, |request, (name, value)| {
                    request
                        .with_environment(name, value)
                        .map_err(map_subprocess_error)
                })?;
        let output = request
            .run(cancellation)
            .await
            .map_err(map_subprocess_error)?;
        // The shared subprocess boundary cannot hand gcloud the already-open
        // ADC descriptor. Comparing the bounded document both before and after
        // execution rejects ordinary rotation/replacement and discards a token
        // minted from a changed file. A same-user A->B->A swap wholly inside
        // the child execution interval remains an unavoidable local TOCTOU
        // residual until that boundary can pass inherited descriptors.
        self.verify_service_adc(credentials)?;
        let stdout = std::str::from_utf8(output.stdout())
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(TokenIdentity {
            access_token: AccessToken::parse(stdout)?,
            email: Some(credentials.email.clone()),
        })
    }

    fn verify_service_adc(&self, credentials: &ServiceAccountAdc) -> Result<(), ClassifiedError> {
        let bytes = read_bounded_required(&self.settings.adc_path, MAX_ADC_BYTES)?;
        if fingerprint(&bytes) != credentials.adc_fingerprint {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        Ok(())
    }

    async fn fetch_quota_percent(
        &self,
        access_token: &AccessToken,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> Result<Option<f64>, ClassifiedError> {
        let usage = self
            .fetch_time_series(access_token, fetched_at, USAGE_FILTER, cancellation)
            .await?;
        let limits = self
            .fetch_time_series(access_token, fetched_at, LIMIT_FILTER, cancellation)
            .await?;
        make_quota_percent(&usage, &limits)
    }

    async fn fetch_time_series(
        &self,
        access_token: &AccessToken,
        fetched_at: Timestamp,
        filter: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<MonitoringTimeSeries>, ClassifiedError> {
        let end = fetched_at.as_offset_date_time();
        let start = end
            .checked_sub(TimeDuration::seconds(QUOTA_WINDOW_SECONDS_I64))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let start = start
            .format(&Rfc3339)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let end = end
            .format(&Rfc3339)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let mut page_token: Option<String> = None;
        let mut seen_tokens = BTreeSet::new();
        let mut all_series = Vec::new();
        for _ in 0..MAX_PAGES {
            let mut url = monitoring_url(&self.monitoring_origin, &self.settings.project_id)?;
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("filter", filter);
                query.append_pair("interval.startTime", &start);
                query.append_pair("interval.endTime", &end);
                query.append_pair("aggregation.alignmentPeriod", "3600s");
                query.append_pair("aggregation.perSeriesAligner", "ALIGN_MAX");
                query.append_pair("view", "FULL");
                if let Some(token) = &page_token {
                    query.append_pair("pageToken", token);
                }
            }
            let authentication = Authentication::bearer(access_token.expose().to_owned())
                .map_err(|error| error.classified())?;
            let request = HttpRequest::get_json(url).authentication(authentication);
            let response = self
                .monitoring_transport
                .send(&request, cancellation)
                .await
                .map_err(|error| error.classified())?;
            let page: MonitoringPage = response.json()?;
            validate_page(&page)?;
            if page.time_series.len() > MAX_SERIES.saturating_sub(all_series.len()) {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            all_series.extend(page.time_series);
            let Some(token) = page.next_page_token.and_then(clean_page_token) else {
                return Ok(all_series);
            };
            if !seen_tokens.insert(token.clone()) {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            page_token = Some(token);
        }
        Err(ClassifiedError::new(ErrorKind::Parse))
    }
}

impl ProviderAdapter for VertexAiProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::VertexAi)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

struct TokenIdentity {
    access_token: AccessToken,
    email: Option<String>,
}

struct AccessToken(Zeroizing<String>);

impl AccessToken {
    fn parse(raw: &str) -> Result<Self, ClassifiedError> {
        let token = raw.trim();
        if token.is_empty()
            || token.len() > MAX_SECRET_BYTES
            || token.chars().any(char::is_whitespace)
            || token.chars().any(char::is_control)
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(Self(Zeroizing::new(token.to_owned())))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl Debug for AccessToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccessToken(<redacted>)")
    }
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: Option<SecretString>,
    token_type: Option<String>,
    id_token: Option<SecretString>,
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
}

#[derive(Deserialize)]
struct MonitoringPage {
    #[serde(rename = "timeSeries", default)]
    time_series: Vec<MonitoringTimeSeries>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct MonitoringTimeSeries {
    metric: MonitoringDescriptor,
    resource: MonitoringDescriptor,
    points: Vec<MonitoringPoint>,
}

#[derive(Deserialize)]
struct MonitoringDescriptor {
    #[serde(rename = "type")]
    _kind: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct MonitoringPoint {
    value: MonitoringValue,
}

#[derive(Deserialize)]
struct MonitoringValue {
    #[serde(rename = "doubleValue")]
    double_value: Option<serde_json::Number>,
    #[serde(rename = "int64Value")]
    int64_value: Option<String>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct QuotaKey {
    quota_metric: String,
    limit_name: String,
    location: String,
}

/// Parses two bounded Cloud Monitoring response bodies and returns the maximum
/// matched quota percentage. `Ok(None)` represents the upstream's benign
/// no-recent-data state.
///
/// # Errors
///
/// Returns a stable parse error for malformed, oversized, non-finite, or
/// structurally ambiguous data.
pub fn parse_quota_usage(
    usage_data: &[u8],
    limit_data: &[u8],
) -> Result<Option<f64>, ClassifiedError> {
    if usage_data.len() > MAX_RESPONSE_BYTES || limit_data.len() > MAX_RESPONSE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let usage: MonitoringPage =
        serde_json::from_slice(usage_data).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let limits: MonitoringPage =
        serde_json::from_slice(limit_data).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    validate_page(&usage)?;
    validate_page(&limits)?;
    make_quota_percent(&usage.time_series, &limits.time_series)
}

fn make_quota_percent(
    usage_series: &[MonitoringTimeSeries],
    limit_series: &[MonitoringTimeSeries],
) -> Result<Option<f64>, ClassifiedError> {
    let usage = aggregate(usage_series)?;
    let limits = aggregate(limit_series)?;
    if usage.is_empty() || limits.is_empty() {
        return Ok(None);
    }
    let mut maximum: Option<f64> = None;
    for (usage_key, used) in usage {
        let limit = if let Some(exact) = limits.get(&usage_key).filter(|value| **value > 0.0) {
            Some(*exact)
        } else if usage_key.limit_name.is_empty() {
            let mut candidates = limits.iter().filter_map(|(key, value)| {
                (*value > 0.0
                    && key.quota_metric == usage_key.quota_metric
                    && key.location == usage_key.location)
                    .then_some(*value)
            });
            let first = candidates.next();
            if candidates.next().is_some() {
                None
            } else {
                first
            }
        } else {
            None
        };
        let Some(limit) = limit else { continue };
        let percent = used / limit * 100.0;
        if !percent.is_finite() || percent < 0.0 {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        maximum = Some(maximum.map_or(percent, |current| current.max(percent)));
    }
    Ok(maximum)
}

fn aggregate(series: &[MonitoringTimeSeries]) -> Result<BTreeMap<QuotaKey, f64>, ClassifiedError> {
    if series.len() > MAX_SERIES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut buckets = BTreeMap::new();
    for entry in series {
        let Some(key) = quota_key(entry)? else {
            continue;
        };
        let Some(value) = maximum_point(&entry.points)? else {
            continue;
        };
        buckets
            .entry(key)
            .and_modify(|current: &mut f64| *current = current.max(value))
            .or_insert(value);
    }
    Ok(buckets)
}

fn quota_key(series: &MonitoringTimeSeries) -> Result<Option<QuotaKey>, ClassifiedError> {
    validate_labels(&series.metric.labels)?;
    validate_labels(&series.resource.labels)?;
    let quota_metric = series
        .metric
        .labels
        .get("quota_metric")
        .or_else(|| series.resource.labels.get("quota_id"));
    let Some(quota_metric) = quota_metric.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    validate_label(quota_metric)?;
    let limit_name = series
        .metric
        .labels
        .get("limit_name")
        .cloned()
        .unwrap_or_default();
    let location = series
        .resource
        .labels
        .get("location")
        .cloned()
        .unwrap_or_else(|| "global".to_owned());
    validate_label(&limit_name)?;
    validate_label(&location)?;
    Ok(Some(QuotaKey {
        quota_metric: quota_metric.clone(),
        limit_name,
        location,
    }))
}

fn maximum_point(points: &[MonitoringPoint]) -> Result<Option<f64>, ClassifiedError> {
    if points.len() > MAX_POINTS_PER_SERIES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut maximum: Option<f64> = None;
    for point in points {
        let value = match (&point.value.double_value, &point.value.int64_value) {
            (Some(value), None) => value.as_f64(),
            (None, Some(value)) => value.parse::<f64>().ok(),
            (None, None) => None,
            (Some(_), Some(_)) => return Err(ClassifiedError::new(ErrorKind::Parse)),
        };
        let Some(value) = value else { continue };
        if !value.is_finite() || value < 0.0 {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        maximum = Some(maximum.map_or(value, |current| current.max(value)));
    }
    Ok(maximum)
}

fn validate_page(page: &MonitoringPage) -> Result<(), ClassifiedError> {
    if page.time_series.len() > MAX_SERIES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if let Some(token) = &page.next_page_token {
        validate_page_token(token)?;
    }
    for series in &page.time_series {
        if series.points.len() > MAX_POINTS_PER_SERIES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        validate_labels(&series.metric.labels)?;
        validate_labels(&series.resource.labels)?;
    }
    Ok(())
}

fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), ClassifiedError> {
    if labels.len() > MAX_LABELS_PER_SERIES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    for (key, value) in labels {
        validate_label(key)?;
        validate_label(value)?;
    }
    Ok(())
}

fn validate_label(value: &str) -> Result<(), ClassifiedError> {
    if value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(())
}

fn clean_page_token(value: String) -> Option<String> {
    validate_page_token(&value).ok()?;
    (!value.is_empty()).then_some(value)
}

fn validate_page_token(value: &str) -> Result<(), ClassifiedError> {
    if value.len() > MAX_PAGE_TOKEN_BYTES
        || value.chars().any(char::is_control)
        || value != value.trim()
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(())
}

fn monitoring_url(origin: &Url, project_id: &str) -> Result<Url, ClassifiedError> {
    let mut url = origin.clone();
    let mut path = url
        .path_segments_mut()
        .map_err(|()| ClassifiedError::new(ErrorKind::Api))?;
    path.clear();
    path.push("v3");
    path.push("projects");
    path.push(project_id);
    path.push("timeSeries");
    drop(path);
    Ok(url)
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    project_id: &str,
    email: Option<&str>,
    quota_percent: Option<f64>,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .email(email.map(str::to_owned))?
        .organization(Some(project_id.to_owned()))?
        .login_method(Some("gcloud".to_owned()))?;
    if let Some(percent) = quota_percent {
        let duration = WindowDuration::from_seconds(QUOTA_WINDOW_SECONDS)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let description = BoundedText::new("Cloud Monitoring quota")
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let window = RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            Some(duration),
            None,
            Some(description),
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        builder = builder.primary(window);
    }
    builder.provenance("vertexai", "oauth")?.build()
}

fn token_is_fresh(credentials: &UserAdc, fetched_at: Timestamp) -> bool {
    credentials.access_token.is_some()
        && credentials.expires_at.is_some_and(|expiry| {
            expiry.unix_timestamp()
                > fetched_at
                    .unix_timestamp()
                    .saturating_add(ACCESS_TOKEN_EARLY_REFRESH_SECONDS)
        })
}

fn map_subprocess_error(error: SubprocessError) -> ClassifiedError {
    let kind = match error {
        SubprocessError::Spawn => ErrorKind::MissingCredential,
        SubprocessError::Cancelled | SubprocessError::Timeout => ErrorKind::Network,
        SubprocessError::NonZero {
            stderr_tag: Some(1),
            ..
        } => ErrorKind::AuthenticationExpired,
        SubprocessError::StdoutTooLarge
        | SubprocessError::StderrTooLarge
        | SubprocessError::OutputRead => ErrorKind::Parse,
        SubprocessError::InvalidConfiguration
        | SubprocessError::Wait
        | SubprocessError::NonZero { .. } => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn validate_loopback_url(url: &Url) -> Result<(), ClassifiedError> {
    let policy = EndpointPolicy::new([(
        url.origin().ascii_serialization(),
        EndpointClass::LoopbackDevelopment,
    )])
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    policy
        .validate(url)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    Ok(())
}

fn required_absolute_directory(
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<PathBuf, ClassifiedError> {
    let value = environment
        .get(name)
        .and_then(|value| clean_setting(value))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    validated_absolute_path(value)
}

fn optional_absolute_directory(
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<PathBuf>, ClassifiedError> {
    environment
        .get(name)
        .and_then(|value| clean_setting(value))
        .map(validated_absolute_path)
        .transpose()
}

fn validated_absolute_path(value: &str) -> Result<PathBuf, ClassifiedError> {
    let path = PathBuf::from(value);
    validate_path_bound(&path)?;
    if !path.is_absolute() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(path)
}

fn validate_path_bound(path: &Path) -> Result<(), ClassifiedError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty() || bytes.len() > 4 * 1024 || bytes.contains(&0) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn read_bounded_required(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    let file =
        fs::File::open(path).map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    read_open_file_bounded(file, limit, ErrorKind::MissingCredential)
}

fn read_open_file_bounded(
    mut file: fs::File,
    limit: u64,
    io_error: ErrorKind,
) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    let metadata = file
        .metadata()
        .map_err(|_| ClassifiedError::new(io_error))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ClassifiedError::new(io_error))?;
    if bytes.len() as u64 > limit {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(bytes)
}

fn load_project_id(
    config_dir: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<Option<String>, ClassifiedError> {
    let config_path = config_dir.join("configurations/config_default");
    validate_path_bound(&config_path)?;
    match fs::File::open(&config_path) {
        Ok(file) => {
            let content = read_open_file_bounded(file, MAX_CONFIG_BYTES, ErrorKind::Parse)?;
            let content = std::str::from_utf8(&content)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            for line in content.lines() {
                let line = line.trim();
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                if key.trim() == "project"
                    && let Some(project) = clean_setting(value)
                {
                    let project = project.to_owned();
                    validate_project(&project)?;
                    return Ok(Some(project));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    }
    for key in [
        "GOOGLE_CLOUD_PROJECT",
        "GCLOUD_PROJECT",
        "CLOUDSDK_CORE_PROJECT",
    ] {
        if let Some(project) = environment.get(key).and_then(|value| clean_setting(value)) {
            validate_project(project)?;
            return Ok(Some(project.to_owned()));
        }
    }
    Ok(None)
}

fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn validate_project(project: &str) -> Result<(), ClassifiedError> {
    if project.is_empty()
        || project.len() > MAX_PROJECT_BYTES
        || !project
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn clean_identity(value: &str) -> Result<String, ClassifiedError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(value.to_owned())
}

fn email_from_id_token(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    if payload.is_empty() || payload.len() > MAX_SECRET_BYTES {
        return None;
    }
    let decoded = decode_base64_url(payload)?;
    let value: IdTokenClaims = serde_json::from_slice(&decoded).ok()?;
    clean_identity(&value.email?).ok()
}

#[derive(Deserialize)]
struct IdTokenClaims {
    email: Option<String>,
}

fn decode_base64_url(value: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::with_capacity(value.len().saturating_mul(3) / 4 + 3));
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        if byte == b'=' {
            break;
        }
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits = bits.checked_add(6)?;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
        if output.len() > MAX_SECRET_BYTES {
            return None;
        }
    }
    Some(output)
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
