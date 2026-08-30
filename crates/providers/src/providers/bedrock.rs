//! AWS Bedrock Cost Explorer billing, `CloudWatch` activity, and profile auth.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, CostAmount, CostProvenance, CostSummary, CostUnit,
    CostUsageCoverage, CostUsageDailyBucket, CostUsageMetrics, CostUsageModelBreakdown,
    CostUsageSnapshot, CostUsageTokenMix, CurrencyCode, DetailRow, DetailSection,
    DetailSensitivity, ErrorKind, ExactDecimal, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value, json};
use time::{Date, Duration as TimeDuration, Month, Time, UtcOffset};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::cloud_signing::AwsCredentials;
use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::EndpointPolicy;
use crate::executable::{ExecutablePath, resolve_executable};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{StderrClassifier, SubprocessError, SubprocessOutput, SubprocessRequest};
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestContentType, TransportConfig,
};

const AUTH_MODE_KEY: &str = "OMARCHY_AI_BAR_BEDROCK_AUTH_MODE";
const BUDGET_KEY: &str = "OMARCHY_AI_BAR_BEDROCK_BUDGET";
const COST_EXPLORER_URL_KEY: &str = "OMARCHY_AI_BAR_BEDROCK_API_URL";
const CLOUDWATCH_URL_KEY: &str = "OMARCHY_AI_BAR_BEDROCK_CLOUDWATCH_API_URL";
const AWS_CLI_PATH_KEY: &str = "OMARCHY_AI_BAR_AWS_CLI_PATH";
const ACCESS_KEY_ID_KEY: &str = "AWS_ACCESS_KEY_ID";
const SECRET_ACCESS_KEY_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const SESSION_TOKEN_KEY: &str = "AWS_SESSION_TOKEN";
const PROFILE_KEY: &str = "AWS_PROFILE";
const REGION_KEY: &str = "AWS_REGION";
const DEFAULT_REGION_KEY: &str = "AWS_DEFAULT_REGION";
const DEFAULT_REGION: &str = "us-east-1";
const COST_EXPLORER_URL: &str = "https://ce.us-east-1.amazonaws.com";
const COST_EXPLORER_REGION: &str = "us-east-1";
const COST_EXPLORER_SERVICE: &str = "ce";
const CLOUDWATCH_SERVICE: &str = "monitoring";
const COST_EXPLORER_TARGET: &str = "AWSInsightsIndexService.GetCostAndUsage";
const CLOUDWATCH_TARGET: &str = "GraniteServiceVersion20100801.GetMetricData";
const HISTORY_DAYS: u16 = 30;
const CLOUDWATCH_DAYS: i64 = 14;
const MAX_PAGES: usize = 20;
const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
const MAX_RESULTS_PER_PAGE: usize = 512;
const MAX_GROUPS_PER_RESULT: usize = 4 * 1024;
const MAX_METRIC_RESULTS_PER_PAGE: usize = 4 * 1024;
const MAX_SERVICE_NAME_BYTES: usize = 160;
const MAX_PROFILE_BYTES: usize = 512;
const MAX_CLI_ENVIRONMENT_VALUES: usize = 32;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CLI_OUTPUT_BYTES: usize = 1024 * 1024;
const AWS_CLI_TIMEOUT: Duration = Duration::from_secs(20);
const EXPIRED_STDERR_TAG: u8 = 1;

/// Bedrock authentication selected for one provider account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BedrockAuthMode {
    /// A complete AWS access-key bundle.
    Keys,
    /// A named AWS profile refreshed through AWS CLI v2 on every fetch.
    Profile,
}

/// One complete AWS access-key bundle.
///
/// Bundles are intentionally atomic: application wiring can select one-shot,
/// environment, or Secret Service credentials without mixing individual
/// fields from different stores.
#[derive(Clone)]
pub struct BedrockCredentialBundle {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl BedrockCredentialBundle {
    /// Creates a bounded complete credential bundle.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for an invalid field.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<impl Into<String>>,
    ) -> Result<Self, ClassifiedError> {
        let access_key_id = clean_owned(access_key_id.into())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let secret_access_key = clean_owned(secret_access_key.into())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let session_token = session_token.and_then(|value| clean_owned(value.into()));
        AwsCredentials::new(
            access_key_id.clone(),
            secret_access_key.clone(),
            session_token.clone(),
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Ok(Self {
            access_key_id: Zeroizing::new(access_key_id),
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: session_token.map(Zeroizing::new),
        })
    }

    fn signer_credentials(&self) -> Result<AwsCredentials, ClassifiedError> {
        AwsCredentials::new(
            self.access_key_id.to_string(),
            self.secret_access_key.to_string(),
            self.session_token
                .as_ref()
                .map(|value| value.as_str().to_owned()),
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))
    }
}

impl Debug for BedrockCredentialBundle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BedrockCredentialBundle")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

struct CliEnvironmentValue {
    name: String,
    value: Zeroizing<String>,
}

impl Clone for CliEnvironmentValue {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            value: Zeroizing::new(self.value.to_string()),
        }
    }
}

impl Debug for CliEnvironmentValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliEnvironmentValue")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

enum BedrockCredentialSource {
    Keys(BedrockCredentialBundle),
    Profile {
        profile: Zeroizing<String>,
        aws_cli: ExecutablePath,
        environment: Vec<CliEnvironmentValue>,
    },
}

impl BedrockCredentialSource {
    const fn mode(&self) -> BedrockAuthMode {
        match self {
            Self::Keys(_) => BedrockAuthMode::Keys,
            Self::Profile { .. } => BedrockAuthMode::Profile,
        }
    }
}

impl Debug for BedrockCredentialSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keys(_) => formatter.write_str("BedrockCredentialSource::Keys(<redacted>)"),
            Self::Profile { environment, .. } => formatter
                .debug_struct("BedrockCredentialSource::Profile")
                .field("profile", &"<redacted>")
                .field("aws_cli", &"<redacted>")
                .field("environment_value_count", &environment.len())
                .finish(),
        }
    }
}

/// Validated Bedrock credentials, endpoints, region, and budget.
pub struct BedrockSettings {
    credential_source: BedrockCredentialSource,
    configured_region: Option<String>,
    budget: Option<Decimal>,
    cost_explorer_endpoint: ConfiguredEndpoint,
    cost_explorer_is_override: bool,
    cloudwatch_endpoint: Option<ConfiguredEndpoint>,
}

impl BedrockSettings {
    /// Resolves standard AWS variables and Omarchy AI Bar overrides.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API error for incomplete auth,
    /// an unavailable profile CLI, or an unsafe endpoint override.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        Self::resolve_with_bundles(environment, None, None)
    }

    /// Resolves settings with atomic application-provided credential bundles.
    ///
    /// Complete one-shot credentials take precedence over a complete
    /// environment bundle, which takes precedence over a complete Secret
    /// Service bundle. Individual fields are never combined.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API error for incomplete auth,
    /// an unavailable profile CLI, or an unsafe endpoint override.
    pub fn resolve_with_bundles(
        environment: &BTreeMap<String, String>,
        one_shot: Option<BedrockCredentialBundle>,
        secret_service: Option<BedrockCredentialBundle>,
    ) -> Result<Self, ClassifiedError> {
        let environment_bundle = environment_bundle(environment)?;
        let has_complete_key_bundle =
            one_shot.is_some() || environment_bundle.is_some() || secret_service.is_some();
        let auth_mode = explicit_auth_mode(environment).unwrap_or_else(|| {
            if clean_environment_value(environment, PROFILE_KEY).is_some()
                && !has_complete_key_bundle
            {
                BedrockAuthMode::Profile
            } else {
                BedrockAuthMode::Keys
            }
        });

        let credential_source = match auth_mode {
            BedrockAuthMode::Keys => BedrockCredentialSource::Keys(
                one_shot
                    .or(environment_bundle)
                    .or(secret_service)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?,
            ),
            BedrockAuthMode::Profile => {
                let profile = clean_environment_value(environment, PROFILE_KEY)
                    .filter(|value| valid_profile(value))
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
                let aws_cli = resolve_aws_cli(environment)?
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
                BedrockCredentialSource::Profile {
                    profile: Zeroizing::new(profile),
                    aws_cli,
                    environment: profile_environment(environment)?,
                }
            }
        };

        let configured_region = clean_environment_value(environment, REGION_KEY)
            .or_else(|| clean_environment_value(environment, DEFAULT_REGION_KEY));
        let budget = environment
            .get(BUDGET_KEY)
            .and_then(|value| clean_setting(value))
            .and_then(parse_decimal)
            .filter(|value| *value > Decimal::ZERO);

        let cost_explorer_override = environment
            .get(COST_EXPLORER_URL_KEY)
            .and_then(|value| clean_setting(value));
        let cost_explorer_endpoint = ConfiguredEndpoint::parse(
            cost_explorer_override.unwrap_or(COST_EXPLORER_URL),
            ConfiguredHttpPolicy::LoopbackHttp,
        )?;
        let cloudwatch_endpoint = environment
            .get(CLOUDWATCH_URL_KEY)
            .and_then(|value| clean_setting(value))
            .map(|value| ConfiguredEndpoint::parse(value, ConfiguredHttpPolicy::LoopbackHttp))
            .transpose()?;

        Ok(Self {
            credential_source,
            configured_region,
            budget,
            cost_explorer_endpoint,
            cost_explorer_is_override: cost_explorer_override.is_some(),
            cloudwatch_endpoint,
        })
    }

    /// Selected authentication mode.
    #[must_use]
    pub const fn auth_mode(&self) -> BedrockAuthMode {
        self.credential_source.mode()
    }

    /// Positive monthly USD budget, when configured.
    #[must_use]
    pub const fn budget(&self) -> Option<Decimal> {
        self.budget
    }

    /// Explicit region from `AWS_REGION` or `AWS_DEFAULT_REGION`.
    #[must_use]
    pub fn configured_region(&self) -> Option<&str> {
        self.configured_region.as_deref()
    }

    /// Validated Cost Explorer endpoint.
    #[must_use]
    pub const fn cost_explorer_url(&self) -> &Url {
        self.cost_explorer_endpoint.url()
    }

    /// Explicit `CloudWatch` override, when configured.
    #[must_use]
    pub fn cloudwatch_url(&self) -> Option<&Url> {
        self.cloudwatch_endpoint
            .as_ref()
            .map(ConfiguredEndpoint::url)
    }
}

impl Debug for BedrockSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BedrockSettings")
            .field("credential_source", &self.credential_source)
            .field("configured_region", &self.configured_region)
            .field("budget", &self.budget)
            .field("cost_explorer_endpoint", &self.cost_explorer_endpoint)
            .field("cost_explorer_is_override", &self.cost_explorer_is_override)
            .field("cloudwatch_endpoint", &self.cloudwatch_endpoint)
            .finish()
    }
}

/// Resolves the partition-aware production `CloudWatch` endpoint for a region.
///
/// # Errors
///
/// Returns a stable parse error unless the region matches AWS's bounded
/// lower-case region grammar.
#[doc(hidden)]
pub fn cloudwatch_url_for_region(region: &str) -> Result<Url, ClassifiedError> {
    cloudwatch_endpoint(region).map(|endpoint| endpoint.url().clone())
}

/// Shell-free named-profile credential resolver backed by AWS CLI v2.
struct BedrockProfileCredentialProvider {
    aws_cli: ExecutablePath,
    environment: Vec<CliEnvironmentValue>,
}

impl BedrockProfileCredentialProvider {
    fn new(aws_cli: ExecutablePath, environment: Vec<CliEnvironmentValue>) -> Self {
        Self {
            aws_cli,
            environment,
        }
    }

    async fn export_credentials(
        &self,
        profile: &str,
        cancellation: &CancellationToken,
    ) -> Result<AwsCredentials, ClassifiedError> {
        let classifier = StderrClassifier::ascii_case_insensitive([
            (EXPIRED_STDERR_TAG, "sso login"),
            (EXPIRED_STDERR_TAG, "expired"),
            (EXPIRED_STDERR_TAG, "token has expired"),
        ])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let request = self
            .request([
                "configure",
                "export-credentials",
                "--profile",
                profile,
                "--format",
                "process",
            ])?
            .with_stderr_classifier(classifier);
        let output = request.run(cancellation).await.map_err(map_export_error)?;
        parse_exported_credentials(&output)
    }

    async fn resolve_region(
        &self,
        profile: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<String>, ClassifiedError> {
        let request = self.request(["configure", "get", "region", "--profile", profile])?;
        match request.run(cancellation).await {
            Ok(output) => Ok(std::str::from_utf8(output.stdout())
                .ok()
                .and_then(clean_owned)),
            Err(SubprocessError::NonZero { .. }) => Ok(None),
            Err(error) => Err(map_subprocess_error(error)),
        }
    }

    fn request<const N: usize>(
        &self,
        arguments: [&str; N],
    ) -> Result<SubprocessRequest, ClassifiedError> {
        let mut request = SubprocessRequest::new(
            self.aws_cli.as_path().to_owned(),
            arguments,
            AWS_CLI_TIMEOUT,
            MAX_CLI_OUTPUT_BYTES,
            MAX_CLI_OUTPUT_BYTES,
        )
        .map_err(map_subprocess_error)?
        .without_environment(PROFILE_KEY)
        .map_err(map_subprocess_error)?;
        for entry in &self.environment {
            request = request
                .with_environment(entry.name.clone(), entry.value.to_string())
                .map_err(map_subprocess_error)?;
        }
        Ok(request)
    }
}

impl Debug for BedrockProfileCredentialProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BedrockProfileCredentialProvider")
            .field("aws_cli", &"<redacted>")
            .field("environment_value_count", &self.environment.len())
            .finish()
    }
}

struct ResolvedCredentials {
    credentials: AwsCredentials,
    region: String,
}

/// Native AWS Bedrock billing and activity adapter.
pub struct BedrockProvider {
    scope: AccountScope,
    settings: BedrockSettings,
    local_offset: UtcOffset,
    use_system_local_offset: bool,
}

impl BedrockProvider {
    /// Creates a production Bedrock provider.
    ///
    /// # Errors
    ///
    /// Rejects an account scope for another provider.
    pub fn new(scope: AccountScope, settings: BedrockSettings) -> Result<Self, ClassifiedError> {
        let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
        let mut provider = Self::with_local_offset(scope, settings, local_offset)?;
        provider.use_system_local_offset = true;
        Ok(provider)
    }

    /// Creates a provider with a deterministic local calendar offset.
    ///
    /// This seam keeps monthly reset tests independent of the host timezone.
    ///
    /// # Errors
    ///
    /// Rejects an account scope for another provider.
    #[doc(hidden)]
    pub fn with_local_offset(
        scope: AccountScope,
        settings: BedrockSettings,
        local_offset: UtcOffset,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Bedrock {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            scope,
            settings,
            local_offset,
            use_system_local_offset: false,
        })
    }

    /// Fetches required monthly spend plus best-effort activity and history.
    ///
    /// # Errors
    ///
    /// Returns stable credential, transport, API, or parse categories without
    /// exposing AWS response text or subprocess stderr.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let resolved = self.resolve_credentials(context.cancellation()).await?;
        let monthly_spend = self
            .fetch_monthly_cost(&resolved.credentials, fetched_at, context.cancellation())
            .await?;

        let activity = if self.should_fetch_cloudwatch() {
            match self
                .fetch_cloudwatch(
                    &resolved.credentials,
                    &resolved.region,
                    fetched_at,
                    context.cancellation(),
                )
                .await
            {
                Ok(activity) => Some(activity),
                Err(error) if context.cancellation().is_cancelled() => return Err(error),
                Err(_) => None,
            }
        } else {
            None
        };

        let history = match self
            .fetch_cost_history_with_credentials(
                &resolved.credentials,
                fetched_at,
                context.cancellation(),
            )
            .await
        {
            Ok(history) => Some(history),
            Err(error) if context.cancellation().is_cancelled() => return Err(error),
            Err(_) => None,
        };

        normalize(BedrockNormalization {
            scope: context.scope().clone(),
            fetched_at,
            local_offset: self.local_offset,
            use_system_local_offset: self.use_system_local_offset,
            monthly_spend,
            budget: self.settings.budget,
            region: &resolved.region,
            activity,
            history,
        })
    }

    /// Fetches the optional rolling 30-day Cost Explorer history independently.
    ///
    /// This path is intended for the runtime's lower-frequency cost-history
    /// refresh source. Named-profile credentials are refreshed for each call.
    ///
    /// # Errors
    ///
    /// Returns stable context, credential, transport, API, or parse failures.
    pub async fn fetch_cost_history_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<CostUsageSnapshot, ClassifiedError> {
        self.validate_context(context)?;
        let resolved = self.resolve_credentials(context.cancellation()).await?;
        self.fetch_cost_history_with_credentials(
            &resolved.credentials,
            fetched_at,
            context.cancellation(),
        )
        .await
    }

    async fn resolve_credentials(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<ResolvedCredentials, ClassifiedError> {
        match &self.settings.credential_source {
            BedrockCredentialSource::Keys(bundle) => Ok(ResolvedCredentials {
                credentials: bundle.signer_credentials()?,
                region: self
                    .settings
                    .configured_region
                    .clone()
                    .unwrap_or_else(|| DEFAULT_REGION.to_owned()),
            }),
            BedrockCredentialSource::Profile {
                profile,
                aws_cli,
                environment,
            } => {
                let provider =
                    BedrockProfileCredentialProvider::new(aws_cli.clone(), environment.clone());
                let credentials = provider.export_credentials(profile, cancellation).await?;
                let region = if let Some(region) = &self.settings.configured_region {
                    region.clone()
                } else {
                    provider
                        .resolve_region(profile, cancellation)
                        .await?
                        .unwrap_or_else(|| DEFAULT_REGION.to_owned())
                };
                Ok(ResolvedCredentials {
                    credentials,
                    region,
                })
            }
        }
    }

    async fn fetch_monthly_cost(
        &self,
        credentials: &AwsCredentials,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> Result<Decimal, ClassifiedError> {
        let now = fetched_at.as_offset_date_time().to_offset(UtcOffset::UTC);
        let start = Date::from_calendar_date(now.year(), now.month(), 1)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let end = now
            .date()
            .checked_add(TimeDuration::DAY)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let pages = self
            .cost_explorer_pages(
                credentials,
                &date_text(start),
                &date_text(end),
                "MONTHLY",
                cancellation,
            )
            .await?;
        pages.into_iter().try_fold(Decimal::ZERO, |sum, page| {
            page.groups.into_iter().try_fold(sum, |sum, group| {
                sum.checked_add(group.amount)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
            })
        })
    }

    async fn fetch_cost_history_with_credentials(
        &self,
        credentials: &AwsCredentials,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> Result<CostUsageSnapshot, ClassifiedError> {
        let now = fetched_at.as_offset_date_time().to_offset(UtcOffset::UTC);
        let start = now
            .date()
            .checked_sub(TimeDuration::days(i64::from(HISTORY_DAYS - 1)))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let end = now
            .date()
            .checked_add(TimeDuration::DAY)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let pages = self
            .cost_explorer_pages(
                credentials,
                &date_text(start),
                &date_text(end),
                "DAILY",
                cancellation,
            )
            .await?;
        build_history(pages, fetched_at)
    }

    async fn cost_explorer_pages(
        &self,
        credentials: &AwsCredentials,
        start: &str,
        end: &str,
        granularity: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ParsedCostPage>, ClassifiedError> {
        let transport = transport_for(&self.settings.cost_explorer_endpoint)?;
        let mut pages = Vec::new();
        let mut next_page_token = None;
        let mut seen_tokens = BTreeSet::new();
        loop {
            if pages.len() == MAX_PAGES {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            let body = cost_explorer_body(start, end, granularity, next_page_token.as_deref())?;
            let request =
                HttpRequest::post(self.settings.cost_explorer_endpoint.url().clone(), body)
                    .map_err(|error| error.classified())?
                    .content_type(RequestContentType::AwsJson11)
                    .public_header("x-amz-target", COST_EXPLORER_TARGET)
                    .map_err(|error| error.classified())?
                    .accepted_statuses(&[400])
                    .map_err(|error| error.classified())?
                    .authentication(
                        Authentication::aws_sig_v4(
                            credentials.clone(),
                            COST_EXPLORER_REGION,
                            COST_EXPLORER_SERVICE,
                        )
                        .map_err(|error| error.classified())?,
                    );
            let response = transport
                .send(&request, cancellation)
                .await
                .map_err(|error| error.classified())?;
            let page = if response.status() == 200 {
                parse_cost_page(response.body())?
            } else if response.status() == 400 && is_data_unavailable(response.body()) {
                ParsedCostPage::default()
            } else {
                return Err(ClassifiedError::new(ErrorKind::Api));
            };
            next_page_token.clone_from(&page.next_page_token);
            if let Some(token) = &next_page_token
                && !seen_tokens.insert(token.clone())
            {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            pages.push(page);
            if next_page_token.is_none() {
                return Ok(pages);
            }
        }
    }

    fn should_fetch_cloudwatch(&self) -> bool {
        !self.settings.cost_explorer_is_override || self.settings.cloudwatch_endpoint.is_some()
    }

    async fn fetch_cloudwatch(
        &self,
        credentials: &AwsCredentials,
        region: &str,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> Result<CloudActivity, ClassifiedError> {
        let generated_endpoint;
        let endpoint = if let Some(endpoint) = &self.settings.cloudwatch_endpoint {
            endpoint
        } else {
            generated_endpoint = cloudwatch_endpoint(region)?;
            &generated_endpoint
        };
        let transport = transport_for(endpoint)?;
        let end = fetched_at.unix_timestamp();
        let start = end
            .checked_sub(CLOUDWATCH_DAYS * 24 * 60 * 60)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let mut totals = CloudMetricTotals::default();
        let mut next_token = None;
        let mut seen_tokens = BTreeSet::new();
        for _ in 0..MAX_PAGES {
            let body = cloudwatch_body(start, end, next_token.as_deref())?;
            let request = HttpRequest::post(endpoint.url().clone(), body)
                .map_err(|error| error.classified())?
                .content_type(RequestContentType::AwsJson10)
                .public_header("x-amz-target", CLOUDWATCH_TARGET)
                .map_err(|error| error.classified())?
                .authentication(
                    Authentication::aws_sig_v4(
                        credentials.clone(),
                        region.to_owned(),
                        CLOUDWATCH_SERVICE,
                    )
                    .map_err(|error| error.classified())?,
                );
            let response = transport
                .send(&request, cancellation)
                .await
                .map_err(|error| error.classified())?;
            if response.status() != 200 {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            let page = parse_cloudwatch_page(response.body())?;
            totals.add(&page.totals)?;
            next_token = page.next_token;
            if let Some(token) = &next_token
                && !seen_tokens.insert(token.clone())
            {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            if next_token.is_none() {
                return totals.finish();
            }
        }
        Err(ClassifiedError::new(ErrorKind::Parse))
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::CloudCredentials {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(())
    }
}

impl ProviderAdapter for BedrockProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Bedrock)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Default)]
struct ParsedCostPage {
    groups: Vec<CostGroup>,
    next_page_token: Option<String>,
}

struct CostGroup {
    day: Option<String>,
    service: String,
    amount: Decimal,
}

#[derive(Debug, Clone, Copy)]
enum CloudMetric {
    InputTokens,
    OutputTokens,
    Requests,
}

impl CloudMetric {
    const ALL: [Self; 3] = [Self::InputTokens, Self::OutputTokens, Self::Requests];

    const fn id(self) -> &'static str {
        match self {
            Self::InputTokens => "inputTokens",
            Self::OutputTokens => "outputTokens",
            Self::Requests => "requests",
        }
    }

    const fn aws_name(self) -> &'static str {
        match self {
            Self::InputTokens => "InputTokenCount",
            Self::OutputTokens => "OutputTokenCount",
            Self::Requests => "Invocations",
        }
    }

    fn from_id(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|metric| metric.id() == value)
    }
}

#[derive(Default)]
struct CloudMetricTotals {
    input_tokens: f64,
    output_tokens: f64,
    requests: f64,
}

impl CloudMetricTotals {
    fn add_metric(&mut self, metric: CloudMetric, value: f64) -> Result<(), ClassifiedError> {
        let target = match metric {
            CloudMetric::InputTokens => &mut self.input_tokens,
            CloudMetric::OutputTokens => &mut self.output_tokens,
            CloudMetric::Requests => &mut self.requests,
        };
        *target += value;
        if !target.is_finite() {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(())
    }

    fn add(&mut self, other: &Self) -> Result<(), ClassifiedError> {
        self.add_metric(CloudMetric::InputTokens, other.input_tokens)?;
        self.add_metric(CloudMetric::OutputTokens, other.output_tokens)?;
        self.add_metric(CloudMetric::Requests, other.requests)
    }

    fn finish(self) -> Result<CloudActivity, ClassifiedError> {
        Ok(CloudActivity {
            input_tokens: rounded_i64(self.input_tokens)?,
            output_tokens: rounded_i64(self.output_tokens)?,
            requests: rounded_i64(self.requests)?,
        })
    }
}

struct CloudWatchPage {
    totals: CloudMetricTotals,
    next_token: Option<String>,
}

#[derive(Clone, Copy)]
struct CloudActivity {
    input_tokens: i64,
    output_tokens: i64,
    requests: i64,
}

struct BedrockNormalization<'a> {
    scope: AccountScope,
    fetched_at: Timestamp,
    local_offset: UtcOffset,
    use_system_local_offset: bool,
    monthly_spend: Decimal,
    budget: Option<Decimal>,
    region: &'a str,
    activity: Option<CloudActivity>,
    history: Option<CostUsageSnapshot>,
}

fn normalize(input: BedrockNormalization<'_>) -> Result<UsageSample, ClassifiedError> {
    let BedrockNormalization {
        scope,
        fetched_at,
        local_offset,
        use_system_local_offset,
        monthly_spend,
        budget,
        region,
        activity,
        history,
    } = input;
    let resets_at = next_local_month(fetched_at, local_offset, use_system_local_offset)?;
    let currency = CurrencyCode::new("USD").map_err(parse_error)?;
    let cost = CostSummary::new(
        CostAmount::money(ExactDecimal::new(monthly_spend), currency),
        ExactDecimal::new(budget.unwrap_or(Decimal::ZERO)),
        Some("Monthly".to_owned()),
        Some(resets_at),
        None,
        None,
        None,
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map_err(parse_error)?;

    let mut login_parts = vec![format!("Spend: {}", format_usd(monthly_spend))];
    if let Some(limit) = budget {
        login_parts.push(format!("Budget: {}", format_usd(limit)));
    }
    if let Some(activity) = activity {
        let total = u128::from(activity.input_tokens.unsigned_abs())
            + u128::from(activity.output_tokens.unsigned_abs());
        login_parts.push(format!("Claude 14d: {} tokens", format_token_count(total)));
        login_parts.push(format!(
            "Requests: {}",
            format_token_count(u128::from(activity.requests.unsigned_abs()))
        ));
    }

    let mut billing_rows = vec![
        detail_row("Month-to-date spend", format_usd(monthly_spend))?,
        detail_row("Region", region.to_owned())?,
    ];
    if let Some(limit) = budget {
        billing_rows.insert(1, detail_row("Monthly budget", format_usd(limit))?);
    }
    let mut details = vec![
        DetailSection::new(Some("AWS billing".to_owned()), billing_rows, None)
            .map_err(parse_error)?,
    ];
    if let Some(activity) = activity {
        details.push(
            DetailSection::new(
                Some("Claude activity (14 days)".to_owned()),
                vec![
                    detail_row("Input tokens", activity.input_tokens.to_string())?,
                    detail_row("Output tokens", activity.output_tokens.to_string())?,
                    detail_row("Requests", activity.requests.to_string())?,
                ],
                None,
            )
            .map_err(parse_error)?,
        );
    }

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .cost(cost)
        .login_method(Some(login_parts.join(" - ")))?
        .detail_sections(details);
    if let Some(limit) = budget {
        let percent = if monthly_spend <= Decimal::ZERO {
            0.0
        } else if monthly_spend >= limit {
            100.0
        } else {
            monthly_spend
                .checked_div(limit)
                .and_then(|value| value.checked_mul(Decimal::from(100_u8)))
                .and_then(|value| value.to_f64())
                .filter(|value| value.is_finite())
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
                .clamp(0.0, 100.0)
        };
        let window = RateWindow::new(
            WindowUsage::known(UsagePercent::new(percent).map_err(parse_error)?),
            None,
            Some(resets_at),
            Some(oab_domain::BoundedText::new("Monthly budget").map_err(parse_error)?),
            None,
            false,
        )
        .map_err(parse_error)?;
        builder = builder.primary(window);
    }
    if let Some(history) = history {
        builder = builder.cost_usage(history);
    }
    builder.provenance("bedrock", "aws")?.build()
}

fn build_history(
    pages: Vec<ParsedCostPage>,
    fetched_at: Timestamp,
) -> Result<CostUsageSnapshot, ClassifiedError> {
    let mut grouped = BTreeMap::<String, BTreeMap<String, Decimal>>::new();
    for group in pages.into_iter().flat_map(|page| page.groups) {
        let Some(day) = group.day else {
            continue;
        };
        // The billing summary retains signed Cost Explorer adjustments, while
        // daily history intentionally includes only positive rows.
        if group.amount <= Decimal::ZERO {
            continue;
        }
        let services = grouped.entry(day).or_default();
        let amount = services.entry(group.service).or_default();
        *amount = amount
            .checked_add(group.amount)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    }

    let mut daily = Vec::new();
    let mut history_total = Decimal::ZERO;
    for (day, services) in grouped {
        let mut day_total = Decimal::ZERO;
        let mut models = Vec::new();
        for (service, amount) in services {
            day_total = day_total
                .checked_add(amount)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            if amount > Decimal::ZERO {
                models.push(
                    CostUsageModelBreakdown::new(
                        service,
                        cost_metrics(Some(amount))?,
                        None,
                        None,
                        None,
                        None,
                    )
                    .map_err(parse_error)?,
                );
            }
        }
        if day_total <= Decimal::ZERO {
            continue;
        }
        history_total = history_total
            .checked_add(day_total)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let names = models.iter().map(|model| model.name().to_owned()).collect();
        daily.push(
            CostUsageDailyBucket::new(
                day,
                None,
                cost_metrics(Some(day_total))?,
                names,
                models,
                Vec::new(),
            )
            .map_err(parse_error)?,
        );
    }
    let session_amount = daily
        .last()
        .and_then(|bucket| bucket.metrics().amount())
        .map(ExactDecimal::get)
        .or(Some(Decimal::ZERO));
    let currency = CurrencyCode::new("USD").map_err(parse_error)?;
    CostUsageSnapshot::new(
        CostUnit::currency(currency),
        cost_metrics(session_amount)?,
        cost_metrics(Some(history_total))?,
        Some(ExactDecimal::new(history_total)),
        HISTORY_DAYS,
        true,
        Some("Last 30 days (UTC)".to_owned()),
        None,
        daily,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        fetched_at,
        CostProvenance::VendorMetered,
    )
    .map_err(parse_error)
}

fn cost_metrics(amount: Option<Decimal>) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::default(),
        None,
        None,
        amount.map(ExactDecimal::new),
        CostUsageCoverage::default(),
    )
    .map_err(parse_error)
}

fn cost_explorer_body(
    start: &str,
    end: &str,
    granularity: &str,
    next_page_token: Option<&str>,
) -> Result<Vec<u8>, ClassifiedError> {
    let mut body = Map::from_iter([
        ("TimePeriod".to_owned(), json!({"Start": start, "End": end})),
        (
            "Granularity".to_owned(),
            Value::String(granularity.to_owned()),
        ),
        ("Metrics".to_owned(), json!(["UnblendedCost"])),
        (
            "GroupBy".to_owned(),
            json!([{"Type": "DIMENSION", "Key": "SERVICE"}]),
        ),
    ]);
    if let Some(token) = next_page_token {
        body.insert("NextPageToken".to_owned(), Value::String(token.to_owned()));
    }
    serde_json::to_vec(&body).map_err(parse_error)
}

fn parse_cost_page(body: &[u8]) -> Result<ParsedCostPage, ClassifiedError> {
    let root = serde_json::from_slice::<Value>(body).map_err(parse_error)?;
    let object = root
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let results = object
        .get("ResultsByTime")
        .and_then(Value::as_array)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if results.len() > MAX_RESULTS_PER_PAGE {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let next_page_token = optional_token(object.get("NextPageToken"))?;
    let mut groups_out = Vec::new();
    for result in results {
        let Some(result) = result.as_object() else {
            continue;
        };
        let day = result
            .get("TimePeriod")
            .and_then(Value::as_object)
            .and_then(|period| period.get("Start"))
            .and_then(Value::as_str)
            .and_then(valid_day_text);
        let Some(groups) = result.get("Groups").and_then(Value::as_array) else {
            continue;
        };
        if groups.len() > MAX_GROUPS_PER_RESULT {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        for group in groups {
            let Some(group) = group.as_object() else {
                continue;
            };
            let Some(service) = group
                .get("Keys")
                .and_then(Value::as_array)
                .and_then(|keys| keys.first())
                .and_then(Value::as_str)
            else {
                continue;
            };
            if !ascii_contains_case_insensitive(service, "bedrock") {
                continue;
            }
            if service.is_empty()
                || service.len() > MAX_SERVICE_NAME_BYTES
                || service.chars().any(char::is_control)
            {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            let amount = group
                .get("Metrics")
                .and_then(Value::as_object)
                .and_then(|metrics| metrics.get("UnblendedCost"))
                .and_then(Value::as_object)
                .and_then(|metric| metric.get("Amount"))
                .and_then(Value::as_str)
                .and_then(parse_decimal)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            groups_out.push(CostGroup {
                day: day.clone(),
                service: service.to_owned(),
                amount,
            });
        }
    }
    Ok(ParsedCostPage {
        groups: groups_out,
        next_page_token,
    })
}

fn is_data_unavailable(body: &[u8]) -> bool {
    let Ok(Value::Object(root)) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let nested = root.get("Error").and_then(Value::as_object);
    [
        root.get("__type"),
        root.get("code"),
        root.get("Code"),
        nested.and_then(|value| value.get("Code")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .any(|value| value.rsplit('#').next() == Some("DataUnavailableException"))
}

fn cloudwatch_body(
    start: i64,
    end: i64,
    next_token: Option<&str>,
) -> Result<Vec<u8>, ClassifiedError> {
    let queries = CloudMetric::ALL
        .into_iter()
        .map(|metric| {
            let search = format!(
                "SEARCH('{{AWS/Bedrock,ModelId}} MetricName=\"{}\" claude', 'Sum', 86400)",
                metric.aws_name()
            );
            json!({
                "Id": metric.id(),
                "Expression": format!("SUM({search})"),
                "ReturnData": true,
            })
        })
        .collect::<Vec<_>>();
    let mut body = Map::from_iter([
        ("StartTime".to_owned(), Value::from(start)),
        ("EndTime".to_owned(), Value::from(end)),
        (
            "ScanBy".to_owned(),
            Value::String("TimestampAscending".to_owned()),
        ),
        ("MetricDataQueries".to_owned(), Value::Array(queries)),
    ]);
    if let Some(token) = next_token {
        body.insert("NextToken".to_owned(), Value::String(token.to_owned()));
    }
    serde_json::to_vec(&body).map_err(parse_error)
}

fn parse_cloudwatch_page(body: &[u8]) -> Result<CloudWatchPage, ClassifiedError> {
    let root = serde_json::from_slice::<Value>(body).map_err(parse_error)?;
    let object = root
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    match object.get("Messages") {
        None | Some(Value::Null) => {}
        Some(Value::Array(messages)) if messages.is_empty() => {}
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    }
    let results = match object.get("MetricDataResults") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(results)) => results.as_slice(),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    if results.len() > MAX_METRIC_RESULTS_PER_PAGE {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut totals = CloudMetricTotals::default();
    for result in results {
        let result = result
            .as_object()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let metric = result
            .get("Id")
            .and_then(Value::as_str)
            .and_then(CloudMetric::from_id)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        if result.get("StatusCode").and_then(Value::as_str) != Some("Complete") {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let values = match result.get("Values") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(values)) => values.as_slice(),
            Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
        };
        for value in values {
            let number = value
                .as_f64()
                .filter(|value| value.is_finite() && *value >= 0.0)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            totals.add_metric(metric, number)?;
        }
    }
    Ok(CloudWatchPage {
        totals,
        next_token: optional_token(object.get("NextToken"))?,
    })
}

fn cloudwatch_endpoint(region: &str) -> Result<ConfiguredEndpoint, ClassifiedError> {
    if !valid_region(region) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else if region.starts_with("eusc-") {
        "amazonaws.eu"
    } else if region.starts_with("us-iso-") {
        "c2s.ic.gov"
    } else if region.starts_with("us-isob-") {
        "sc2s.sgov.gov"
    } else if region.starts_with("eu-isoe-") {
        "cloud.adc-e.uk"
    } else if region.starts_with("us-isof-") {
        "csp.hci.ic.gov"
    } else {
        "amazonaws.com"
    };
    ConfiguredEndpoint::parse(
        &format!("https://monitoring.{region}.{suffix}"),
        ConfiguredHttpPolicy::HttpsOnly,
    )
}

fn transport_for(endpoint: &ConfiguredEndpoint) -> Result<HttpTransport, ClassifiedError> {
    let policy = EndpointPolicy::new([(
        endpoint.url().origin().ascii_serialization(),
        endpoint.class(),
    )])
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn explicit_auth_mode(environment: &BTreeMap<String, String>) -> Option<BedrockAuthMode> {
    match clean_environment_value(environment, AUTH_MODE_KEY)?
        .to_ascii_lowercase()
        .as_str()
    {
        "keys" => Some(BedrockAuthMode::Keys),
        "profile" => Some(BedrockAuthMode::Profile),
        _ => None,
    }
}

fn environment_bundle(
    environment: &BTreeMap<String, String>,
) -> Result<Option<BedrockCredentialBundle>, ClassifiedError> {
    let Some(access_key_id) = clean_environment_value(environment, ACCESS_KEY_ID_KEY) else {
        return Ok(None);
    };
    let Some(secret_access_key) = clean_environment_value(environment, SECRET_ACCESS_KEY_KEY)
    else {
        return Ok(None);
    };
    BedrockCredentialBundle::new(
        access_key_id,
        secret_access_key,
        clean_environment_value(environment, SESSION_TOKEN_KEY),
    )
    .map(Some)
}

fn profile_environment(
    environment: &BTreeMap<String, String>,
) -> Result<Vec<CliEnvironmentValue>, ClassifiedError> {
    let mut values = Vec::new();
    for (name, value) in environment {
        if name == PROFILE_KEY || !name.starts_with("AWS_") {
            continue;
        }
        let Some(value) = clean_owned(value) else {
            continue;
        };
        if values.len() == MAX_CLI_ENVIRONMENT_VALUES {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        values.push(CliEnvironmentValue {
            name: name.clone(),
            value: Zeroizing::new(value),
        });
    }
    Ok(values)
}

fn resolve_aws_cli(
    environment: &BTreeMap<String, String>,
) -> Result<Option<ExecutablePath>, ClassifiedError> {
    let configured = environment.get(AWS_CLI_PATH_KEY).map(String::as_str);
    let path = environment.get("PATH").map(String::as_str).map(OsStr::new);
    let home = environment
        .get("HOME")
        .and_then(|value| clean_setting(value))
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(PathBuf::from));
    let mut fallbacks = vec![
        PathBuf::from("/usr/bin/aws"),
        PathBuf::from("/usr/local/bin/aws"),
    ];
    if let Some(home) = home {
        fallbacks.push(home.join(".local/bin/aws"));
    }
    resolve_executable("aws", configured, path, &fallbacks)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn parse_exported_credentials(
    output: &SubprocessOutput,
) -> Result<AwsCredentials, ClassifiedError> {
    let root = serde_json::from_slice::<Value>(output.stdout()).map_err(parse_error)?;
    let object = root
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let access_key_id = object
        .get("AccessKeyId")
        .and_then(Value::as_str)
        .and_then(clean_owned)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let secret_access_key = object
        .get("SecretAccessKey")
        .and_then(Value::as_str)
        .and_then(clean_owned)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let session_token = match object.get("SessionToken") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => clean_owned(value),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    AwsCredentials::new(access_key_id, secret_access_key, session_token)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn map_export_error(error: SubprocessError) -> ClassifiedError {
    match error {
        SubprocessError::NonZero {
            stderr_tag: Some(EXPIRED_STDERR_TAG),
            ..
        } => ClassifiedError::new(ErrorKind::AuthenticationExpired),
        other => map_subprocess_error(other),
    }
}

fn map_subprocess_error(error: SubprocessError) -> ClassifiedError {
    match error {
        SubprocessError::Spawn => ClassifiedError::new(ErrorKind::MissingCredential),
        SubprocessError::Cancelled | SubprocessError::Timeout | SubprocessError::Wait => {
            ClassifiedError::new(ErrorKind::Network)
        }
        SubprocessError::InvalidConfiguration | SubprocessError::NonZero { .. } => {
            ClassifiedError::new(ErrorKind::Api)
        }
        SubprocessError::OutputRead
        | SubprocessError::StdoutTooLarge
        | SubprocessError::StderrTooLarge => ClassifiedError::new(ErrorKind::Parse),
    }
}

fn optional_token(value: Option<&Value>) -> Result<Option<String>, ClassifiedError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let token = clean_owned(value);
            if token
                .as_ref()
                .is_some_and(|token| token.len() > MAX_PAGE_TOKEN_BYTES)
            {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            Ok(token)
        }
        Some(_) => Err(ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn clean_environment_value(environment: &BTreeMap<String, String>, key: &str) -> Option<String> {
    environment.get(key).and_then(clean_owned)
}

fn clean_owned(value: impl AsRef<str>) -> Option<String> {
    clean_setting(value.as_ref()).map(str::to_owned)
}

fn valid_profile(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_PROFILE_BYTES && !value.chars().any(char::is_control)
}

fn valid_region(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() >= 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
        && parts
            .last()
            .is_some_and(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_day_text(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return None;
    }
    let year = value[0..4].parse::<i32>().ok()?;
    let month = value[5..7].parse::<u8>().ok()?;
    let day = value[8..10].parse::<u8>().ok()?;
    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()?;
    Some(value.to_owned())
}

fn parse_decimal(value: &str) -> Option<Decimal> {
    Decimal::from_scientific(value)
        .or_else(|_| value.parse())
        .ok()
}

fn ascii_contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn rounded_i64(value: f64) -> Result<i64, ClassifiedError> {
    const I64_UPPER_BOUND: f64 = 9_223_372_036_854_775_808.0;
    let rounded = value.round();
    if rounded >= I64_UPPER_BOUND {
        return Ok(i64::MAX);
    }
    rounded
        .to_i64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn next_local_month(
    fetched_at: Timestamp,
    fallback_offset: UtcOffset,
    use_system_local_offset: bool,
) -> Result<Timestamp, ClassifiedError> {
    if use_system_local_offset {
        return next_local_month_with_resolver(fetched_at, fallback_offset, |instant| {
            UtcOffset::local_offset_at(instant).ok()
        });
    }
    next_local_month_with_resolver(fetched_at, fallback_offset, |_| None)
}

fn next_local_month_with_resolver(
    fetched_at: Timestamp,
    fallback_offset: UtcOffset,
    mut resolve_offset: impl FnMut(time::OffsetDateTime) -> Option<UtcOffset>,
) -> Result<Timestamp, ClassifiedError> {
    let local_offset = resolve_offset(fetched_at.as_offset_date_time()).unwrap_or(fallback_offset);
    let local = fetched_at.as_offset_date_time().to_offset(local_offset);
    let (year, month) = if local.month() == Month::December {
        (
            local
                .year()
                .checked_add(1)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
            Month::January,
        )
    } else {
        let number = u8::from(local.month()).saturating_add(1);
        (
            local.year(),
            Month::try_from(number).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        )
    };
    let date = Date::from_calendar_date(year, month, 1)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let local_midnight = date.with_time(Time::MIDNIGHT);
    let mut target_offset = local_offset;
    for _ in 0..4 {
        let candidate = local_midnight.assume_offset(target_offset);
        let observed = resolve_offset(candidate).unwrap_or(target_offset);
        if observed == target_offset {
            return Timestamp::new(candidate).map_err(parse_error);
        }
        target_offset = observed;
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn date_text(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn detail_row(label: &str, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Public).map_err(parse_error)
}

fn format_usd(value: Decimal) -> String {
    format!("${value:.2}")
}

fn format_token_count(value: u128) -> String {
    if value >= 1_000_000 {
        format_scaled_count(value, 1_000_000, 'M')
    } else if value >= 1_000 {
        format_scaled_count(value, 1_000, 'K')
    } else {
        value.to_string()
    }
}

fn format_scaled_count(value: u128, divisor: u128, suffix: char) -> String {
    let mut whole = value / divisor;
    let remainder = value % divisor;
    let mut tenth = (remainder * 10 + divisor / 2) / divisor;
    if tenth == 10 {
        whole += 1;
        tenth = 0;
    }
    format!("{whole}.{tenth}{suffix}")
}

fn parse_error<T>(_: T) -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_calendar_resolves_the_offset_at_the_future_month_boundary() {
        let fetched_at = Timestamp::parse("2026-03-01T12:00:00Z").expect("fetch timestamp");
        let transition = Timestamp::parse("2026-03-08T07:00:00Z")
            .expect("transition timestamp")
            .as_offset_date_time();
        let standard = UtcOffset::from_hms(-5, 0, 0).expect("standard offset");
        let daylight = UtcOffset::from_hms(-4, 0, 0).expect("daylight offset");

        let reset = next_local_month_with_resolver(fetched_at, standard, |instant| {
            Some(if instant < transition {
                standard
            } else {
                daylight
            })
        })
        .expect("DST-aware reset");

        assert_eq!(
            reset,
            Timestamp::parse("2026-04-01T04:00:00Z").expect("expected reset")
        );
    }
}
