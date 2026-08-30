//! Amp Free, subscription, and credit usage through the native CLI or bearer API.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, NamedRateWindow, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample,
    WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};
use url::Url;
use zeroize::Zeroizing;

use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::executable::{ExecutablePath, resolve_executable};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{StderrClassifier, SubprocessError, SubprocessRequest};
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
};

const API_ENDPOINT: &str = "https://ampcode.com/api/internal?userDisplayBalanceInfo";
const API_TOKEN_KEY: &str = "AMP_API_KEY";
const CLI_OVERRIDE: &str = "OMARCHY_AI_BAR_AMP_PATH";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_DISPLAY_TEXT_BYTES: usize = 256 * 1024;
const MAX_DISPLAY_LINES: usize = 4_096;
const MAX_WORKSPACES: usize = 23;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_PLAN_BYTES: usize = 256;
const MAX_WORKSPACE_NAME_BYTES: usize = 110;
const CLI_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_STDOUT_BYTES: usize = MAX_DISPLAY_TEXT_BYTES;
const CLI_STDERR_BYTES: usize = MAX_DISPLAY_TEXT_BYTES;
const MAX_CLI_CUSTOM_VALUE_BYTES: usize = 4 * 1024;
const AUTH_STDERR_TAG: u8 = 1;
const MONTHLY_SECONDS: u64 = 30 * 24 * 60 * 60;

/// A bounded Amp access token which is zeroized on drop.
#[derive(Clone)]
pub struct AmpApiCredential {
    value: Zeroizing<String>,
}

impl AmpApiCredential {
    /// Resolves `AMP_API_KEY`, preserving the baseline trim-and-unquote behavior.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for absent or unsafe values.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        environment
            .get(API_TOKEN_KEY)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
            .and_then(Self::new)
    }

    /// Validates one explicitly selected Amp access token.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for empty, oversized, or
    /// line-breaking values.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ClassifiedError> {
        let value = clean_setting(value.as_ref())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        if value.len() > MAX_TOKEN_BYTES || value.contains(['\r', '\n']) {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        Ok(Self {
            value: Zeroizing::new(value.to_owned()),
        })
    }

    fn authentication(&self) -> Result<Authentication, ClassifiedError> {
        Authentication::bearer(self.value.as_str().to_owned()).map_err(|error| error.classified())
    }
}

impl Debug for AmpApiCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AmpApiCredential(<redacted>)")
    }
}

/// Resolved shell-free Amp CLI configuration.
pub struct AmpCliSettings {
    executable: ExecutablePath,
    environment: Vec<(String, String)>,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl AmpCliSettings {
    /// Resolves the Amp executable from the application override, absolute
    /// `PATH` entries, and bounded Linux install locations.
    ///
    /// # Errors
    ///
    /// Returns missing-credential when no executable is installed and API for
    /// an invalid or unavailable authoritative override.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let executable = resolve_amp(environment)?;
        Self::from_executable(executable, environment)
    }

    /// Creates CLI settings from one explicit absolute executable path.
    ///
    /// # Errors
    ///
    /// Returns API for a relative/non-executable path or unsafe environment.
    pub fn new(
        executable: impl Into<PathBuf>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let executable = executable.into();
        let configured = executable
            .to_str()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        let executable = resolve_executable("amp", Some(configured), None, &[])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_executable(executable, environment)
    }

    fn from_executable(
        executable: ExecutablePath,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let sanitized = sanitized_cli_environment(environment, executable.as_path())?;
        Ok(Self {
            executable,
            environment: sanitized,
            timeout: CLI_TIMEOUT,
            max_stdout_bytes: CLI_STDOUT_BYTES,
            max_stderr_bytes: CLI_STDERR_BYTES,
        })
    }

    /// Returns the resolved executable for setup diagnostics.
    #[must_use]
    pub fn executable(&self) -> &Path {
        self.executable.as_path()
    }

    /// Overrides resource limits for deterministic subprocess tests.
    ///
    /// # Errors
    ///
    /// Rejects zero or production-exceeding values.
    #[doc(hidden)]
    pub fn with_test_limits(
        mut self,
        timeout: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, ClassifiedError> {
        if timeout.is_zero()
            || timeout > CLI_TIMEOUT
            || max_stdout_bytes == 0
            || max_stdout_bytes > CLI_STDOUT_BYTES
            || max_stderr_bytes == 0
            || max_stderr_bytes > CLI_STDERR_BYTES
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        self.timeout = timeout;
        self.max_stdout_bytes = max_stdout_bytes;
        self.max_stderr_bytes = max_stderr_bytes;
        Ok(self)
    }
}

impl Debug for AmpCliSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmpCliSettings")
            .field("executable", &"<redacted>")
            .field("environment_entries", &self.environment.len())
            .field("timeout", &self.timeout)
            .field("max_stdout_bytes", &self.max_stdout_bytes)
            .field("max_stderr_bytes", &self.max_stderr_bytes)
            .finish()
    }
}

/// Amp adapter permanently bound to one account and one explicit source.
pub struct AmpProvider {
    scope: AccountScope,
    backend: Backend,
}

enum Backend {
    Api(ApiBackend),
    Cli(AmpCliSettings),
}

struct ApiBackend {
    credential: AmpApiCredential,
    endpoint: Url,
    transport: HttpTransport,
}

impl AmpProvider {
    /// Resolves and constructs only the selected non-browser source.
    ///
    /// Browser-session and manual-cookie modes are intentionally owned by the
    /// shared Linux browser boundary rather than silently mixed here.
    ///
    /// # Errors
    ///
    /// Returns a stable error for unsupported sources or unusable credentials.
    pub fn resolve(
        scope: AccountScope,
        source: ProviderSource,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        match source {
            ProviderSource::ApiKey => Self::new_api(scope, AmpApiCredential::resolve(environment)?),
            ProviderSource::Cli => Self::new_cli(scope, AmpCliSettings::resolve(environment)?),
            ProviderSource::BrowserSession
            | ProviderSource::ManualCookie
            | ProviderSource::CloudCredentials
            | ProviderSource::ConfigurableEndpoint
            | ProviderSource::OAuth
            | ProviderSource::LocalData => Err(ClassifiedError::new(ErrorKind::Api)),
        }
    }

    /// Creates the production fixed-origin bearer API adapter.
    ///
    /// # Errors
    ///
    /// Returns API for a wrong provider scope or invalid transport setup.
    pub fn new_api(
        scope: AccountScope,
        credential: AmpApiCredential,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        let endpoint =
            Url::parse(API_ENDPOINT).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let policy = EndpointPolicy::new([(
            endpoint.origin().ascii_serialization(),
            EndpointClass::PublicHttps,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Self::from_api_transport(scope, credential, endpoint, transport)
    }

    /// Creates the shell-free Amp CLI adapter.
    ///
    /// # Errors
    ///
    /// Returns API for a wrong provider scope.
    pub fn new_cli(scope: AccountScope, settings: AmpCliSettings) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        Ok(Self {
            scope,
            backend: Backend::Cli(settings),
        })
    }

    /// Deterministic loopback seam retaining transport-owned endpoint policy.
    ///
    /// # Errors
    ///
    /// Rejects wrong-provider scopes and malformed balance endpoints.
    #[doc(hidden)]
    pub fn from_api_transport(
        scope: AccountScope,
        credential: AmpApiCredential,
        endpoint: Url,
        transport: HttpTransport,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        validate_api_endpoint(&endpoint)?;
        Ok(Self {
            scope,
            backend: Backend::Api(ApiBackend {
                credential,
                endpoint,
                transport,
            }),
        })
    }

    /// Source to which this adapter is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        match self.backend {
            Backend::Api(_) => ProviderSource::ApiKey,
            Backend::Cli(_) => ProviderSource::Cli,
        }
    }

    /// Fetches one sample at an injected wall-clock instant.
    ///
    /// # Errors
    ///
    /// Returns only stable scope, credential, subprocess, transport, or parse
    /// classifications without provider-controlled text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        match &self.backend {
            Backend::Api(backend) => fetch_api(backend, context, fetched_at).await,
            Backend::Cli(settings) => fetch_cli(settings, context, fetched_at).await,
        }
    }
}

impl Debug for AmpProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmpProvider")
            .field("scope", &self.scope)
            .field("source", &self.source())
            .finish_non_exhaustive()
    }
}

impl ProviderAdapter for AmpProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Amp)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

async fn fetch_api(
    backend: &ApiBackend,
    context: &ProviderContext,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let body = serde_json::to_vec(&serde_json::json!({
        "method": "userDisplayBalanceInfo",
        "params": {},
    }))
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let request = HttpRequest::post_json(backend.endpoint.clone(), body)
        .map_err(|error| error.classified())?
        .accept(RequestAccept::Json)
        .content_type(RequestContentType::Json)
        .authentication(backend.credential.authentication()?)
        .accepted_statuses(&[401, 403])
        .map_err(|error| error.classified())?;
    let response = backend
        .transport
        .send(&request, context.cancellation())
        .await
        .map_err(|error| error.classified())?;
    if matches!(response.status(), 401 | 403) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if response.status() != 200 {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let wire: UsageApiResponse = response.json()?;
    if !wire.ok {
        return Err(ClassifiedError::new(
            if wire.error.as_ref().and_then(|error| error.code.as_deref()) == Some("auth-required")
            {
                ErrorKind::AuthenticationExpired
            } else {
                ErrorKind::Api
            },
        ));
    }
    let display_text = wire
        .result
        .map(|result| result.display_text)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    parse_display_text(
        context.scope().clone(),
        fetched_at,
        &display_text,
        ProviderSource::ApiKey,
    )
}

async fn fetch_cli(
    settings: &AmpCliSettings,
    context: &ProviderContext,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let classifier = StderrClassifier::ascii_case_insensitive([
        (AUTH_STDERR_TAG, "not logged in"),
        (AUTH_STDERR_TAG, "not authenticated"),
        (AUTH_STDERR_TAG, "authentication required"),
        (AUTH_STDERR_TAG, "login required"),
        (AUTH_STDERR_TAG, "please login"),
        (AUTH_STDERR_TAG, "please log in"),
        (AUTH_STDERR_TAG, "sign in"),
    ])
    .map_err(map_subprocess_error)?;
    let mut request = SubprocessRequest::new(
        settings.executable.as_path(),
        ["usage"],
        settings.timeout,
        settings.max_stdout_bytes,
        settings.max_stderr_bytes,
    )
    .map_err(map_subprocess_error)?
    .with_cleared_environment()
    .with_stderr_classifier(classifier);
    for (name, value) in &settings.environment {
        request = request
            .with_environment(name, value)
            .map_err(map_subprocess_error)?;
    }
    request = request
        .with_environment("NO_COLOR", "1")
        .map_err(map_subprocess_error)?
        .with_environment("TERM", "dumb")
        .map_err(map_subprocess_error)?;
    let output = request
        .run(context.cancellation())
        .await
        .map_err(map_subprocess_error)?;
    let bytes = if output
        .stdout()
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        output.stdout()
    } else {
        output.stderr()
    };
    let text = std::str::from_utf8(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if text.trim().is_empty() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    parse_display_text(
        context.scope().clone(),
        fetched_at,
        text,
        ProviderSource::Cli,
    )
}

/// Parses Amp's complete CLI/API display-text format into the shared domain.
///
/// This includes legacy rolling free-tier balances, current daily percentages,
/// both subscription syntaxes, individual credits, workspace credits, ANSI
/// output, Markdown-bold labels, account identity, and reset metadata.
///
/// # Errors
///
/// Returns a stable parse/authentication error for malformed, signed-out, or
/// resource-excessive text. Only Amp API-key and CLI sources are accepted.
pub fn parse_display_text(
    scope: AccountScope,
    fetched_at: Timestamp,
    display_text: &str,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope(&scope)?;
    let strategy = match source {
        ProviderSource::ApiKey => "api",
        ProviderSource::Cli => "cli",
        ProviderSource::BrowserSession
        | ProviderSource::ManualCookie
        | ProviderSource::CloudCredentials
        | ProviderSource::ConfigurableEndpoint
        | ProviderSource::OAuth
        | ProviderSource::LocalData => return Err(ClassifiedError::new(ErrorKind::Api)),
    };
    let parsed = ParsedUsage::parse(display_text, fetched_at)?;
    parsed.normalize(scope, fetched_at, strategy)
}

#[derive(Deserialize)]
struct UsageApiResponse {
    ok: bool,
    result: Option<UsageApiResult>,
    error: Option<UsageApiError>,
}

#[derive(Deserialize)]
struct UsageApiResult {
    #[serde(rename = "displayText")]
    display_text: String,
}

#[derive(Deserialize)]
struct UsageApiError {
    code: Option<String>,
}

struct ParsedUsage {
    free: Option<FreeUsage>,
    subscription: Option<SubscriptionUsage>,
    individual_credits: Option<Decimal>,
    workspaces: Vec<WorkspaceBalance>,
    email: Option<String>,
    organization: Option<String>,
}

struct FreeUsage {
    quota: Decimal,
    used: Decimal,
    hourly_replenishment: Decimal,
    duration_seconds: Option<u64>,
    reset_kind: FreeReset,
}

#[derive(Clone, Copy)]
enum FreeReset {
    Rolling,
    Daily,
    None,
}

struct SubscriptionUsage {
    plan: String,
    other_used_percent: f64,
    orb_used_percent: f64,
    resets_at: Timestamp,
    reset_description: String,
}

struct WorkspaceBalance {
    name: String,
    remaining: Decimal,
}

impl ParsedUsage {
    fn parse(text: &str, fetched_at: Timestamp) -> Result<Self, ClassifiedError> {
        if text.len() > MAX_DISPLAY_TEXT_BYTES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let stripped = strip_ansi(text)?;
        let stripped = stripped.replace("**", "");
        if stripped.lines().count() > MAX_DISPLAY_LINES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }

        let mut identity = None;
        let mut legacy_free = None;
        let mut daily_free = None;
        let mut subscription = None;
        let mut individual_credits = None;
        let mut workspaces = Vec::new();

        for raw_line in stripped.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if identity.is_none() {
                identity = parse_identity(line)?;
            }
            if let Some(body) = strip_prefix_ascii_case(line, "Amp Free:") {
                if legacy_free.is_none() {
                    legacy_free = parse_legacy_free(body)?;
                }
                if daily_free.is_none() {
                    daily_free = parse_daily_free(body);
                }
                continue;
            }
            if subscription.is_none() {
                subscription = parse_subscription(line, fetched_at)?;
                if subscription.is_some() {
                    continue;
                }
            }
            if individual_credits.is_none()
                && let Some(body) = strip_prefix_ascii_case(line, "Individual credits:")
            {
                individual_credits = parse_remaining_amount(body);
                continue;
            }
            if let Some(body) = strip_prefix_ascii_case(line, "Workspace ") {
                if workspaces.len() == MAX_WORKSPACES {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                if let Some((name, remaining)) = parse_workspace(body)? {
                    workspaces.push(WorkspaceBalance { name, remaining });
                }
            }
        }

        let (email, organization) = identity.map_or((None, None), |(email, organization)| {
            (Some(email), organization)
        });
        if email.is_none() && looks_signed_out(&stripped) {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        let free = legacy_free.or(daily_free);
        if free.is_none()
            && subscription.is_none()
            && individual_credits.is_none()
            && workspaces.is_empty()
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(Self {
            free,
            subscription,
            individual_credits,
            workspaces,
            email,
            organization,
        })
    }

    fn normalize(
        self,
        scope: AccountScope,
        fetched_at: Timestamp,
        strategy: &'static str,
    ) -> Result<UsageSample, ClassifiedError> {
        let free_window = self
            .free
            .as_ref()
            .map(|free| free.rate_window(fetched_at))
            .transpose()?;
        let mut builder = UsageSampleBuilder::new(scope, fetched_at)
            .email(self.email)?
            .organization(self.organization)?;

        if let Some(subscription) = self.subscription {
            let primary = subscription_window(
                subscription.other_used_percent,
                subscription.resets_at,
                &subscription.reset_description,
            )?;
            let secondary = subscription_window(
                subscription.orb_used_percent,
                subscription.resets_at,
                &subscription.reset_description,
            )?;
            builder = builder
                .primary(primary)
                .secondary(secondary)
                .login_method(Some(subscription.plan))?;
            if let Some(free_window) = free_window {
                builder = builder.extra_windows(vec![NamedRateWindow::new(
                    bounded("amp-free")?,
                    bounded("Amp Free")?,
                    free_window,
                )]);
            }
        } else {
            builder = builder.login_method(Some(if free_window.is_some() {
                "Amp Free".to_owned()
            } else {
                "Amp".to_owned()
            }))?;
            if let Some(free_window) = free_window {
                builder = builder.primary(free_window);
            }
        }

        let mut rows = Vec::new();
        if let Some(credits) = self.individual_credits {
            rows.push(detail_row(
                "Individual credits".to_owned(),
                format_usd(credits),
            )?);
        }
        for workspace in self.workspaces {
            rows.push(detail_row(
                format!("Workspace {}", workspace.name),
                format_usd(workspace.remaining),
            )?);
        }
        if !rows.is_empty() {
            builder = builder.detail_sections(vec![
                DetailSection::new(Some("Credits".to_owned()), rows, None)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ]);
        }
        builder.provenance("amp", strategy)?.build()
    }
}

impl FreeUsage {
    fn rate_window(&self, fetched_at: Timestamp) -> Result<RateWindow, ClassifiedError> {
        let quota = self.quota.max(Decimal::ZERO);
        let used = self.used.max(Decimal::ZERO);
        let percent = if quota > Decimal::ZERO {
            (used * Decimal::from(100_u8) / quota)
                .to_f64()
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
                .clamp(0.0, 100.0)
        } else {
            0.0
        };
        let (resets_at, description) = match self.reset_kind {
            FreeReset::Daily => (
                Some(next_eastern_daily_reset(fetched_at)?),
                Some(bounded("resets daily")?),
            ),
            FreeReset::Rolling
                if quota > Decimal::ZERO && self.hourly_replenishment > Decimal::ZERO =>
            {
                let nanoseconds = (used / self.hourly_replenishment
                    * Decimal::from(3_600_000_000_000_u64))
                .round_dp(0)
                .to_i128()
                .filter(|nanoseconds| {
                    *nanoseconds >= 0 && *nanoseconds <= i128::from(i64::MAX) * 1_000_000_000
                })
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                let reset = fetched_at
                    .as_offset_date_time()
                    .checked_add(time::Duration::nanoseconds_i128(nanoseconds))
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                (
                    Some(
                        Timestamp::new(reset)
                            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                    ),
                    None,
                )
            }
            FreeReset::Rolling | FreeReset::None => (None, None),
        };
        RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            self.duration_seconds
                .map(WindowDuration::from_seconds)
                .transpose()
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            resets_at,
            description,
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
    }
}

fn parse_identity(line: &str) -> Result<Option<(String, Option<String>)>, ClassifiedError> {
    let Some(body) = strip_prefix_ascii_case(line, "Signed in as ") else {
        return Ok(None);
    };
    let body = body.trim();
    if body.is_empty() {
        return Ok(None);
    }
    let (email, organization) = if body.ends_with(')') {
        if let Some(open) = body.rfind(" (") {
            (&body[..open], body[open + 2..body.len() - 1].trim())
        } else {
            (body, "")
        }
    } else {
        (body, "")
    };
    let email = clean_parser_text(email, MAX_IDENTITY_BYTES)?;
    if email.split_whitespace().count() != 1 {
        return Ok(None);
    }
    let organization = if organization.is_empty() {
        None
    } else {
        Some(clean_parser_text(organization, MAX_IDENTITY_BYTES)?)
    };
    Ok(Some((email, organization)))
}

fn parse_legacy_free(body: &str) -> Result<Option<FreeUsage>, ClassifiedError> {
    let Some((remaining, rest)) = take_amount(body) else {
        return Ok(None);
    };
    let Some(rest) = rest.trim_start().strip_prefix('/') else {
        return Ok(None);
    };
    let Some((quota, rest)) = take_amount(rest) else {
        return Ok(None);
    };
    let Some(after_remaining) = strip_prefix_ascii_case(rest.trim_start(), "remaining") else {
        return Ok(None);
    };
    let hourly = find_ascii_case_insensitive(after_remaining, "replenishes")
        .and_then(|index| take_amount(&after_remaining[index + "replenishes".len()..]))
        .map_or(Decimal::ZERO, |(value, _)| value);
    let duration_seconds = if hourly > Decimal::ZERO {
        let hours = (quota / hourly)
            .round()
            .to_u64()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .max(1);
        Some(
            hours
                .checked_mul(3_600)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
        )
    } else {
        None
    };
    Ok(Some(FreeUsage {
        quota,
        used: (quota - remaining).max(Decimal::ZERO),
        hourly_replenishment: hourly,
        duration_seconds,
        reset_kind: if hourly > Decimal::ZERO {
            FreeReset::Rolling
        } else {
            FreeReset::None
        },
    }))
}

fn parse_daily_free(body: &str) -> Option<FreeUsage> {
    let (remaining, rest) = take_decimal(body)?;
    let rest = rest.trim_start().strip_prefix('%')?;
    let rest = strip_prefix_ascii_case(rest.trim_start(), "remaining")?;
    let remaining = remaining.clamp(Decimal::ZERO, Decimal::from(100_u8));
    Some(FreeUsage {
        quota: Decimal::from(100_u8),
        used: Decimal::from(100_u8) - remaining,
        hourly_replenishment: Decimal::ZERO,
        duration_seconds: Some(24 * 60 * 60),
        reset_kind: if contains_ascii_case_insensitive(rest, "resets daily") {
            FreeReset::Daily
        } else {
            FreeReset::None
        },
    })
}

fn parse_subscription(
    line: &str,
    fetched_at: Timestamp,
) -> Result<Option<SubscriptionUsage>, ClassifiedError> {
    let (plan, suffix) = if let Some(body) = strip_prefix_ascii_case(line, "Subscription ") {
        let Some(colon) = body.find(':') else {
            return Ok(None);
        };
        (&body[..colon], &body[colon + 1..])
    } else if let Some(body) = strip_prefix_ascii_case(line, "Amp ") {
        let Some(index) = find_ascii_case_insensitive(body, " Subscription:") else {
            return Ok(None);
        };
        (&body[..index], &body[index + " Subscription:".len()..])
    } else {
        return Ok(None);
    };
    let plan = clean_parser_text(plan, MAX_PLAN_BYTES)?;
    let Some((other_remaining, rest)) = take_decimal(suffix) else {
        return Ok(None);
    };
    let Some(rest) = strip_prefix_ascii_case(rest.trim_start(), "% other usage and ") else {
        return Ok(None);
    };
    let Some((orb_remaining, rest)) = take_decimal(rest) else {
        return Ok(None);
    };
    let Some(rest) = strip_prefix_ascii_case(rest.trim_start(), "% orb usage remaining") else {
        return Ok(None);
    };
    let Some(index) = find_ascii_case_insensitive(rest, "resets upon renewal in ") else {
        return Ok(None);
    };
    let renewal = &rest[index + "resets upon renewal in ".len()..];
    let Some((value, unit)) = take_unsigned_integer(renewal) else {
        return Ok(None);
    };
    let unit = unit.trim_start();
    let (resets_at, singular) = if starts_with_ascii_case(unit, "month") {
        (add_calendar_months(fetched_at, value)?, "month")
    } else if starts_with_ascii_case(unit, "day") {
        let days = i64::from(value);
        let at = fetched_at
            .as_offset_date_time()
            .checked_add(time::Duration::days(days))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        (
            Timestamp::new(at).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            "day",
        )
    } else {
        return Ok(None);
    };
    let other_remaining = decimal_percent(other_remaining)?;
    let orb_remaining = decimal_percent(orb_remaining)?;
    Ok(Some(SubscriptionUsage {
        plan,
        other_used_percent: 100.0 - other_remaining,
        orb_used_percent: 100.0 - orb_remaining,
        resets_at,
        reset_description: format!(
            "renews in {value} {singular}{}",
            if value == 1 { "" } else { "s" }
        ),
    }))
}

fn parse_remaining_amount(body: &str) -> Option<Decimal> {
    let (value, rest) = take_amount(body)?;
    strip_prefix_ascii_case(rest.trim_start(), "remaining").map(|_| value)
}

fn parse_workspace(body: &str) -> Result<Option<(String, Decimal)>, ClassifiedError> {
    let Some(colon) = body.find(':') else {
        return Ok(None);
    };
    let name = clean_parser_text(&body[..colon], MAX_WORKSPACE_NAME_BYTES)?;
    Ok(parse_remaining_amount(&body[colon + 1..]).map(|remaining| (name, remaining)))
}

fn subscription_window(
    percent: f64,
    resets_at: Timestamp,
    description: &str,
) -> Result<RateWindow, ClassifiedError> {
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(
            WindowDuration::from_seconds(MONTHLY_SECONDS)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(resets_at),
        Some(bounded(description)?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn decimal_percent(value: Decimal) -> Result<f64, ClassifiedError> {
    value
        .clamp(Decimal::ZERO, Decimal::from(100_u8))
        .to_f64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn take_amount(value: &str) -> Option<(Decimal, &str)> {
    let value = value.trim_start();
    let value = value.strip_prefix('+').unwrap_or(value).trim_start();
    take_decimal(value.strip_prefix('$').unwrap_or(value))
}

fn take_decimal(value: &str) -> Option<(Decimal, &str)> {
    let value = value.trim_start();
    let end = value
        .bytes()
        .take_while(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'.'))
        .count();
    if end == 0 || end > 64 {
        return None;
    }
    let raw = &value[..end];
    if raw.starts_with([',', '.'])
        || raw.ends_with([',', '.'])
        || raw.matches('.').count() > 1
        || !valid_grouping(raw)
    {
        return None;
    }
    let canonical = raw.replace(',', "");
    Decimal::from_str(&canonical)
        .ok()
        .filter(|decimal| *decimal >= Decimal::ZERO)
        .map(|decimal| (decimal, &value[end..]))
}

fn valid_grouping(raw: &str) -> bool {
    let whole = raw.split('.').next().unwrap_or(raw);
    if !whole.contains(',') {
        return whole.bytes().all(|byte| byte.is_ascii_digit());
    }
    let mut groups = whole.split(',');
    let Some(first) = groups.next() else {
        return false;
    };
    !first.is_empty()
        && first.len() <= 3
        && first.bytes().all(|byte| byte.is_ascii_digit())
        && groups.all(|group| group.len() == 3 && group.bytes().all(|byte| byte.is_ascii_digit()))
}

fn take_unsigned_integer(value: &str) -> Option<(u32, &str)> {
    let value = value.trim_start();
    let end = value
        .bytes()
        .take_while(|byte| byte.is_ascii_digit() || *byte == b',')
        .count();
    if end == 0 || end > 16 || !valid_grouping(&value[..end]) {
        return None;
    }
    value[..end]
        .replace(',', "")
        .parse()
        .ok()
        .map(|number| (number, &value[end..]))
}

fn strip_ansi(value: &str) -> Result<String, ClassifiedError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != 0x1b {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        if index >= bytes.len() {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        match bytes[index] {
            b'[' => {
                index += 1;
                while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                    index += 1;
                }
                if index == bytes.len() {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                index += 1;
            }
            b']' => {
                index += 1;
                let mut terminated = false;
                while index < bytes.len() {
                    if bytes[index] == 0x07 {
                        index += 1;
                        terminated = true;
                        break;
                    }
                    if bytes[index] == 0x1b && bytes.get(index + 1).copied() == Some(b'\\') {
                        index += 2;
                        terminated = true;
                        break;
                    }
                    index += 1;
                }
                if !terminated {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
            }
            _ => index += 1,
        }
    }
    String::from_utf8(output).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn next_eastern_daily_reset(fetched_at: Timestamp) -> Result<Timestamp, ClassifiedError> {
    let utc = fetched_at.as_offset_date_time();
    let offset = eastern_offset_at_utc(utc)?;
    let local = utc.to_offset(offset);
    let mut date = local.date();
    if local.time() >= Time::from_hms(20, 0, 0).map_err(parse_error)? {
        date = date
            .next_day()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    }
    let wall = PrimitiveDateTime::new(date, Time::from_hms(20, 0, 0).map_err(parse_error)?);
    let target_offset = eastern_offset_for_local_date(date)?;
    Timestamp::new(wall.assume_offset(target_offset))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn eastern_offset_at_utc(utc: OffsetDateTime) -> Result<UtcOffset, ClassifiedError> {
    let year = utc.year();
    let start_date = nth_weekday(year, Month::March, Weekday::Sunday, 2)?;
    let end_date = nth_weekday(year, Month::November, Weekday::Sunday, 1)?;
    let start = PrimitiveDateTime::new(start_date, Time::from_hms(7, 0, 0).map_err(parse_error)?)
        .assume_utc();
    let end = PrimitiveDateTime::new(end_date, Time::from_hms(6, 0, 0).map_err(parse_error)?)
        .assume_utc();
    offset(if utc >= start && utc < end { -4 } else { -5 })
}

fn eastern_offset_for_local_date(date: Date) -> Result<UtcOffset, ClassifiedError> {
    let start = nth_weekday(date.year(), Month::March, Weekday::Sunday, 2)?;
    let end = nth_weekday(date.year(), Month::November, Weekday::Sunday, 1)?;
    offset(if date >= start && date < end { -4 } else { -5 })
}

fn nth_weekday(
    year: i32,
    month: Month,
    weekday: Weekday,
    ordinal: u8,
) -> Result<Date, ClassifiedError> {
    let first = Date::from_calendar_date(year, month, 1).map_err(parse_error)?;
    let delta =
        (weekday.number_days_from_monday() + 7 - first.weekday().number_days_from_monday()) % 7;
    first
        .checked_add(time::Duration::days(i64::from(
            delta + 7 * ordinal.saturating_sub(1),
        )))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn offset(hours: i8) -> Result<UtcOffset, ClassifiedError> {
    UtcOffset::from_hms(hours, 0, 0).map_err(parse_error)
}

fn add_calendar_months(fetched_at: Timestamp, months: u32) -> Result<Timestamp, ClassifiedError> {
    let instant = fetched_at.as_offset_date_time();
    let local_offset = UtcOffset::local_offset_at(instant).unwrap_or(UtcOffset::UTC);
    let local = instant.to_offset(local_offset);
    let month_index = i64::from(local.year())
        .checked_mul(12)
        .and_then(|total| total.checked_add(i64::from(u8::from(local.month()) - 1)))
        .and_then(|total| total.checked_add(i64::from(months)))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let year = i32::try_from(month_index.div_euclid(12))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let month = Month::try_from(u8::try_from(month_index.rem_euclid(12) + 1).map_err(parse_error)?)
        .map_err(parse_error)?;
    let day = local.day().min(days_in_month(year, month)?);
    let date = Date::from_calendar_date(year, month, day).map_err(parse_error)?;
    let wall = PrimitiveDateTime::new(date, local.time());
    let mut target_offset = local_offset;
    for _ in 0..4 {
        let candidate = wall.assume_offset(target_offset);
        let observed = UtcOffset::local_offset_at(candidate).unwrap_or(target_offset);
        if observed == target_offset {
            return Timestamp::new(candidate).map_err(parse_error);
        }
        target_offset = observed;
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn days_in_month(year: i32, month: Month) -> Result<u8, ClassifiedError> {
    let (next_year, next_month) = if month == Month::December {
        (
            year.checked_add(1)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
            Month::January,
        )
    } else {
        (
            year,
            Month::try_from(u8::from(month) + 1).map_err(parse_error)?,
        )
    };
    let next = Date::from_calendar_date(next_year, next_month, 1).map_err(parse_error)?;
    Ok(next
        .previous_day()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .day())
}

fn looks_signed_out(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("sign in")
        || lower.contains("log in")
        || lower.contains("login")
        || lower.contains("/login")
}

fn clean_parser_text(value: &str, maximum: usize) -> Result<String, ClassifiedError> {
    let value = value.trim();
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(value.to_owned())
}

fn bounded<const MAX: usize>(value: impl AsRef<str>) -> Result<BoundedText<MAX>, ClassifiedError> {
    BoundedText::new(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn detail_row(label: String, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Personal)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_usd(value: Decimal) -> String {
    let fixed = format!("{value:.2}");
    let (whole, fraction) = fixed.split_once('.').unwrap_or((&fixed, "00"));
    let mut grouped = String::with_capacity(fixed.len() + fixed.len() / 3 + 1);
    for (index, byte) in whole.bytes().enumerate() {
        if index > 0 && (whole.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    format!("${grouped}.{fraction}")
}

fn starts_with_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    starts_with_ascii_case(value, prefix).then(|| &value[prefix.len()..])
}

fn find_ascii_case_insensitive(value: &str, needle: &str) -> Option<usize> {
    value
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    find_ascii_case_insensitive(value, needle).is_some()
}

fn map_subprocess_error(error: SubprocessError) -> ClassifiedError {
    let kind = match error {
        SubprocessError::NonZero {
            stderr_tag: Some(AUTH_STDERR_TAG),
            ..
        } => ErrorKind::AuthenticationExpired,
        SubprocessError::Spawn => ErrorKind::MissingCredential,
        SubprocessError::Cancelled | SubprocessError::Timeout | SubprocessError::Wait => {
            ErrorKind::Network
        }
        SubprocessError::StdoutTooLarge
        | SubprocessError::StderrTooLarge
        | SubprocessError::OutputRead => ErrorKind::Parse,
        SubprocessError::InvalidConfiguration | SubprocessError::NonZero { .. } => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn resolve_amp(environment: &BTreeMap<String, String>) -> Result<ExecutablePath, ClassifiedError> {
    let configured = environment.get(CLI_OVERRIDE).map(String::as_str);
    let path = environment.get("PATH").map(String::as_ref);
    let mut fallbacks = Vec::new();
    if let Some(home) = environment
        .get("HOME")
        .and_then(|value| clean_setting(value))
    {
        let home = Path::new(home);
        if home.is_absolute() {
            fallbacks.push(home.join(".local/bin/amp"));
            fallbacks.push(home.join(".amp/bin/amp"));
        }
    }
    fallbacks.extend([
        PathBuf::from("/usr/local/bin/amp"),
        PathBuf::from("/usr/bin/amp"),
    ]);
    let resolved = resolve_executable("amp", configured, path, &fallbacks)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    resolved.ok_or_else(|| {
        if configured.and_then(clean_setting).is_some() {
            ClassifiedError::new(ErrorKind::Api)
        } else {
            ClassifiedError::new(ErrorKind::MissingCredential)
        }
    })
}

fn sanitized_cli_environment(
    source: &BTreeMap<String, String>,
    executable: &Path,
) -> Result<Vec<(String, String)>, ClassifiedError> {
    const ALLOWED: [&str; 18] = [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "PATH",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ];
    let mut environment = Vec::new();
    for name in ALLOWED {
        if let Some(value) = source.get(name) {
            if value.contains('\0') || value.len() > 64 * 1024 {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            environment.push((name.to_owned(), value.clone()));
        }
    }
    if let Some(value) = validated_amp_url(source)? {
        environment.push(("AMP_URL".to_owned(), value));
    }
    for name in ["AMP_HOME", "AMP_SETTINGS_FILE"] {
        if let Some(value) = validated_amp_path(source, name)? {
            environment.push((name.to_owned(), value));
        }
    }
    let mut paths = Vec::new();
    if let Some(parent) = executable.parent().filter(|path| path.is_absolute()) {
        paths.push(parent.to_path_buf());
    }
    if let Some(raw) = source.get("PATH") {
        for path in std::env::split_paths(raw)
            .filter(|path| path.is_absolute())
            .take(256)
        {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    for path in ["/usr/local/bin", "/usr/bin", "/bin"].map(PathBuf::from) {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    let path = std::env::join_paths(paths).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let path = path
        .into_string()
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if path.len() > 64 * 1024 {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    if let Some(existing) = environment.iter_mut().find(|(name, _)| name == "PATH") {
        existing.1 = path;
    } else {
        environment.push(("PATH".to_owned(), path));
    }
    Ok(environment)
}

fn validated_amp_url(source: &BTreeMap<String, String>) -> Result<Option<String>, ClassifiedError> {
    let Some(value) = validated_amp_custom_value(source, "AMP_URL")? else {
        return Ok(None);
    };
    let endpoint = ConfiguredEndpoint::parse(value, ConfiguredHttpPolicy::LoopbackHttp)?;
    Ok(Some(endpoint.url().as_str().to_owned()))
}

fn validated_amp_path(
    source: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<String>, ClassifiedError> {
    validated_amp_custom_value(source, name).map(|value| value.map(str::to_owned))
}

fn validated_amp_custom_value<'a>(
    source: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<Option<&'a str>, ClassifiedError> {
    let Some(raw) = source.get(name) else {
        return Ok(None);
    };
    if raw.len() > MAX_CLI_CUSTOM_VALUE_BYTES || raw.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let Some(value) = clean_setting(raw) else {
        return Ok(None);
    };
    Ok(Some(value))
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

fn validate_scope(scope: &AccountScope) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Amp {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_api_endpoint(endpoint: &Url) -> Result<(), ClassifiedError> {
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/api/internal"
        || endpoint.query() != Some("userDisplayBalanceInfo")
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn parse_error<T>(_: T) -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
