//! Doubao Ark request quotas, Volcengine plan usage, and bounded `arkcli` SSO.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, NamedRateWindow, ProviderId, RateWindow,
    Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use time::Duration as TimeDuration;
use url::Url;
use zeroize::Zeroizing;

use crate::cloud_signing::{SigningError, VolcengineCredentials};
use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::executable::{ExecutablePath, resolve_executable};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{StderrClassifier, SubprocessError, SubprocessRequest};
use crate::transport::{
    Authentication, HttpRequest, HttpResponse, HttpTransport, RequestAccept, RequestContentType,
    TransportConfig,
};

const ARK_ORIGIN: &str = "https://ark.cn-beijing.volces.com";
const ARK_PROBE_PATH: &str = "/api/coding/v3/chat/completions";
const VOLCENGINE_ORIGIN: &str = "https://open.volcengineapi.com";
const ARKCLI_OVERRIDE: &str = "OMARCHY_AI_BAR_ARKCLI_PATH";
const API_KEY_NAMES: [&str; 3] = ["ARK_API_KEY", "VOLCENGINE_API_KEY", "DOUBAO_API_KEY"];
const ACCESS_KEY_NAMES: [&str; 4] = [
    "VOLCENGINE_ACCESS_KEY_ID",
    "VOLCENGINE_ACCESS_KEY",
    "VOLC_ACCESSKEY",
    "DOUBAO_ACCESS_KEY_ID",
];
const SECRET_KEY_NAMES: [&str; 5] = [
    "VOLCENGINE_SECRET_ACCESS_KEY",
    "VOLCENGINE_SECRET_KEY",
    "VOLCENGINE_ACCESS_KEY_SECRET",
    "VOLC_SECRETKEY",
    "DOUBAO_SECRET_ACCESS_KEY",
];
const REGION_NAMES: [&str; 4] = [
    "VOLCENGINE_REGION",
    "VOLCENGINE_REGION_ID",
    "VOLC_REGION",
    "DOUBAO_REGION",
];
const DEFAULT_REGION: &str = "cn-beijing";
const PROBE_MODELS: [&str; 3] = [
    "doubao-seed-2.0-code",
    "doubao-1.5-pro-32k",
    "doubao-lite-32k",
];
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_API_KEY_BYTES: usize = 16 * 1024;
const MAX_ITEMS: usize = 64;
const MAX_PERIODS_PER_ITEM: usize = 64;
const MAX_QUOTAS: usize = 128;
const MAX_LEVEL_BYTES: usize = 128;
const ARKCLI_STDOUT_BYTES: usize = 256 * 1024;
const ARKCLI_STDERR_BYTES: usize = 64 * 1024;
const ARKCLI_TIMEOUT: Duration = Duration::from_secs(15);
const AUTH_STDERR_TAG: u8 = 1;

/// A bounded Ark bearer key, zeroized on drop and redacted in diagnostics.
#[derive(Clone)]
pub struct DoubaoApiCredential {
    value: Zeroizing<String>,
}

impl DoubaoApiCredential {
    /// Resolves the first non-empty baseline environment key.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when no bounded key exists.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let value = first_setting(environment, &API_KEY_NAMES)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::new(value)
    }

    /// Validates an explicitly supplied Ark bearer key.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for empty, oversized, or
    /// line-breaking input.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ClassifiedError> {
        let value = clean_setting(value.as_ref())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        if value.len() > MAX_API_KEY_BYTES || value.contains(['\r', '\n']) {
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

impl Debug for DoubaoApiCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("DoubaoApiCredential(<redacted>)")
    }
}

/// Resolves a complete Volcengine AK/SK/region bundle without partial fallback.
///
/// # Errors
///
/// Returns missing-credential unless both key components are present, and API
/// for an invalid signing region.
pub fn resolve_cloud_credentials(
    environment: &BTreeMap<String, String>,
) -> Result<VolcengineCredentials, ClassifiedError> {
    let access_key = first_setting(environment, &ACCESS_KEY_NAMES)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let secret_key = first_setting(environment, &SECRET_KEY_NAMES)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let region = first_setting(environment, &REGION_NAMES).unwrap_or(DEFAULT_REGION);
    VolcengineCredentials::new(access_key, secret_key, region).map_err(|error| {
        let kind = if error == SigningError::InvalidCredential {
            ErrorKind::MissingCredential
        } else {
            ErrorKind::Api
        };
        ClassifiedError::new(kind)
    })
}

/// Exact shell-free `arkcli` invocation and sanitized environment.
pub struct DoubaoCliSettings {
    executable: ExecutablePath,
    environment: Vec<(String, String)>,
}

impl DoubaoCliSettings {
    /// Discovers `arkcli` from `OMARCHY_AI_BAR_ARKCLI_PATH`, `PATH`, and Linux
    /// install roots.
    ///
    /// # Errors
    ///
    /// Returns missing-credential when no executable is available, or API when
    /// an explicit override is not an absolute executable file.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let executable = resolve_arkcli(environment)?;
        Self::new(executable.into_path_buf(), environment)
    }

    /// Builds a CLI account from one explicit absolute executable.
    ///
    /// # Errors
    ///
    /// Returns API for a relative path or an unsafe sanitized environment.
    pub fn new(
        executable: impl Into<PathBuf>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let executable = executable.into();
        let configured = executable
            .to_str()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        let executable = resolve_executable("arkcli", Some(configured), None, &[])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let environment = sanitized_cli_environment(environment, executable.as_path())?;
        Ok(Self {
            executable,
            environment,
        })
    }

    /// Resolved executable, primarily for setup diagnostics.
    #[must_use]
    pub fn executable(&self) -> &Path {
        self.executable.as_path()
    }
}

impl Debug for DoubaoCliSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DoubaoCliSettings")
            .field("executable", &"<redacted>")
            .field("environment_entries", &self.environment.len())
            .finish()
    }
}

/// Native Doubao adapter bound to exactly one account and authentication source.
pub struct DoubaoProvider {
    scope: AccountScope,
    backend: Backend,
}

enum Backend {
    Cloud(CloudBackend),
    Api(ApiBackend),
    Cli(DoubaoCliSettings),
}

struct CloudBackend {
    credentials: VolcengineCredentials,
    origin: Url,
    transport: HttpTransport,
}

struct ApiBackend {
    credential: DoubaoApiCredential,
    endpoint: Url,
    transport: HttpTransport,
}

impl DoubaoProvider {
    /// Resolves and constructs the explicitly selected source. No source ever
    /// falls back to another account mechanism.
    ///
    /// # Errors
    ///
    /// Returns stable credential or configuration errors.
    pub fn resolve(
        scope: AccountScope,
        source: ProviderSource,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        match source {
            ProviderSource::CloudCredentials => {
                Self::new_cloud(scope, resolve_cloud_credentials(environment)?)
            }
            ProviderSource::ApiKey => {
                Self::new_api_key(scope, DoubaoApiCredential::resolve(environment)?)
            }
            ProviderSource::Cli => Self::new_cli(scope, DoubaoCliSettings::resolve(environment)?),
            ProviderSource::ConfigurableEndpoint
            | ProviderSource::ManualCookie
            | ProviderSource::BrowserSession
            | ProviderSource::OAuth
            | ProviderSource::LocalData => Err(ClassifiedError::new(ErrorKind::Api)),
        }
    }

    /// Creates the fixed-origin Volcengine signed plan client.
    ///
    /// # Errors
    ///
    /// Returns API for another provider scope or invalid transport setup.
    pub fn new_cloud(
        scope: AccountScope,
        credentials: VolcengineCredentials,
    ) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(VOLCENGINE_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let policy = EndpointPolicy::new([(
            origin.origin().ascii_serialization(),
            EndpointClass::PublicHttps,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Self::from_cloud_transport(scope, credentials, origin, transport)
    }

    /// Creates the fixed-origin Ark bearer-key probe client.
    ///
    /// # Errors
    ///
    /// Returns API for another provider scope or invalid transport setup.
    pub fn new_api_key(
        scope: AccountScope,
        credential: DoubaoApiCredential,
    ) -> Result<Self, ClassifiedError> {
        let mut endpoint =
            Url::parse(ARK_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        endpoint.set_path(ARK_PROBE_PATH);
        let policy = EndpointPolicy::new([(
            endpoint.origin().ascii_serialization(),
            EndpointClass::PublicHttps,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Self::from_api_transport(scope, credential, endpoint, transport)
    }

    /// Creates the shell-free `arkcli` account adapter.
    ///
    /// # Errors
    ///
    /// Returns API for another provider scope.
    pub fn new_cli(
        scope: AccountScope,
        settings: DoubaoCliSettings,
    ) -> Result<Self, ClassifiedError> {
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
    /// Rejects another provider scope or a credential-bearing/non-origin URL.
    #[doc(hidden)]
    pub fn from_cloud_transport(
        scope: AccountScope,
        credentials: VolcengineCredentials,
        origin: Url,
        transport: HttpTransport,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        validate_origin(&origin)?;
        Ok(Self {
            scope,
            backend: Backend::Cloud(CloudBackend {
                credentials,
                origin,
                transport,
            }),
        })
    }

    /// Deterministic loopback seam retaining transport-owned endpoint policy.
    ///
    /// # Errors
    ///
    /// Rejects another provider scope or an unsafe endpoint.
    #[doc(hidden)]
    pub fn from_api_transport(
        scope: AccountScope,
        credential: DoubaoApiCredential,
        endpoint: Url,
        transport: HttpTransport,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        validate_request_url(&endpoint)?;
        Ok(Self {
            scope,
            backend: Backend::Api(ApiBackend {
                credential,
                endpoint,
                transport,
            }),
        })
    }

    /// Source to which this provider instance is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        match self.backend {
            Backend::Cloud(_) => ProviderSource::CloudCredentials,
            Backend::Api(_) => ProviderSource::ApiKey,
            Backend::Cli(_) => ProviderSource::Cli,
        }
    }

    /// Fetches at one injected wall-clock instant for deterministic reset parsing.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted credential, transport, or parse classification.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        match &self.backend {
            Backend::Cloud(backend) => fetch_cloud(backend, context, fetched_at).await,
            Backend::Api(backend) => fetch_api(backend, context, fetched_at).await,
            Backend::Cli(settings) => fetch_cli(settings, context, fetched_at).await,
        }
    }
}

impl Debug for DoubaoProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DoubaoProvider")
            .field("scope", &self.scope)
            .field("source", &self.source())
            .finish_non_exhaustive()
    }
}

impl ProviderAdapter for DoubaoProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Doubao)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

async fn fetch_cloud(
    backend: &CloudBackend,
    context: &ProviderContext,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let coding_url = action_url(&backend.origin, "GetCodingPlanUsage");
    let coding_response = send_signed(backend, context, coding_url, &[]).await?;
    if coding_response.status() != 200 {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let coding = parse_coding_plan(coding_response.body())?;

    let agent_url = action_url(&backend.origin, "GetAFPUsage");
    let agent = match send_signed(backend, context, agent_url, &[403, 404]).await {
        Ok(response) if response.status() == 200 => match parse_agent_plan(response.body()) {
            Ok(agent) => Some(agent),
            Err(error) if coding.quotas.is_empty() => return Err(error),
            Err(_) => None,
        },
        Err(error) if context.cancellation().is_cancelled() => return Err(error),
        Err(error) if coding.quotas.is_empty() => return Err(error),
        Ok(_) | Err(_) => None,
    };

    let plan = merge_cloud_plans(coding, agent);
    normalize_plan(context.scope().clone(), fetched_at, plan, "cloud")
}

async fn send_signed(
    backend: &CloudBackend,
    context: &ProviderContext,
    url: Url,
    accepted_statuses: &[u16],
) -> Result<HttpResponse, ClassifiedError> {
    let request = HttpRequest::post(url, Vec::new())
        .map_err(|error| error.classified())?
        .accept(RequestAccept::Json)
        .content_type(RequestContentType::FormUrlEncodedUtf8)
        .authentication(Authentication::volcengine_v4(backend.credentials.clone()))
        .accepted_statuses(accepted_statuses)
        .map_err(|error| error.classified())?;
    backend
        .transport
        .send(&request, context.cancellation())
        .await
        .map_err(|error| error.classified())
}

async fn fetch_api(
    backend: &ApiBackend,
    context: &ProviderContext,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let mut last_model_error = None;
    for model in PROBE_MODELS {
        match probe(backend, context, fetched_at, model).await {
            Ok(initial) => {
                let result = if initial.is_ambiguous_zero() {
                    confirm_zero(backend, context, fetched_at, model, initial).await?
                } else {
                    initial
                };
                return normalize_probe(context.scope().clone(), fetched_at, &result);
            }
            Err(ProbeError::Unavailable(kind)) => last_model_error = Some(kind),
            Err(ProbeError::Fatal(error)) => return Err(error),
        }
    }
    Err(ClassifiedError::new(
        last_model_error.unwrap_or(ErrorKind::Api),
    ))
}

async fn confirm_zero(
    backend: &ApiBackend,
    context: &ProviderContext,
    fetched_at: Timestamp,
    model: &str,
    initial: ProbeResult,
) -> Result<ProbeResult, ClassifiedError> {
    match probe(backend, context, fetched_at, model).await {
        Ok(confirmation) if confirmation.status == 429 && !confirmation.reliable => Ok(initial),
        Ok(mut confirmation) if confirmation.is_ambiguous_zero() => {
            confirmation.reliable = false;
            Ok(confirmation)
        }
        Ok(confirmation) => Ok(confirmation),
        Err(_) if context.cancellation().is_cancelled() => {
            Err(ClassifiedError::new(ErrorKind::Network))
        }
        Err(_) => Ok(initial),
    }
}

enum ProbeError {
    Unavailable(ErrorKind),
    Fatal(ClassifiedError),
}

struct ProbeResult {
    status: u16,
    remaining: Option<i64>,
    limit: Option<i64>,
    reset: Option<Timestamp>,
    reliable: bool,
}

impl ProbeResult {
    fn is_ambiguous_zero(&self) -> bool {
        self.status == 200
            && self.reliable
            && self.limit.is_some_and(|limit| limit > 0)
            && self.remaining == Some(0)
    }
}

async fn probe(
    backend: &ApiBackend,
    context: &ProviderContext,
    fetched_at: Timestamp,
    model: &str,
) -> Result<ProbeResult, ProbeError> {
    let body = serde_json::to_vec(&ProbeRequest {
        model,
        max_tokens: 1,
        messages: [ProbeMessage {
            role: "user",
            content: "hi",
        }],
    })
    .map_err(|_| ProbeError::Fatal(ClassifiedError::new(ErrorKind::Api)))?;
    let request = HttpRequest::post_json(backend.endpoint.clone(), body)
        .map_err(|error| ProbeError::Fatal(error.classified()))?
        .authentication(
            backend
                .credential
                .authentication()
                .map_err(ProbeError::Fatal)?,
        )
        .accepted_statuses(&[403, 404, 429])
        .map_err(|error| ProbeError::Fatal(error.classified()))?
        .response_headers(&[
            "x-ratelimit-remaining-requests",
            "x-ratelimit-limit-requests",
            "x-ratelimit-reset-requests",
        ])
        .map_err(|error| ProbeError::Fatal(error.classified()))?;
    let response = backend
        .transport
        .send(&request, context.cancellation())
        .await
        .map_err(|error| ProbeError::Fatal(error.classified()))?;
    match response.status() {
        200 | 429 => {}
        403 => return Err(ProbeError::Unavailable(ErrorKind::PermissionDenied)),
        404 => return Err(ProbeError::Unavailable(ErrorKind::Api)),
        _ => return Err(ProbeError::Fatal(ClassifiedError::new(ErrorKind::Api))),
    }
    let remaining = response
        .header("x-ratelimit-remaining-requests")
        .and_then(parse_nonnegative_header);
    let limit = response
        .header("x-ratelimit-limit-requests")
        .and_then(parse_nonnegative_header);
    let reset = response
        .header("x-ratelimit-reset-requests")
        .and_then(|value| parse_reset(value, fetched_at));
    let reliable = if response.status() == 429 {
        limit.is_some()
    } else {
        limit.is_some() && remaining.is_some()
    };
    Ok(ProbeResult {
        status: response.status(),
        remaining: if response.status() == 429 && limit.is_some() {
            Some(remaining.unwrap_or(0))
        } else {
            remaining
        },
        limit,
        reset,
        reliable,
    })
}

#[derive(Serialize)]
struct ProbeRequest<'a> {
    model: &'a str,
    max_tokens: u8,
    messages: [ProbeMessage<'a>; 1],
}

#[derive(Serialize)]
struct ProbeMessage<'a> {
    role: &'a str,
    content: &'a str,
}

fn normalize_probe(
    scope: AccountScope,
    fetched_at: Timestamp,
    probe: &ProbeResult,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if probe.reliable
        && let (Some(remaining), Some(limit)) = (probe.remaining, probe.limit)
        && limit > 0
    {
        let used = limit.saturating_sub(remaining).max(0);
        let description = BoundedText::new(format!("{used}/{limit} requests"))
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let percent = (Decimal::from(used) * Decimal::from(100_u8) / Decimal::from(limit))
            .to_f64()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .clamp(0.0, 100.0);
        let window = RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            None,
            probe.reset,
            Some(description),
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        builder = builder.primary(window);
    }
    builder.provenance("doubao", "api")?.build()
}

async fn fetch_cli(
    settings: &DoubaoCliSettings,
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
    ])
    .map_err(map_subprocess_error)?;
    let mut request = SubprocessRequest::new(
        settings.executable.as_path(),
        ["usage", "plan", "--format", "json"],
        ARKCLI_TIMEOUT,
        ARKCLI_STDOUT_BYTES,
        ARKCLI_STDERR_BYTES,
    )
    .map_err(map_subprocess_error)?
    .with_cleared_environment()
    .with_stderr_classifier(classifier);
    for (name, value) in &settings.environment {
        request = request
            .with_environment(name, value)
            .map_err(map_subprocess_error)?;
    }
    let output = request
        .run(context.cancellation())
        .await
        .map_err(map_subprocess_error)?;
    let plan = parse_arkcli(output.stdout())?;
    normalize_plan(context.scope().clone(), fetched_at, plan, "cli")
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Product {
    Coding,
    Agent,
    CodingTeam,
    AgentTeam,
}

struct Quota {
    product: Product,
    level: String,
    percent: f64,
    reset: Option<Timestamp>,
}

struct PlanUsage {
    status: Option<String>,
    updated_at: Option<Timestamp>,
    quotas: Vec<Quota>,
}

fn normalize_plan(
    scope: AccountScope,
    fetched_at: Timestamp,
    plan: PlanUsage,
    strategy: &'static str,
) -> Result<UsageSample, ClassifiedError> {
    let primary = find_window(
        &plan.quotas,
        Product::Coding,
        &["session", "5-hour", "five_hour", "5h"],
        300,
    )?;
    let secondary = find_window(
        &plan.quotas,
        Product::Coding,
        &["weekly", "week"],
        7 * 24 * 60,
    )?;
    let tertiary = find_window(
        &plan.quotas,
        Product::Coding,
        &["monthly", "month"],
        30 * 24 * 60,
    )?;
    let mut extras = Vec::new();
    for (product, prefix) in [
        (Product::Agent, "doubao-agent"),
        (Product::CodingTeam, "doubao-coding-team"),
        (Product::AgentTeam, "doubao-agent-team"),
    ] {
        append_named_window(
            &mut extras,
            &plan.quotas,
            product,
            &["session", "5-hour", "five_hour", "5h"],
            300,
            &format!("{prefix}-session"),
            "5-hour",
        )?;
        append_named_window(
            &mut extras,
            &plan.quotas,
            product,
            &["weekly", "week"],
            7 * 24 * 60,
            &format!("{prefix}-weekly"),
            "Weekly",
        )?;
        append_named_window(
            &mut extras,
            &plan.quotas,
            product,
            &["monthly", "month"],
            30 * 24 * 60,
            &format!("{prefix}-monthly"),
            "Monthly",
        )?;
    }

    let sample_time = plan.updated_at.unwrap_or(fetched_at);
    let mut builder = UsageSampleBuilder::new(scope, sample_time)
        .extra_windows(extras)
        .login_method(plan.status)?;
    if let Some(window) = primary {
        builder = builder.primary(window);
    }
    if let Some(window) = secondary {
        builder = builder.secondary(window);
    }
    if let Some(window) = tertiary {
        builder = builder.tertiary(window);
    }
    builder.provenance("doubao", strategy)?.build()
}

#[allow(clippy::too_many_arguments)]
fn append_named_window(
    windows: &mut Vec<NamedRateWindow>,
    quotas: &[Quota],
    product: Product,
    levels: &[&str],
    minutes: i64,
    id: &str,
    title: &str,
) -> Result<(), ClassifiedError> {
    let Some(window) = find_window(quotas, product, levels, minutes)? else {
        return Ok(());
    };
    windows.push(NamedRateWindow::new(
        BoundedText::new(id).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
        BoundedText::new(title).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
        window,
    ));
    Ok(())
}

fn find_window(
    quotas: &[Quota],
    product: Product,
    levels: &[&str],
    minutes: i64,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let quota = quotas.iter().find(|quota| {
        quota.product == product
            && levels
                .iter()
                .any(|level| quota.level.eq_ignore_ascii_case(level))
    });
    quota.map(|quota| quota_window(quota, minutes)).transpose()
}

fn quota_window(quota: &Quota, minutes: i64) -> Result<RateWindow, ClassifiedError> {
    let percent = UsagePercent::new(quota.percent.clamp(0.0, 100.0))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let duration = WindowDuration::from_provider_minutes(minutes)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        quota.reset,
        None,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

#[derive(Deserialize)]
struct CodingEnvelope {
    #[serde(rename = "Result")]
    result: CodingResult,
}

#[derive(Deserialize)]
struct CodingResult {
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "UpdateTimestamp")]
    update_timestamp: Option<f64>,
    #[serde(rename = "QuotaUsage", default)]
    quota_usage: Vec<CodingQuota>,
}

#[derive(Deserialize)]
struct CodingQuota {
    #[serde(rename = "Level")]
    level: String,
    #[serde(rename = "Percent")]
    percent: f64,
    #[serde(rename = "ResetTimestamp")]
    reset_timestamp: Option<f64>,
}

fn parse_coding_plan(body: &[u8]) -> Result<PlanUsage, ClassifiedError> {
    let wire: CodingEnvelope =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if wire.result.quota_usage.len() > MAX_QUOTAS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let status = clean_bounded_text(wire.result.status, 256)?;
    let mut quotas = Vec::with_capacity(wire.result.quota_usage.len());
    for quota in wire.result.quota_usage {
        validate_level(&quota.level)?;
        quotas.push(Quota {
            product: Product::Coding,
            level: quota.level,
            percent: validate_percent(quota.percent)?,
            reset: optional_epoch(quota.reset_timestamp, EpochUnit::Seconds)?,
        });
    }
    Ok(PlanUsage {
        status,
        updated_at: optional_epoch(wire.result.update_timestamp, EpochUnit::Seconds)?,
        quotas,
    })
}

#[derive(Deserialize)]
struct AgentEnvelope {
    #[serde(rename = "Result")]
    result: AgentResult,
}

#[derive(Deserialize)]
struct AgentResult {
    #[serde(rename = "AFPFiveHour")]
    five_hour: Option<AgentWindow>,
    #[serde(rename = "AFPWeekly")]
    weekly: Option<AgentWindow>,
    #[serde(rename = "AFPMonthly")]
    monthly: Option<AgentWindow>,
}

#[derive(Deserialize)]
struct AgentWindow {
    #[serde(rename = "Quota")]
    quota: f64,
    #[serde(rename = "Used")]
    used: f64,
    #[serde(rename = "ResetTime")]
    reset_time: Option<f64>,
}

fn parse_agent_plan(body: &[u8]) -> Result<PlanUsage, ClassifiedError> {
    let wire: AgentEnvelope =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let mut quotas = Vec::new();
    for (level, window) in [
        ("5h", wire.result.five_hour),
        ("weekly", wire.result.weekly),
        ("monthly", wire.result.monthly),
    ] {
        let Some(window) = window else { continue };
        if !window.quota.is_finite() || !window.used.is_finite() {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        if window.quota <= 0.0 {
            continue;
        }
        quotas.push(Quota {
            product: Product::Agent,
            level: level.to_owned(),
            percent: (window.used / window.quota * 100.0).clamp(0.0, 100.0),
            reset: optional_epoch(window.reset_time, EpochUnit::Milliseconds)?,
        });
    }
    Ok(PlanUsage {
        status: None,
        updated_at: None,
        quotas,
    })
}

fn merge_cloud_plans(coding: PlanUsage, agent: Option<PlanUsage>) -> PlanUsage {
    match agent {
        Some(agent) if coding.quotas.is_empty() && !agent.quotas.is_empty() => agent,
        Some(mut agent) if !agent.quotas.is_empty() => {
            let mut quotas = coding.quotas;
            quotas.append(&mut agent.quotas);
            PlanUsage {
                status: coding.status,
                updated_at: coding.updated_at.or(agent.updated_at),
                quotas,
            }
        }
        _ => coding,
    }
}

#[derive(Deserialize)]
struct ArkcliEnvelope {
    viewer: Option<ArkcliViewer>,
    items: Vec<ArkcliItem>,
}

#[derive(Deserialize)]
struct ArkcliViewer {
    auth_method: Option<String>,
}

#[derive(Deserialize)]
struct ArkcliItem {
    product: String,
    subscribed: Option<bool>,
    periods: Option<Vec<ArkcliPeriod>>,
    updated_at: Option<f64>,
    #[serde(rename = "error")]
    _error: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct ArkcliPeriod {
    label: String,
    percent: f64,
    reset_at: Option<ResetValue>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ResetValue {
    Text(String),
    Number(f64),
}

fn parse_arkcli(body: &[u8]) -> Result<PlanUsage, ClassifiedError> {
    let wire: ArkcliEnvelope =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if wire.items.len() > MAX_ITEMS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let status = clean_bounded_text(wire.viewer.and_then(|viewer| viewer.auth_method), 256)?;
    if status
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("none"))
    {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }

    for item in &wire.items {
        if parse_product(&item.product).is_some()
            && item.subscribed != Some(false)
            && item.periods.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
    }

    let mut quotas = Vec::new();
    let mut newest_update = None;
    for item in wire.items {
        let Some(product) = parse_product(&item.product) else {
            continue;
        };
        if item.subscribed == Some(false) {
            continue;
        }
        let periods = item.periods.unwrap_or_default();
        if periods.len() > MAX_PERIODS_PER_ITEM {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        if !periods.is_empty()
            && let Some(update) = optional_epoch(item.updated_at, EpochUnit::Auto)?
            && newest_update.is_none_or(|current| update > current)
        {
            newest_update = Some(update);
        }
        for period in periods {
            if quotas.len() == MAX_QUOTAS {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            validate_level(&period.label)?;
            quotas.push(Quota {
                product,
                level: period.label,
                percent: validate_percent(period.percent)?,
                reset: parse_reset_value(period.reset_at)?,
            });
        }
    }
    if quotas.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(PlanUsage {
        status,
        updated_at: newest_update,
        quotas,
    })
}

fn parse_product(value: &str) -> Option<Product> {
    if value.eq_ignore_ascii_case("coding-plan") {
        Some(Product::Coding)
    } else if value.eq_ignore_ascii_case("agent-plan") {
        Some(Product::Agent)
    } else if value.eq_ignore_ascii_case("coding-plan-team") {
        Some(Product::CodingTeam)
    } else if value.eq_ignore_ascii_case("agent-plan-team") {
        Some(Product::AgentTeam)
    } else {
        None
    }
}

fn parse_reset_value(value: Option<ResetValue>) -> Result<Option<Timestamp>, ClassifiedError> {
    match value {
        None => Ok(None),
        Some(ResetValue::Text(value)) => {
            let value = value.trim();
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Timestamp::parse(value).ok())
            }
        }
        Some(ResetValue::Number(value)) => optional_epoch(Some(value), EpochUnit::Auto),
    }
}

#[derive(Clone, Copy)]
enum EpochUnit {
    Seconds,
    Milliseconds,
    Auto,
}

fn optional_epoch(
    value: Option<f64>,
    unit: EpochUnit,
) -> Result<Option<Timestamp>, ClassifiedError> {
    let Some(mut value) = value else {
        return Ok(None);
    };
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if value <= 0.0 {
        return Ok(None);
    }
    if matches!(unit, EpochUnit::Milliseconds)
        || matches!(unit, EpochUnit::Auto) && value >= 100_000_000_000.0
    {
        value /= 1000.0;
    }
    let seconds = value
        .trunc()
        .to_i64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::from_unix_timestamp(seconds)
        .map(Some)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn parse_reset(raw: &str, fetched_at: Timestamp) -> Option<Timestamp> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(timestamp) = Timestamp::parse(raw) {
        return Some(timestamp);
    }
    let seconds = parse_duration_seconds(raw)?;
    let at = fetched_at
        .as_offset_date_time()
        .checked_add(TimeDuration::seconds(i64::try_from(seconds).ok()?))?;
    Timestamp::new(at).ok()
}

fn parse_duration_seconds(raw: &str) -> Option<u64> {
    if let Ok(seconds) = raw.parse::<u64>() {
        return (seconds > 0).then_some(seconds);
    }
    let bytes = raw.as_bytes();
    let mut index = 0_usize;
    let mut total = 0_u64;
    let mut components = 0_u8;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if start == index || index == bytes.len() {
            return None;
        }
        let number = raw[start..index].parse::<u64>().ok()?;
        let multiplier = match bytes[index] {
            b'd' => 86_400,
            b'h' => 3_600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        total = total.checked_add(number.checked_mul(multiplier)?)?;
        components = components.checked_add(1)?;
        index += 1;
    }
    (components > 0 && total > 0).then_some(total)
}

fn parse_nonnegative_header(value: &str) -> Option<i64> {
    let parsed = value.trim().parse::<i64>().ok()?;
    (parsed >= 0).then_some(parsed)
}

fn action_url(origin: &Url, action: &str) -> Url {
    let mut url = origin.clone();
    url.set_path("/");
    url.set_query(None);
    url.query_pairs_mut()
        .append_pair("Action", action)
        .append_pair("Version", "2024-01-01");
    url
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

fn validate_scope(scope: &AccountScope) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Doubao {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_origin(url: &Url) -> Result<(), ClassifiedError> {
    validate_request_url(url)?;
    if url.path() != "/" || url.query().is_some() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_request_url(url: &Url) -> Result<(), ClassifiedError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn first_setting<'a>(environment: &'a BTreeMap<String, String>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .filter_map(|name| environment.get(*name))
        .find_map(|value| clean_setting(value))
}

fn validate_level(level: &str) -> Result<(), ClassifiedError> {
    if level.is_empty() || level.len() > MAX_LEVEL_BYTES || level.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(())
}

fn validate_percent(percent: f64) -> Result<f64, ClassifiedError> {
    if !percent.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(percent.clamp(0.0, 100.0))
}

fn clean_bounded_text(
    value: Option<String>,
    max_bytes: usize,
) -> Result<Option<String>, ClassifiedError> {
    let Some(value) = value else { return Ok(None) };
    let Some(value) = clean_setting(&value) else {
        return Ok(None);
    };
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(Some(value.to_owned()))
}

fn resolve_arkcli(
    environment: &BTreeMap<String, String>,
) -> Result<ExecutablePath, ClassifiedError> {
    let configured = environment.get(ARKCLI_OVERRIDE).map(String::as_str);
    let path = environment.get("PATH").map(String::as_ref);
    let mut fallbacks = Vec::new();
    if let Some(home) = environment
        .get("HOME")
        .and_then(|value| clean_setting(value))
    {
        let home = Path::new(home);
        if home.is_absolute() {
            fallbacks.push(home.join(".local/bin/arkcli"));
        }
    }
    fallbacks.extend([
        PathBuf::from("/usr/local/bin/arkcli"),
        PathBuf::from("/usr/bin/arkcli"),
    ]);
    let resolved = resolve_executable("arkcli", configured, path, &fallbacks)
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
    const ALLOWED: [&str; 7] = [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "PATH",
        "LANG",
        "LC_ALL",
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

    let mut paths = Vec::new();
    if let Some(parent) = executable.parent().filter(|path| path.is_absolute()) {
        paths.push(parent.to_path_buf());
    }
    if let Some(raw) = source.get("PATH") {
        for path in std::env::split_paths(raw).filter(|path| path.is_absolute()) {
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
    if let Some(existing) = environment.iter_mut().find(|(name, _)| name == "PATH") {
        existing.1 = path;
    } else {
        environment.push(("PATH".to_owned(), path));
    }
    Ok(environment)
}
