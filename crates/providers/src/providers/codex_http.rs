//! Bounded Codex PAT and OAuth HTTP usage adapter.

use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;
use std::time::Duration;

use nix::sys::utsname::uname;
use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, PrivacyKey, ResetCreditsSnapshot, Timestamp,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::codex::{CodexAttemptFailure, CodexBearerCredentials, CodexPatCredentials};
use crate::endpoint::{EndpointClass, EndpointPolicy, classify_https_endpoint};
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, TransportConfig, TransportError,
};

const DEFAULT_CHATGPT_BASE_URL: &str = "https://chatgpt.com/backend-api/";
const WHOAMI_URL: &str = "https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami";
const CHATGPT_USAGE_PATH: &str = "/wham/usage";
const CODEX_USAGE_PATH: &str = "/api/codex/usage";
const PAT_ORIGINATOR: &str = "codex_cli_rs";
const OAUTH_USER_AGENT: &str = "omarchy-ai-bar";

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_CONFIG_LINE_BYTES: usize = 4096;
const MAX_CONFIG_LINES: usize = 4096;
const MAX_URL_BYTES: usize = 4096;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_NODES: usize = 16 * 1024;
const MAX_ADDITIONAL_LIMITS: usize = 128;
const MAX_ACCOUNT_ID_BYTES: usize = 1024;
const MAX_PLAN_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 512;
const MAX_CLI_VERSION_BYTES: usize = 128;
const MAX_REDIRECTS: u8 = 3;

/// Stable, redacted Codex HTTP failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodexHttpError {
    /// HTTP 401 or 403 from either authenticated endpoint.
    #[error("Codex authentication was rejected")]
    Unauthorized,
    /// A successful response was malformed, incompatible, or over its bound.
    #[error("Codex returned an invalid response")]
    InvalidResponse,
    /// A completed HTTP response failed outside the authentication class.
    #[error("Codex returned a server error")]
    Server {
        /// Safe numeric status, when the transport received one.
        status: Option<u16>,
    },
    /// Connection, TLS, or local request timeout failure.
    #[error("Codex could not be reached")]
    Network,
    /// Cooperative cancellation won the request race.
    #[error("Codex request was cancelled")]
    Cancelled,
    /// Endpoint or request configuration was rejected before transmission.
    #[error("Codex HTTP configuration is invalid")]
    Configuration,
}

impl CodexHttpError {
    /// Failure class consumed by the closed Codex source planner.
    #[must_use]
    pub const fn attempt_failure(self) -> CodexAttemptFailure {
        match self {
            Self::Unauthorized => CodexAttemptFailure::Unauthorized,
            Self::InvalidResponse => CodexAttemptFailure::InvalidResponse,
            Self::Server { .. } => CodexAttemptFailure::Server,
            Self::Network | Self::Cancelled => CodexAttemptFailure::Network,
            Self::Configuration => CodexAttemptFailure::Other,
        }
    }

    /// Public-safe domain projection.
    #[must_use]
    pub fn classified(self) -> ClassifiedError {
        let kind = match self {
            Self::Unauthorized => ErrorKind::AuthenticationExpired,
            Self::InvalidResponse => ErrorKind::Parse,
            Self::Server { .. } => ErrorKind::ProviderUnavailable,
            Self::Network | Self::Cancelled => ErrorKind::Network,
            Self::Configuration => ErrorKind::Api,
        };
        ClassifiedError::new(kind)
    }

    /// Numeric response status when the failure came from a completed request.
    #[must_use]
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::Server { status } => status,
            Self::Unauthorized
            | Self::InvalidResponse
            | Self::Network
            | Self::Cancelled
            | Self::Configuration => None,
        }
    }
}

impl From<TransportError> for CodexHttpError {
    fn from(error: TransportError) -> Self {
        let status = error.http_status();
        match error {
            TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
                Self::Unauthorized
            }
            TransportError::Cancelled => Self::Cancelled,
            TransportError::Timeout | TransportError::Network => Self::Network,
            TransportError::ResponseTooLarge
            | TransportError::MalformedResponse
            | TransportError::TooManyRedirects => Self::InvalidResponse,
            TransportError::RequestTimeout
            | TransportError::RateLimited { .. }
            | TransportError::ProviderUnavailable { .. }
            | TransportError::Api { .. } => Self::Server { status },
            TransportError::Endpoint(_) | TransportError::InvalidConfiguration => {
                Self::Configuration
            }
        }
    }
}

/// Known and forward-compatible Codex subscription plans.
#[derive(Clone, PartialEq, Eq)]
pub enum CodexPlanType {
    /// Guest access.
    Guest,
    /// Free individual access.
    Free,
    /// Go subscription.
    Go,
    /// Plus subscription.
    Plus,
    /// Pro subscription.
    Pro,
    /// Free workspace access.
    FreeWorkspace,
    /// Team workspace.
    Team,
    /// Business workspace.
    Business,
    /// Education workspace.
    Education,
    /// Quorum workspace.
    Quorum,
    /// K-12 workspace.
    K12,
    /// Enterprise workspace.
    Enterprise,
    /// Legacy EDU workspace.
    Edu,
    /// A bounded plan value introduced after this adapter.
    Unknown(String),
}

impl Debug for CodexPlanType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Guest => "Guest",
            Self::Free => "Free",
            Self::Go => "Go",
            Self::Plus => "Plus",
            Self::Pro => "Pro",
            Self::FreeWorkspace => "FreeWorkspace",
            Self::Team => "Team",
            Self::Business => "Business",
            Self::Education => "Education",
            Self::Quorum => "Quorum",
            Self::K12 => "K12",
            Self::Enterprise => "Enterprise",
            Self::Edu => "Edu",
            Self::Unknown(_) => "Unknown(<redacted>)",
        };
        formatter.write_str(name)
    }
}

impl CodexPlanType {
    /// Provider wire value.
    #[must_use]
    pub fn raw_value(&self) -> &str {
        match self {
            Self::Guest => "guest",
            Self::Free => "free",
            Self::Go => "go",
            Self::Plus => "plus",
            Self::Pro => "pro",
            Self::FreeWorkspace => "free_workspace",
            Self::Team => "team",
            Self::Business => "business",
            Self::Education => "education",
            Self::Quorum => "quorum",
            Self::K12 => "k12",
            Self::Enterprise => "enterprise",
            Self::Edu => "edu",
            Self::Unknown(value) => value,
        }
    }
}

/// One exact Codex quota window from the usage response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodexWindowSnapshot {
    used_percent: i64,
    reset_at: i64,
    limit_window_seconds: i64,
}

impl CodexWindowSnapshot {
    /// Integer utilization reported by Codex.
    #[must_use]
    pub const fn used_percent(&self) -> i64 {
        self.used_percent
    }

    /// Unix reset timestamp reported by Codex.
    #[must_use]
    pub const fn reset_at(&self) -> i64 {
        self.reset_at
    }

    /// Window duration in seconds.
    #[must_use]
    pub const fn limit_window_seconds(&self) -> i64 {
        self.limit_window_seconds
    }
}

/// Optional monthly spend-control limit in a usage response.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CodexSpendControlLimit {
    limit: Option<f64>,
    used: Option<f64>,
    remaining_percent: Option<f64>,
    resets_at: Option<i64>,
}

impl CodexSpendControlLimit {
    /// Total credit limit.
    #[must_use]
    pub const fn limit(&self) -> Option<f64> {
        self.limit
    }

    /// Credits consumed.
    #[must_use]
    pub const fn used(&self) -> Option<f64> {
        self.used
    }

    /// Remaining percentage when supplied directly.
    #[must_use]
    pub const fn remaining_percent(&self) -> Option<f64> {
        self.remaining_percent
    }

    /// Unix reset timestamp.
    #[must_use]
    pub const fn resets_at(&self) -> Option<i64> {
        self.resets_at
    }
}

/// Primary/secondary quota lanes plus their lossy decode state.
#[derive(Debug, Clone, PartialEq)]
pub struct CodexRateLimitDetails {
    primary_window: Option<CodexWindowSnapshot>,
    secondary_window: Option<CodexWindowSnapshot>,
    individual_limit: Option<CodexSpendControlLimit>,
    primary_window_decode_failed: bool,
    secondary_window_decode_failed: bool,
}

impl CodexRateLimitDetails {
    /// Primary window, when independently decodable.
    #[must_use]
    pub const fn primary_window(&self) -> Option<&CodexWindowSnapshot> {
        self.primary_window.as_ref()
    }

    /// Secondary window, when independently decodable.
    #[must_use]
    pub const fn secondary_window(&self) -> Option<&CodexWindowSnapshot> {
        self.secondary_window.as_ref()
    }

    /// Rate-limit-local individual spend cap.
    #[must_use]
    pub const fn individual_limit(&self) -> Option<&CodexSpendControlLimit> {
        self.individual_limit.as_ref()
    }

    /// Whether a non-null primary window was malformed.
    #[must_use]
    pub const fn primary_window_decode_failed(&self) -> bool {
        self.primary_window_decode_failed
    }

    /// Whether a non-null secondary window was malformed.
    #[must_use]
    pub const fn secondary_window_decode_failed(&self) -> bool {
        self.secondary_window_decode_failed
    }

    /// Whether either independently decoded window was malformed.
    #[must_use]
    pub const fn has_window_decode_failure(&self) -> bool {
        self.primary_window_decode_failed || self.secondary_window_decode_failed
    }
}

/// Optional prepaid-credit state returned beside quota windows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CodexCreditDetails {
    has_credits: bool,
    unlimited: bool,
    balance: Option<f64>,
}

impl CodexCreditDetails {
    /// Whether the account has a prepaid-credit facility.
    #[must_use]
    pub const fn has_credits(&self) -> bool {
        self.has_credits
    }

    /// Whether the facility is unlimited.
    #[must_use]
    pub const fn unlimited(&self) -> bool {
        self.unlimited
    }

    /// Finite numeric balance, accepting the provider's number or string forms.
    #[must_use]
    pub const fn balance(&self) -> Option<f64> {
        self.balance
    }
}

/// One lossy model-specific entry from `additional_rate_limits`.
#[derive(Clone, PartialEq)]
pub struct CodexAdditionalRateLimit {
    limit_name: Option<String>,
    metered_feature: Option<String>,
    rate_limit: Option<CodexRateLimitDetails>,
    rate_limit_decode_failed: bool,
    metadata_truncated: bool,
}

impl CodexAdditionalRateLimit {
    /// Provider display label.
    #[must_use]
    pub fn limit_name(&self) -> Option<&str> {
        self.limit_name.as_deref()
    }

    /// Stable metered-feature identifier.
    #[must_use]
    pub fn metered_feature(&self) -> Option<&str> {
        self.metered_feature.as_deref()
    }

    /// Independently decoded rate-limit object.
    #[must_use]
    pub const fn rate_limit(&self) -> Option<&CodexRateLimitDetails> {
        self.rate_limit.as_ref()
    }

    /// Whether a present rate-limit object or either of its windows failed decoding.
    #[must_use]
    pub fn has_window_decode_failure(&self) -> bool {
        self.rate_limit_decode_failed
            || self
                .rate_limit
                .as_ref()
                .is_some_and(CodexRateLimitDetails::has_window_decode_failure)
    }

    fn has_decode_failure(&self) -> bool {
        self.metadata_truncated || self.has_window_decode_failure()
    }
}

impl Debug for CodexAdditionalRateLimit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAdditionalRateLimit")
            .field("has_limit_name", &self.limit_name.is_some())
            .field("has_metered_feature", &self.metered_feature.is_some())
            .field("has_rate_limit", &self.rate_limit.is_some())
            .field("rate_limit_decode_failed", &self.rate_limit_decode_failed)
            .field("metadata_truncated", &self.metadata_truncated)
            .finish()
    }
}

/// Bounded, forward-compatible core response from Codex usage HTTP APIs.
#[derive(Clone, PartialEq)]
pub struct CodexUsageResponse {
    account_id: Option<String>,
    plan_type: Option<CodexPlanType>,
    identity_metadata_truncated: bool,
    rate_limit: Option<CodexRateLimitDetails>,
    credits: Option<CodexCreditDetails>,
    individual_limit: Option<CodexSpendControlLimit>,
    spend_control_individual_limit: Option<CodexSpendControlLimit>,
    spend_control_present: bool,
    additional_rate_limits: Option<Vec<CodexAdditionalRateLimit>>,
    additional_rate_limits_decode_failed: bool,
}

impl CodexUsageResponse {
    /// Provider account identifier, with snake-case precedence over camel-case.
    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// Known or bounded forward-compatible plan.
    #[must_use]
    pub const fn plan_type(&self) -> Option<&CodexPlanType> {
        self.plan_type.as_ref()
    }

    /// Whether an otherwise string-shaped account or plan label exceeded its parser bound.
    #[must_use]
    pub const fn identity_metadata_truncated(&self) -> bool {
        self.identity_metadata_truncated
    }

    /// Core primary and secondary limits.
    #[must_use]
    pub const fn rate_limit(&self) -> Option<&CodexRateLimitDetails> {
        self.rate_limit.as_ref()
    }

    /// Optional prepaid-credit state.
    #[must_use]
    pub const fn credits(&self) -> Option<&CodexCreditDetails> {
        self.credits.as_ref()
    }

    /// Response-root individual limit before precedence resolution.
    #[must_use]
    pub const fn individual_limit(&self) -> Option<&CodexSpendControlLimit> {
        self.individual_limit.as_ref()
    }

    /// Nested `spend_control` individual limit before precedence resolution.
    #[must_use]
    pub const fn spend_control_individual_limit(&self) -> Option<&CodexSpendControlLimit> {
        self.spend_control_individual_limit.as_ref()
    }

    /// Whether either `spend_control` alias was present, including null/malformed values.
    #[must_use]
    pub const fn spend_control_present(&self) -> bool {
        self.spend_control_present
    }

    /// Lossily retained model-specific limits. `None` preserves absent/non-array distinction.
    #[must_use]
    pub fn additional_rate_limits(&self) -> Option<&[CodexAdditionalRateLimit]> {
        self.additional_rate_limits.as_deref()
    }

    /// Whether any non-null additional entry or nested window was malformed or truncated by bounds.
    #[must_use]
    pub const fn additional_rate_limits_decode_failed(&self) -> bool {
        self.additional_rate_limits_decode_failed
    }

    /// Individual-limit precedence from the pinned API: root, rate-limit, then spend-control.
    #[must_use]
    pub fn resolved_individual_limit(&self) -> Option<&CodexSpendControlLimit> {
        self.individual_limit
            .as_ref()
            .or_else(|| {
                self.rate_limit
                    .as_ref()
                    .and_then(CodexRateLimitDetails::individual_limit)
            })
            .or(self.spend_control_individual_limit.as_ref())
    }
}

impl Debug for CodexUsageResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexUsageResponse")
            .field(
                "account_id",
                &self.account_id.as_ref().map(|_| "<redacted>"),
            )
            .field("plan_type", &self.plan_type)
            .field(
                "identity_metadata_truncated",
                &self.identity_metadata_truncated,
            )
            .field("rate_limit", &self.rate_limit)
            .field("credits", &self.credits)
            .field("individual_limit", &self.individual_limit)
            .field(
                "spend_control_individual_limit",
                &self.spend_control_individual_limit,
            )
            .field("spend_control_present", &self.spend_control_present)
            .field(
                "additional_rate_limit_count",
                &self.additional_rate_limits.as_ref().map(Vec::len),
            )
            .field(
                "additional_rate_limits_decode_failed",
                &self.additional_rate_limits_decode_failed,
            )
            .finish()
    }
}

/// Parses one bounded Codex core usage response.
///
/// Optional root fields, windows, credits, and additional limits retain the
/// pinned lossy behavior. Malformed primary and secondary windows never suppress
/// a valid sibling, and malformed additional elements never suppress valid ones.
///
/// # Errors
///
/// Returns [`CodexHttpError::InvalidResponse`] for an invalid root document or
/// document-wide byte/depth/node bound violation.
pub fn parse_codex_usage_response(data: &[u8]) -> Result<CodexUsageResponse, CodexHttpError> {
    let root = decode_bounded_object(data)?;
    let identity_metadata_truncated = ["account_id", "accountId"]
        .into_iter()
        .any(|key| string_exceeds_bound(&root, key, MAX_ACCOUNT_ID_BYTES))
        || string_exceeds_bound(&root, "plan_type", MAX_PLAN_BYTES);
    let account_id = lossy_string_alias(&root, "account_id", "accountId", MAX_ACCOUNT_ID_BYTES);
    let plan_type = root
        .get("plan_type")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= MAX_PLAN_BYTES)
        .map(parse_plan);
    let rate_limit = root.get("rate_limit").and_then(parse_rate_limit);
    let credits = root.get("credits").and_then(parse_credits);
    let individual_limit = lossy_limit_alias(&root, "individual_limit", "individualLimit");
    let spend_control_individual_limit =
        parse_spend_control_alias(&root, "spend_control", "spendControl");
    let spend_control_present =
        root.contains_key("spend_control") || root.contains_key("spendControl");
    let (additional_rate_limits, additional_rate_limits_decode_failed) =
        parse_additional_limits(root.get("additional_rate_limits"));

    Ok(CodexUsageResponse {
        account_id,
        plan_type,
        identity_metadata_truncated,
        rate_limit,
        credits,
        individual_limit,
        spend_control_individual_limit,
        spend_control_present,
        additional_rate_limits,
        additional_rate_limits_decode_failed,
    })
}

/// PAT identity returned by the mandatory whoami request.
#[derive(Clone, PartialEq, Eq)]
pub struct CodexPatWhoami {
    account_id: Option<String>,
    email: Option<String>,
    plan_type: Option<String>,
}

impl CodexPatWhoami {
    /// Token-owned account identifier.
    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// Token-owned account email.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Token-owned plan label.
    #[must_use]
    pub fn plan_type(&self) -> Option<&str> {
        self.plan_type.as_deref()
    }
}

impl Debug for CodexPatWhoami {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexPatWhoami")
            .field(
                "account_id",
                &self.account_id.as_ref().map(|_| "<redacted>"),
            )
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field("plan_type", &self.plan_type.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Result of mandatory sequential PAT whoami and usage requests.
#[derive(Debug, Clone, PartialEq)]
pub struct CodexPatUsageFetch {
    usage: CodexUsageResponse,
    whoami: Option<CodexPatWhoami>,
}

impl CodexPatUsageFetch {
    /// Parsed core usage response.
    #[must_use]
    pub const fn usage(&self) -> &CodexUsageResponse {
        &self.usage
    }

    /// Whoami identity that scoped the usage request.
    #[must_use]
    pub const fn whoami(&self) -> Option<&CodexPatWhoami> {
        self.whoami.as_ref()
    }
}

/// Fully resolved fixed whoami and configured usage routes.
#[derive(Clone)]
pub struct CodexHttpRoutes {
    whoami: Url,
    whoami_class: EndpointClass,
    usage: Url,
    usage_class: EndpointClass,
    reset_credits: Url,
}

impl CodexHttpRoutes {
    /// Resolves the default or an injected `chatgpt_base_url` configuration.
    ///
    /// The injected text is parsed only for this key; no file is read. An
    /// explicit malformed or insecure value fails closed instead of silently
    /// sending credentials to the default endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`CodexHttpError::Configuration`] for oversized/ambiguous config,
    /// non-HTTPS endpoints, URL credentials, query/fragment state, or invalid URLs.
    pub fn from_config_text(config_text: Option<&str>) -> Result<Self, CodexHttpError> {
        let whoami = Url::parse(WHOAMI_URL).map_err(|_| CodexHttpError::Configuration)?;
        let whoami_class =
            classify_https_endpoint(&whoami).map_err(|_| CodexHttpError::Configuration)?;
        let usage = resolve_usage_url(config_text)?;
        let usage_class =
            classify_https_endpoint(&usage).map_err(|_| CodexHttpError::Configuration)?;
        validate_exact_origin(&whoami, whoami_class)?;
        validate_exact_origin(&usage, usage_class)?;
        let reset_credits = reset_credits_url(&usage)?;
        Ok(Self {
            whoami,
            whoami_class,
            usage,
            usage_class,
            reset_credits,
        })
    }

    /// Creates loopback-only routes for deterministic integration tests.
    ///
    /// # Errors
    ///
    /// Rejects non-loopback, credential-bearing, query-bearing, or fragmented URLs.
    pub fn loopback(whoami: Url, usage: Url) -> Result<Self, CodexHttpError> {
        validate_exact_origin(&whoami, EndpointClass::LoopbackDevelopment)?;
        validate_exact_origin(&usage, EndpointClass::LoopbackDevelopment)?;
        let reset_credits = reset_credits_url(&usage)?;
        Ok(Self {
            whoami,
            whoami_class: EndpointClass::LoopbackDevelopment,
            usage,
            usage_class: EndpointClass::LoopbackDevelopment,
            reset_credits,
        })
    }

    /// Fixed PAT whoami URL.
    #[must_use]
    pub const fn whoami_url(&self) -> &Url {
        &self.whoami
    }

    /// Resolved Codex usage URL.
    #[must_use]
    pub const fn usage_url(&self) -> &Url {
        &self.usage
    }

    /// Reset inventory endpoint on the same configured origin as usage.
    #[must_use]
    pub const fn reset_credits_url(&self) -> &Url {
        &self.reset_credits
    }

    pub(crate) const fn is_loopback_only(&self) -> bool {
        matches!(self.whoami_class, EndpointClass::LoopbackDevelopment)
            && matches!(self.usage_class, EndpointClass::LoopbackDevelopment)
    }
}

impl Debug for CodexHttpRoutes {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexHttpRoutes")
            .field("whoami_origin", &origin(&self.whoami))
            .field("usage_origin", &origin(&self.usage))
            .field("paths", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Cookie-less, bounded Codex HTTP client.
///
/// Whoami and usage intentionally use separate exact-origin transports. Even
/// when both origins are approved for the overall flow, authentication cannot
/// cross from one to the other through a redirect.
pub struct CodexHttpClient {
    routes: CodexHttpRoutes,
    whoami_transport: HttpTransport,
    usage_transport: HttpTransport,
}

impl CodexHttpClient {
    /// Creates the production client from default or injected config text.
    ///
    /// # Errors
    ///
    /// Returns a redacted configuration failure for unsafe routes or transport setup.
    pub fn from_config_text(config_text: Option<&str>) -> Result<Self, CodexHttpError> {
        let routes = CodexHttpRoutes::from_config_text(config_text)?;
        Self::with_transport_config(routes, transport_config()?)
    }

    /// Creates a client for already validated routes with explicit bounded transport settings.
    ///
    /// This seam supports short deterministic loopback deadlines while retaining
    /// the same cookie-less transport and exact-origin redirect policy.
    ///
    /// # Errors
    ///
    /// Returns a redacted configuration failure if either exact-origin transport cannot be built.
    pub fn with_transport_config(
        routes: CodexHttpRoutes,
        config: TransportConfig,
    ) -> Result<Self, CodexHttpError> {
        let whoami_transport = transport_for(&routes.whoami, routes.whoami_class, config)?;
        let usage_transport = transport_for(&routes.usage, routes.usage_class, config)?;
        Ok(Self {
            routes,
            whoami_transport,
            usage_transport,
        })
    }

    /// Performs mandatory PAT whoami followed by account-scoped usage.
    ///
    /// The second request is never attempted unless whoami succeeds and decodes.
    /// The usage account header comes only from that token-owned response.
    ///
    /// # Errors
    ///
    /// Returns stable authentication, parse, server, network, cancellation, or
    /// configuration classes without response bodies, URLs, identity, or tokens.
    pub async fn fetch_pat_usage(
        &self,
        credentials: &CodexPatCredentials,
        cli_version: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<CodexPatUsageFetch, CodexHttpError> {
        let user_agent = codex_cli_user_agent(cli_version)?;
        let whoami_request = pat_request(
            self.routes.whoami.clone(),
            credentials.token(),
            &user_agent,
            None,
        )?;
        let whoami_response = self
            .whoami_transport
            .send(&whoami_request, cancellation)
            .await
            .map_err(CodexHttpError::from)?;
        let whoami = parse_whoami(whoami_response.body())?;

        let usage_request = pat_request(
            self.routes.usage.clone(),
            credentials.token(),
            &user_agent,
            whoami.account_id(),
        )?;
        let usage_response = self
            .usage_transport
            .send(&usage_request, cancellation)
            .await
            .map_err(CodexHttpError::from)?;
        let usage = parse_codex_usage_response(usage_response.body())?;
        Ok(CodexPatUsageFetch {
            usage,
            whoami: Some(whoami),
        })
    }

    /// Fetches core OAuth/API-key usage with an optional managed-account override.
    ///
    /// A non-empty managed account wins over the credential account, matching the
    /// pinned managed-workspace routing seam. A blank override is treated as absent.
    ///
    /// # Errors
    ///
    /// Returns stable authentication, parse, server, network, cancellation, or
    /// configuration classes without response bodies, URLs, identity, or tokens.
    pub async fn fetch_oauth_usage(
        &self,
        credentials: &CodexBearerCredentials,
        managed_account_override: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<CodexUsageResponse, CodexHttpError> {
        let account_id =
            clean_account_override(managed_account_override)?.or_else(|| credentials.account_id());
        let request = oauth_request(
            self.routes.usage.clone(),
            credentials.access_token(),
            account_id,
        )?;
        let response = self
            .usage_transport
            .send(&request, cancellation)
            .await
            .map_err(CodexHttpError::from)?;
        parse_codex_usage_response(response.body())
    }
    /// Fetches banked resets using the exact OAuth authority of the usage request.
    ///
    /// # Errors
    /// Returns redacted HTTP or inventory validation failures. No redemption is performed.
    pub async fn fetch_reset_credits(
        &self,
        credentials: &CodexBearerCredentials,
        managed_account_override: Option<&str>,
        key: &PrivacyKey,
        scope: AccountScope,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> Result<ResetCreditsSnapshot, CodexHttpError> {
        let account_id =
            clean_account_override(managed_account_override)?.or_else(|| credentials.account_id());
        let request = oauth_request(
            self.routes.reset_credits.clone(),
            credentials.access_token(),
            account_id,
        )?
        .public_header("openai-beta", "codex-1")
        .map_err(CodexHttpError::from)?
        .public_header("originator", "Codex Desktop")
        .map_err(CodexHttpError::from)?;
        let response = tokio::time::timeout(
            Duration::from_secs(4),
            self.usage_transport.send(&request, cancellation),
        )
        .await
        .map_err(|_| CodexHttpError::Network)?
        .map_err(CodexHttpError::from)?;
        super::codex_resets::parse_codex_reset_credits(response.body(), key, scope, fetched_at)
    }
}

impl Debug for CodexHttpClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexHttpClient")
            .field("routes", &self.routes)
            .field("transports", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn decode_bounded_object(data: &[u8]) -> Result<Map<String, Value>, CodexHttpError> {
    if data.is_empty() || data.len() > MAX_RESPONSE_BYTES {
        return Err(CodexHttpError::InvalidResponse);
    }
    let value: Value = serde_json::from_slice(data).map_err(|_| CodexHttpError::InvalidResponse)?;
    let mut nodes = 0_usize;
    validate_json(&value, 0, &mut nodes)?;
    value
        .as_object()
        .cloned()
        .ok_or(CodexHttpError::InvalidResponse)
}

fn validate_json(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), CodexHttpError> {
    if depth > MAX_JSON_DEPTH || *nodes >= MAX_JSON_NODES {
        return Err(CodexHttpError::InvalidResponse);
    }
    *nodes += 1;
    match value {
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_json(value, depth + 1, nodes)),
        Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_json(value, depth + 1, nodes)),
        _ => Ok(()),
    }
}

fn parse_plan(value: &str) -> CodexPlanType {
    match value {
        "guest" => CodexPlanType::Guest,
        "free" => CodexPlanType::Free,
        "go" => CodexPlanType::Go,
        "plus" => CodexPlanType::Plus,
        "pro" => CodexPlanType::Pro,
        "free_workspace" => CodexPlanType::FreeWorkspace,
        "team" => CodexPlanType::Team,
        "business" => CodexPlanType::Business,
        "education" => CodexPlanType::Education,
        "quorum" => CodexPlanType::Quorum,
        "k12" => CodexPlanType::K12,
        "enterprise" => CodexPlanType::Enterprise,
        "edu" => CodexPlanType::Edu,
        unknown => CodexPlanType::Unknown(unknown.to_owned()),
    }
}

fn parse_window(value: &Value) -> Option<CodexWindowSnapshot> {
    let object = value.as_object()?;
    Some(CodexWindowSnapshot {
        used_percent: object.get("used_percent")?.as_i64()?,
        reset_at: object.get("reset_at")?.as_i64()?,
        limit_window_seconds: object.get("limit_window_seconds")?.as_i64()?,
    })
}

fn parse_lossy_window(
    object: &Map<String, Value>,
    key: &str,
) -> (Option<CodexWindowSnapshot>, bool) {
    let Some(value) = object.get(key) else {
        return (None, false);
    };
    if value.is_null() {
        return (None, false);
    }
    let parsed = parse_window(value);
    let failed = parsed.is_none();
    (parsed, failed)
}

fn parse_rate_limit(value: &Value) -> Option<CodexRateLimitDetails> {
    let object = value.as_object()?;
    let (primary_window, primary_window_decode_failed) =
        parse_lossy_window(object, "primary_window");
    let (secondary_window, secondary_window_decode_failed) =
        parse_lossy_window(object, "secondary_window");
    Some(CodexRateLimitDetails {
        primary_window,
        secondary_window,
        individual_limit: lossy_limit_alias(object, "individual_limit", "individualLimit"),
        primary_window_decode_failed,
        secondary_window_decode_failed,
    })
}

fn parse_limit(value: &Value) -> Option<CodexSpendControlLimit> {
    let object = value.as_object()?;
    Some(CodexSpendControlLimit {
        limit: object.get("limit").and_then(flexible_f64),
        used: object.get("used").and_then(flexible_f64),
        remaining_percent: object
            .get("remainingPercent")
            .and_then(flexible_f64)
            .or_else(|| object.get("remaining_percent").and_then(flexible_f64)),
        resets_at: object
            .get("resetsAt")
            .and_then(flexible_i64)
            .or_else(|| object.get("resets_at").and_then(flexible_i64))
            .or_else(|| object.get("reset_at").and_then(flexible_i64)),
    })
}

fn lossy_limit_alias(
    object: &Map<String, Value>,
    snake: &str,
    camel: &str,
) -> Option<CodexSpendControlLimit> {
    object
        .get(snake)
        .and_then(parse_limit)
        .or_else(|| object.get(camel).and_then(parse_limit))
}

fn parse_spend_control_alias(
    object: &Map<String, Value>,
    snake: &str,
    camel: &str,
) -> Option<CodexSpendControlLimit> {
    if let Some(wrapper) = object.get(snake).and_then(Value::as_object) {
        // A successfully decoded snake-case wrapper wins even when its nested
        // optional limit is absent. This matches the pinned decoder's
        // `(try? snake) ?? (try? camel)` wrapper precedence.
        return lossy_limit_alias(wrapper, "individual_limit", "individualLimit");
    }
    object.get(camel).and_then(parse_spend_control)
}

fn parse_spend_control(value: &Value) -> Option<CodexSpendControlLimit> {
    let object = value.as_object()?;
    lossy_limit_alias(object, "individual_limit", "individualLimit")
}

fn parse_credits(value: &Value) -> Option<CodexCreditDetails> {
    let object = value.as_object()?;
    Some(CodexCreditDetails {
        has_credits: object
            .get("has_credits")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        unlimited: object
            .get("unlimited")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        balance: object.get("balance").and_then(flexible_f64),
    })
}

fn parse_additional_limits(value: Option<&Value>) -> (Option<Vec<CodexAdditionalRateLimit>>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    if value.is_null() {
        return (None, false);
    }
    let Some(values) = value.as_array() else {
        return (None, true);
    };
    let mut limits = Vec::with_capacity(values.len().min(MAX_ADDITIONAL_LIMITS));
    let mut decode_failed = values.len() > MAX_ADDITIONAL_LIMITS;
    for value in values.iter().take(MAX_ADDITIONAL_LIMITS) {
        let Some(limit) = parse_additional_limit(value) else {
            decode_failed = true;
            continue;
        };
        decode_failed |= limit.has_decode_failure();
        limits.push(limit);
    }
    (Some(limits), decode_failed)
}

fn parse_additional_limit(value: &Value) -> Option<CodexAdditionalRateLimit> {
    let object = value.as_object()?;
    let rate_limit_value = object.get("rate_limit");
    let rate_limit = rate_limit_value.and_then(parse_rate_limit);
    let rate_limit_decode_failed =
        rate_limit_value.is_some_and(|value| !value.is_null()) && rate_limit.is_none();
    let limit_name = bounded_string(object.get("limit_name"), MAX_LABEL_BYTES);
    let metered_feature = bounded_string(object.get("metered_feature"), MAX_LABEL_BYTES);
    let metadata_truncated = ["limit_name", "metered_feature"].into_iter().any(|key| {
        object
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() > MAX_LABEL_BYTES)
    });
    Some(CodexAdditionalRateLimit {
        limit_name,
        metered_feature,
        rate_limit,
        rate_limit_decode_failed,
        metadata_truncated,
    })
}

fn flexible_f64(value: &Value) -> Option<f64> {
    let parsed = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(value) if value.len() <= MAX_LABEL_BYTES => value.trim().parse().ok(),
        _ => None,
    }?;
    parsed.is_finite().then_some(parsed)
}

fn flexible_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                return Some(value);
            }
            decimal_i64(&number.to_string())
        }
        Value::String(value) if value.len() <= MAX_LABEL_BYTES => value.trim().parse().ok(),
        _ => None,
    }
}

fn decimal_i64(value: &str) -> Option<i64> {
    Decimal::from_str(value)
        .or_else(|_| Decimal::from_scientific(value))
        .ok()?
        .trunc()
        .to_i64()
}

fn bounded_string(value: Option<&Value>, max_bytes: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| value.len() <= max_bytes)
        .map(str::to_owned)
}

fn string_exceeds_bound(object: &Map<String, Value>, key: &str, max_bytes: usize) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| value.len() > max_bytes)
}

fn lossy_string_alias(
    object: &Map<String, Value>,
    snake: &str,
    camel: &str,
    max_bytes: usize,
) -> Option<String> {
    bounded_string(object.get(snake), max_bytes)
        .or_else(|| bounded_string(object.get(camel), max_bytes))
}

fn parse_whoami(data: &[u8]) -> Result<CodexPatWhoami, CodexHttpError> {
    let object = decode_bounded_object(data)?;
    Ok(CodexPatWhoami {
        account_id: strict_optional_clean_string(
            &object,
            "chatgpt_account_id",
            MAX_ACCOUNT_ID_BYTES,
        )?,
        email: strict_optional_clean_string(&object, "email", MAX_LABEL_BYTES)?,
        plan_type: strict_optional_clean_string(&object, "chatgpt_plan_type", MAX_PLAN_BYTES)?,
    })
}

fn strict_optional_clean_string(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>, CodexHttpError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value.as_str().ok_or(CodexHttpError::InvalidResponse)?;
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > max_bytes || value.contains(['\r', '\n']) {
        return Err(CodexHttpError::InvalidResponse);
    }
    Ok(Some(value.to_owned()))
}

fn pat_request(
    url: Url,
    token: &str,
    user_agent: &str,
    account_id: Option<&str>,
) -> Result<HttpRequest, CodexHttpError> {
    let authentication = Authentication::bearer(token.to_owned()).map_err(CodexHttpError::from)?;
    let mut request = HttpRequest::get_json(url)
        .authentication(authentication)
        .public_header("user-agent", user_agent)
        .map_err(CodexHttpError::from)?
        .public_header("originator", PAT_ORIGINATOR)
        .map_err(CodexHttpError::from)?;
    if let Some(account_id) = account_id {
        request = request
            .sensitive_header("chatgpt-account-id", account_id.to_owned())
            .map_err(CodexHttpError::from)?;
    }
    Ok(request)
}

fn oauth_request(
    url: Url,
    token: &str,
    account_id: Option<&str>,
) -> Result<HttpRequest, CodexHttpError> {
    let authentication = Authentication::bearer(token.to_owned()).map_err(CodexHttpError::from)?;
    let mut request = HttpRequest::get_json(url)
        .authentication(authentication)
        .public_header("user-agent", OAUTH_USER_AGENT)
        .map_err(CodexHttpError::from)?;
    if let Some(account_id) = account_id {
        request = request
            .sensitive_header("chatgpt-account-id", account_id.to_owned())
            .map_err(CodexHttpError::from)?;
    }
    Ok(request)
}

fn clean_account_override(value: Option<&str>) -> Result<Option<&str>, CodexHttpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_ACCOUNT_ID_BYTES || value.contains(['\r', '\n']) {
        return Err(CodexHttpError::Configuration);
    }
    Ok(Some(value))
}

/// Builds the bounded Linux Codex CLI-shaped PAT user agent.
///
/// A detected CLI version is normalized exactly like the pinned client. The OS
/// triplet comes from `uname(2)` and safely falls back to `0.0.0` only when the
/// kernel release cannot be read or normalized.
///
/// # Errors
///
/// Returns [`CodexHttpError::Configuration`] for an oversized or line-breaking
/// injected CLI version.
pub fn codex_cli_user_agent(cli_version: Option<&str>) -> Result<String, CodexHttpError> {
    let version = normalize_cli_version(cli_version)?;
    let os_version = linux_os_version();
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => "unknown",
    };
    Ok(version.map_or_else(
        || format!("codex_cli_rs (Linux {os_version}; {architecture})"),
        |version| format!("codex_cli_rs/{version} (Linux {os_version}; {architecture})"),
    ))
}

fn normalize_cli_version(value: Option<&str>) -> Result<Option<&str>, CodexHttpError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > MAX_CLI_VERSION_BYTES || value.contains(['\r', '\n']) {
        return Err(CodexHttpError::Configuration);
    }
    let mut parts = value.split_whitespace();
    let first = parts.next().ok_or(CodexHttpError::Configuration)?;
    let second = parts.next();
    let version = if first.eq_ignore_ascii_case("codex-cli") && second.is_some() {
        second
    } else {
        Some(first)
    };
    Ok(version.filter(|version| !version.is_empty()))
}

fn linux_os_version() -> String {
    uname()
        .ok()
        .and_then(|name| name.release().to_str().and_then(kernel_version_triplet))
        .unwrap_or_else(|| "0.0.0".to_owned())
}

fn kernel_version_triplet(release: &str) -> Option<String> {
    if release.is_empty()
        || release.len() > MAX_LABEL_BYTES
        || release.chars().any(char::is_control)
    {
        return None;
    }
    let mut components = release
        .split(|character: char| !character.is_ascii_digit())
        .filter(|component| !component.is_empty())
        .map(str::parse::<u32>);
    let major = components.next()?.ok()?;
    let minor = components.next().transpose().ok()?.unwrap_or(0);
    let patch = components.next().transpose().ok()?.unwrap_or(0);
    Some(format!("{major}.{minor}.{patch}"))
}

fn reset_credits_url(usage: &Url) -> Result<Url, CodexHttpError> {
    let base = usage
        .path()
        .strip_suffix(CHATGPT_USAGE_PATH)
        .or_else(|| usage.path().strip_suffix(CODEX_USAGE_PATH))
        .or_else(|| usage.path().strip_suffix("/usage"))
        .ok_or(CodexHttpError::Configuration)?;
    let mut url = usage.clone();
    url.set_path(&format!("{base}/wham/rate-limit-reset-credits"));
    Ok(url)
}

fn resolve_usage_url(config_text: Option<&str>) -> Result<Url, CodexHttpError> {
    let configured = match config_text {
        Some(text) => parse_config_base_url(text)?,
        None => None,
    };
    let raw = configured.as_deref().unwrap_or(DEFAULT_CHATGPT_BASE_URL);
    if raw.len() > MAX_URL_BYTES || raw.chars().any(char::is_control) {
        return Err(CodexHttpError::Configuration);
    }
    let mut base = Url::parse(raw).map_err(|_| CodexHttpError::Configuration)?;
    if base.scheme() != "https"
        || base.host().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(CodexHttpError::Configuration);
    }
    let host = base
        .host_str()
        .ok_or(CodexHttpError::Configuration)?
        .to_ascii_lowercase();
    let mut path = base.path().trim_end_matches('/').to_owned();
    if matches!(host.as_str(), "chatgpt.com" | "chat.openai.com") && !path.contains("/backend-api")
    {
        path.push_str("/backend-api");
    }
    let usage_path = if path.contains("/backend-api") {
        CHATGPT_USAGE_PATH
    } else {
        CODEX_USAGE_PATH
    };
    path.push_str(usage_path);
    if path.len() > MAX_URL_BYTES {
        return Err(CodexHttpError::Configuration);
    }
    base.set_path(&path);
    validate_exact_origin(
        &base,
        classify_https_endpoint(&base).map_err(|_| CodexHttpError::Configuration)?,
    )?;
    Ok(base)
}

fn parse_config_base_url(config: &str) -> Result<Option<String>, CodexHttpError> {
    if config.len() > MAX_CONFIG_BYTES {
        return Err(CodexHttpError::Configuration);
    }
    let mut found = None;
    for (index, raw_line) in config.lines().enumerate() {
        if index >= MAX_CONFIG_LINES || raw_line.len() > MAX_CONFIG_LINE_BYTES {
            return Err(CodexHttpError::Configuration);
        }
        let Some((raw_key, _)) = raw_line.split_once('=') else {
            continue;
        };
        if raw_key.trim() != "chatgpt_base_url" {
            continue;
        }
        let line = strip_toml_comment(raw_line)?.trim();
        let Some((_, raw_value)) = line.split_once('=') else {
            return Err(CodexHttpError::Configuration);
        };
        if found.is_some() {
            return Err(CodexHttpError::Configuration);
        }
        let value = parse_config_string(raw_value.trim())?;
        found = Some(value.to_owned());
    }
    Ok(found)
}

fn strip_toml_comment(line: &str) -> Result<&str, CodexHttpError> {
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' && quote == Some(b'"') {
            escaped = true;
            continue;
        }
        if matches!(byte, b'"' | b'\'') {
            match quote {
                Some(current) if current == byte => quote = None,
                None => quote = Some(byte),
                Some(_) => {}
            }
            continue;
        }
        if byte == b'#' && quote.is_none() {
            return Ok(&line[..index]);
        }
    }
    if quote.is_some() || escaped {
        return Err(CodexHttpError::Configuration);
    }
    Ok(line)
}

fn parse_config_string(value: &str) -> Result<&str, CodexHttpError> {
    if value.is_empty() {
        return Err(CodexHttpError::Configuration);
    }
    let bytes = value.as_bytes();
    if matches!(bytes.first(), Some(b'"' | b'\'')) {
        let quote = bytes[0];
        if bytes.len() < 2 || bytes.last() != Some(&quote) {
            return Err(CodexHttpError::Configuration);
        }
        let inner = &value[1..value.len() - 1];
        if inner.contains(['\r', '\n', '\\']) {
            return Err(CodexHttpError::Configuration);
        }
        let inner = inner.trim();
        return (!inner.is_empty())
            .then_some(inner)
            .ok_or(CodexHttpError::Configuration);
    }
    if value.chars().any(char::is_whitespace) {
        return Err(CodexHttpError::Configuration);
    }
    Ok(value)
}

fn validate_exact_origin(url: &Url, class: EndpointClass) -> Result<(), CodexHttpError> {
    if url.query().is_some() || url.fragment().is_some() {
        return Err(CodexHttpError::Configuration);
    }
    let policy =
        EndpointPolicy::new([(origin(url), class)]).map_err(|_| CodexHttpError::Configuration)?;
    policy
        .validate(url)
        .map_err(|_| CodexHttpError::Configuration)?;
    Ok(())
}

fn origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn transport_for(
    url: &Url,
    class: EndpointClass,
    config: TransportConfig,
) -> Result<HttpTransport, CodexHttpError> {
    let policy =
        EndpointPolicy::new([(origin(url), class)]).map_err(|_| CodexHttpError::Configuration)?;
    HttpTransport::new(policy, config).map_err(CodexHttpError::from)
}

fn transport_config() -> Result<TransportConfig, CodexHttpError> {
    TransportConfig::new(
        Duration::from_secs(10),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        MAX_REDIRECTS,
        RetryPolicy::none(),
    )
    .map_err(CodexHttpError::from)
}
