//! Codex app-server protocol adapter.
//!
//! Executable discovery and credential planning intentionally live outside
//! this module. The adapter owns only the fixed, read-only app-server
//! invocation, its bounded JSON-RPC lifecycle, and response normalization.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CreditLimitSnapshot, CreditsSnapshot,
    DataConfidence, DisplayPercent, ErrorKind, ExactDecimal, IdentitySnapshot, ProviderId,
    RateWindow, Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::codex::CodexAttemptFailure;
use crate::executable::ExecutablePath;
use crate::json_rpc_child::{JsonRpcChild, JsonRpcChildError, JsonRpcChildRequest, JsonRpcVersion};
use crate::normalize::UsageSampleBuilder;

const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(8);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const MAX_LIMIT_ENTRIES: usize = 128;
const MAX_LIMIT_KEY_BYTES: usize = 256;
const MAX_RECOVERY_BODY_BYTES: usize = 128 * 1024;
const MAX_RECOVERY_JSON_DEPTH: usize = 32;
const MAX_RECOVERY_JSON_NODES: usize = 8 * 1024;
const MAX_RECOVERY_STRING_BYTES: usize = 64 * 1024;
const MAX_NUMERIC_TEXT_BYTES: usize = 128;

// Keep this list closed and explicit. In particular, credentials and dynamic
// loader controls must never cross from the bar into a provider-owned child.
const CHILD_ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "HOME",
    "PATH",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_ADDRESS",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "NIX_SSL_CERT_FILE",
    "AWS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
];

/// The protocol operation whose deadline elapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAppServerStage {
    /// The app-server initialization handshake.
    Initialize,
    /// The mandatory rate-limit request.
    RateLimits,
    /// The optional account-enrichment request.
    Account,
}

/// Stable, path-free and secret-free app-server failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CodexAppServerError {
    /// Fixed child construction failed local validation.
    #[error("Codex app-server configuration is invalid")]
    InvalidConfiguration,
    /// The resolved executable could not be started.
    #[error("Codex app-server could not be started")]
    Start,
    /// Cooperative cancellation stopped the operation.
    #[error("Codex app-server operation was cancelled")]
    Cancelled,
    /// A protocol operation exceeded its fixed deadline.
    #[error("Codex app-server operation timed out")]
    Timeout {
        /// Safe operation classification; no peer text is retained.
        stage: CodexAppServerStage,
    },
    /// The child process streams failed or closed unexpectedly.
    #[error("Codex app-server transport failed")]
    Transport,
    /// A response exceeded the provider's fixed memory ceiling.
    #[error("Codex app-server response exceeded its size limit")]
    ResponseTooLarge,
    /// A response envelope or supported result shape was malformed.
    #[error("Codex app-server returned invalid data")]
    Protocol,
    /// The peer returned an unrecoverable JSON-RPC error.
    #[error("Codex app-server returned an error")]
    Remote {
        /// Optional peer code; the potentially sensitive message is discarded.
        code: Option<i64>,
    },
    /// The authoritative rate response contained no usable limits, credits, or identity.
    #[error("Codex app-server returned no rate limits")]
    NoRateLimits,
}

impl CodexAppServerError {
    /// Failure class consumed by the closed Codex source planner.
    #[must_use]
    pub const fn attempt_failure(self) -> CodexAttemptFailure {
        match self {
            Self::Start => CodexAttemptFailure::Unavailable,
            Self::Timeout { .. } | Self::Transport => CodexAttemptFailure::Network,
            Self::ResponseTooLarge | Self::Protocol | Self::NoRateLimits => {
                CodexAttemptFailure::InvalidResponse
            }
            Self::Remote { .. } => CodexAttemptFailure::Server,
            Self::InvalidConfiguration | Self::Cancelled => CodexAttemptFailure::Other,
        }
    }

    /// Public-safe domain projection.
    #[must_use]
    pub fn classified(self) -> ClassifiedError {
        let kind = match self {
            Self::Start | Self::Remote { .. } => ErrorKind::ProviderUnavailable,
            Self::Cancelled | Self::Timeout { .. } | Self::Transport => ErrorKind::Network,
            Self::ResponseTooLarge | Self::Protocol | Self::NoRateLimits => ErrorKind::Parse,
            Self::InvalidConfiguration => ErrorKind::Api,
        };
        ClassifiedError::new(kind)
    }
}

/// One authoritative app-server result.
///
/// Credits remain separate from usage to preserve the upstream ability to
/// represent credits-only payloads. Identity is also retained when no quota
/// window is available.
#[derive(Clone)]
pub struct CodexAppServerSnapshot {
    usage: Option<UsageSample>,
    credits: Option<CreditsSnapshot>,
    identity: Option<IdentitySnapshot>,
}

impl CodexAppServerSnapshot {
    /// Normalized quota usage, including an identity-only unavailable sample.
    #[must_use]
    pub const fn usage(&self) -> Option<&UsageSample> {
        self.usage.as_ref()
    }

    /// Provider credit balance and optional periodic spending limit.
    #[must_use]
    pub const fn credits(&self) -> Option<&CreditsSnapshot> {
        self.credits.as_ref()
    }

    /// Best-effort account identity from the same child session.
    #[must_use]
    pub const fn identity(&self) -> Option<&IdentitySnapshot> {
        self.identity.as_ref()
    }

    /// Consumes the app-server lanes into the runtime's single usage sample.
    ///
    /// Windowed and identity-only samples already carry their same-session
    /// credits. When the app-server returns credits alone, this synthesizes the
    /// empty usage marker used by the pinned CLI strategy. Unsafe recovered
    /// identity is never reintroduced.
    ///
    /// # Errors
    ///
    /// Returns [`CodexAppServerError::NoRateLimits`] if the snapshot contains
    /// neither usage nor credits, or [`CodexAppServerError::Protocol`] if the
    /// retained bounded identity cannot be projected into the domain model.
    pub fn into_usage_sample(self) -> Result<UsageSample, CodexAppServerError> {
        if let Some(usage) = self.usage {
            return Ok(usage);
        }
        let credits = self.credits.ok_or(CodexAppServerError::NoRateLimits)?;
        let email = self
            .identity
            .as_ref()
            .and_then(IdentitySnapshot::email)
            .map(|value| value.as_str().to_owned());
        let login_method = self
            .identity
            .as_ref()
            .and_then(IdentitySnapshot::login_method)
            .map(|value| value.as_str().to_owned());
        UsageSampleBuilder::new(credits.scope().clone(), credits.updated_at())
            .credits(credits)
            .confidence(DataConfidence::Unknown)
            .email(email)
            .and_then(|builder| builder.login_method(login_method))
            .and_then(|builder| builder.provenance("codex", "cli"))
            .and_then(UsageSampleBuilder::build)
            .map_err(|_| CodexAppServerError::Protocol)
    }
}

impl Debug for CodexAppServerSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAppServerSnapshot")
            .field("has_usage", &self.usage.is_some())
            .field("has_credits", &self.credits.is_some())
            .field("has_identity", &self.identity.is_some())
            .finish()
    }
}

/// A client for one already-resolved Codex executable.
pub struct CodexAppServerClient {
    executable: ExecutablePath,
    environment: Vec<(String, String)>,
}

impl CodexAppServerClient {
    /// Creates the protocol adapter with an empty child environment.
    ///
    /// Executable discovery and any environment selection remain caller-owned.
    #[must_use]
    pub const fn new(executable: ExecutablePath) -> Self {
        Self {
            executable,
            environment: Vec::new(),
        }
    }

    /// Creates the protocol adapter from a deterministic, closed environment allowlist.
    ///
    /// The selected values are validated using the same hard bounds as the
    /// child transport. API keys, unrelated application settings, dynamic
    /// loader variables, and arbitrary names are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`CodexAppServerError::InvalidConfiguration`] when an allowed
    /// value violates the child transport's fixed bounds.
    pub fn from_environment(
        executable: ExecutablePath,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, CodexAppServerError> {
        Self::from_environment_with_authority(executable, environment, None)
    }

    pub(crate) fn from_environment_for_authority(
        executable: ExecutablePath,
        environment: &BTreeMap<String, String>,
        home: &str,
        codex_home: &str,
    ) -> Result<Self, CodexAppServerError> {
        Self::from_environment_with_authority(executable, environment, Some((home, codex_home)))
    }

    fn from_environment_with_authority(
        executable: ExecutablePath,
        environment: &BTreeMap<String, String>,
        authority: Option<(&str, &str)>,
    ) -> Result<Self, CodexAppServerError> {
        let selected = CHILD_ENVIRONMENT_ALLOWLIST
            .iter()
            .filter_map(|name| {
                let authority_value = match (*name, authority) {
                    ("HOME", Some((home, _))) => Some(home),
                    ("CODEX_HOME", Some((_, codex_home))) => Some(codex_home),
                    _ => None,
                };
                authority_value
                    .map(str::to_owned)
                    .or_else(|| environment.get(*name).cloned())
                    .map(|value| ((*name).to_owned(), value))
            })
            .collect();
        let client = Self {
            executable,
            environment: selected,
        };
        client.child_request()?;
        Ok(client)
    }

    /// Fetches one account-scoped app-server snapshot.
    ///
    /// Every successfully spawned child is explicitly shut down, including
    /// cancellation, timeout, remote-error recovery, and parser failures.
    ///
    /// # Errors
    ///
    /// Returns a stable [`CodexAppServerError`] for child lifecycle, bounded
    /// protocol, cancellation, or authoritative no-data failures.
    pub async fn fetch(
        &self,
        scope: AccountScope,
        fetched_at: Timestamp,
        cancellation: &CancellationToken,
    ) -> Result<CodexAppServerSnapshot, CodexAppServerError> {
        if scope.provider() != ProviderId::Codex {
            return Err(CodexAppServerError::InvalidConfiguration);
        }
        let request = self.child_request()?;
        let mut child = request
            .spawn(cancellation)
            .await
            .map_err(|error| map_child_error(error, CodexAppServerStage::Initialize))?;
        let result = fetch_from_child(&mut child, &scope, fetched_at, cancellation).await;
        child.shutdown().await;
        result
    }

    fn child_request(&self) -> Result<JsonRpcChildRequest, CodexAppServerError> {
        let mut request = JsonRpcChildRequest::new(
            self.executable.clone(),
            fixed_arguments(),
            JsonRpcVersion::Omitted,
            MAX_FRAME_BYTES,
            MAX_STDERR_BYTES,
        )
        .map_err(|_| CodexAppServerError::InvalidConfiguration)?
        .with_cleared_environment();
        for (name, value) in &self.environment {
            request = request
                .with_environment(name.as_str(), value.as_str())
                .map_err(|_| CodexAppServerError::InvalidConfiguration)?;
        }
        Ok(request)
    }
}

impl Debug for CodexAppServerClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAppServerClient")
            .field("executable", &"<redacted>")
            .field("environment_entry_count", &self.environment.len())
            .finish()
    }
}

fn fixed_arguments() -> [OsString; 5] {
    ["-s", "read-only", "-a", "never", "app-server"].map(OsString::from)
}

async fn fetch_from_child(
    child: &mut JsonRpcChild,
    scope: &AccountScope,
    fetched_at: Timestamp,
    cancellation: &CancellationToken,
) -> Result<CodexAppServerSnapshot, CodexAppServerError> {
    child
        .request(
            "initialize",
            Some(json!({
                "clientInfo": {
                    "name": "omarchy-ai-bar",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            })),
            INITIALIZE_TIMEOUT,
            cancellation,
        )
        .await
        .map_err(|error| map_child_error(error, CodexAppServerStage::Initialize))?;
    child
        .notify(
            "initialized",
            Some(json!({})),
            INITIALIZE_TIMEOUT,
            cancellation,
        )
        .await
        .map_err(|error| map_child_error(error, CodexAppServerStage::Initialize))?;

    let response = match child
        .request(
            "account/rateLimits/read",
            None,
            REQUEST_TIMEOUT,
            cancellation,
        )
        .await
    {
        Ok(response) => response,
        Err(JsonRpcChildError::Remote(error)) => {
            if cancellation.is_cancelled() {
                return Err(CodexAppServerError::Cancelled);
            }
            return recover_remote_snapshot(error.expose_message(), scope, fetched_at)
                .ok_or(CodexAppServerError::Remote { code: error.code() });
        }
        Err(error) => return Err(map_child_error(error, CodexAppServerStage::RateLimits)),
    };
    let rate = ParsedRateResponse::parse(&response)?;
    let account = read_account_best_effort(child, cancellation).await?;
    if cancellation.is_cancelled() {
        return Err(CodexAppServerError::Cancelled);
    }
    normalize_success(rate, account.as_ref(), scope, fetched_at)
}

async fn read_account_best_effort(
    child: &mut JsonRpcChild,
    cancellation: &CancellationToken,
) -> Result<Option<AccountFields>, CodexAppServerError> {
    match child
        .request("account/read", None, REQUEST_TIMEOUT, cancellation)
        .await
    {
        Ok(value) => Ok(parse_account_response(&value)),
        Err(JsonRpcChildError::Cancelled) => Err(CodexAppServerError::Cancelled),
        Err(_) if cancellation.is_cancelled() => Err(CodexAppServerError::Cancelled),
        Err(_) => Ok(None),
    }
}

fn map_child_error(error: JsonRpcChildError, stage: CodexAppServerStage) -> CodexAppServerError {
    match error {
        JsonRpcChildError::InvalidConfiguration => CodexAppServerError::InvalidConfiguration,
        JsonRpcChildError::Spawn => CodexAppServerError::Start,
        JsonRpcChildError::Cancelled => CodexAppServerError::Cancelled,
        JsonRpcChildError::Timeout => CodexAppServerError::Timeout { stage },
        JsonRpcChildError::StdoutTooLarge | JsonRpcChildError::StderrTooLarge => {
            CodexAppServerError::ResponseTooLarge
        }
        JsonRpcChildError::Protocol => CodexAppServerError::Protocol,
        JsonRpcChildError::Remote(error) => CodexAppServerError::Remote { code: error.code() },
        JsonRpcChildError::StdinClosed
        | JsonRpcChildError::StdoutRead
        | JsonRpcChildError::StderrRead
        | JsonRpcChildError::Closed => CodexAppServerError::Transport,
    }
}

#[derive(Default)]
struct AccountFields {
    email: Option<String>,
    plan: Option<String>,
}

fn parse_account_response(value: &Value) -> Option<AccountFields> {
    let root = value.as_object()?;
    let account = root.get("account")?;
    if account.is_null() {
        return Some(AccountFields::default());
    }
    let object = account.as_object()?;
    let account_type = object.get("type")?.as_str()?;
    match account_type.to_ascii_lowercase().as_str() {
        "apikey" => Some(AccountFields::default()),
        "chatgpt" => {
            let email = account_string_or_default(object, "email")?;
            let plan = account_string_or_default(object, "planType")?;
            Some(AccountFields {
                email: identity_text(Some(&email)),
                plan: identity_text(Some(&plan)),
            })
        }
        _ => None,
    }
}

fn account_string_or_default(object: &Map<String, Value>, key: &str) -> Option<String> {
    match object.get(key) {
        None | Some(Value::Null) => Some("unknown".to_owned()),
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => None,
    }
}

struct ParsedRateResponse {
    limits: ParsedLimit,
    by_id: Vec<ParsedLimitEntry>,
}

impl ParsedRateResponse {
    fn parse(value: &Value) -> Result<Self, CodexAppServerError> {
        let root = value.as_object().ok_or(CodexAppServerError::Protocol)?;
        let limits = root
            .get("rateLimits")
            .and_then(Value::as_object)
            .map(ParsedLimit::parse)
            .ok_or(CodexAppServerError::Protocol)?;
        let by_id = parse_limit_map(root.get("rateLimitsByLimitId"))
            .or_else(|| parse_limit_map(root.get("rate_limits_by_limit_id")))
            .unwrap_or_default();
        Ok(Self { limits, by_id })
    }
}

struct ParsedLimitEntry {
    key: String,
    limit: ParsedLimit,
}

struct ParsedLimit {
    limit_id: Option<String>,
    limit_name: Option<String>,
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
    credits: Option<ParsedCredits>,
    individual_limit: Option<ParsedSpendLimit>,
    plan: Option<String>,
}

impl ParsedLimit {
    fn parse(object: &Map<String, Value>) -> Self {
        Self {
            limit_id: alias_string(object, &["limitId", "limit_id"]),
            limit_name: alias_string(object, &["limitName", "limit_name"]),
            primary: object.get("primary").and_then(parse_rpc_window),
            secondary: object.get("secondary").and_then(parse_rpc_window),
            credits: object.get("credits").and_then(parse_rpc_credits),
            individual_limit: alias_parsed(
                object,
                &["individualLimit", "individual_limit"],
                parse_spend_limit,
            ),
            plan: alias_string(object, &["planType", "plan_type"])
                .and_then(|value| identity_text(Some(&value))),
        }
    }
}

struct ParsedCredits {
    balance: Option<Decimal>,
}

struct ParsedSpendLimit {
    limit: Option<Decimal>,
    used: Option<Decimal>,
    remaining_percent: Option<Decimal>,
    resets_at: Option<i64>,
}

fn parse_limit_map(value: Option<&Value>) -> Option<Vec<ParsedLimitEntry>> {
    let object = value?.as_object()?;
    if object.len() > MAX_LIMIT_ENTRIES {
        return None;
    }
    object
        .iter()
        .map(|(key, value)| {
            if key.len() > MAX_LIMIT_KEY_BYTES {
                return None;
            }
            Some(ParsedLimitEntry {
                key: key.clone(),
                limit: ParsedLimit::parse(value.as_object()?),
            })
        })
        .collect()
}

fn parse_rpc_window(value: &Value) -> Option<RateWindow> {
    let object = value.as_object()?;
    let used = alias_parsed(object, &["usedPercent", "used_percent"], flexible_f64)?;
    let duration = alias_parsed(
        object,
        &["windowDurationMins", "window_duration_mins"],
        flexible_i64,
    )
    .and_then(|minutes| WindowDuration::optional_from_provider_minutes(minutes).ok())
    .flatten();
    let resets_at =
        alias_parsed(object, &["resetsAt", "resets_at"], flexible_i64).and_then(valid_timestamp);
    rate_window(used, duration, resets_at)
}

fn parse_rpc_credits(value: &Value) -> Option<ParsedCredits> {
    let object = value.as_object()?;
    alias_parsed(object, &["hasCredits", "has_credits"], Value::as_bool)?;
    object.get("unlimited")?.as_bool()?;
    let balance = match object.get("balance") {
        None | Some(Value::Null) => None,
        Some(value @ (Value::String(_) | Value::Number(_))) => flexible_decimal(value),
        Some(_) => return None,
    };
    Some(ParsedCredits { balance })
}

fn parse_spend_limit(value: &Value) -> Option<ParsedSpendLimit> {
    let object = value.as_object()?;
    Some(ParsedSpendLimit {
        limit: object.get("limit").and_then(flexible_decimal),
        used: object.get("used").and_then(flexible_decimal),
        remaining_percent: alias_parsed(
            object,
            &["remainingPercent", "remaining_percent"],
            flexible_decimal,
        ),
        resets_at: alias_parsed(object, &["resetsAt", "resets_at"], flexible_i64),
    })
}

fn alias_parsed<T>(
    object: &Map<String, Value>,
    names: &[&str],
    parser: impl Fn(&Value) -> Option<T>,
) -> Option<T> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(&parser))
}

fn alias_string(object: &Map<String, Value>, names: &[&str]) -> Option<String> {
    alias_parsed(object, names, |value| value.as_str().map(ToOwned::to_owned))
}

fn flexible_f64(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) if text.len() <= MAX_NUMERIC_TEXT_BYTES => text.trim().parse().ok()?,
        _ => return None,
    };
    number.is_finite().then_some(number)
}

fn flexible_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
            .or_else(|| number.as_f64().and_then(truncated_i64)),
        Value::String(text) if text.len() <= MAX_NUMERIC_TEXT_BYTES => {
            text.trim().parse::<i64>().ok()
        }
        _ => None,
    }
}

fn truncated_i64(value: f64) -> Option<i64> {
    Decimal::from_f64_retain(value)?.trunc().to_i64()
}

fn flexible_decimal(value: &Value) -> Option<Decimal> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) if text.len() <= MAX_NUMERIC_TEXT_BYTES => text.trim().to_owned(),
        _ => return None,
    };
    (!text.is_empty())
        .then(|| Decimal::from_str(&text).ok())
        .flatten()
}

fn rate_window(
    used_percent: f64,
    duration: Option<WindowDuration>,
    resets_at: Option<Timestamp>,
) -> Option<RateWindow> {
    let usage = UsagePercent::new(used_percent).ok()?;
    RateWindow::new(
        WindowUsage::known(usage),
        duration,
        resets_at,
        None,
        None,
        false,
    )
    .ok()
}

fn valid_timestamp(seconds: i64) -> Option<Timestamp> {
    Timestamp::from_unix_timestamp(seconds).ok()
}

fn normalize_success(
    rate: ParsedRateResponse,
    account: Option<&AccountFields>,
    scope: &AccountScope,
    fetched_at: Timestamp,
) -> Result<CodexAppServerSnapshot, CodexAppServerError> {
    let rate_plan = rate.limits.plan.clone();
    let identity_fields = AccountFields {
        email: account.as_ref().and_then(|value| value.email.clone()),
        plan: account
            .as_ref()
            .and_then(|value| value.plan.clone())
            .or_else(|| rate_plan.clone()),
    };
    let identity = build_identity(scope, &identity_fields)?;
    let credits = build_credits(&rate, scope, fetched_at);
    let should_make_empty_usage = credits.is_none() || rate_plan.is_some();
    let (primary, secondary) = normalize_windows(rate.limits.primary, rate.limits.secondary);
    let usage = build_usage(
        scope,
        fetched_at,
        primary,
        secondary,
        &identity_fields,
        should_make_empty_usage,
        credits.as_ref(),
    )?;
    if usage.is_none() && credits.is_none() {
        return Err(CodexAppServerError::NoRateLimits);
    }
    Ok(CodexAppServerSnapshot {
        usage,
        credits,
        identity: Some(identity),
    })
}

fn build_identity(
    scope: &AccountScope,
    fields: &AccountFields,
) -> Result<IdentitySnapshot, CodexAppServerError> {
    let email = fields
        .email
        .clone()
        .map(BoundedText::<256>::new)
        .transpose()
        .map_err(|_| CodexAppServerError::Protocol)?;
    let plan = fields
        .plan
        .clone()
        .map(BoundedText::<256>::new)
        .transpose()
        .map_err(|_| CodexAppServerError::Protocol)?;
    Ok(IdentitySnapshot::new(
        scope.clone(),
        None,
        email,
        None,
        None,
        None,
        plan,
    ))
}

fn build_usage(
    scope: &AccountScope,
    fetched_at: Timestamp,
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
    fields: &AccountFields,
    make_empty_if_identified: bool,
    credits: Option<&CreditsSnapshot>,
) -> Result<Option<UsageSample>, CodexAppServerError> {
    let has_windows = primary.is_some() || secondary.is_some();
    let has_identity = fields.email.is_some() || fields.plan.is_some();
    if !(has_windows || make_empty_if_identified && has_identity) {
        return Ok(None);
    }
    let mut builder =
        UsageSampleBuilder::new(scope.clone(), fetched_at).confidence(DataConfidence::Unknown);
    if let Some(window) = primary {
        builder = builder.primary(window);
    }
    if let Some(window) = secondary {
        builder = builder.secondary(window);
    }
    if let Some(credits) = credits {
        builder = builder.credits(credits.clone());
    }
    let sample = builder
        .email(fields.email.clone())
        .and_then(|builder| builder.login_method(fields.plan.clone()))
        .and_then(|builder| builder.provenance("codex", "cli"))
        .and_then(UsageSampleBuilder::build)
        .map_err(|_| CodexAppServerError::Protocol)?;
    Ok(Some(sample))
}

fn normalize_windows(
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
) -> (Option<RateWindow>, Option<RateWindow>) {
    match (primary, secondary) {
        (Some(primary), Some(secondary)) => {
            match (window_role(&primary), window_role(&secondary)) {
                (WindowRole::Weekly, WindowRole::Session | WindowRole::Unknown) => {
                    (Some(secondary), Some(primary))
                }
                _ => (Some(primary), Some(secondary)),
            }
        }
        (Some(window), None) if window_role(&window) == WindowRole::Weekly => (None, Some(window)),
        (Some(window), None) => (Some(window), None),
        (None, Some(window)) if window_role(&window) != WindowRole::Weekly => (Some(window), None),
        (None, Some(window)) => (None, Some(window)),
        (None, None) => (None, None),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowRole {
    Session,
    Weekly,
    Unknown,
}

fn window_role(window: &RateWindow) -> WindowRole {
    match window.duration().map(WindowDuration::seconds) {
        Some(18_000) => WindowRole::Session,
        Some(604_800) => WindowRole::Weekly,
        _ => WindowRole::Unknown,
    }
}

fn build_credits(
    rate: &ParsedRateResponse,
    scope: &AccountScope,
    fetched_at: Timestamp,
) -> Option<CreditsSnapshot> {
    let balance = rate
        .limits
        .credits
        .as_ref()
        .map(|credits| credits.balance.unwrap_or(Decimal::ZERO).max(Decimal::ZERO));
    let limit = find_credit_limit(rate, fetched_at);
    if balance.is_none() && limit.is_none() {
        return None;
    }
    CreditsSnapshot::new(
        scope.clone(),
        ExactDecimal::new(balance.unwrap_or(Decimal::ZERO)),
        Vec::new(),
        fetched_at,
        limit,
    )
    .ok()
}

fn find_credit_limit(
    rate: &ParsedRateResponse,
    fetched_at: Timestamp,
) -> Option<CreditLimitSnapshot> {
    if let Some(limit) = make_credit_limit(&rate.limits, fetched_at) {
        return Some(limit);
    }
    let mut entries = rate.by_id.iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        limit_sort_key(left)
            .cmp(limit_sort_key(right))
            .then_with(|| left.key.cmp(&right.key))
    });
    entries
        .into_iter()
        .find_map(|entry| make_credit_limit(&entry.limit, fetched_at))
}

fn limit_sort_key(entry: &ParsedLimitEntry) -> &str {
    entry
        .limit
        .limit_name
        .as_deref()
        .or(entry.limit.limit_id.as_deref())
        .unwrap_or("")
}

fn make_credit_limit(snapshot: &ParsedLimit, fetched_at: Timestamp) -> Option<CreditLimitSnapshot> {
    let individual = snapshot.individual_limit.as_ref()?;
    let limit = individual.limit.filter(|value| *value > Decimal::ZERO)?;
    let supplied_remaining = individual
        .remaining_percent
        .map(|value| value.clamp(Decimal::ZERO, Decimal::ONE_HUNDRED));
    let used = match individual.used {
        Some(value) => value.max(Decimal::ZERO),
        None => match supplied_remaining {
            Some(remaining) => Decimal::ONE_HUNDRED
                .checked_sub(remaining)?
                .checked_mul(limit)?
                .checked_div(Decimal::ONE_HUNDRED)?,
            None => Decimal::ZERO,
        },
    };
    let remaining = match supplied_remaining {
        Some(remaining) => remaining,
        None => Decimal::ONE_HUNDRED
            .checked_sub(used.checked_mul(Decimal::ONE_HUNDRED)?.checked_div(limit)?)?
            .clamp(Decimal::ZERO, Decimal::ONE_HUNDRED),
    };
    let remaining = DisplayPercent::new(remaining.to_f64()?).ok()?;
    let resets_at = individual
        .resets_at
        .filter(|value| *value > 0)
        .and_then(valid_timestamp);
    CreditLimitSnapshot::new(
        snapshot.limit_name.as_deref().unwrap_or(""),
        ExactDecimal::new(used),
        ExactDecimal::new(limit),
        remaining,
        resets_at,
        fetched_at,
    )
    .ok()
}

fn identity_text(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    BoundedText::<256>::new(value)
        .ok()
        .map(|value| value.as_str().to_owned())
}

fn recover_remote_snapshot(
    message: &str,
    scope: &AccountScope,
    fetched_at: Timestamp,
) -> Option<CodexAppServerSnapshot> {
    let body = extract_recovery_body(message)?;
    let root = body.as_object()?;
    let fields = AccountFields {
        email: root
            .get("email")
            .and_then(Value::as_str)
            .and_then(|value| identity_text(Some(value))),
        plan: root
            .get("plan_type")
            .and_then(Value::as_str)
            .and_then(|value| identity_text(Some(value))),
    };
    let parsed_windows = root
        .get("rate_limit")
        .and_then(Value::as_object)
        .map(parse_recovery_windows)
        .unwrap_or_default();
    let (primary, secondary) = normalize_windows(parsed_windows.primary, parsed_windows.secondary);
    let unsafe_window_recovery = parsed_windows.decode_failed && primary.is_none();
    let credits = root
        .get("credits")
        .and_then(parse_recovery_credits)
        .and_then(|remaining| {
            CreditsSnapshot::new(
                scope.clone(),
                ExactDecimal::new(remaining),
                Vec::new(),
                fetched_at,
                None,
            )
            .ok()
        });
    let usage = if unsafe_window_recovery {
        None
    } else {
        build_usage(
            scope,
            fetched_at,
            primary,
            secondary,
            &fields,
            false,
            credits.as_ref(),
        )
        .ok()?
    };
    if usage.is_none() && credits.is_none() {
        return None;
    }
    let identity = usage.as_ref().map(|sample| sample.identity().clone());
    Some(CodexAppServerSnapshot {
        usage,
        credits,
        identity,
    })
}

#[derive(Default)]
struct RecoveryWindows {
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
    decode_failed: bool,
}

fn parse_recovery_windows(object: &Map<String, Value>) -> RecoveryWindows {
    let (primary, primary_failed) = parse_recovery_window_field(object, "primary_window");
    let (secondary, secondary_failed) = parse_recovery_window_field(object, "secondary_window");
    RecoveryWindows {
        primary,
        secondary,
        decode_failed: primary_failed || secondary_failed,
    }
}

fn parse_recovery_window_field(
    object: &Map<String, Value>,
    key: &str,
) -> (Option<RateWindow>, bool) {
    let Some(value) = object.get(key) else {
        return (None, false);
    };
    if value.is_null() {
        return (None, false);
    }
    let parsed = parse_recovery_window(value);
    let failed = parsed.is_none();
    (parsed, failed)
}

fn parse_recovery_window(value: &Value) -> Option<RateWindow> {
    let object = value.as_object()?;
    let used = object.get("used_percent").and_then(flexible_f64)?;
    let reset = object.get("reset_at").and_then(flexible_i64)?;
    let duration_seconds = object.get("limit_window_seconds").and_then(flexible_i64)?;
    let duration = u64::try_from(duration_seconds)
        .ok()
        .and_then(|seconds| WindowDuration::from_seconds(seconds).ok());
    rate_window(used, duration, valid_timestamp(reset))
}

fn parse_recovery_credits(value: &Value) -> Option<Decimal> {
    let object = value.as_object()?;
    let balance = object.get("balance").and_then(flexible_decimal)?;
    (balance >= Decimal::ZERO).then_some(balance)
}

fn extract_recovery_body(message: &str) -> Option<Value> {
    let suffix = message.split_once("body=")?.1;
    let start = suffix.find('{')?;
    let object = balanced_object(&suffix[start..])?;
    if object.len() > MAX_RECOVERY_BODY_BYTES {
        return None;
    }
    let value: Value = serde_json::from_str(object).ok()?;
    bounded_recovery_json(&value).then_some(value)
}

fn balanced_object(value: &str) -> Option<&str> {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if index >= MAX_RECOVERY_BODY_BYTES {
            return None;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth = depth.checked_add(1)?,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return value.get(..=index);
                }
            }
            _ => {}
        }
    }
    None
}

fn bounded_recovery_json(root: &Value) -> bool {
    let mut stack = vec![(root, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_RECOVERY_JSON_NODES || depth > MAX_RECOVERY_JSON_DEPTH {
            return false;
        }
        match value {
            Value::String(value) if value.len() > MAX_RECOVERY_STRING_BYTES => return false,
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values
                    .keys()
                    .any(|key| key.len() > MAX_RECOVERY_STRING_BYTES)
                {
                    return false;
                }
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    true
}
