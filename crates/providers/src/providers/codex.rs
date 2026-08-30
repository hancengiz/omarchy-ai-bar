//! Codex credential provenance and source planning.
//!
//! The native Codex CLI owns `$CODEX_HOME/auth.json` (or `~/.codex/auth.json`).
//! This module parses that document without persisting or refreshing it. External
//! legacy/OpenCode OAuth files remain opt-in and read-only.

use std::fmt::{self, Debug, Formatter};

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use oab_domain::Timestamp;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use zeroize::Zeroizing;

const MAX_AUTH_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 4096;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_ID_BYTES: usize = 1024;
const NATIVE_REFRESH_SKEW_SECONDS: i64 = 5 * 60;
const EXTERNAL_REFRESH_SKEW_SECONDS: i64 = 60;
const LAST_REFRESH_MAX_AGE_SECONDS: i64 = 8 * 24 * 60 * 60;

/// Ownership boundary for one Codex credential document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexCredentialSource {
    /// The Codex CLI-owned `$CODEX_HOME/auth.json` document.
    Native,
    /// The historical `~/.config/codex/auth.json` document.
    Legacy,
    /// `OpenCode`'s `${XDG_DATA_HOME}/opencode/auth.json` document.
    OpenCode,
}

impl CodexCredentialSource {
    /// Whether the native Codex CLI may rotate this source.
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::Native)
    }
}

/// Bearer material selected from a Codex credential document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexBearerKind {
    /// `ChatGPT` OAuth access and refresh tokens.
    OAuth,
    /// An `OPENAI_API_KEY` embedded by the Codex CLI.
    ApiKey,
}

/// A validated Codex personal access token.
pub struct CodexPatCredentials {
    token: Zeroizing<String>,
    source: CodexCredentialSource,
}

impl CodexPatCredentials {
    /// Secret token bytes for an authenticated request boundary.
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    /// Provider-owned source of the token.
    #[must_use]
    pub const fn source(&self) -> CodexCredentialSource {
        self.source
    }
}

impl Debug for CodexPatCredentials {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexPatCredentials")
            .field("token", &"<redacted>")
            .field("source", &self.source)
            .finish()
    }
}

/// Validated Codex OAuth or embedded API-key material.
pub struct CodexBearerCredentials {
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    id_token: Option<Zeroizing<String>>,
    account_id: Option<String>,
    last_refresh: Option<Timestamp>,
    expires_at: Option<Timestamp>,
    source: CodexCredentialSource,
    kind: CodexBearerKind,
}

impl CodexBearerCredentials {
    /// Secret bearer token bytes for an authenticated request boundary.
    #[must_use]
    pub fn access_token(&self) -> &str {
        self.access_token.as_str()
    }

    /// Secret refresh token bytes. API-key and some read-only sources have none.
    #[must_use]
    pub fn refresh_token(&self) -> &str {
        self.refresh_token.as_str()
    }

    /// Optional ID token bytes used only for bounded local identity decoding.
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref().map(String::as_str)
    }

    /// Stable provider account identifier, when supplied or recoverable from JWT claims.
    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// Credential timestamp recorded by the owning application.
    #[must_use]
    pub const fn last_refresh(&self) -> Option<Timestamp> {
        self.last_refresh
    }

    /// Exact integer JWT/OpenCode expiry when one was safely decoded.
    #[must_use]
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Provider-owned source of the credential.
    #[must_use]
    pub const fn source(&self) -> CodexCredentialSource {
        self.source
    }

    /// OAuth versus embedded API-key authentication.
    #[must_use]
    pub const fn kind(&self) -> CodexBearerKind {
        self.kind
    }

    /// Whether the owning application must rotate this credential at `now`.
    #[must_use]
    pub fn needs_refresh_at(&self, now: Timestamp) -> bool {
        if self.kind == CodexBearerKind::ApiKey {
            return false;
        }
        if let Some(expires_at) = self.expires_at {
            let skew = if self.source.is_native() {
                NATIVE_REFRESH_SKEW_SECONDS
            } else {
                EXTERNAL_REFRESH_SKEW_SECONDS
            };
            return expires_at
                .unix_timestamp()
                .saturating_sub(now.unix_timestamp())
                <= skew;
        }
        let Some(last_refresh) = self.last_refresh else {
            return true;
        };
        now.unix_timestamp()
            .saturating_sub(last_refresh.unix_timestamp())
            > LAST_REFRESH_MAX_AGE_SECONDS
    }
}

impl Debug for CodexBearerCredentials {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexBearerCredentials")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "account_id",
                &self.account_id.as_ref().map(|_| "<redacted>"),
            )
            .field("last_refresh", &self.last_refresh)
            .field("expires_at", &self.expires_at)
            .field("source", &self.source)
            .field("kind", &self.kind)
            .finish()
    }
}

/// Stable credential parsing or authority failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodexCredentialError {
    /// The authoritative native document is absent.
    #[error("Codex credentials are missing")]
    NotFound,
    /// The authoritative document exists but cannot be read safely.
    #[error("Codex credentials could not be read safely")]
    Unreadable,
    /// JSON, shape, or bounded-field validation failed.
    #[error("Codex credentials are malformed")]
    Invalid,
    /// A valid JSON object contained no supported credential.
    #[error("Codex credentials contain no supported token")]
    MissingTokens,
    /// Native OAuth must be refreshed by the Codex CLI owner.
    #[error("Codex native credentials require owner refresh")]
    NativeRefreshRequired,
    /// External OAuth material is stale and must be refreshed by its owner.
    #[error("external Codex credentials are stale and read-only")]
    ReadOnlySource,
}

/// Parses only a native Codex personal access token lane.
///
/// OAuth/API-key material is deliberately ignored, so automatic planning can
/// classify a missing PAT and continue to the independently parsed bearer lane.
///
/// # Errors
///
/// Returns a stable invalid or missing-token error without exposing input bytes.
pub fn parse_native_codex_pat(data: &[u8]) -> Result<CodexPatCredentials, CodexCredentialError> {
    let object = decode_bounded_object(data)?;
    pat_credentials(&object, CodexCredentialSource::Native)?
        .ok_or(CodexCredentialError::MissingTokens)
}

/// Parses the source-authorized Codex bearer lane.
///
/// Native documents accept the embedded API key before OAuth. Legacy Codex
/// documents accept OAuth only. `OpenCode` uses its nested `openai` OAuth entry.
/// PAT fields are ignored for every bearer lane.
///
/// # Errors
///
/// Returns a stable invalid or missing-token error without exposing input bytes.
pub fn parse_codex_bearer(
    data: &[u8],
    source: CodexCredentialSource,
) -> Result<CodexBearerCredentials, CodexCredentialError> {
    let object = decode_bounded_object(data)?;
    match source {
        CodexCredentialSource::Native => match api_key_credentials(&object, source)? {
            Some(credentials) => Ok(credentials),
            None => oauth_credentials(&object, source)?.ok_or(CodexCredentialError::MissingTokens),
        },
        CodexCredentialSource::Legacy => {
            oauth_credentials(&object, source)?.ok_or(CodexCredentialError::MissingTokens)
        }
        CodexCredentialSource::OpenCode => parse_opencode_object(&object),
    }
}

/// Parses `OpenCode`'s bounded, read-only `OpenAI` OAuth entry.
///
/// # Errors
///
/// Returns a stable invalid or missing-token error without exposing input bytes.
pub fn parse_opencode_oauth(data: &[u8]) -> Result<CodexBearerCredentials, CodexCredentialError> {
    let object = decode_bounded_object(data)?;
    parse_opencode_object(&object)
}

fn parse_opencode_object(
    object: &Map<String, Value>,
) -> Result<CodexBearerCredentials, CodexCredentialError> {
    let Some(auth) = object.get("openai").and_then(Value::as_object) else {
        return Err(CodexCredentialError::MissingTokens);
    };
    let Some(kind) = auth
        .get("type")
        .and_then(Value::as_str)
        .and_then(clean_text)
    else {
        return Err(CodexCredentialError::MissingTokens);
    };
    if !kind.eq_ignore_ascii_case("oauth") {
        return Err(CodexCredentialError::MissingTokens);
    }
    let access_token = required_clean_secret(auth.get("access"))?;
    let refresh_token = optional_clean_secret(auth.get("refresh"))?.unwrap_or_default();
    let account_id = auth
        .get("accountId")
        .and_then(Value::as_str)
        .and_then(clean_account_id);
    let expires_at = parse_epoch_milliseconds(auth.get("expires"));
    Ok(CodexBearerCredentials {
        access_token: Zeroizing::new(access_token),
        refresh_token: Zeroizing::new(refresh_token),
        id_token: None,
        account_id,
        last_refresh: None,
        expires_at,
        source: CodexCredentialSource::OpenCode,
        kind: CodexBearerKind::OAuth,
    })
}

/// Native-file outcome that controls privacy-preserving external fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexNativeCredentialOutcome {
    /// Native `auth.json` was absent.
    Missing,
    /// Native `auth.json` existed but could not be opened safely.
    Unreadable,
    /// Native `auth.json` was malformed or contained no supported credential.
    Invalid,
    /// Native `auth.json` produced usable credential material.
    Available,
}

/// Maps a native bearer-lane failure onto its external-fallback authority.
///
/// Missing-token and malformed documents remain an identity boundary. Only an
/// absent file becomes [`CodexNativeCredentialOutcome::Missing`].
#[must_use]
pub const fn native_oauth_error_outcome(
    error: CodexCredentialError,
) -> CodexNativeCredentialOutcome {
    match error {
        CodexCredentialError::NotFound => CodexNativeCredentialOutcome::Missing,
        CodexCredentialError::Unreadable => CodexNativeCredentialOutcome::Unreadable,
        CodexCredentialError::Invalid
        | CodexCredentialError::MissingTokens
        | CodexCredentialError::NativeRefreshRequired
        | CodexCredentialError::ReadOnlySource => CodexNativeCredentialOutcome::Invalid,
    }
}

/// Whether opt-in legacy/OpenCode lookup may follow the native outcome.
#[must_use]
pub const fn may_try_external_credentials(
    outcome: CodexNativeCredentialOutcome,
    allow_external: bool,
    explicit_codex_home: bool,
) -> bool {
    allow_external
        && !explicit_codex_home
        && matches!(outcome, CodexNativeCredentialOutcome::Missing)
}

const EXTERNAL_OAUTH_SOURCES: [CodexCredentialSource; 2] = [
    CodexCredentialSource::Legacy,
    CodexCredentialSource::OpenCode,
];

/// Ordered read-only OAuth fallbacks after a native bearer-lane outcome.
///
/// The returned order is historical Codex home followed by `OpenCode`. Callers
/// ignore individual external read/parse failures and retain the original
/// native `NotFound` error if neither candidate succeeds. A whitespace-only
/// `CODEX_HOME` is treated as absent, matching the provider baseline.
#[must_use]
pub fn external_oauth_sources(
    native_outcome: CodexNativeCredentialOutcome,
    allow_external: bool,
    codex_home: Option<&str>,
) -> &'static [CodexCredentialSource] {
    let explicit_codex_home = codex_home.and_then(clean_text).is_some();
    if may_try_external_credentials(native_outcome, allow_external, explicit_codex_home) {
        &EXTERNAL_OAUTH_SOURCES
    } else {
        &[]
    }
}

/// Codex-home authority selected by account routing before PAT discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexPatHomeScope {
    /// No configured Codex home; use ambient `$HOME/.codex`.
    Ambient,
    /// An explicitly selected profile home owned by the Codex CLI.
    Profile,
    /// An app-managed OAuth workspace home that may not hide the ambient PAT.
    Managed,
    /// A fail-closed placeholder for an unavailable managed account store.
    FailClosed,
}

/// Authoritative root for native PAT lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexPatRoot {
    /// Ambient `$HOME/.codex`.
    Ambient,
    /// The explicitly selected profile's `CODEX_HOME`.
    Profile,
}

/// Selects the one root whose native `auth.json` may supply the PAT lane.
///
/// Managed and fail-closed OAuth homes always route to ambient PAT authority.
/// A profile wins only when its own PAT is present; otherwise lookup falls back
/// to ambient authority.
#[must_use]
pub const fn select_codex_pat_root(
    scope: CodexPatHomeScope,
    profile_has_usable_pat: bool,
) -> CodexPatRoot {
    match scope {
        CodexPatHomeScope::Profile if profile_has_usable_pat => CodexPatRoot::Profile,
        CodexPatHomeScope::Ambient
        | CodexPatHomeScope::Profile
        | CodexPatHomeScope::Managed
        | CodexPatHomeScope::FailClosed => CodexPatRoot::Ambient,
    }
}

/// User-selected Codex source mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexSourceMode {
    /// PAT, OAuth/API-key, then ambient CLI owner recovery.
    Auto,
    /// Native personal access token only.
    Pat,
    /// OAuth/API-key, with CLI only for native owner refresh.
    OAuth,
    /// Codex app-server only.
    Cli,
}

/// One bounded source attempt in a Codex plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexSourceAttempt {
    /// Native PAT HTTP usage.
    Pat,
    /// Native or explicitly consented read-only OAuth/API-key HTTP usage.
    OAuth,
    /// Normal ambient Codex app-server usage.
    Cli,
    /// Codex app-server allowed only after native OAuth reports owner refresh.
    CliOwnerRecovery,
}

/// Stable failure class used to decide whether a planned source may continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAttemptFailure {
    /// The attempt had no usable credential, executable, or selected resource.
    Unavailable,
    /// The remote endpoint rejected otherwise valid authentication.
    Unauthorized,
    /// Credential discovery or parsing produced a classified local failure.
    Credential(CodexCredentialError),
    /// A refresh token was expired, revoked, or already reused.
    TerminalRefresh,
    /// A remote response violated its expected schema.
    InvalidResponse,
    /// A remote service returned a non-authentication server failure.
    Server,
    /// A transport operation failed.
    Network,
    /// Any failure not explicitly safe for fallback.
    Other,
}

/// Whether the pinned Codex pipeline may inspect the next planned attempt.
///
/// `Unavailable` represents the pipeline's availability gate; a following
/// attempt must still pass its own availability check. All unrecognized and
/// transient failures stop so they cannot repeatedly spawn `codex app-server`.
#[must_use]
pub const fn should_continue_codex_plan(
    mode: CodexSourceMode,
    attempt: CodexSourceAttempt,
    failure: CodexAttemptFailure,
) -> bool {
    match attempt {
        CodexSourceAttempt::Pat => {
            matches!(mode, CodexSourceMode::Auto)
                && matches!(
                    failure,
                    CodexAttemptFailure::Unavailable
                        | CodexAttemptFailure::Unauthorized
                        | CodexAttemptFailure::Credential(
                            CodexCredentialError::NotFound
                                | CodexCredentialError::Unreadable
                                | CodexCredentialError::MissingTokens
                        )
                )
        }
        CodexSourceAttempt::OAuth => match mode {
            CodexSourceMode::Auto => matches!(
                failure,
                CodexAttemptFailure::Unavailable
                    | CodexAttemptFailure::Unauthorized
                    | CodexAttemptFailure::TerminalRefresh
                    | CodexAttemptFailure::Credential(
                        CodexCredentialError::NotFound
                            | CodexCredentialError::Unreadable
                            | CodexCredentialError::MissingTokens
                            | CodexCredentialError::NativeRefreshRequired
                    )
            ),
            CodexSourceMode::OAuth => matches!(
                failure,
                CodexAttemptFailure::Unavailable
                    | CodexAttemptFailure::Credential(CodexCredentialError::NativeRefreshRequired)
            ),
            CodexSourceMode::Pat | CodexSourceMode::Cli => false,
        },
        CodexSourceAttempt::Cli | CodexSourceAttempt::CliOwnerRecovery => false,
    }
}

/// Whether explicit OAuth may invoke the Codex CLI as its credential owner.
///
/// The app-server has no supported way to carry a selected managed-workspace
/// account. Recovery is therefore admitted only for stale native credentials
/// in explicit OAuth mode, with no managed workspace and a resolved executable.
/// Missing or read-only external credentials can never launch ambient Codex.
#[must_use]
pub const fn may_attempt_codex_cli_owner_recovery(
    mode: CodexSourceMode,
    managed_workspace_selected: bool,
    executable_available: bool,
    credential_source: Option<CodexCredentialSource>,
    credential_needs_refresh: bool,
) -> bool {
    matches!(mode, CodexSourceMode::OAuth)
        && !managed_workspace_selected
        && executable_available
        && matches!(credential_source, Some(CodexCredentialSource::Native))
        && credential_needs_refresh
}

/// Closed, ordered Codex source plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexSourcePlan {
    attempts: Vec<CodexSourceAttempt>,
}

impl CodexSourcePlan {
    /// Builds the exact bounded plan for one source selection.
    ///
    /// `allow_ambient_cli` controls the ordinary auto-mode CLI attempt. The
    /// explicit OAuth plan always retains its owner-recovery attempt; runtime
    /// availability must reject that attempt for managed workspace scopes.
    #[must_use]
    pub fn new(mode: CodexSourceMode, allow_ambient_cli: bool) -> Self {
        let attempts = match mode {
            CodexSourceMode::Auto if allow_ambient_cli => vec![
                CodexSourceAttempt::Pat,
                CodexSourceAttempt::OAuth,
                CodexSourceAttempt::Cli,
            ],
            CodexSourceMode::Auto => {
                vec![CodexSourceAttempt::Pat, CodexSourceAttempt::OAuth]
            }
            CodexSourceMode::Pat => vec![CodexSourceAttempt::Pat],
            CodexSourceMode::OAuth => vec![
                CodexSourceAttempt::OAuth,
                CodexSourceAttempt::CliOwnerRecovery,
            ],
            CodexSourceMode::Cli => vec![CodexSourceAttempt::Cli],
        };
        Self { attempts }
    }

    /// Ordered attempts. The list contains at most three entries.
    #[must_use]
    pub fn attempts(&self) -> &[CodexSourceAttempt] {
        &self.attempts
    }
}

fn decode_bounded_object(data: &[u8]) -> Result<Map<String, Value>, CodexCredentialError> {
    if data.is_empty() || data.len() > MAX_AUTH_DOCUMENT_BYTES {
        return Err(CodexCredentialError::Invalid);
    }
    let value: Value = serde_json::from_slice(data).map_err(|_| CodexCredentialError::Invalid)?;
    let mut nodes = 0_usize;
    validate_json(&value, 0, &mut nodes)?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(CodexCredentialError::Invalid),
    }
}

fn validate_json(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), CodexCredentialError> {
    if depth > MAX_JSON_DEPTH || *nodes >= MAX_JSON_NODES {
        return Err(CodexCredentialError::Invalid);
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

fn pat_credentials(
    object: &Map<String, Value>,
    source: CodexCredentialSource,
) -> Result<Option<CodexPatCredentials>, CodexCredentialError> {
    let token = ["personal_access_token", "personalAccessToken"]
        .into_iter()
        .find_map(|key| object.get(key).and_then(Value::as_str).and_then(clean_text));
    token
        .map(|token| {
            validate_secret(token)?;
            Ok(CodexPatCredentials {
                token: Zeroizing::new(token.to_owned()),
                source,
            })
        })
        .transpose()
}

fn api_key_credentials(
    object: &Map<String, Value>,
    source: CodexCredentialSource,
) -> Result<Option<CodexBearerCredentials>, CodexCredentialError> {
    let Some(raw) = object.get("OPENAI_API_KEY").and_then(Value::as_str) else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    validate_secret(raw)?;
    Ok(Some(CodexBearerCredentials {
        access_token: Zeroizing::new(raw.to_owned()),
        refresh_token: Zeroizing::new(String::new()),
        id_token: None,
        account_id: None,
        last_refresh: None,
        expires_at: None,
        source,
        kind: CodexBearerKind::ApiKey,
    }))
}

fn oauth_credentials(
    object: &Map<String, Value>,
    source: CodexCredentialSource,
) -> Result<Option<CodexBearerCredentials>, CodexCredentialError> {
    let Some(tokens) = object.get("tokens").and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(access_token) = alias_string(tokens, "access_token", "accessToken") else {
        return Ok(None);
    };
    let Some(refresh_token) = alias_string(tokens, "refresh_token", "refreshToken") else {
        return Ok(None);
    };
    validate_secret(access_token)?;
    validate_secret(refresh_token)?;
    let id_token = alias_string(tokens, "id_token", "idToken")
        .map(|value| {
            validate_secret(value)?;
            Ok(Zeroizing::new(value.to_owned()))
        })
        .transpose()?;
    let explicit_account =
        alias_string(tokens, "account_id", "accountId").and_then(clean_account_id);
    let account_id = explicit_account.or_else(|| {
        account_id_from_jwts(id_token.as_deref().map(String::as_str), Some(access_token))
    });
    let last_refresh = object
        .get("last_refresh")
        .and_then(Value::as_str)
        .and_then(|value| Timestamp::parse(value).ok());
    let expires_at = source
        .is_native()
        .then(|| expiration_from_jwt(access_token))
        .flatten();
    Ok(Some(CodexBearerCredentials {
        access_token: Zeroizing::new(access_token.to_owned()),
        refresh_token: Zeroizing::new(refresh_token.to_owned()),
        id_token,
        account_id,
        last_refresh,
        expires_at,
        source,
        kind: CodexBearerKind::OAuth,
    }))
}

fn alias_string<'a>(object: &'a Map<String, Value>, snake: &str, camel: &str) -> Option<&'a str> {
    object
        .get(snake)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            object
                .get(camel)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
}

fn clean_text(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn clean_account_id(value: &str) -> Option<String> {
    let value = clean_text(value)?;
    (value.len() <= MAX_ACCOUNT_ID_BYTES).then(|| value.to_owned())
}

fn validate_secret(value: &str) -> Result<(), CodexCredentialError> {
    if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.contains(['\r', '\n']) {
        return Err(CodexCredentialError::Invalid);
    }
    Ok(())
}

fn required_clean_secret(value: Option<&Value>) -> Result<String, CodexCredentialError> {
    let Some(value) = value.and_then(Value::as_str).and_then(clean_text) else {
        return Err(CodexCredentialError::MissingTokens);
    };
    validate_secret(value)?;
    Ok(value.to_owned())
}

fn optional_clean_secret(value: Option<&Value>) -> Result<Option<String>, CodexCredentialError> {
    value
        .and_then(Value::as_str)
        .and_then(clean_text)
        .map(|value| {
            validate_secret(value)?;
            Ok(value.to_owned())
        })
        .transpose()
}

fn account_id_from_jwts(id_token: Option<&str>, access_token: Option<&str>) -> Option<String> {
    [id_token, access_token]
        .into_iter()
        .flatten()
        .find_map(account_id_from_jwt)
}

fn account_id_from_jwt(token: &str) -> Option<String> {
    let payload = decode_jwt_payload(token, false)?;
    let object = payload.as_object()?;
    object
        .get("chatgpt_account_id")
        .and_then(Value::as_str)
        .and_then(clean_account_id)
        .or_else(|| {
            object
                .get("https://api.openai.com/auth")
                .and_then(Value::as_object)
                .and_then(|auth| auth.get("chatgpt_account_id"))
                .and_then(Value::as_str)
                .and_then(clean_account_id)
        })
        .or_else(|| {
            object
                .get("organizations")
                .and_then(Value::as_array)
                .and_then(|organizations| {
                    organizations.iter().find_map(|organization| {
                        organization
                            .as_object()
                            .and_then(|object| object.get("id"))
                            .and_then(Value::as_str)
                            .and_then(clean_account_id)
                    })
                })
        })
}

fn expiration_from_jwt(token: &str) -> Option<Timestamp> {
    let payload = decode_jwt_payload_bytes(token, true)?;
    let expiration = serde_json::from_slice::<IntegerExpirationClaim>(&payload)
        .ok()?
        .0?;
    Timestamp::from_unix_timestamp(expiration).ok()
}

struct IntegerExpirationClaim(Option<i64>);

impl<'de> Deserialize<'de> for IntegerExpirationClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ClaimVisitor;

        impl<'de> Visitor<'de> for ClaimVisitor {
            type Value = IntegerExpirationClaim;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JWT payload object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut expiration = None;
                let mut saw_expiration = false;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "exp" {
                        if saw_expiration {
                            return Err(serde::de::Error::duplicate_field("exp"));
                        }
                        saw_expiration = true;
                        let value = map.next_value::<Value>()?;
                        expiration = value.as_i64();
                        if expiration.is_none() {
                            return Err(serde::de::Error::custom(
                                "exp must use exact integer JSON spelling",
                            ));
                        }
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(IntegerExpirationClaim(expiration))
            }
        }

        deserializer.deserialize_map(ClaimVisitor)
    }
}

fn decode_jwt_payload(token: &str, require_nonempty_parts: bool) -> Option<Value> {
    let payload = decode_jwt_payload_bytes(token, require_nonempty_parts)?;
    serde_json::from_slice(&payload).ok()
}

fn decode_jwt_payload_bytes(token: &str, require_nonempty_parts: bool) -> Option<Vec<u8>> {
    if token.len() > MAX_SECRET_BYTES {
        return None;
    }
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || (require_nonempty_parts && parts.iter().any(|part| part.is_empty())) {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| URL_SAFE.decode(parts[1]))
        .ok()
        .filter(|payload| payload.len() <= MAX_SECRET_BYTES)
}

fn parse_epoch_milliseconds(value: Option<&Value>) -> Option<Timestamp> {
    let raw = value?.as_number()?.to_string();
    let milliseconds = Decimal::from_scientific(&raw)
        .or_else(|_| raw.parse())
        .ok()?;
    if milliseconds.is_sign_negative() {
        return None;
    }
    let nanoseconds = (milliseconds * Decimal::from(1_000_000_u64))
        .trunc()
        .to_i128()?;
    let instant = OffsetDateTime::from_unix_timestamp_nanos(nanoseconds).ok()?;
    Timestamp::new(instant).ok()
}
