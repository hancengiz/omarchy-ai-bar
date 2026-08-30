//! Kilo credit and pass usage through API keys or provider-owned CLI auth state.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const APP_TRPC_ORIGIN: &str = "https://app.kilo.ai/api/trpc/";
const PROFILE_API_ORIGIN: &str = "https://api.kilo.ai/api/";
const API_KEY_NAME: &str = "KILO_API_KEY";
const PROCEDURES: [&str; 3] = [
    "user.getCreditBlocks",
    "kiloPass.getState",
    "user.getAutoTopUpPaymentMethod",
];
const PROCEDURE_PATH: &str =
    "user.getCreditBlocks,kiloPass.getState,user.getAutoTopUpPaymentMethod";
const BATCH_INPUT: &str = r#"{"0":{"json":null},"1":{"json":null},"2":{"json":null}}"#;
const ORGANIZATIONS_PROCEDURE: &str = "user.getOrganizations";
const ORGANIZATIONS_INPUT: &str = r#"{"0":{"json":null}}"#;
const ORGANIZATION_HEADER: &str = "X-KILOCODE-ORGANIZATIONID";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_AUTH_FILE_BYTES: u64 = 256 * 1024;
const MAX_AUTH_FILE_BYTES_USIZE: usize = 256 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_BLOCKS: usize = 1_024;
const MAX_CONTEXTS: usize = 256;
const MAX_OBJECT_MEMBERS: usize = 256;
const MAX_NESTED_ARRAY: usize = 1_024;
const MAX_ORGANIZATIONS: usize = 256;
const MAX_PROVIDER_STRING_BYTES: usize = 256;
const MAX_MONEY: f64 = 1_000_000_000_000_000.0;
const PASS_TOTAL_CENTS_KEYS: &[&str] = &[
    "amountCents",
    "totalCents",
    "planAmountCents",
    "monthlyAmountCents",
    "limitCents",
    "includedCents",
    "valueCents",
];
const PASS_TOTAL_MICRO_USD_KEYS: &[&str] = &[
    "amount_mUsd",
    "total_mUsd",
    "planAmount_mUsd",
    "limit_mUsd",
    "included_mUsd",
    "value_mUsd",
];
const PASS_TOTAL_KEYS: &[&str] = &[
    "amount",
    "total",
    "limit",
    "included",
    "value",
    "creditsTotal",
    "totalCredits",
    "planAmount",
];
const PASS_USED_CENTS_KEYS: &[&str] = &[
    "usedCents",
    "spentCents",
    "consumedCents",
    "usedAmountCents",
    "consumedAmountCents",
];
const PASS_USED_MICRO_USD_KEYS: &[&str] = &[
    "used_mUsd",
    "spent_mUsd",
    "consumed_mUsd",
    "usedAmount_mUsd",
];
const PASS_USED_KEYS: &[&str] = &[
    "used",
    "spent",
    "consumed",
    "usage",
    "creditsUsed",
    "usedAmount",
    "consumedAmount",
];
const PASS_REMAINING_CENTS_KEYS: &[&str] = &[
    "remainingCents",
    "remainingAmountCents",
    "availableCents",
    "leftCents",
    "balanceCents",
];
const PASS_REMAINING_MICRO_USD_KEYS: &[&str] = &[
    "remaining_mUsd",
    "available_mUsd",
    "left_mUsd",
    "balance_mUsd",
];
const PASS_REMAINING_KEYS: &[&str] = &[
    "remaining",
    "available",
    "left",
    "balance",
    "creditsRemaining",
    "remainingAmount",
    "availableAmount",
];
const PASS_BONUS_CENTS_KEYS: &[&str] = &[
    "bonusCents",
    "bonusAmountCents",
    "includedBonusCents",
    "bonusRemainingCents",
];
const PASS_BONUS_MICRO_USD_KEYS: &[&str] = &["bonus_mUsd", "bonusAmount_mUsd"];
const PASS_BONUS_KEYS: &[&str] = &["bonus", "bonusAmount", "bonusCredits", "includedBonus"];
const PASS_RESET_KEYS: &[&str] = &[
    "resetAt",
    "resetsAt",
    "nextResetAt",
    "renewAt",
    "renewsAt",
    "nextRenewalAt",
    "currentPeriodEnd",
    "periodEndsAt",
    "expiresAt",
    "expiryAt",
];

/// Personal or organization-scoped Kilo usage routing.
#[derive(Clone, PartialEq, Eq)]
pub enum KiloUsageScope {
    /// The token owner's personal balance and pass.
    Personal,
    /// One exact organization selected by its provider identifier.
    Organization {
        id: BoundedText<256>,
        name: BoundedText<256>,
    },
}

impl KiloUsageScope {
    /// Creates a bounded organization scope.
    ///
    /// # Errors
    ///
    /// Returns an API configuration error for an invalid identifier or name.
    pub fn organization(
        id: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, ClassifiedError> {
        let id = BoundedText::new(id.into()).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let name =
            BoundedText::new(name.into()).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self::Organization { id, name })
    }

    /// Stable scope identifier used by account selection state.
    #[must_use]
    pub fn scope_identifier(&self) -> String {
        match self {
            Self::Personal => "personal".to_owned(),
            Self::Organization { id, .. } => format!("org:{}", id.as_str()),
        }
    }

    /// Organization identifier sent on usage requests, when selected.
    #[must_use]
    pub fn organization_id(&self) -> Option<&str> {
        match self {
            Self::Personal => None,
            Self::Organization { id, .. } => Some(id.as_str()),
        }
    }

    /// Human-readable scope label.
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            Self::Personal => "Personal",
            Self::Organization { name, .. } => name.as_str(),
        }
    }
}

impl Debug for KiloUsageScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Personal => formatter.write_str("KiloUsageScope::Personal"),
            Self::Organization { .. } => formatter
                .debug_struct("KiloUsageScope::Organization")
                .field("id", &"<redacted>")
                .field("name", &"<redacted>")
                .finish(),
        }
    }
}

/// One bounded organization returned by Kilo account discovery.
#[derive(Clone, PartialEq, Eq)]
pub struct KiloOrganization {
    id: BoundedText<256>,
    name: BoundedText<256>,
    role: Option<BoundedText<256>>,
}

impl KiloOrganization {
    /// Provider organization identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Provider organization name, falling back to the identifier.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Optional membership role.
    #[must_use]
    pub fn role(&self) -> Option<&str> {
        self.role.as_ref().map(BoundedText::as_str)
    }
}

impl Debug for KiloOrganization {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KiloOrganization")
            .field("id", &"<redacted>")
            .field("name", &"<redacted>")
            .field("role", &self.role.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A CLI session resolved from Kilo's read-only Linux auth document.
pub struct KiloCliCredential {
    credential: ApiKeyCredential,
    auth_path: PathBuf,
}

impl KiloCliCredential {
    /// Resolves and reads `$XDG_DATA_HOME/kilo/auth.json`, falling back to
    /// `$HOME/.local/share/kilo/auth.json` only when XDG data is unset.
    ///
    /// The file is opened once with `O_NOFOLLOW`, checked through that handle,
    /// bounded, parsed, and never copied into application-owned storage.
    ///
    /// # Errors
    ///
    /// Returns missing-credential for an absent session, permission-denied for
    /// an unreadable file, parse for malformed or oversized state, and API for
    /// unsafe path configuration.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let auth_path = resolve_auth_path(environment)?;
        let bytes = read_auth_file(&auth_path)?;
        let document: AuthDocument =
            serde_json::from_slice(&bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let access = document
            .kilo
            .and_then(|section| section.access)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        validate_present_cli_token(&access.0)?;
        let credential = ApiKeyCredential::from_zeroizing(access.0)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(Self {
            credential,
            auth_path,
        })
    }

    /// Exact provider-owned file selected for setup diagnostics.
    #[must_use]
    pub fn auth_path(&self) -> &Path {
        &self.auth_path
    }

    /// Consumes this session and returns its opaque transport credential.
    ///
    /// The returned type never exposes token text; this is the loopback-test
    /// and constructor boundary used to attach the provider-owned session to
    /// the exact-origin client without persisting another credential copy.
    #[doc(hidden)]
    #[must_use]
    pub fn into_transport_credential(self) -> ApiKeyCredential {
        self.credential
    }
}

impl Debug for KiloCliCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KiloCliCredential")
            .field("credential", &"<redacted>")
            .field("auth_path", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
struct AuthDocument {
    kilo: Option<AuthSection>,
}

#[derive(Deserialize)]
struct AuthSection {
    access: Option<OwnedSecret>,
}

struct OwnedSecret(Zeroizing<String>);

impl<'de> Deserialize<'de> for OwnedSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .map(Zeroizing::new)
            .map(Self)
    }
}

fn validate_present_cli_token(value: &str) -> Result<(), ClassifiedError> {
    let mut cleaned = value.trim();
    if cleaned.len() >= 2
        && ((cleaned.starts_with('"') && cleaned.ends_with('"'))
            || (cleaned.starts_with('\'') && cleaned.ends_with('\'')))
    {
        cleaned = cleaned[1..cleaned.len() - 1].trim();
    }
    if cleaned.is_empty() || cleaned.len() > MAX_CREDENTIAL_BYTES || cleaned.contains(['\r', '\n'])
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(())
}

/// Resolves the Kilo API key from its single fixed environment key.
///
/// # Errors
///
/// Returns missing-credential for an empty, malformed, or absent key.
pub fn resolve_api_credential(
    environment: &BTreeMap<String, String>,
) -> Result<ApiKeyCredential, ClassifiedError> {
    ApiKeyCredential::resolve(environment, &[API_KEY_NAME])
}

/// Native Kilo adapter permanently bound to one account, auth source, and usage scope.
pub struct KiloProvider {
    usage_client: FixedApiClient,
    profile_client: FixedApiClient,
    usage_scope: KiloUsageScope,
}

impl KiloProvider {
    /// Resolves exactly the selected Kilo source without cross-source fallback.
    ///
    /// # Errors
    ///
    /// Returns stable credential or configuration errors. The runtime may
    /// implement automatic API-to-CLI fallback by constructing each source in
    /// order; an account client never changes source after construction.
    pub fn resolve(
        scope: AccountScope,
        source: ProviderSource,
        environment: &BTreeMap<String, String>,
        usage_scope: KiloUsageScope,
    ) -> Result<Self, ClassifiedError> {
        match source {
            ProviderSource::ApiKey => {
                Self::new_api_key(scope, resolve_api_credential(environment)?, usage_scope)
            }
            ProviderSource::Cli => {
                Self::new_cli(scope, KiloCliCredential::resolve(environment)?, usage_scope)
            }
            ProviderSource::ConfigurableEndpoint
            | ProviderSource::ManualCookie
            | ProviderSource::BrowserSession
            | ProviderSource::OAuth
            | ProviderSource::LocalData
            | ProviderSource::CloudCredentials => Err(ClassifiedError::new(ErrorKind::Api)),
        }
    }

    /// Creates a production API-key client.
    ///
    /// # Errors
    ///
    /// Returns an API error for an invalid account or fixed configuration.
    pub fn new_api_key(
        scope: AccountScope,
        credential: ApiKeyCredential,
        usage_scope: KiloUsageScope,
    ) -> Result<Self, ClassifiedError> {
        Self::build(scope, ProviderSource::ApiKey, credential, usage_scope)
    }

    /// Creates a production client using the Kilo-owned CLI session token.
    ///
    /// # Errors
    ///
    /// Returns an API error for an invalid account or fixed configuration.
    pub fn new_cli(
        scope: AccountScope,
        credential: KiloCliCredential,
        usage_scope: KiloUsageScope,
    ) -> Result<Self, ClassifiedError> {
        Self::build(
            scope,
            ProviderSource::Cli,
            credential.credential,
            usage_scope,
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        credential: ApiKeyCredential,
        usage_scope: KiloUsageScope,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        let app_url =
            Url::parse(APP_TRPC_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let profile_url =
            Url::parse(PROFILE_API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let usage_client = FixedApiClient::new_bearer(
            scope.clone(),
            app_url,
            EndpointClass::PublicHttps,
            credential.clone(),
            transport_config()?,
        )?;
        let profile_client = FixedApiClient::new_bearer(
            scope,
            profile_url,
            EndpointClass::PublicHttps,
            credential,
            transport_config()?,
        )?;
        let usage_client = bind_source(usage_client, source)?;
        let profile_client = bind_source(profile_client, source)?;
        Self::from_clients(usage_client, profile_client, usage_scope)
    }

    /// Deterministic exact-origin seam for loopback tests.
    ///
    /// # Errors
    ///
    /// Rejects clients from another provider, account, or source.
    #[doc(hidden)]
    pub fn from_clients(
        usage_client: FixedApiClient,
        profile_client: FixedApiClient,
        usage_scope: KiloUsageScope,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(usage_client.scope())?;
        if profile_client.scope() != usage_client.scope()
            || profile_client.source() != usage_client.source()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            usage_client,
            profile_client,
            usage_scope,
        })
    }

    /// Account source to which this provider is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.usage_client.source()
    }

    /// Personal or organization usage scope to which requests are bound.
    #[must_use]
    pub const fn usage_scope(&self) -> &KiloUsageScope {
        &self.usage_scope
    }

    /// Fetches one normalized credit/pass sample at an injected timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable classified scope, transport, status, or parse failures.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let url = usage_batch_url(&self.usage_client)?;
        let headers = self
            .usage_scope
            .organization_id()
            .map_or_else(Vec::new, |id| vec![(ORGANIZATION_HEADER, id)]);
        let response = self
            .usage_client
            .get_json_with_public_headers_and_status_map(context, url, &headers, kilo_status)
            .await?;
        let snapshot = parse_usage_response(response.body())?;
        normalize(
            context.scope().clone(),
            fetched_at,
            &snapshot,
            source_label(self.source()),
        )
    }

    /// Discovers bounded organizations for the exact selected credential.
    ///
    /// Kilo's tRPC route is authoritative. HTTP 404 alone activates the fixed
    /// profile endpoint fallback; all other errors retain their classification.
    ///
    /// # Errors
    ///
    /// Returns stable scope, transport, status, or schema failures.
    pub async fn fetch_organizations(
        &self,
        context: &ProviderContext,
    ) -> Result<Vec<KiloOrganization>, ClassifiedError> {
        self.validate_context(context)?;
        let url = organizations_url(&self.usage_client)?;
        match self
            .usage_client
            .get_json_with_status_map(context, url, organizations_status)
            .await
        {
            Ok(response) => return parse_organizations(response.body()),
            Err(error) if error.kind() == ErrorKind::MissingCredential => {}
            Err(error) => return Err(error),
        }
        let url = self.profile_client.url("profile")?;
        let response = self
            .profile_client
            .get_json_with_status_map(context, url, kilo_status)
            .await?;
        parse_organizations(response.body())
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != self.usage_client.scope() || context.source() != self.source() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(())
    }
}

impl Debug for KiloProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KiloProvider")
            .field("scope", self.usage_client.scope())
            .field("source", &self.source())
            .field("usage_scope", &self.usage_scope)
            .finish_non_exhaustive()
    }
}

impl ProviderAdapter for KiloProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Kilo)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

fn bind_source(
    client: FixedApiClient,
    source: ProviderSource,
) -> Result<FixedApiClient, ClassifiedError> {
    if source == ProviderSource::ApiKey {
        Ok(client)
    } else {
        client.with_source(source)
    }
}

fn validate_scope(scope: &AccountScope) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Kilo {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn usage_batch_url(client: &FixedApiClient) -> Result<Url, ClassifiedError> {
    batch_url(client, PROCEDURE_PATH, BATCH_INPUT)
}

fn organizations_url(client: &FixedApiClient) -> Result<Url, ClassifiedError> {
    batch_url(client, ORGANIZATIONS_PROCEDURE, ORGANIZATIONS_INPUT)
}

fn batch_url(
    client: &FixedApiClient,
    procedure_path: &str,
    input: &str,
) -> Result<Url, ClassifiedError> {
    let mut url = client.url(procedure_path)?;
    url.query_pairs_mut()
        .append_pair("batch", "1")
        .append_pair("input", input);
    Ok(url)
}

fn source_label(source: ProviderSource) -> &'static str {
    match source {
        ProviderSource::ApiKey => "api",
        ProviderSource::Cli => "cli",
        ProviderSource::ConfigurableEndpoint
        | ProviderSource::ManualCookie
        | ProviderSource::BrowserSession
        | ProviderSource::OAuth
        | ProviderSource::LocalData
        | ProviderSource::CloudCredentials => "invalid",
    }
}

fn kilo_status(status: u16) -> Option<ErrorKind> {
    match status {
        401 | 403 => Some(ErrorKind::AuthenticationExpired),
        404 => Some(ErrorKind::Api),
        500..=599 => Some(ErrorKind::ProviderUnavailable),
        _ => None,
    }
}

fn organizations_status(status: u16) -> Option<ErrorKind> {
    if status == 404 {
        // Private sentinel: HTTP 404 alone selects the fixed profile fallback
        // and this classification is never returned to a caller.
        Some(ErrorKind::MissingCredential)
    } else {
        kilo_status(status)
    }
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

fn resolve_auth_path(environment: &BTreeMap<String, String>) -> Result<PathBuf, ClassifiedError> {
    let path = if let Some(root) = environment
        .get("XDG_DATA_HOME")
        .and_then(|value| clean_setting(value))
    {
        validated_root(root)?.join("kilo/auth.json")
    } else {
        let home = environment
            .get("HOME")
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        validated_root(home)?.join(".local/share/kilo/auth.json")
    };
    validate_path(&path)?;
    Ok(path)
}

fn validated_root(raw: &str) -> Result<PathBuf, ClassifiedError> {
    if raw.chars().any(char::is_control)
        || raw
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let path = PathBuf::from(raw);
    validate_path(&path)?;
    Ok(path)
}

fn validate_path(path: &Path) -> Result<(), ClassifiedError> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn read_auth_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .map_err(|error| classify_auth_io(&error))?;
    validate_open_auth_file(&file)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(MAX_AUTH_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| classify_auth_io(&error))?;
    if bytes.len() > MAX_AUTH_FILE_BYTES_USIZE {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(bytes)
}

fn validate_open_auth_file(file: &File) -> Result<(), ClassifiedError> {
    let metadata = file.metadata().map_err(|error| classify_auth_io(&error))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_AUTH_FILE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(())
}

fn classify_auth_io(error: &std::io::Error) -> ClassifiedError {
    match error.kind() {
        IoErrorKind::NotFound => ClassifiedError::new(ErrorKind::MissingCredential),
        IoErrorKind::PermissionDenied => ClassifiedError::new(ErrorKind::PermissionDenied),
        _ => ClassifiedError::new(ErrorKind::Parse),
    }
}

#[derive(Default)]
struct UsageFields {
    credits_used: Option<f64>,
    credits_total: Option<f64>,
    credits_remaining: Option<f64>,
    pass_used: Option<f64>,
    pass_total: Option<f64>,
    pass_remaining: Option<f64>,
    pass_bonus: Option<f64>,
    pass_resets_at: Option<Timestamp>,
    plan_name: Option<String>,
    auto_top_up_enabled: Option<bool>,
    auto_top_up_method: Option<String>,
}

struct PassFields {
    used: Option<f64>,
    total: Option<f64>,
    remaining: Option<f64>,
    bonus: Option<f64>,
    resets_at: Option<Timestamp>,
}

#[derive(Default)]
struct CreditFields {
    used: Option<f64>,
    total: Option<f64>,
    remaining: Option<f64>,
}

fn parse_usage_response(bytes: &[u8]) -> Result<UsageFields, ClassifiedError> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let entries = response_entries(&root)?;
    let mut payloads: [Option<&Value>; 3] = [None, None, None];
    for (index, procedure) in PROCEDURES.iter().enumerate() {
        let Some(entry) = entries[index] else {
            continue;
        };
        if let Some(error) = trpc_error(entry) {
            if *procedure != PROCEDURES[2] {
                return Err(error);
            }
            continue;
        }
        payloads[index] = result_payload(entry);
    }

    let credits = credit_fields(payloads[0])?;
    let pass = pass_fields(payloads[1])?;
    let plan_name = plan_name(payloads[1])?;
    let (auto_top_up_enabled, auto_top_up_method) =
        auto_top_up_state(payloads[0], payloads[2]).unwrap_or_default();
    Ok(UsageFields {
        credits_used: credits.used,
        credits_total: credits.total,
        credits_remaining: credits.remaining,
        pass_used: pass.used,
        pass_total: pass.total,
        pass_remaining: pass.remaining,
        pass_bonus: pass.bonus,
        pass_resets_at: pass.resets_at,
        plan_name,
        auto_top_up_enabled,
        auto_top_up_method,
    })
}

fn response_entries(root: &Value) -> Result<[Option<&Value>; 3], ClassifiedError> {
    let mut entries = [None, None, None];
    match root {
        Value::Array(values) => {
            if values.len() > PROCEDURES.len() {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            for (index, value) in values.iter().enumerate() {
                if !value.is_object() {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                entries[index] = Some(value);
            }
        }
        Value::Object(object) if object.contains_key("result") || object.contains_key("error") => {
            entries[0] = Some(root);
        }
        Value::Object(object) => {
            if object.len() > PROCEDURES.len() {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            for (key, value) in object {
                let index = key
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < PROCEDURES.len())
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                if !value.is_object() {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                entries[index] = Some(value);
            }
        }
        _ => return Err(ClassifiedError::new(ErrorKind::Parse)),
    }
    Ok(entries)
}

fn trpc_error(entry: &Value) -> Option<ClassifiedError> {
    let error = entry.get("error")?.as_object()?;
    let code = string_at(error, &["json", "data", "code"])
        .or_else(|| string_at(error, &["data", "code"]))
        .or_else(|| string_at(error, &["code"]));
    let message = string_at(error, &["json", "message"]).or_else(|| string_at(error, &["message"]));
    let unauthorized = [code, message].into_iter().flatten().any(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("unauthorized") || value.contains("forbidden")
    });
    if unauthorized {
        return Some(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let not_found = [code, message].into_iter().flatten().any(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("not_found") || value.contains("not found")
    });
    Some(ClassifiedError::new(if not_found {
        ErrorKind::Api
    } else {
        ErrorKind::Parse
    }))
}

fn string_at<'a>(object: &'a Map<String, Value>, path: &[&str]) -> Option<&'a str> {
    let mut value = object.get(*path.first()?)?;
    for component in &path[1..] {
        value = value.as_object()?.get(*component)?;
    }
    value.as_str()
}

fn result_payload(entry: &Value) -> Option<&Value> {
    let result = entry.get("result")?;
    if let Some(data) = result.get("data") {
        if let Some(json) = data.get("json") {
            return (!json.is_null()).then_some(json);
        }
        return (!data.is_null()).then_some(data);
    }
    let json = result.get("json")?;
    (!json.is_null()).then_some(json)
}

fn credit_fields(payload: Option<&Value>) -> Result<CreditFields, ClassifiedError> {
    let Some(payload) = payload else {
        return Ok(CreditFields::default());
    };
    let contexts = dictionary_contexts(payload)?;
    if let Some(blocks) = first_array(&contexts, &["creditBlocks"])? {
        let mut total = 0.0;
        let mut remaining = 0.0;
        let mut saw_total = false;
        let mut saw_remaining = false;
        for block in blocks {
            let Some(block) = block.as_object() else {
                continue;
            };
            if let Some(value) = number(block.get("amount_mUsd"))? {
                total = checked_add(total, value / 1_000_000.0)?;
                saw_total = true;
            }
            if let Some(value) = number(block.get("balance_mUsd"))? {
                remaining = checked_add(remaining, value / 1_000_000.0)?;
                saw_remaining = true;
            }
        }
        if saw_total || saw_remaining {
            let total = saw_total.then_some(total.max(0.0));
            let remaining = saw_remaining.then_some(remaining.max(0.0));
            let used = total
                .zip(remaining)
                .map(|(total, remaining)| (total - remaining).max(0.0));
            return Ok(CreditFields {
                used,
                total,
                remaining,
            });
        }
    }

    let block_contexts = first_array(&contexts, &["blocks"])?
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(Value::as_object)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut used = first_number(
        &block_contexts,
        &["used", "usedCredits", "consumed", "spent", "creditsUsed"],
    )?;
    let mut total = first_number(
        &block_contexts,
        &["total", "totalCredits", "creditsTotal", "limit"],
    )?;
    let mut remaining = first_number(
        &block_contexts,
        &["remaining", "remainingCredits", "creditsRemaining"],
    )?;
    if used.is_none() {
        used = first_number(
            &contexts,
            &["used", "usedCredits", "creditsUsed", "consumed", "spent"],
        )?;
    }
    if total.is_none() {
        total = first_number(
            &contexts,
            &["total", "totalCredits", "creditsTotal", "limit"],
        )?;
    }
    if remaining.is_none() {
        remaining = first_number(
            &contexts,
            &["remaining", "remainingCredits", "creditsRemaining"],
        )?;
    }
    if total.is_none() {
        total = used
            .zip(remaining)
            .map(|(used, remaining)| used + remaining);
    }
    if used.is_none()
        && total.is_none()
        && remaining.is_none()
        && let Some(balance_micro_usd) = first_number(&contexts, &["totalBalance_mUsd"])?
    {
        let balance = (balance_micro_usd / 1_000_000.0).max(0.0);
        return Ok(CreditFields {
            used: Some(0.0),
            total: Some(balance),
            remaining: Some(balance),
        });
    }
    Ok(CreditFields {
        used,
        total,
        remaining,
    })
}

fn pass_fields(payload: Option<&Value>) -> Result<PassFields, ClassifiedError> {
    if let Some(subscription) = subscription(payload) {
        return subscription_pass_fields(subscription);
    }
    let contexts = payload
        .map(dictionary_contexts)
        .transpose()?
        .unwrap_or_default();
    fallback_pass_fields(&contexts)
}

fn subscription_pass_fields(
    subscription: &Map<String, Value>,
) -> Result<PassFields, ClassifiedError> {
    let used = number(subscription.get("currentPeriodUsageUsd"))?.map(|value| value.max(0.0));
    let base = number(subscription.get("currentPeriodBaseCreditsUsd"))?.map(|value| value.max(0.0));
    let bonus = number(subscription.get("currentPeriodBonusCreditsUsd"))?
        .unwrap_or(0.0)
        .max(0.0);
    let total = base.map(|base| base + bonus);
    let remaining = total.zip(used).map(|(total, used)| (total - used).max(0.0));
    let resets_at = first_date_in_object(
        subscription,
        &["nextBillingAt", "nextRenewalAt", "renewsAt", "renewAt"],
    )?;
    Ok(PassFields {
        used,
        total,
        remaining,
        bonus: (bonus > 0.0).then_some(bonus),
        resets_at,
    })
}

fn fallback_pass_fields(contexts: &[&Map<String, Value>]) -> Result<PassFields, ClassifiedError> {
    let mut total = money_amount(
        contexts,
        PASS_TOTAL_CENTS_KEYS,
        PASS_TOTAL_MICRO_USD_KEYS,
        PASS_TOTAL_KEYS,
    )?;
    let mut used = money_amount(
        contexts,
        PASS_USED_CENTS_KEYS,
        PASS_USED_MICRO_USD_KEYS,
        PASS_USED_KEYS,
    )?;
    let mut remaining = money_amount(
        contexts,
        PASS_REMAINING_CENTS_KEYS,
        PASS_REMAINING_MICRO_USD_KEYS,
        PASS_REMAINING_KEYS,
    )?;
    let bonus = money_amount(
        contexts,
        PASS_BONUS_CENTS_KEYS,
        PASS_BONUS_MICRO_USD_KEYS,
        PASS_BONUS_KEYS,
    )?;
    let resets_at = first_date(contexts, PASS_RESET_KEYS)?;
    if total.is_none() {
        total = used
            .zip(remaining)
            .map(|(used, remaining)| used + remaining);
    }
    if used.is_none() {
        used = total
            .zip(remaining)
            .map(|(total, remaining)| (total - remaining).max(0.0));
    }
    if remaining.is_none() {
        remaining = total.zip(used).map(|(total, used)| (total - used).max(0.0));
    }
    Ok(PassFields {
        used,
        total,
        remaining,
        bonus,
        resets_at,
    })
}

fn plan_name(payload: Option<&Value>) -> Result<Option<String>, ClassifiedError> {
    if let Some(subscription) = subscription(payload) {
        if let Some(tier) = provider_string(subscription.get("tier"))? {
            return Ok(Some(match tier.as_str() {
                "tier_19" => "Starter".to_owned(),
                "tier_49" => "Pro".to_owned(),
                "tier_199" => "Expert".to_owned(),
                _ => tier,
            }));
        }
        return Ok(Some("Kilo Pass".to_owned()));
    }
    let contexts = payload
        .map(dictionary_contexts)
        .transpose()?
        .unwrap_or_default();
    if let Some(value) = first_string(
        &contexts,
        &[
            "planName",
            "tier",
            "tierName",
            "passName",
            "subscriptionName",
        ],
    )? {
        return Ok(Some(value));
    }
    for path in [
        &["plan", "name"][..],
        &["subscription", "plan", "name"],
        &["subscription", "name"],
        &["pass", "name"],
        &["state", "name"],
        &["state"],
    ] {
        if let Some(value) = string_path_in_contexts(&contexts, path)? {
            return Ok(Some(value));
        }
    }
    if let Some(value) = first_string(&contexts, &["name"])?
        && value.to_ascii_lowercase().contains("pass")
    {
        return Ok(Some(value));
    }
    Ok(None)
}

fn auto_top_up_state(
    credit_payload: Option<&Value>,
    auto_payload: Option<&Value>,
) -> Result<(Option<bool>, Option<String>), ClassifiedError> {
    let credit_contexts = credit_payload
        .map(dictionary_contexts)
        .transpose()?
        .unwrap_or_default();
    let auto_contexts = auto_payload
        .map(dictionary_contexts)
        .transpose()?
        .unwrap_or_default();
    let status_enabled = first_string(&auto_contexts, &["status"])?
        .as_deref()
        .and_then(bool_from_status);
    let enabled = first_bool(&auto_contexts, &["enabled", "isEnabled", "active"])?
        .or(status_enabled)
        .or(first_bool(&credit_contexts, &["autoTopUpEnabled"])?);
    let raw_method = first_string(
        &auto_contexts,
        &["paymentMethod", "paymentMethodType", "method", "cardBrand"],
    )?;
    let amount = money_amount(
        &auto_contexts,
        &["amountCents"],
        &[],
        &["amount", "topUpAmount", "amountUsd"],
    )?;
    let method = raw_method.or_else(|| {
        amount
            .filter(|amount| *amount > 0.0)
            .map(currency_amount_label)
    });
    Ok((enabled, method))
}

fn subscription(payload: Option<&Value>) -> Option<&Map<String, Value>> {
    let object = payload?.as_object()?;
    if let Some(value) = object.get("subscription") {
        return value.as_object();
    }
    (object.contains_key("currentPeriodUsageUsd")
        || object.contains_key("currentPeriodBaseCreditsUsd")
        || object.contains_key("currentPeriodBonusCreditsUsd")
        || object.contains_key("tier"))
    .then_some(object)
}

fn dictionary_contexts(payload: &Value) -> Result<Vec<&Map<String, Value>>, ClassifiedError> {
    let root = payload
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let mut contexts = Vec::new();
    let mut queue = VecDeque::from([(root, 0_u8)]);
    while let Some((current, depth)) = queue.pop_front() {
        if current.len() > MAX_OBJECT_MEMBERS || contexts.len() >= MAX_CONTEXTS {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        contexts.push(current);
        if depth >= 2 {
            continue;
        }
        for value in current.values() {
            if let Some(object) = value.as_object() {
                queue.push_back((object, depth.saturating_add(1)));
            } else if let Some(values) = value.as_array() {
                if values.len() > MAX_NESTED_ARRAY {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                for object in values.iter().filter_map(Value::as_object) {
                    queue.push_back((object, depth.saturating_add(1)));
                }
            }
        }
    }
    Ok(contexts)
}

fn first_array<'a>(
    contexts: &[&'a Map<String, Value>],
    keys: &[&str],
) -> Result<Option<&'a [Value]>, ClassifiedError> {
    for context in contexts {
        for key in keys {
            if let Some(value) = context.get(*key) {
                let values = value
                    .as_array()
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                if values.len() > MAX_BLOCKS {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                return Ok(Some(values));
            }
        }
    }
    Ok(None)
}

fn first_number(
    contexts: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<f64>, ClassifiedError> {
    for context in contexts {
        for key in keys {
            if context.contains_key(*key)
                && let Some(value) = number(context.get(*key))?
            {
                return Ok(Some(value));
            }
        }
    }
    Ok(None)
}

fn first_string(
    contexts: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<String>, ClassifiedError> {
    for context in contexts {
        for key in keys {
            if let Some(value) = provider_string(context.get(*key))? {
                return Ok(Some(value));
            }
        }
    }
    Ok(None)
}

fn string_path_in_contexts(
    contexts: &[&Map<String, Value>],
    path: &[&str],
) -> Result<Option<String>, ClassifiedError> {
    for context in contexts {
        let mut value = context.get(path[0]);
        for component in &path[1..] {
            value = value
                .and_then(Value::as_object)
                .and_then(|object| object.get(*component));
        }
        if let Some(value) = provider_string(value)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn first_bool(
    contexts: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<bool>, ClassifiedError> {
    for context in contexts {
        for key in keys {
            if let Some(value) = context.get(*key) {
                if value.is_null() {
                    continue;
                }
                if let Some(value) = bool_value(value) {
                    return Ok(Some(value));
                }
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
        }
    }
    Ok(None)
}

fn first_date(
    contexts: &[&Map<String, Value>],
    keys: &[&str],
) -> Result<Option<Timestamp>, ClassifiedError> {
    for context in contexts {
        if let Some(date) = first_date_in_object(context, keys)? {
            return Ok(Some(date));
        }
    }
    Ok(None)
}

fn first_date_in_object(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Result<Option<Timestamp>, ClassifiedError> {
    for key in keys {
        if object.contains_key(*key)
            && let Some(date) = date_value(object.get(*key))?
        {
            return Ok(Some(date));
        }
    }
    Ok(None)
}

fn money_amount(
    contexts: &[&Map<String, Value>],
    cents_keys: &[&str],
    micro_usd_keys: &[&str],
    plain_keys: &[&str],
) -> Result<Option<f64>, ClassifiedError> {
    if let Some(value) = first_number(contexts, cents_keys)? {
        return Ok(Some(value / 100.0));
    }
    if let Some(value) = first_number(contexts, micro_usd_keys)? {
        return Ok(Some(value / 1_000_000.0));
    }
    first_number(contexts, plain_keys)
}

fn number(value: Option<&Value>) -> Result<Option<f64>, ClassifiedError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let parsed = match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|value| value.is_finite() && value.abs() <= MAX_MONEY)
    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(Some(parsed))
}

fn provider_string(value: Option<&Value>) -> Result<Option<String>, ClassifiedError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_str()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_PROVIDER_STRING_BYTES || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(Some(value.to_owned()))
}

fn bool_value(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value.as_i64().and_then(|value| match value {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "enabled" | "on" => Some(true),
            "false" | "0" | "no" | "disabled" | "off" => Some(false),
            _ => None,
        },
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn bool_from_status(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "enabled" | "active" | "on" => Some(true),
        "disabled" | "inactive" | "off" | "none" => Some(false),
        _ => None,
    }
}

fn date_value(value: Option<&Value>) -> Result<Option<Timestamp>, ClassifiedError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    if let Some(value) = value.as_str() {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        if let Ok(number) = value.parse::<f64>() {
            return epoch_timestamp(number).map(Some);
        }
        return Timestamp::parse(value)
            .map(Some)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse));
    }
    let number = value
        .as_f64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    epoch_timestamp(number).map(Some)
}

fn epoch_timestamp(value: f64) -> Result<Timestamp, ClassifiedError> {
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let seconds = if value.abs() > 10_000_000_000.0 {
        value / 1_000.0
    } else {
        value
    };
    let seconds = Decimal::from_f64(seconds)
        .and_then(|value| value.trunc().to_i64())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::from_unix_timestamp(seconds).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn checked_add(left: f64, right: f64) -> Result<f64, ClassifiedError> {
    let result = left + right;
    if result.is_finite() && result.abs() <= MAX_MONEY {
        Ok(result)
    } else {
        Err(ClassifiedError::new(ErrorKind::Parse))
    }
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    fields: &UsageFields,
    source: &'static str,
) -> Result<UsageSample, ClassifiedError> {
    let credits_total = fields
        .credits_total
        .map(|value| value.max(0.0))
        .or_else(|| {
            fields
                .credits_used
                .zip(fields.credits_remaining)
                .map(|(used, remaining)| (used + remaining).max(0.0))
        });
    let credits_used = fields.credits_used.map_or_else(
        || {
            credits_total
                .zip(fields.credits_remaining)
                .map_or(0.0, |(total, remaining)| (total - remaining).max(0.0))
        },
        |value| value.max(0.0),
    );

    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(total) = credits_total {
        let percent = if total > 0.0 {
            (credits_used / total * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };
        let description = format!(
            "{}/{} credits",
            compact_number(credits_used),
            compact_number(total)
        );
        builder = builder.primary(rate_window(percent, None, Some(description))?);
    }

    let pass_total = fields.pass_total.map(|value| value.max(0.0)).or_else(|| {
        fields
            .pass_used
            .zip(fields.pass_remaining)
            .map(|(used, remaining)| (used + remaining).max(0.0))
    });
    if let Some(total) = pass_total {
        let used = fields.pass_used.map_or_else(
            || {
                fields
                    .pass_remaining
                    .map_or(0.0, |remaining| (total - remaining).max(0.0))
            },
            |value| value.max(0.0),
        );
        let bonus = fields.pass_bonus.unwrap_or(0.0).max(0.0);
        let base = (total - bonus).max(0.0);
        let percent = if total > 0.0 {
            (used / total * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };
        let description = if bonus > 0.0 {
            format!("${:.2} / ${base:.2} (+ ${bonus:.2} bonus)", used.max(0.0))
        } else {
            format!("${:.2} / ${base:.2}", used.max(0.0))
        };
        builder = builder.secondary(rate_window(
            percent,
            fields.pass_resets_at,
            Some(description),
        )?);
    }

    let login_method = login_method(
        fields.plan_name.as_deref(),
        fields.auto_top_up_enabled,
        fields.auto_top_up_method.as_deref(),
    );
    builder
        .login_method(login_method)?
        .provenance("kilo", source)?
        .build()
}

fn rate_window(
    used_percent: f64,
    resets_at: Option<Timestamp>,
    description: Option<String>,
) -> Result<RateWindow, ClassifiedError> {
    let description = description
        .map(BoundedText::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(used_percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        resets_at,
        description,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn login_method(plan: Option<&str>, enabled: Option<bool>, method: Option<&str>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(plan) = plan.map(str::trim).filter(|value| !value.is_empty()) {
        parts.push(plan.to_owned());
    }
    if let Some(enabled) = enabled {
        if enabled {
            parts.push(
                match method.map(str::trim).filter(|value| !value.is_empty()) {
                    Some(method) => format!("Auto top-up: {method}"),
                    None => "Auto top-up: enabled".to_owned(),
                },
            );
        } else {
            parts.push("Auto top-up: off".to_owned());
        }
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

fn compact_number(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
    }
}

fn currency_amount_label(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("${value:.0}")
    } else {
        format!("${value:.2}")
    }
}

fn parse_organizations(bytes: &[u8]) -> Result<Vec<KiloOrganization>, ClassifiedError> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let raw = organization_array(&root).unwrap_or(&[]);
    if raw.len() > MAX_ORGANIZATIONS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    raw.iter().filter_map(parse_organization).collect()
}

fn organization_array(root: &Value) -> Option<&[Value]> {
    if let Some(entries) = root.as_array() {
        return organizations_from_trpc_entry(entries.first()?);
    }
    let object = root.as_object()?;
    if let Some(organizations) = object.get("organizations").and_then(Value::as_array) {
        return Some(organizations);
    }
    organizations_from_trpc_entry(root)
}

fn organizations_from_trpc_entry(entry: &Value) -> Option<&[Value]> {
    let data = entry.get("result")?.get("data")?;
    if let Some(organizations) = data.as_array() {
        return Some(organizations);
    }
    let json = data.get("json")?;
    json.as_array().map(Vec::as_slice).or_else(|| {
        json.get("organizations")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
    })
}

fn parse_organization(value: &Value) -> Option<Result<KiloOrganization, ClassifiedError>> {
    let object = value.as_object()?;
    let id = match provider_string(object.get("id")) {
        Ok(Some(id)) => id,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    let name = match provider_string(object.get("name")) {
        Ok(Some(name)) => name,
        Ok(None) => id.clone(),
        Err(error) => return Some(Err(error)),
    };
    let role = match provider_string(object.get("role")) {
        Ok(role) => role,
        Err(error) => return Some(Err(error)),
    };
    Some((|| {
        Ok(KiloOrganization {
            id: BoundedText::new(id).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            name: BoundedText::new(name).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            role: role
                .map(BoundedText::new)
                .transpose()
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        })
    })())
}
