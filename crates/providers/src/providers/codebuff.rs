//! Native `Codebuff` credit usage with XDG credential-file discovery.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, DetailRow, DetailSection, DetailSensitivity, ErrorKind,
    ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::configured_endpoint::clean_setting;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const DEFAULT_API_BASE: &str = "https://www.codebuff.com/";
const API_KEY_ENV: &str = "CODEBUFF_API_KEY";
const API_URL_ENV: &str = "CODEBUFF_API_URL";
const CREDENTIAL_PATH_OVERRIDE: &str = "OMARCHY_AI_BAR_CODEBUFF_CREDENTIALS_PATH";
const MAX_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CREDENTIAL_FILE_BYTES_USIZE: usize = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 256;
const SUBSCRIPTION_GRACE: Duration = Duration::from_secs(2);
const FINGERPRINT_BODY: &[u8] = br#"{"fingerprintId":"omarchy-ai-bar-usage"}"#;

/// Credential origin selected by the baseline environment-first precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodebuffCredentialSource {
    /// `CODEBUFF_API_KEY` supplied by the account environment.
    Environment,
    /// The provider-owned `manicode/credentials.json` file.
    AuthFile,
}

impl CodebuffCredentialSource {
    const fn provider_source(self) -> ProviderSource {
        match self {
            Self::Environment => ProviderSource::ApiKey,
            Self::AuthFile => ProviderSource::LocalData,
        }
    }
}

/// Validated endpoint and zeroizing credential selected for one account.
pub struct CodebuffSettings {
    credential: ApiKeyCredential,
    credential_source: CodebuffCredentialSource,
    api_base: Url,
    api_class: EndpointClass,
}

impl CodebuffSettings {
    /// Resolves `CODEBUFF_API_KEY` first, then the provider-owned XDG file.
    ///
    /// The default local path is
    /// `$XDG_CONFIG_HOME/manicode/credentials.json`, falling back to
    /// `$HOME/.config/manicode/credentials.json`. The file is opened read-only
    /// with `O_NOFOLLOW`; its bytes and selected token remain zeroizing.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential, permission, parse, or endpoint errors.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        Self::resolve_inner(environment, None)
    }

    /// Resolves with a deterministic credentials path for integration tests.
    ///
    /// Environment credentials still take precedence, so an unused path is
    /// never opened or validated.
    ///
    /// # Errors
    ///
    /// Returns the same stable categories as [`Self::resolve`].
    #[doc(hidden)]
    pub fn resolve_with_auth_path(
        environment: &BTreeMap<String, String>,
        auth_path: impl AsRef<Path>,
    ) -> Result<Self, ClassifiedError> {
        Self::resolve_inner(environment, Some(auth_path.as_ref()))
    }

    fn resolve_inner(
        environment: &BTreeMap<String, String>,
        auth_path: Option<&Path>,
    ) -> Result<Self, ClassifiedError> {
        let (credential, credential_source) = if let Some(raw) = environment
            .get(API_KEY_ENV)
            .and_then(|value| clean_setting(value))
        {
            (
                ApiKeyCredential::new(raw)?,
                CodebuffCredentialSource::Environment,
            )
        } else {
            let path = auth_path.map_or_else(
                || resolve_auth_path(environment),
                |path| {
                    validate_path(path)?;
                    Ok(path.to_owned())
                },
            )?;
            (
                read_auth_credential(&path)?,
                CodebuffCredentialSource::AuthFile,
            )
        };
        let raw_base = environment
            .get(API_URL_ENV)
            .and_then(|value| clean_setting(value))
            .unwrap_or(DEFAULT_API_BASE);
        let (api_base, api_class) = normalize_api_base(raw_base)?;
        Ok(Self {
            credential,
            credential_source,
            api_base,
            api_class,
        })
    }

    /// Credential origin without exposing any credential bytes or path.
    #[must_use]
    pub const fn credential_source(&self) -> CodebuffCredentialSource {
        self.credential_source
    }

    /// Validated HTTPS base URL.
    #[must_use]
    pub const fn api_base(&self) -> &Url {
        &self.api_base
    }
}

impl Debug for CodebuffSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodebuffSettings")
            .field("credential", &"<redacted>")
            .field("credential_source", &self.credential_source)
            .field("api_base", &"<redacted>")
            .field("api_class", &self.api_class)
            .finish()
    }
}

/// Native `Codebuff` API adapter.
pub struct CodebuffProvider {
    client: FixedApiClient,
    include_subscription: bool,
    subscription_grace: Duration,
}

impl Debug for CodebuffProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodebuffProvider")
            .field("scope", self.client.scope())
            .field("source", &self.client.source())
            .field("include_subscription", &self.include_subscription)
            .field("subscription_grace", &self.subscription_grace)
            .finish()
    }
}

impl CodebuffProvider {
    /// Creates the production exact-origin client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid scope or transport configuration.
    pub fn new(scope: AccountScope, settings: CodebuffSettings) -> Result<Self, ClassifiedError> {
        let source = settings.credential_source.provider_source();
        let client = FixedApiClient::new_bearer(
            scope,
            settings.api_base,
            settings.api_class,
            settings.credential,
            transport_config()?,
        )?
        .with_source(source)?;
        Self::from_client(client)
    }

    /// Wraps one account/source-bound client for deterministic fixtures.
    ///
    /// # Errors
    ///
    /// Rejects another provider or a source other than API key/local data.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        Self::from_client_with_grace(client, SUBSCRIPTION_GRACE)
    }

    /// Test seam for the optional subscription deadline.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid client scope or a zero deadline.
    #[doc(hidden)]
    pub fn from_client_with_grace(
        client: FixedApiClient,
        subscription_grace: Duration,
    ) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Codebuff
            || !matches!(
                client.source(),
                ProviderSource::ApiKey | ProviderSource::LocalData
            )
            || subscription_grace.is_zero()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let include_subscription = client.source() == ProviderSource::LocalData;
        Ok(Self {
            client,
            include_subscription,
            subscription_grace,
        })
    }

    /// Fetches required credits and optional local-login subscription details.
    ///
    /// # Errors
    ///
    /// Returns only required usage/configuration failures. Subscription errors
    /// and deadline expiry are best-effort, matching the baseline behavior.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let usage_url = self.client.url("api/v1/usage")?;
        let (usage, subscription) = if self.include_subscription {
            let subscription_url = self.client.url("api/user/subscription")?;
            let usage_request =
                self.client
                    .post_json(context, usage_url, FINGERPRINT_BODY.to_vec());
            let subscription_request = self.client.get_json(context, subscription_url);
            tokio::pin!(usage_request);
            tokio::pin!(subscription_request);

            let mut early_subscription = None;
            let usage_response = loop {
                tokio::select! {
                    biased;
                    response = &mut usage_request => break response,
                    response = &mut subscription_request, if early_subscription.is_none() => {
                        early_subscription = Some(response);
                    }
                }
            }
            .map_err(map_auth_error)?;
            let usage = parse_usage(usage_response.body())?;
            let subscription_response = match early_subscription {
                Some(response) => Some(response),
                None => tokio::time::timeout(self.subscription_grace, &mut subscription_request)
                    .await
                    .ok(),
            };
            let subscription = subscription_response
                .and_then(Result::ok)
                .and_then(|response| parse_subscription(response.body()).ok());
            (usage, subscription)
        } else {
            let usage_response = self
                .client
                .post_json(context, usage_url, FINGERPRINT_BODY.to_vec())
                .await
                .map_err(map_auth_error)?;
            (parse_usage(usage_response.body())?, None)
        };
        normalize(
            context.scope().clone(),
            fetched_at,
            self.client.source(),
            &usage,
            subscription.as_ref(),
        )
    }
}

impl ProviderAdapter for CodebuffProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Codebuff)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Default)]
struct UsagePayload {
    used: Option<f64>,
    total: Option<f64>,
    remaining: Option<f64>,
    next_quota_reset: Option<Timestamp>,
    auto_top_up_enabled: Option<bool>,
}

#[derive(Default)]
struct SubscriptionPayload {
    status: Option<String>,
    tier: Option<String>,
    billing_period_end: Option<Timestamp>,
    weekly_used: Option<f64>,
    weekly_limit: Option<f64>,
    weekly_resets_at: Option<Timestamp>,
    email: Option<String>,
}

fn parse_usage(bytes: &[u8]) -> Result<UsagePayload, ClassifiedError> {
    let root = parse_object(bytes)?;
    Ok(UsagePayload {
        used: first_number(&root, &["usage", "used"]),
        total: first_number(&root, &["quota", "limit"]),
        remaining: first_number(&root, &["remainingBalance", "remaining"]),
        next_quota_reset: root.get("next_quota_reset").and_then(parse_timestamp),
        auto_top_up_enabled: root
            .get("autoTopupEnabled")
            .and_then(Value::as_bool)
            .or_else(|| root.get("auto_topup_enabled").and_then(Value::as_bool)),
    })
}

fn parse_subscription(bytes: &[u8]) -> Result<SubscriptionPayload, ClassifiedError> {
    let root = parse_object(bytes)?;
    let subscription = root.get("subscription").and_then(Value::as_object);
    let rate_limit = root.get("rateLimit").and_then(Value::as_object);
    let tier = first_identity_from_maps(
        &[
            (subscription, "displayName"),
            (Some(&root), "displayName"),
            (subscription, "tier"),
            (Some(&root), "tier"),
            (subscription, "scheduledTier"),
        ],
        true,
    )?;
    let email = match identity_from_map(Some(&root), "email", false)? {
        Some(email) => Some(email),
        None => root
            .get("user")
            .and_then(Value::as_object)
            .map(|user| identity_from_map(Some(user), "email", false))
            .transpose()?
            .flatten(),
    };
    Ok(SubscriptionPayload {
        status: identity_from_map(subscription, "status", false)?,
        tier,
        billing_period_end: first_timestamp(
            subscription,
            &["billingPeriodEnd", "currentPeriodEnd"],
        ),
        weekly_used: first_number_optional_map(rate_limit, &["weeklyUsed", "used"]),
        weekly_limit: first_number_optional_map(rate_limit, &["weeklyLimit", "limit"]),
        weekly_resets_at: first_timestamp(rate_limit, &["weeklyResetsAt"]),
        email,
    })
}

fn parse_object(bytes: &[u8]) -> Result<Map<String, Value>, ClassifiedError> {
    match serde_json::from_slice(bytes).map_err(parse_error)? {
        Value::Object(object) => Ok(object),
        _ => Err(ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn first_number(object: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    first_number_optional_map(Some(object), keys)
}

fn first_number_optional_map(object: Option<&Map<String, Value>>, keys: &[&str]) -> Option<f64> {
    let object = object?;
    keys.iter()
        .find_map(|key| object.get(*key).and_then(number_value))
}

fn number_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64().filter(|value| value.is_finite()),
        Value::String(value) if value.len() <= 128 => value
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite()),
        _ => None,
    }
}

fn first_timestamp(object: Option<&Map<String, Value>>, keys: &[&str]) -> Option<Timestamp> {
    let object = object?;
    keys.iter()
        .find_map(|key| object.get(*key).and_then(parse_timestamp))
}

fn parse_timestamp(value: &Value) -> Option<Timestamp> {
    match value {
        Value::String(value) if value.len() <= 128 => Timestamp::parse(value.trim())
            .ok()
            .or_else(|| decimal_timestamp(value.trim())),
        Value::Number(number) => decimal_timestamp(&number.to_string()),
        _ => None,
    }
}

fn decimal_timestamp(value: &str) -> Option<Timestamp> {
    let value = Decimal::from_scientific(value)
        .or_else(|_| Decimal::from_str(value))
        .ok()?;
    let threshold = Decimal::from(10_000_000_000_u64);
    let seconds = if value > threshold {
        value / Decimal::from(1000_u16)
    } else {
        value
    };
    Timestamp::from_unix_timestamp(seconds.trunc().to_i64()?).ok()
}

fn first_identity_from_maps(
    candidates: &[(Option<&Map<String, Value>>, &str)],
    allow_number: bool,
) -> Result<Option<String>, ClassifiedError> {
    for (object, key) in candidates {
        if let Some(value) = identity_from_map(*object, key, allow_number)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn identity_from_map(
    object: Option<&Map<String, Value>>,
    key: &str,
    allow_number: bool,
) -> Result<Option<String>, ClassifiedError> {
    let Some(value) = object.and_then(|object| object.get(key)) else {
        return Ok(None);
    };
    let value = match value {
        Value::String(value) => value.trim().to_owned(),
        Value::Number(value) if allow_number => value.to_string(),
        _ => return Ok(None),
    };
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_IDENTITY_BYTES || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(Some(value))
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    source: ProviderSource,
    usage: &UsagePayload,
    subscription: Option<&SubscriptionPayload>,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(primary) = credit_window(usage)? {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = subscription.and_then(weekly_window).transpose()? {
        builder = builder.secondary(secondary);
    }
    let details = detail_sections(usage, subscription)?;
    let email = subscription.and_then(|value| value.email.clone());
    let login_method = login_method(usage, subscription);
    let expiry = subscription.and_then(|value| value.billing_period_end);
    builder
        .email(email)?
        .login_method(login_method)?
        .subscription_expires_at(expiry)
        .detail_sections(details)
        .provenance(
            "codebuff",
            if source == ProviderSource::LocalData {
                "auth-file"
            } else {
                "api-key"
            },
        )?
        .build()
}

fn credit_window(usage: &UsagePayload) -> Result<Option<RateWindow>, ClassifiedError> {
    let total = usage
        .total
        .map(|value| value.max(0.0))
        .or_else(|| Some((usage.used? + usage.remaining?).max(0.0)));
    let Some(total) = total else {
        return if usage.used.is_some() || usage.remaining.is_some() {
            make_window(100.0, None, usage.next_quota_reset).map(Some)
        } else {
            Ok(None)
        };
    };
    if total <= 0.0 {
        return make_window(100.0, None, usage.next_quota_reset).map(Some);
    }
    let used = usage.used.map_or_else(
        || (total - usage.remaining.unwrap_or(0.0)).max(0.0),
        |value| value.max(0.0),
    );
    make_window(used / total * 100.0, None, usage.next_quota_reset).map(Some)
}

fn weekly_window(
    subscription: &SubscriptionPayload,
) -> Option<Result<RateWindow, ClassifiedError>> {
    let limit = subscription.weekly_limit?.max(0.0);
    if limit <= 0.0 {
        return None;
    }
    let used = subscription.weekly_used.unwrap_or(0.0).max(0.0);
    Some(make_window(
        used / limit * 100.0,
        Some(7 * 24 * 60),
        subscription.weekly_resets_at,
    ))
}

fn make_window(
    percent: f64,
    minutes: Option<i64>,
    resets_at: Option<Timestamp>,
) -> Result<RateWindow, ClassifiedError> {
    let duration = minutes
        .map(WindowDuration::from_provider_minutes)
        .transpose()
        .map_err(parse_error)?;
    RateWindow::new(
        WindowUsage::known(UsagePercent::new(percent.clamp(0.0, 100.0)).map_err(parse_error)?),
        duration,
        resets_at,
        None,
        None,
        false,
    )
    .map_err(parse_error)
}

fn login_method(
    usage: &UsagePayload,
    subscription: Option<&SubscriptionPayload>,
) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(tier) = subscription.and_then(|value| value.tier.as_deref()) {
        parts.push(title_case(tier));
    }
    if let Some(remaining) = usage.remaining {
        parts.push(format!("{} remaining", compact_number(remaining)));
    }
    if usage.auto_top_up_enabled == Some(true) {
        parts.push("auto top-up".to_owned());
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

fn detail_sections(
    usage: &UsagePayload,
    subscription: Option<&SubscriptionPayload>,
) -> Result<Vec<DetailSection>, ClassifiedError> {
    let mut rows = Vec::new();
    push_number_detail(&mut rows, "Credits used", usage.used)?;
    push_number_detail(&mut rows, "Credits total", usage.total)?;
    push_number_detail(&mut rows, "Credits remaining", usage.remaining)?;
    if let Some(subscription) = subscription {
        push_text_detail(&mut rows, "Plan", subscription.tier.as_deref())?;
        push_text_detail(
            &mut rows,
            "Subscription status",
            subscription.status.as_deref(),
        )?;
        push_number_detail(&mut rows, "Weekly used", subscription.weekly_used)?;
        push_number_detail(&mut rows, "Weekly limit", subscription.weekly_limit)?;
    }
    if let Some(enabled) = usage.auto_top_up_enabled {
        rows.push(detail_row(
            "Automatic top-up",
            if enabled { "Enabled" } else { "Disabled" }.to_owned(),
        )?);
    }
    if rows.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(vec![
            DetailSection::new(Some("Codebuff credits".to_owned()), rows, None)
                .map_err(parse_error)?,
        ])
    }
}

fn push_number_detail(
    rows: &mut Vec<DetailRow>,
    label: &str,
    value: Option<f64>,
) -> Result<(), ClassifiedError> {
    if let Some(value) = value {
        rows.push(detail_row(label, compact_number(value))?);
    }
    Ok(())
}

fn push_text_detail(
    rows: &mut Vec<DetailRow>,
    label: &str,
    value: Option<&str>,
) -> Result<(), ClassifiedError> {
    if let Some(value) = value {
        rows.push(detail_row(label, value.to_owned())?);
    }
    Ok(())
}

fn detail_row(label: &str, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Public).map_err(parse_error)
}

fn compact_number(value: f64) -> String {
    let value = if value >= 1_000.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned()
    };
    group_decimal(&value)
}

fn group_decimal(value: &str) -> String {
    let (whole, fraction) = value
        .split_once('.')
        .map_or((value, None), |(whole, fraction)| (whole, Some(fraction)));
    let (sign, digits) = whole
        .strip_prefix('-')
        .map_or(("", whole), |digits| ("-", digits));
    if digits.len() <= 3 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.to_owned();
    }
    let mut grouped = String::with_capacity(value.len() + digits.len() / 3);
    grouped.push_str(sign);
    for (index, byte) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    if let Some(fraction) = fraction {
        grouped.push('.');
        grouped.push_str(fraction);
    }
    grouped
}

fn title_case(value: &str) -> String {
    value
        .split_whitespace()
        .map(|word| {
            let mut characters = word.chars();
            let Some(first) = characters.next() else {
                return String::new();
            };
            first
                .to_uppercase()
                .chain(characters.flat_map(char::to_lowercase))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn resolve_auth_path(environment: &BTreeMap<String, String>) -> Result<PathBuf, ClassifiedError> {
    if let Some(value) = environment
        .get(CREDENTIAL_PATH_OVERRIDE)
        .and_then(|value| clean_setting(value))
    {
        let path = PathBuf::from(value);
        validate_path(&path)?;
        return Ok(path);
    }
    let config_home = if let Some(value) = environment
        .get("XDG_CONFIG_HOME")
        .and_then(|value| clean_setting(value))
    {
        PathBuf::from(value)
    } else {
        let home = environment
            .get("HOME")
            .and_then(|value| clean_setting(value))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        PathBuf::from(home).join(".config")
    };
    validate_path(&config_home)?;
    let path = config_home.join("manicode/credentials.json");
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

fn read_auth_credential(path: &Path) -> Result<ApiKeyCredential, ClassifiedError> {
    validate_path(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|error| classify_auth_io(&error))?;
    let bytes = read_bounded_auth_file(file)?;
    let payload: CredentialsFile = serde_json::from_slice(&bytes).map_err(parse_error)?;
    let default = payload.default.and_then(|profile| profile.auth_token);
    let token = default
        .filter(|token| !secret_is_empty_after_cleaning(&token.0))
        .or(payload.auth_token)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    ApiKeyCredential::from_zeroizing(token.0)
}

fn secret_is_empty_after_cleaning(raw: &str) -> bool {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = &value[1..value.len() - 1];
    }
    value.trim().is_empty()
}

fn read_bounded_auth_file(mut file: File) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    let metadata = file.metadata().map_err(|error| classify_auth_io(&error))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(MAX_CREDENTIAL_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| classify_auth_io(&error))?;
    if bytes.len() > MAX_CREDENTIAL_FILE_BYTES_USIZE {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(bytes)
}

fn classify_auth_io(error: &std::io::Error) -> ClassifiedError {
    match error.kind() {
        std::io::ErrorKind::NotFound => ClassifiedError::new(ErrorKind::MissingCredential),
        std::io::ErrorKind::PermissionDenied => ClassifiedError::new(ErrorKind::PermissionDenied),
        _ => ClassifiedError::new(ErrorKind::Parse),
    }
}

#[derive(Deserialize)]
struct CredentialsFile {
    #[serde(default)]
    default: Option<CredentialsProfile>,
    #[serde(rename = "authToken", default)]
    auth_token: Option<SecretToken>,
}

#[derive(Deserialize)]
struct CredentialsProfile {
    #[serde(rename = "authToken", default)]
    auth_token: Option<SecretToken>,
}

struct SecretToken(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .map(Zeroizing::new)
            .map(Self)
    }
}

fn normalize_api_base(raw: &str) -> Result<(Url, EndpointClass), ClassifiedError> {
    let raw = clean_setting(raw).ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if raw.contains('\\') || raw.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let candidate = if has_explicit_scheme(raw) {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let mut url = Url::parse(&candidate).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let class = classify_https_endpoint(&url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let mut path = url.path().trim_end_matches('/').to_owned();
    path.push('/');
    url.set_path(&path);
    Ok((url, class))
}

fn has_explicit_scheme(raw: &str) -> bool {
    let Some(colon) = raw.find(':') else {
        return false;
    };
    raw[colon..].starts_with("://")
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}

fn map_auth_error(error: ClassifiedError) -> ClassifiedError {
    if error.kind() == ErrorKind::PermissionDenied {
        ClassifiedError::new(ErrorKind::AuthenticationExpired)
    } else {
        error
    }
}

fn parse_error<T>(_: T) -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
