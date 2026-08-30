//! Devin quota usage through an explicit Bearer capture or Linux Chromium profile.

use std::cmp::Reverse;
use std::fmt::{self, Debug, Formatter};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, ErrorKind, ExactDecimal, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::browser_profile::{BrowserKind, BrowserProfile, BrowserProfileDiscovery};
use crate::chromium_leveldb::{ChromiumHttpsOrigin, ChromiumLevelDbReader};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, TransportConfig, TransportError,
};

const PRODUCTION_ORIGIN: &str = "https://app.devin.ai";
const STORAGE_ORIGIN: &str = "https://app.devin.ai";
const LOCAL_STORAGE_DIRECTORY: &str = "Local Storage/leveldb";
const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const EXTERNAL_ORG_PREFIX: &str = "last-internal-org-for-external-org-v1-";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 256 * 1024;
const MAX_JSON_STRING_AGGREGATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_ORGANIZATION_BYTES: usize = 256;
const MAX_BROWSER_PROFILES: usize = 128;
const MAX_STORAGE_ENTRIES: usize = 2_048;
const MAX_STORAGE_ENTRY_BYTES: usize = 256 * 1024;
const MAX_STORAGE_AGGREGATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_OVERAGE_MAGNITUDE: i64 = 1_000_000_000_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

struct DevinSession {
    token: Zeroizing<String>,
    organization: Option<String>,
    internal_organization_id: Option<String>,
}

impl DevinSession {
    fn organization_score(&self) -> u8 {
        u8::from(self.organization.is_some())
            + 2 * u8::from(self.internal_organization_id.is_some())
    }
}

impl Debug for DevinSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevinSession")
            .field("token", &"<redacted>")
            .field("has_organization", &self.organization.is_some())
            .field(
                "has_internal_organization_id",
                &self.internal_organization_id.is_some(),
            )
            .finish()
    }
}

/// Devin adapter permanently bound to one account and explicit credential source.
pub struct DevinProvider {
    scope: AccountScope,
    source: ProviderSource,
    origin: Url,
    sessions: Vec<DevinSession>,
    transport: HttpTransport,
}

impl DevinProvider {
    /// Creates the production adapter from a bare token, Bearer header, or copied cURL request.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, capture, organization, scope, or endpoint error.
    pub fn new_manual(
        scope: AccountScope,
        raw: &str,
        organization_override: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        let origin = Url::parse(PRODUCTION_ORIGIN).map_err(|_| api_error())?;
        Self::from_manual_capture_at(
            scope,
            raw,
            organization_override,
            &origin,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates a manual adapter at an injected exact loopback origin for isolated tests.
    ///
    /// A URL in a copied cURL request remains restricted to exact `app.devin.ai`; the injected
    /// origin replaces only the already-authorized network destination.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted capture, credential, organization, scope, or endpoint error.
    #[doc(hidden)]
    pub fn from_manual_capture_at(
        scope: AccountScope,
        raw: &str,
        organization_override: Option<&str>,
        origin: &Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let token = parse_manual_token(raw)?;
        let organization = normalize_optional_organization(organization_override)?;
        let internal_organization_id = organization.as_deref().and_then(internal_org_id);
        let session = DevinSession {
            token,
            organization,
            internal_organization_id,
        };
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            origin,
            endpoint_class,
            vec![session],
        )
    }

    /// Creates the production adapter from explicitly enabled Linux browser-profile discovery.
    ///
    /// Discovery and `LevelDB` reads happen only below the caller-injected roots. Firefox and Zen
    /// are ignored because Devin's session state is stored in Chromium local storage.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, bounded local-data, organization, scope, or endpoint
    /// error.
    pub fn new_browser(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        organization_override: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        let origin = Url::parse(PRODUCTION_ORIGIN).map_err(|_| api_error())?;
        Self::from_browser_discovery_at(
            scope,
            discovery,
            organization_override,
            &origin,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates a browser adapter at an injected exact loopback origin for isolated tests.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, bounded local-data, organization, scope, or endpoint
    /// error.
    #[doc(hidden)]
    pub fn from_browser_discovery_at(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        organization_override: Option<&str>,
        origin: &Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let organization_override = normalize_optional_organization(organization_override)?;
        let report = discovery.discover();
        let mut profile_count = 0_usize;
        let mut sessions = Vec::new();
        for profile in report.profiles() {
            if !is_chromium_family(profile.browser()) {
                continue;
            }
            profile_count = profile_count.checked_add(1).ok_or_else(parse_error)?;
            if profile_count > MAX_BROWSER_PROFILES {
                return Err(parse_error());
            }
            let Ok(storage) = read_profile_storage(profile) else {
                continue;
            };
            if let Some(session) = session_from_storage(&storage, organization_override.as_deref())
            {
                sessions.push(session);
                if sessions.len() > MAX_BROWSER_SESSIONS {
                    return Err(parse_error());
                }
            }
        }
        let sessions = rank_and_deduplicate_sessions(sessions);
        if sessions.is_empty() {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            origin,
            endpoint_class,
            sessions,
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        origin: &Url,
        endpoint_class: EndpointClass,
        sessions: Vec<DevinSession>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Devin
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
            || sessions.is_empty()
            || sessions.len() > MAX_BROWSER_SESSIONS
        {
            return Err(api_error());
        }
        validate_origin(origin, endpoint_class)?;
        let policy = EndpointPolicy::new([(origin.origin().ascii_serialization(), endpoint_class)])
            .map_err(|_| api_error())?;
        policy.validate(origin).map_err(|_| api_error())?;
        let config = TransportConfig::new(
            CONNECT_TIMEOUT,
            REQUEST_TIMEOUT,
            MAX_RESPONSE_BYTES,
            0,
            RetryPolicy::none(),
        )
        .map_err(|_| api_error())?;
        let transport = HttpTransport::new(policy, config).map_err(|_| api_error())?;
        Ok(Self {
            scope,
            source,
            origin: origin.clone(),
            sessions,
            transport,
        })
    }

    /// Fetches one deterministic sample at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable redacted scope, credential, local-data, network, status, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }
        let mut last_error = None;
        for session in &self.sessions {
            let Some(organization) = session.organization.as_deref() else {
                let error = api_error();
                if self.source == ProviderSource::ManualCookie {
                    return Err(error);
                }
                last_error = Some(error);
                continue;
            };
            match self
                .fetch_session(context, fetched_at, session, organization)
                .await
            {
                Ok(sample) => return Ok(sample),
                Err(failure) => {
                    if self.source == ProviderSource::ManualCookie || !failure.try_next_session {
                        return Err(failure.error);
                    }
                    last_error = Some(failure.error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }

    async fn fetch_session(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        session: &DevinSession,
        organization: &str,
    ) -> Result<UsageSample, SessionFailure> {
        let paths = candidate_paths(organization, session.internal_organization_id.as_deref());
        let mut last_failure = None;
        for path in paths {
            let url = quota_url(&self.origin, &path).map_err(SessionFailure::terminal)?;
            let authentication = Authentication::bearer(session.token.as_str().to_owned())
                .map_err(|_| SessionFailure::terminal(api_error()))?;
            let mut request = HttpRequest::get_json(url)
                .authentication(authentication)
                .public_header("accept-language", ACCEPT_LANGUAGE)
                .and_then(|request| request.public_header("user-agent", USER_AGENT))
                .map_err(|_| SessionFailure::terminal(api_error()))?;
            if let Some(internal_id) = session.internal_organization_id.as_deref() {
                request = request
                    .sensitive_header("x-cog-org-id", internal_id.to_owned())
                    .map_err(|_| SessionFailure::terminal(api_error()))?;
            }
            match self.transport.send(&request, context.cancellation()).await {
                Ok(response) => {
                    if response.status() != 200 {
                        last_failure = Some(SessionFailure {
                            error: api_error(),
                            try_next_session: true,
                        });
                        continue;
                    }
                    return parse_quota_response(
                        self.scope.clone(),
                        fetched_at,
                        response.body(),
                        Some(organization),
                        self.source,
                    )
                    .map_err(SessionFailure::terminal);
                }
                Err(TransportError::AuthenticationExpired | TransportError::PermissionDenied) => {
                    return Err(SessionFailure {
                        error: ClassifiedError::new(ErrorKind::AuthenticationExpired),
                        try_next_session: true,
                    });
                }
                Err(error) => {
                    let try_next_session = completed_status_failure(&error);
                    last_failure = Some(SessionFailure {
                        error: error.classified(),
                        try_next_session,
                    });
                }
            }
        }
        Err(last_failure.unwrap_or_else(|| SessionFailure::terminal(api_error())))
    }
}

impl Debug for DevinProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevinProvider")
            .field("scope", &self.scope)
            .field("source", &self.source)
            .field("origin", &"<redacted>")
            .field("session_count", &self.sessions.len())
            .field("transport", &"<configured>")
            .finish()
    }
}

impl ProviderAdapter for DevinProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Devin)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

struct SessionFailure {
    error: ClassifiedError,
    try_next_session: bool,
}

impl SessionFailure {
    const fn terminal(error: ClassifiedError) -> Self {
        Self {
            error,
            try_next_session: false,
        }
    }
}

fn completed_status_failure(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::RequestTimeout
            | TransportError::RateLimited { .. }
            | TransportError::ProviderUnavailable { .. }
            | TransportError::Api { .. }
    )
}

fn validate_origin(origin: &Url, endpoint_class: EndpointClass) -> Result<(), ClassifiedError> {
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        return Err(api_error());
    }
    match endpoint_class {
        EndpointClass::PublicHttps if origin.as_str() == "https://app.devin.ai/" => Ok(()),
        EndpointClass::LoopbackDevelopment => EndpointPolicy::new([(
            origin.origin().ascii_serialization(),
            EndpointClass::LoopbackDevelopment,
        )])
        .and_then(|policy| policy.validate(origin).map(|_| ()))
        .map_err(|_| api_error()),
        EndpointClass::PublicHttps | EndpointClass::PrivateHttps | EndpointClass::PrivateHttp => {
            Err(api_error())
        }
    }
}

fn quota_url(origin: &Url, path: &[String]) -> Result<Url, ClassifiedError> {
    let mut url = origin.clone();
    {
        let mut segments = url.path_segments_mut().map_err(|()| api_error())?;
        segments.clear().push("api");
        for segment in path {
            segments.push(segment);
        }
        segments.extend(["billing", "quota", "usage"]);
    }
    Ok(url)
}

fn candidate_paths(organization: &str, internal_id: Option<&str>) -> Vec<Vec<String>> {
    let mut paths = Vec::new();
    if let Some(internal_id) = internal_id {
        push_unique_path(&mut paths, vec![internal_id.to_owned()]);
    }
    let normalized =
        normalize_organization(organization).unwrap_or_else(|| organization.to_owned());
    let normalized_segments = normalized.split('/').map(str::to_owned).collect::<Vec<_>>();
    push_unique_path(&mut paths, normalized_segments);
    if let Some(slug) = normalized.strip_prefix("org/") {
        push_unique_path(&mut paths, vec![slug.to_owned()]);
    }
    if !normalized.starts_with("org/") && !normalized.starts_with("organizations/") {
        push_unique_path(&mut paths, vec!["org".to_owned(), normalized]);
    }
    if let Some(internal_id) = internal_id {
        push_unique_path(
            &mut paths,
            vec!["organizations".to_owned(), internal_id.to_owned()],
        );
    }
    paths
}

fn push_unique_path(paths: &mut Vec<Vec<String>>, path: Vec<String>) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

fn parse_manual_token(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    if raw.len() > 64 * 1024 || raw.chars().any(|character| character == '\0') {
        return Err(parse_error());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let captured = if starts_with_curl(trimmed)
        || trimmed
            .split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
    {
        let policy = ManualCapturePolicy::new(["app.devin.ai"], [CaptureHeader::Authorization])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(trimmed).map_err(classify_capture_error)?;
        capture
            .header(CaptureHeader::Authorization)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?
            .to_owned()
    } else {
        trimmed.to_owned()
    };
    let mut captured = Zeroizing::new(captured);
    let token = Zeroizing::new(
        if captured
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
        {
            captured[7..].trim().to_owned()
        } else {
            captured.trim().to_owned()
        },
    );
    captured.zeroize();
    validate_token(token.as_str())?;
    Ok(token)
}

fn starts_with_curl(raw: &str) -> bool {
    raw.split_ascii_whitespace()
        .next()
        .is_some_and(|value| value == "curl")
}

fn validate_token(token: &str) -> Result<(), ClassifiedError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token.chars().any(char::is_control)
        || token.contains(['\r', '\n'])
    {
        return Err(parse_error());
    }
    Authentication::bearer(token.to_owned()).map_err(|_| parse_error())?;
    Ok(())
}

fn classify_capture_error(error: ManualCaptureError) -> ClassifiedError {
    ClassifiedError::new(match error {
        ManualCaptureError::MissingSecret => ErrorKind::MissingCredential,
        ManualCaptureError::InvalidPolicy
        | ManualCaptureError::InputTooLarge
        | ManualCaptureError::InvalidSyntax
        | ManualCaptureError::UnsafeSyntax
        | ManualCaptureError::UnsafeOption
        | ManualCaptureError::TooManyTokens
        | ManualCaptureError::TooManyHeaders
        | ManualCaptureError::InvalidSecret
        | ManualCaptureError::DuplicateSecret
        | ManualCaptureError::ConflictingHeader
        | ManualCaptureError::DisallowedHeader
        | ManualCaptureError::DisallowedUrl => ErrorKind::Parse,
    })
}

fn normalize_optional_organization(raw: Option<&str>) -> Result<Option<String>, ClassifiedError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    normalize_organization(raw).map(Some).ok_or_else(api_error)
}

/// Normalizes one pinned Devin organization slug, internal ID, or dashboard URL.
///
/// Unsafe, unbounded, or non-Devin URL input is rejected as `None`.
#[must_use]
pub fn normalize_organization(raw: &str) -> Option<String> {
    let mut value = raw.trim();
    if value.is_empty()
        || value.len() > MAX_ORGANIZATION_BYTES
        || value.chars().any(char::is_control)
    {
        return None;
    }
    let from_url;
    if value.contains("://") {
        let url = Url::parse(value).ok()?;
        let host = url.host_str()?.to_ascii_lowercase();
        if host != "devin.ai" && !host.ends_with(".devin.ai") {
            return None;
        }
        let mut segments = url.path_segments()?.filter(|segment| !segment.is_empty());
        let prefix = segments.next()?;
        let component = segments.next()?;
        if !matches!(prefix, "org" | "organizations") || !valid_org_component(component) {
            return None;
        }
        from_url = format!("{prefix}/{component}");
        value = &from_url;
    }
    value = value.trim_matches('/');
    let (prefix, component) = if let Some(component) = value.strip_prefix("org/") {
        ("org", component)
    } else if let Some(component) = value.strip_prefix("organizations/") {
        ("organizations", component)
    } else if is_internal_org_id(value) {
        ("organizations", value)
    } else {
        ("org", value)
    };
    if !valid_org_component(component) {
        return None;
    }
    Some(format!("{prefix}/{component}"))
}

fn valid_org_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ORGANIZATION_BYTES - "organizations/".len()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_internal_org_id(value: &str) -> bool {
    (value.starts_with("org-") || value.starts_with("org_")) && valid_org_component(value)
}

fn internal_org_id(normalized: &str) -> Option<String> {
    normalized
        .strip_prefix("organizations/")
        .filter(|value| is_internal_org_id(value))
        .map(str::to_owned)
}

fn is_chromium_family(browser: BrowserKind) -> bool {
    matches!(
        browser,
        BrowserKind::Chromium
            | BrowserKind::GoogleChrome
            | BrowserKind::Brave
            | BrowserKind::BraveOrigin
            | BrowserKind::MicrosoftEdge
    )
}

struct StorageEntry {
    key: Zeroizing<String>,
    value: Zeroizing<String>,
}

impl Debug for StorageEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageEntry")
            .field("key", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

fn read_profile_storage(profile: &BrowserProfile) -> Result<Vec<StorageEntry>, ClassifiedError> {
    let reader = ChromiumLevelDbReader::open(profile, Path::new(LOCAL_STORAGE_DIRECTORY))
        .map_err(|_| parse_error())?;
    let origin = ChromiumHttpsOrigin::parse(STORAGE_ORIGIN).map_err(|_| api_error())?;
    let local = reader
        .local_storage_entries(&origin)
        .map_err(|_| parse_error())?;
    let mut storage = Vec::new();
    let mut aggregate = 0_usize;
    for entry in local {
        insert_storage(
            &mut storage,
            entry.expose_key(),
            entry.expose_value(),
            false,
            &mut aggregate,
        )?;
    }
    for entry in reader.text_entries().map_err(|_| parse_error())? {
        if is_useful_storage_key(entry.expose_key()) {
            insert_storage(
                &mut storage,
                entry.expose_key(),
                entry.expose_value(),
                true,
                &mut aggregate,
            )?;
        }
    }
    Ok(storage)
}

fn insert_storage(
    storage: &mut Vec<StorageEntry>,
    key: &str,
    value: &str,
    only_if_missing: bool,
    aggregate: &mut usize,
) -> Result<(), ClassifiedError> {
    if key.len() > MAX_STORAGE_ENTRY_BYTES || value.len() > MAX_STORAGE_ENTRY_BYTES {
        return Err(parse_error());
    }
    if only_if_missing && storage.iter().any(|entry| entry.key.as_str() == key) {
        return Ok(());
    }
    if storage.len() == MAX_STORAGE_ENTRIES {
        return Err(parse_error());
    }
    *aggregate = aggregate
        .checked_add(key.len())
        .and_then(|bytes| bytes.checked_add(value.len()))
        .filter(|bytes| *bytes <= MAX_STORAGE_AGGREGATE_BYTES)
        .ok_or_else(parse_error)?;
    storage.push(StorageEntry {
        key: Zeroizing::new(key.to_owned()),
        value: decode_storage_value(value),
    });
    Ok(())
}

fn decode_storage_value(value: &str) -> Zeroizing<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Zeroizing::new(String::new());
    }
    if let Ok(decoded) = serde_json::from_str::<String>(trimmed) {
        return Zeroizing::new(decoded.trim().to_owned());
    }
    Zeroizing::new(trimmed.trim_matches('"').trim().to_owned())
}

fn is_useful_storage_key(key: &str) -> bool {
    key.ends_with("auth1_session")
        || key.contains("auth0spajs@@::")
        || key.contains(EXTERNAL_ORG_PREFIX)
        || key.contains("post-auth-v")
        || key.contains("member-info-v")
        || key.contains("feature-flags-cache:org-")
        || key.contains("feature-flags-cache:org_")
}

fn session_from_storage(
    storage: &[StorageEntry],
    organization_override: Option<&str>,
) -> Option<DevinSession> {
    let token = access_token(storage)?;
    let (organization, internal_organization_id) =
        organization_info(storage, organization_override);
    Some(DevinSession {
        token,
        organization,
        internal_organization_id,
    })
}

fn access_token(storage: &[StorageEntry]) -> Option<Zeroizing<String>> {
    for entry in storage
        .iter()
        .filter(|entry| entry.key.ends_with("auth1_session"))
    {
        let Some(json) = ParsedStorageJson::parse(entry.value.as_str()) else {
            continue;
        };
        let Some(token) = json
            .value
            .as_object()
            .and_then(|object| object.get("token"))
            .and_then(Value::as_str)
            .map(str::trim)
        else {
            continue;
        };
        if token.starts_with("auth1_") && token.len() > 20 && validate_token(token).is_ok() {
            return Some(Zeroizing::new(token.to_owned()));
        }
    }
    for entry in storage
        .iter()
        .filter(|entry| entry.key.contains("auth0spajs@@::"))
    {
        if let Some(token) = access_token_from_json(entry.value.as_str()) {
            return Some(token);
        }
    }
    storage
        .iter()
        .find_map(|entry| access_token_from_json(entry.value.as_str()))
}

fn access_token_from_json(raw: &str) -> Option<Zeroizing<String>> {
    let json = ParsedStorageJson::parse(raw)?;
    let token = first_string(&json.value, &["access_token", "accessToken"])?;
    let token = token.trim();
    if token.len() > 20
        && (token.starts_with("eyJ") || token.contains('.'))
        && validate_token(token).is_ok()
    {
        Some(Zeroizing::new(token.to_owned()))
    } else {
        None
    }
}

struct ParsedStorageJson {
    value: Value,
}

impl ParsedStorageJson {
    fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() || raw.len() > MAX_STORAGE_ENTRY_BYTES {
            return None;
        }
        let parsed = Self {
            value: serde_json::from_str(raw).ok()?,
        };
        validate_json_tree(&parsed.value).ok()?;
        Some(parsed)
    }
}

impl Drop for ParsedStorageJson {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.value);
    }
}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        Value::Object(values) => {
            let old = std::mem::take(values);
            for (mut key, mut value) in old {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn organization_info(
    storage: &[StorageEntry],
    organization_override: Option<&str>,
) -> (Option<String>, Option<String>) {
    let normalized_override = organization_override.and_then(normalize_organization);
    let override_slug = normalized_override
        .as_deref()
        .and_then(|value| value.strip_prefix("org/"));
    let mut first_internal = None;
    for entry in storage
        .iter()
        .filter(|entry| entry.key.contains(EXTERNAL_ORG_PREFIX))
    {
        let Some((_, suffix)) = entry.key.split_once(EXTERNAL_ORG_PREFIX) else {
            continue;
        };
        let organization_id = cleaned_org_id(entry.value.as_str());
        if first_internal.is_none() {
            first_internal.clone_from(&organization_id);
        }
        if override_slug == Some(suffix) {
            return (normalized_override, organization_id);
        }
        if normalized_override.is_none() && suffix != "null" && valid_org_component(suffix) {
            return (Some(format!("org/{suffix}")), organization_id);
        }
    }
    if let Some(inferred) = inferred_organization_info(storage, normalized_override.as_deref()) {
        return inferred;
    }
    if let Some(organization) = normalized_override {
        let internal = first_internal.or_else(|| internal_org_id(&organization));
        return (Some(organization), internal);
    }
    (
        first_internal
            .as_ref()
            .map(|internal| format!("organizations/{internal}")),
        first_internal,
    )
}

fn inferred_organization_info(
    storage: &[StorageEntry],
    normalized_override: Option<&str>,
) -> Option<(Option<String>, Option<String>)> {
    let override_slug = normalized_override.and_then(|value| value.strip_prefix("org/"));
    let override_internal = normalized_override.and_then(internal_org_id);
    let mut fallback_slug = None;
    let mut fallback_internal = None;
    for entry in storage {
        let json = ParsedStorageJson::parse(entry.value.as_str());
        let internal = json
            .as_ref()
            .and_then(|json| {
                first_string(
                    &json.value,
                    &["internalOrgId", "internal_org_id", "org_id", "orgId"],
                )
            })
            .and_then(cleaned_org_id)
            .or_else(|| internal_org_id_from_storage_key(entry.key.as_str()));
        let slug = slug_from_post_auth_key(entry.key.as_str())
            .or_else(|| {
                json.as_ref().and_then(|json| {
                    first_string(
                        &json.value,
                        &["orgName", "org_name", "externalOrgId", "external_org_id"],
                    )
                })
            })
            .and_then(cleaned_slug);
        if override_internal.as_deref() == internal.as_deref() && override_internal.is_some() {
            return Some((normalized_override.map(str::to_owned), internal));
        }
        if override_slug == slug.as_deref() && override_slug.is_some() {
            return Some((normalized_override.map(str::to_owned), internal));
        }
        if fallback_slug.is_none() {
            fallback_slug = slug;
        }
        if fallback_internal.is_none() {
            fallback_internal = internal;
        }
    }
    if let Some(override_value) = normalized_override
        && fallback_internal.is_some()
    {
        return Some((Some(override_value.to_owned()), fallback_internal));
    }
    if let Some(slug) = fallback_slug {
        return Some((Some(format!("org/{slug}")), fallback_internal));
    }
    fallback_internal.map(|internal| (Some(format!("organizations/{internal}")), Some(internal)))
}

fn first_string<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if names.contains(&key.as_str())
                    && let Some(value) = value.as_str().filter(|value| !value.is_empty())
                {
                    return Some(value);
                }
                if let Some(value) = first_string(value, names) {
                    return Some(value);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(|value| first_string(value, names)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

fn cleaned_org_id(raw: &str) -> Option<String> {
    let decoded = decode_storage_value(raw);
    is_internal_org_id(decoded.as_str()).then(|| decoded.to_string())
}

fn cleaned_slug(raw: &str) -> Option<String> {
    let decoded = decode_storage_value(raw);
    let value = decoded.trim_matches('/').trim();
    let value = value.strip_prefix("org/").unwrap_or(value);
    (value != "null" && !is_internal_org_id(value) && valid_org_component(value))
        .then(|| value.to_owned())
}

fn slug_from_post_auth_key(key: &str) -> Option<&str> {
    key.split_once("-org_name-").map(|(_, slug)| slug)
}

fn internal_org_id_from_storage_key(key: &str) -> Option<String> {
    let bytes = key.as_bytes();
    for index in 0..bytes.len().saturating_sub(3) {
        if &bytes[index..index + 4] != b"org-" && &bytes[index..index + 4] != b"org_" {
            continue;
        }
        let mut end = index + 4;
        while bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
            end += 1;
        }
        if end >= index + 12 {
            let candidate = std::str::from_utf8(&bytes[index..end]).ok()?;
            if is_internal_org_id(candidate) {
                return Some(candidate.to_owned());
            }
        }
    }
    None
}

fn rank_and_deduplicate_sessions(sessions: Vec<DevinSession>) -> Vec<DevinSession> {
    let mut deduplicated: Vec<DevinSession> = Vec::new();
    for session in sessions {
        if let Some(index) = deduplicated
            .iter()
            .position(|existing| existing.token.as_str() == session.token.as_str())
        {
            if session.organization_score() > deduplicated[index].organization_score() {
                deduplicated[index] = session;
            }
        } else {
            deduplicated.push(session);
        }
    }
    deduplicated.sort_by_key(|session| Reverse(session.organization_score()));
    deduplicated
}

struct ParsedQuota {
    daily: Option<ParsedWindow>,
    weekly: Option<ParsedWindow>,
    plan: Option<String>,
    overage: Option<Decimal>,
}

#[derive(Clone, Copy)]
struct ParsedWindow {
    used_percent: f64,
    resets_at: Option<Timestamp>,
}

/// Parses one bounded Devin quota response into the normalized domain model.
///
/// # Errors
///
/// Returns stable scope, source, JSON-bound, field-bound, timestamp, or domain errors without
/// retaining response text.
pub fn parse_quota_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    organization: Option<&str>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Devin
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(api_error());
    }
    let root = parse_bounded_json(body)?;
    let parsed = parse_quota(&root)?;
    normalize_quota(scope, fetched_at, parsed, organization, source)
}

fn parse_quota(root: &Value) -> Result<ParsedQuota, ClassifiedError> {
    let current = root.as_object();
    let daily = current
        .and_then(|object| {
            current_window(object.get("daily_percentage"), object.get("daily_reset_at"))
        })
        .or_else(|| find_window(root, is_daily_key));
    let weekly = current
        .and_then(|object| {
            current_window(
                object.get("weekly_percentage"),
                object.get("weekly_reset_at"),
            )
        })
        .or_else(|| find_window(root, is_weekly_key));
    if daily.is_none() && weekly.is_none() {
        return Err(parse_error());
    }
    let plan = find_plan(root);
    let overage = current.and_then(find_overage);
    Ok(ParsedQuota {
        daily,
        weekly,
        plan,
        overage,
    })
}

fn current_window(percent: Option<&Value>, resets_at: Option<&Value>) -> Option<ParsedWindow> {
    let used_percent = number(percent?)?;
    Some(ParsedWindow {
        used_percent: if used_percent < 1.0 {
            used_percent * 100.0
        } else {
            used_percent
        },
        resets_at: resets_at.and_then(parse_timestamp),
    })
}

fn find_window(value: &Value, key_matches: fn(&str) -> bool) -> Option<ParsedWindow> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key_matches(key)
                    && let Some(window) = window_from(value)
                {
                    return Some(window);
                }
            }
            object
                .values()
                .find_map(|value| find_window(value, key_matches))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|value| find_window(value, key_matches)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

fn window_from(value: &Value) -> Option<ParsedWindow> {
    let Some(object) = value.as_object() else {
        return percent_from(value).map(|used_percent| ParsedWindow {
            used_percent,
            resets_at: None,
        });
    };
    if let Some(used_percent) = percent_from(value) {
        return Some(ParsedWindow {
            used_percent,
            resets_at: find_reset(object),
        });
    }
    object.values().find_map(window_from)
}

fn percent_from(value: &Value) -> Option<f64> {
    if let Some(value) = number(value) {
        return Some(if value <= 1.0 { value * 100.0 } else { value });
    }
    let object = value.as_object()?;
    for key in [
        "used_percent",
        "usedPercent",
        "usage_percent",
        "usagePercent",
        "percent_used",
        "percentUsed",
        "percent",
    ] {
        if let Some(value) = object.get(key).and_then(number) {
            return Some(if value <= 1.0 { value * 100.0 } else { value });
        }
    }
    for key in [
        "remaining_percent",
        "remainingPercent",
        "percent_remaining",
        "percentRemaining",
    ] {
        if let Some(value) = object.get(key).and_then(number) {
            let remaining = if value <= 1.0 { value * 100.0 } else { value };
            return Some(100.0 - remaining);
        }
    }
    let used = first_number(
        object,
        &["used", "usage", "used_count", "usedCount", "consumed"],
    );
    let limit = first_number(object, &["limit", "quota", "total", "max", "available"]);
    if let (Some(used), Some(limit)) = (used, limit)
        && limit > 0.0
    {
        return Some(used / limit * 100.0);
    }
    let remaining = first_number(object, &["remaining", "left", "available"]);
    match (remaining, limit) {
        (Some(remaining), Some(limit)) if limit > 0.0 => Some((limit - remaining) / limit * 100.0),
        _ => None,
    }
}

fn first_number(object: &Map<String, Value>, names: &[&str]) -> Option<f64> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(number))
}

fn number(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.trim().parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }?;
    number.is_finite().then_some(number)
}

fn find_plan(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) => {
            for key in [
                "plan_name",
                "planName",
                "plan",
                "tier",
                "subscription_tier",
                "subscriptionTier",
            ] {
                if let Some(plan) = object
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(clean_display)
                {
                    return Some(plan);
                }
            }
            object.values().find_map(find_plan)
        }
        Value::Array(values) => values.iter().find_map(find_plan),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

fn clean_display(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 256 || raw.chars().any(char::is_control) {
        return None;
    }
    let words = raw
        .split(['_', '-'])
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut characters = word.chars();
            let first = characters.next()?;
            Some(format!("{}{}", first.to_uppercase(), characters.as_str()))
        })
        .collect::<Option<Vec<_>>>()?;
    (!words.is_empty()).then(|| words.join(" "))
}

fn find_reset(object: &Map<String, Value>) -> Option<Timestamp> {
    object.iter().find_map(|(key, value)| {
        key.to_ascii_lowercase()
            .contains("reset")
            .then(|| parse_timestamp(value))
            .flatten()
    })
}

fn parse_timestamp(value: &Value) -> Option<Timestamp> {
    if let Some(raw) = value.as_str()
        && let Ok(timestamp) = OffsetDateTime::parse(raw, &Rfc3339)
    {
        return Timestamp::new(timestamp).ok();
    }
    let mut seconds = decimal_number(value)?;
    if seconds <= Decimal::ZERO {
        return None;
    }
    if seconds > Decimal::from(10_000_000_000_u64) {
        seconds = seconds.checked_div(Decimal::from(1_000_u16))?;
    }
    let nanos = seconds
        .checked_mul(Decimal::from(1_000_000_000_u64))?
        .trunc()
        .to_i128()?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|timestamp| Timestamp::new(timestamp).ok())
}

fn find_overage(object: &Map<String, Value>) -> Option<Decimal> {
    object
        .get("overage_balance")
        .and_then(nonnegative_decimal)
        .or_else(|| {
            object
                .get("overage_balance_cents")
                .and_then(nonnegative_decimal)
                .and_then(|value| value.checked_div(Decimal::from(100_u8)))
        })
}

fn nonnegative_decimal(value: &Value) -> Option<Decimal> {
    let value = decimal_number(value)?;
    (value >= Decimal::ZERO && value <= Decimal::from(MAX_OVERAGE_MAGNITUDE)).then_some(value)
}

fn decimal_number(value: &Value) -> Option<Decimal> {
    match value {
        Value::Number(number) => Decimal::from_str(&number.to_string()).ok(),
        Value::String(string) => Decimal::from_str(string.trim()).ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

fn is_daily_key(raw: &str) -> bool {
    let key = raw.to_ascii_lowercase();
    !key.contains("hide") && (key.contains("daily") || key.contains("day"))
}

fn is_weekly_key(raw: &str) -> bool {
    let key = raw.to_ascii_lowercase();
    !key.contains("hide") && (key.contains("weekly") || key.contains("week"))
}

fn normalize_quota(
    scope: AccountScope,
    fetched_at: Timestamp,
    parsed: ParsedQuota,
    organization: Option<&str>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    let organization = organization
        .and_then(normalize_organization)
        .and_then(|value| {
            value
                .strip_prefix("org/")
                .or_else(|| value.strip_prefix("organizations/"))
                .map(str::to_owned)
        });
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .organization(organization)?
        .login_method(parsed.plan)?
        .provenance(
            "devin",
            if source == ProviderSource::ManualCookie {
                "manual_bearer"
            } else {
                "browser_local_storage"
            },
        )?;
    if let Some(daily) = parsed.daily {
        builder = builder.primary(normalize_window(daily, 86_400, "Daily")?);
    }
    if let Some(weekly) = parsed.weekly {
        builder = builder.secondary(normalize_window(weekly, 604_800, "Weekly")?);
    }
    if let Some(overage) = parsed.overage {
        let currency = CurrencyCode::new("USD").map_err(|_| api_error())?;
        let cost = CostSummary::new(
            CostAmount::money(ExactDecimal::new(overage), currency),
            ExactDecimal::new(Decimal::ZERO),
            Some("Extra usage balance".to_owned()),
            None,
            None,
            None,
            None,
            fetched_at,
            None,
            None,
            CostProvenance::VendorMetered,
        )
        .map_err(|_| parse_error())?;
        builder = builder.cost(cost);
    }
    builder.build()
}

fn normalize_window(
    window: ParsedWindow,
    duration_seconds: u64,
    description: &'static str,
) -> Result<RateWindow, ClassifiedError> {
    let percent =
        UsagePercent::new(window.used_percent.clamp(0.0, 100.0)).map_err(|_| parse_error())?;
    let duration = WindowDuration::from_seconds(duration_seconds).map_err(|_| parse_error())?;
    let description = BoundedText::new(description).map_err(|_| api_error())?;
    RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        window.resets_at,
        Some(description),
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn parse_bounded_json(body: &[u8]) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let root = serde_json::from_slice(body).map_err(|_| parse_error())?;
    validate_json_tree(&root)?;
    Ok(root)
}

fn validate_json_tree(root: &Value) -> Result<(), ClassifiedError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    let mut string_bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(parse_error)?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(parse_error());
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().rev().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                for key in values.keys() {
                    add_json_string_bytes(&mut string_bytes, key.len())?;
                }
                stack.extend(values.values().rev().map(|value| (value, depth + 1)));
            }
            Value::String(value) => add_json_string_bytes(&mut string_bytes, value.len())?,
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn add_json_string_bytes(total: &mut usize, length: usize) -> Result<(), ClassifiedError> {
    if length > MAX_JSON_STRING_BYTES {
        return Err(parse_error());
    }
    *total = total
        .checked_add(length)
        .filter(|total| *total <= MAX_JSON_STRING_AGGREGATE_BYTES)
        .ok_or_else(parse_error)?;
    Ok(())
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
