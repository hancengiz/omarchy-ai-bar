//! Native Manus credit-balance adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, TransportConfig, TransportError,
};

const API_ORIGIN: &str = "https://api.manus.im";
const MANUS_ORIGIN: &str = "https://manus.im";
const WWW_MANUS_ORIGIN: &str = "https://www.manus.im";
const CREDITS_PATH: &str = "/user.v1.UserService/GetAvailableCredits";
const SESSION_COOKIE_NAME: &str = "session_id";
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_COOKIE_HEADER_BYTES: usize = 64 * 1024;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_REFRESH_INTERVAL_BYTES: usize = 128;
const MAX_WINDOW_DESCRIPTION_BYTES: usize = 120;
const COCOA_REFERENCE_UNIX_SECONDS: f64 = 978_307_200.0;
const EXPECTED_CREDIT_KEYS: [&str; 8] = [
    "totalCredits",
    "freeCredits",
    "periodicCredits",
    "addonCredits",
    "refreshCredits",
    "maxRefreshCredits",
    "proMonthlyCredits",
    "eventCredits",
];
const ENVELOPE_KEYS: [&str; 4] = ["data", "result", "response", "availableCredits"];
const TOKEN_ENV_KEYS: [&str; 4] = [
    "MANUS_SESSION_TOKEN",
    "manus_session_token",
    "MANUS_SESSION_ID",
    "manus_session_id",
];
const COOKIE_ENV_KEYS: [&str; 2] = ["MANUS_COOKIE", "manus_cookie"];

struct Routes {
    credits: Url,
    cookie_targets: [Url; 2],
}

/// Fixed Manus API and browser-cookie routing.
///
/// Production construction pins the three baseline HTTPS origins. The
/// loopback constructor is a typed seam for isolated HTTP tests only.
pub struct ManusRouteSet {
    routes: Routes,
    class: EndpointClass,
}

impl ManusRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origins(
            Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            Url::parse(MANUS_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            Url::parse(WWW_MANUS_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates exact loopback API and browser-cookie routes for local tests.
    ///
    /// # Errors
    ///
    /// Rejects non-origin, credential-bearing, or non-loopback URLs.
    #[doc(hidden)]
    pub fn loopback(
        api_origin: Url,
        manus_origin: Url,
        www_manus_origin: Url,
    ) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            api_origin,
            manus_origin,
            www_manus_origin,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        api_origin: Url,
        manus_origin: Url,
        www_manus_origin: Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        for origin in [&api_origin, &manus_origin, &www_manus_origin] {
            validate_bare_origin(origin, class)?;
        }
        if class == EndpointClass::PublicHttps
            && (!same_origin(&api_origin, API_ORIGIN)?
                || !same_origin(&manus_origin, MANUS_ORIGIN)?
                || !same_origin(&www_manus_origin, WWW_MANUS_ORIGIN)?)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        if !matches!(
            class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            routes: Routes {
                credits: with_path(api_origin, CREDITS_PATH),
                cookie_targets: [manus_origin, www_manus_origin],
            },
            class,
        })
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        EndpointPolicy::new([(
            self.routes.credits.origin().ascii_serialization(),
            self.class,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
    }

    const fn cookie_policy(&self) -> CookieUrlPolicy {
        match self.class {
            EndpointClass::LoopbackDevelopment => CookieUrlPolicy::LoopbackHttp,
            EndpointClass::PublicHttps
            | EndpointClass::PrivateHttps
            | EndpointClass::PrivateHttp => CookieUrlPolicy::HttpsOnly,
        }
    }
}

impl Debug for ManusRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManusRouteSet")
            .field("routes", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

fn validate_bare_origin(url: &Url, class: EndpointClass) -> Result<(), ClassifiedError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    EndpointPolicy::new([(url.as_str(), class)])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    Ok(())
}

fn same_origin(actual: &Url, expected: &str) -> Result<bool, ClassifiedError> {
    let expected = Url::parse(expected).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    Ok(actual.origin() == expected.origin())
}

fn with_path(mut origin: Url, path: &str) -> Url {
    origin.set_path(path);
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

/// Manus adapter bound to one account and one explicit credential source.
pub struct ManusProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: ManusRouteSet,
    tokens: Vec<Zeroizing<String>>,
    transport: HttpTransport,
}

impl ManusProvider {
    /// Creates the production manual-session adapter from a bare token, Cookie
    /// header, or inert cURL capture.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or configuration failure.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, ManusRouteSet::production()?)
    }

    /// Creates a manual adapter with an injected fixed transport route.
    ///
    /// A captured cURL URL must still name an exact production Manus host;
    /// only the subsequently rebuilt API request uses the injected route.
    ///
    /// # Errors
    ///
    /// Returns stable redacted capture or configuration failures.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: ManusRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let token = parse_manual_token(raw)?;
        Self::build(scope, ProviderSource::ManualCookie, routes, vec![token])
    }

    /// Creates the production adapter from the pinned Manus environment
    /// aliases, preserving their case-sensitive precedence.
    ///
    /// Environment credentials remain manual-session credentials and are not
    /// written to any browser-session cache by this adapter.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration failure for a non-Manus scope.
    pub fn from_environment(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
    ) -> Result<Option<Self>, ClassifiedError> {
        Self::from_environment_routes(scope, environment, ManusRouteSet::production()?)
    }

    /// Creates an environment-backed adapter with an injected fixed route.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration failure for a non-Manus scope.
    #[doc(hidden)]
    pub fn from_environment_routes(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
        routes: ManusRouteSet,
    ) -> Result<Option<Self>, ClassifiedError> {
        if scope.provider() != ProviderId::Manus {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let token_value = first_present(environment, &TOKEN_ENV_KEYS)
            .and_then(clean_environment_value)
            .and_then(parse_setting_token);
        let token = token_value.or_else(|| {
            first_present(environment, &COOKIE_ENV_KEYS)
                .and_then(clean_environment_value)
                .and_then(parse_setting_token)
        });
        let Some(token) = token else {
            return Ok(None);
        };
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            routes,
            vec![Zeroizing::new(token)],
        )
        .map(Some)
    }

    /// Creates a production browser-session adapter from one injected jar.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, or configuration failures.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::new_browser_sessions(scope, &[jar], now)
    }

    /// Creates a production browser adapter from ordered, isolated profile
    /// jars. Active tokens are deduplicated while preserving profile order.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, or configuration failures.
    pub fn new_browser_sessions(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jars_routes(scope, jars, now, ManusRouteSet::production()?)
    }

    /// Creates a browser adapter with injected fixed routes.
    ///
    /// # Errors
    ///
    /// Returns a stable failure when no ordered jar supplies an active,
    /// host-matching `session_id` value.
    #[doc(hidden)]
    pub fn from_browser_jars_routes(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
        routes: ManusRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let tokens = browser_tokens(&routes, jars, now)?;
        Self::build(scope, ProviderSource::BrowserSession, routes, tokens)
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: ManusRouteSet,
        tokens: Vec<Zeroizing<String>>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Manus
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
            || tokens.is_empty()
            || tokens.iter().any(|token| !valid_token(token))
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let policy = routes.endpoint_policy()?;
        policy
            .validate(&routes.routes.credits)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            routes,
            tokens,
            transport,
        })
    }

    /// Source to which this adapter is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Fetches credits at an injected wall-clock instant.
    ///
    /// Browser-profile tokens are attempted in stable order only when the
    /// preceding token receives HTTP 401 or 403. All other failures stop the
    /// sequence immediately.
    ///
    /// # Errors
    ///
    /// Returns stable account, credential, network, status, or parse failures.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }

        for token in &self.tokens {
            match self.send_credits(context, token).await {
                Ok(body) => {
                    return parse_usage_response(
                        self.scope.clone(),
                        fetched_at,
                        &body,
                        self.source,
                    );
                }
                Err(TransportError::AuthenticationExpired | TransportError::PermissionDenied) => {}
                Err(error) => return Err(error.classified()),
            }
        }
        Err(ClassifiedError::new(ErrorKind::AuthenticationExpired))
    }

    async fn send_credits(
        &self,
        context: &ProviderContext,
        token: &str,
    ) -> Result<Vec<u8>, TransportError> {
        let request = HttpRequest::post_json(self.routes.routes.credits.clone(), b"{}".to_vec())?
            .public_header("origin", MANUS_ORIGIN)?
            .public_header("referer", "https://manus.im/")?
            .public_header("connect-protocol-version", "1")?
            .public_header("user-agent", USER_AGENT)?
            .authentication(Authentication::bearer(token.to_owned())?);
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await?;
        if response.status() != 200 {
            return Err(TransportError::Api {
                status: response.status(),
            });
        }
        Ok(response.body().to_vec())
    }
}

impl ProviderAdapter for ManusProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Manus)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for ManusProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManusProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("token_count", &self.tokens.len())
            .field("transport", &"<redacted>")
            .finish()
    }
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(10),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn parse_manual_token(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    if !trimmed.contains(['=', ';'])
        && !trimmed.chars().any(char::is_whitespace)
        && valid_token(trimmed)
    {
        return Ok(Zeroizing::new(trimmed.to_owned()));
    }

    let policy = ManualCapturePolicy::new(
        ["manus.im", "www.manus.im", "api.manus.im"],
        [CaptureHeader::Cookie],
    )
    .map_err(classify_capture_error)?
    .with_ignored_url_query();
    let capture = policy.parse(raw).map_err(|error| {
        if error == ManualCaptureError::MissingSecret {
            ClassifiedError::new(ErrorKind::Parse)
        } else {
            classify_capture_error(error)
        }
    })?;
    let cookie = capture
        .header(CaptureHeader::Cookie)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    cookie_token(cookie)
        .map(|token| Zeroizing::new(token.to_owned()))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn parse_setting_token(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if !raw.contains(['=', ';']) {
        return valid_token(raw).then(|| raw.to_owned());
    }
    cookie_token(raw).map(str::to_owned)
}

fn first_present<'a>(environment: &'a BTreeMap<String, String>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| environment.get(*name).map(String::as_str))
}

fn clean_environment_value(raw: &str) -> Option<&str> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = value[1..value.len() - 1].trim();
    }
    (!value.is_empty()).then_some(value)
}

fn browser_tokens(
    routes: &ManusRouteSet,
    jars: &[&CookieJar],
    now: OffsetDateTime,
) -> Result<Vec<Zeroizing<String>>, ClassifiedError> {
    if jars.len() > MAX_BROWSER_SESSIONS {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let any_records = jars.iter().any(|jar| !jar.is_empty());
    let mut tokens = Vec::<Zeroizing<String>>::new();
    for jar in jars {
        for url in &routes.routes.cookie_targets {
            let target = ValidatedCookieUrl::new(url.clone(), routes.cookie_policy())
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
            let header = jar
                .header_for(&target, now)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
            let Some(token) = header
                .as_ref()
                .and_then(|header| cookie_token(header.expose()))
            else {
                continue;
            };
            if !tokens.iter().any(|existing| existing.as_str() == token) {
                tokens.push(Zeroizing::new(token.to_owned()));
            }
        }
    }
    if tokens.is_empty() {
        return Err(ClassifiedError::new(if any_records {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::MissingCredential
        }));
    }
    Ok(tokens)
}

fn cookie_token(header: &str) -> Option<&str> {
    if header.len() > MAX_COOKIE_HEADER_BYTES || header.chars().any(char::is_control) {
        return None;
    }
    header.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        let value = value.trim();
        (name.trim().eq_ignore_ascii_case(SESSION_COOKIE_NAME) && valid_token(value))
            .then_some(value)
    })
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn classify_capture_error(error: ManualCaptureError) -> ClassifiedError {
    let kind = match error {
        ManualCaptureError::MissingSecret => ErrorKind::MissingCredential,
        ManualCaptureError::InputTooLarge
        | ManualCaptureError::InvalidPolicy
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
    };
    ClassifiedError::new(kind)
}

#[derive(Debug)]
struct Credits {
    total: f64,
    free: f64,
    periodic: f64,
    _addon: f64,
    refresh: f64,
    max_refresh: f64,
    pro_monthly: f64,
    _event: f64,
    next_refresh: Option<Timestamp>,
    refresh_interval: Option<String>,
}

/// Parses one required Manus credits response into the native usage model.
///
/// # Errors
///
/// Returns stable scope or bounded-parse failures without response text.
pub fn parse_usage_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Manus
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let root = parse_bounded_json(body)?;
    let root = root
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let credits = parse_credits(select_credits_object(root)?)?;
    normalize_credits(scope, fetched_at, &credits)
}

fn parse_bounded_json(body: &[u8]) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let root = serde_json::from_slice::<Value>(body)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let mut stack = vec![(&root, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        match value {
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            Value::Array(values) => {
                stack.extend(values.iter().rev().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.keys().any(|key| key.len() > MAX_JSON_STRING_BYTES) {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                stack.extend(values.values().rev().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(root)
}

fn select_credits_object(
    root: &Map<String, Value>,
) -> Result<&Map<String, Value>, ClassifiedError> {
    let envelope_is_decodable = ENVELOPE_KEYS.iter().all(|key| {
        root.get(*key)
            .is_none_or(|value| value.is_null() || value.is_object())
    });
    if envelope_is_decodable {
        for key in ENVELOPE_KEYS {
            if let Some(object) = root.get(key).and_then(Value::as_object) {
                return Ok(object);
            }
        }
    }
    if EXPECTED_CREDIT_KEYS
        .iter()
        .any(|key| root.contains_key(*key))
    {
        return Ok(root);
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn parse_credits(object: &Map<String, Value>) -> Result<Credits, ClassifiedError> {
    Ok(Credits {
        total: lossy_number(object.get("totalCredits"))?,
        free: lossy_number(object.get("freeCredits"))?,
        periodic: lossy_number(object.get("periodicCredits"))?,
        _addon: lossy_number(object.get("addonCredits"))?,
        refresh: lossy_number(object.get("refreshCredits"))?,
        max_refresh: lossy_number(object.get("maxRefreshCredits"))?,
        pro_monthly: lossy_number(object.get("proMonthlyCredits"))?,
        _event: lossy_number(object.get("eventCredits"))?,
        next_refresh: flexible_timestamp(object.get("nextRefreshTime")),
        refresh_interval: bounded_optional_interval(object.get("refreshInterval")),
    })
}

fn lossy_number(value: Option<&Value>) -> Result<f64, ClassifiedError> {
    let Some(value) = value else {
        return Ok(0.0);
    };
    let parsed = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(value) => value.trim().parse::<f64>().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => return Ok(0.0),
    };
    let Some(parsed) = parsed else {
        return Ok(0.0);
    };
    if !parsed.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(parsed)
}

fn flexible_timestamp(value: Option<&Value>) -> Option<Timestamp> {
    match value? {
        Value::Number(number) => {
            let unix = number.as_f64()? + COCOA_REFERENCE_UNIX_SECONDS;
            finite_seconds_timestamp(unix)
        }
        Value::String(value) if !value.is_empty() => OffsetDateTime::parse(value, &Rfc3339)
            .ok()
            .and_then(|date| Timestamp::from_unix_timestamp(date.unix_timestamp()).ok()),
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Array(_) | Value::Object(_) => {
            None
        }
    }
}

fn finite_seconds_timestamp(seconds: f64) -> Option<Timestamp> {
    if !seconds.is_finite() {
        return None;
    }
    Timestamp::from_unix_timestamp(seconds.trunc().to_i64()?).ok()
}

fn bounded_optional_interval(value: Option<&Value>) -> Option<String> {
    let value = value?.as_str()?;
    (value.len() <= MAX_REFRESH_INTERVAL_BYTES && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn normalize_credits(
    scope: AccountScope,
    fetched_at: Timestamp,
    credits: &Credits,
) -> Result<UsageSample, ClassifiedError> {
    let total = format_credit_count(credits.total)?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if credits.pro_monthly > 0.0 {
        let used = ((credits.pro_monthly - credits.periodic) / credits.pro_monthly * 100.0)
            .clamp(0.0, 100.0);
        let description = format!(
            "Total {total} • Free {}",
            format_credit_count(credits.free)?
        );
        builder = builder.primary(rate_window(used, None, description)?);
    }
    if credits.max_refresh > 0.0 {
        let used = ((credits.max_refresh - credits.refresh) / credits.max_refresh * 100.0)
            .clamp(0.0, 100.0);
        let refresh = format_credit_count(credits.refresh)?;
        let maximum = format_credit_count(credits.max_refresh)?;
        let fallback_description = format!("{refresh} / {maximum}");
        let description = credits.refresh_interval.as_deref().map_or_else(
            || fallback_description.clone(),
            |interval| {
                if interval.is_empty() {
                    return fallback_description.clone();
                }
                let candidate = format!("{}: {refresh} / {maximum}", title_case(interval));
                let bounded: Result<BoundedText<MAX_WINDOW_DESCRIPTION_BYTES>, _> =
                    BoundedText::new(candidate.clone());
                bounded.map_or(fallback_description.clone(), |_| candidate)
            },
        );
        builder = builder.secondary(rate_window(used, credits.next_refresh, description)?);
    }
    builder
        .login_method(Some(format!("Balance: {total} credits")))?
        .provenance("manus", "web")?
        .build()
}

fn rate_window(
    percent: f64,
    resets_at: Option<Timestamp>,
    description: String,
) -> Result<RateWindow, ClassifiedError> {
    let percent = UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let description =
        BoundedText::new(description).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(percent),
        None,
        resets_at,
        Some(description),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_credit_count(value: f64) -> Result<String, ClassifiedError> {
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let rounded = value.round();
    let raw = if rounded == 0.0 {
        "0".to_owned()
    } else {
        format!("{rounded:.0}")
    };
    let (sign, digits) = raw
        .strip_prefix('-')
        .map_or(("", raw.as_str()), |digits| ("-", digits));
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut grouped = String::with_capacity(raw.len() + raw.len() / 3);
    grouped.push_str(sign);
    for (index, byte) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    Ok(grouped)
}

fn title_case(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut starts_word = true;
    for character in value.chars() {
        if character.is_alphanumeric() {
            if starts_word {
                output.extend(character.to_uppercase());
            } else {
                output.extend(character.to_lowercase());
            }
            starts_word = false;
        } else {
            output.push(character);
            starts_word = true;
        }
    }
    output
}
