//! Native `LongCat` token-pack quota and expiring fuel-pack adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};
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
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig, TransportError,
};

const PRODUCTION_ORIGIN: &str = "https://longcat.chat";
const USER_CURRENT_PATH: &str = "/api/v1/user-current";
const TOKEN_PACKS_SUMMARY_PATH: &str = "/api/pay/quota/metering/token-packs/summary";
const TOKEN_USAGE_PATH: &str = "/api/lc-platform/v1/tokenUsage";
const PENDING_FUEL_PATH: &str = "/api/lc-platform/v1/pending-fuel-packages";
const USAGE_REFERER: &str = "https://longcat.chat/platform/usage";
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_ACCOUNT_NAME_BYTES: usize = 256;
const MAX_FUEL_PACKAGES: usize = 8_192;
const COOKIE_ENV_KEYS: [&str; 2] = ["LONGCAT_MANUAL_COOKIE", "longcat_manual_cookie"];

#[derive(Clone, Copy)]
enum Route {
    Account,
    Summary,
    LegacyUsage,
    Fuel,
}

struct Routes {
    account: Url,
    summary: Url,
    legacy_usage: Url,
    fuel: Url,
}

impl Routes {
    const fn get(&self, route: Route) -> &Url {
        match route {
            Route::Account => &self.account,
            Route::Summary => &self.summary,
            Route::LegacyUsage => &self.legacy_usage,
            Route::Fuel => &self.fuel,
        }
    }
}

/// Fixed `LongCat` console routing.
///
/// Production construction pins the baseline HTTPS origin. The loopback
/// constructor is a typed seam for deterministic local transport tests only.
pub struct LongCatRouteSet {
    routes: Routes,
    class: EndpointClass,
}

impl LongCatRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origin(
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| api_error())?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates exact loopback LongCat routes for local tests.
    ///
    /// # Errors
    ///
    /// Rejects non-origin, credential-bearing, or non-loopback URLs.
    #[doc(hidden)]
    pub fn loopback(origin: Url) -> Result<Self, ClassifiedError> {
        Self::from_origin(origin, EndpointClass::LoopbackDevelopment)
    }

    fn from_origin(origin: Url, class: EndpointClass) -> Result<Self, ClassifiedError> {
        validate_bare_origin(&origin, class)?;
        if class == EndpointClass::PublicHttps && !same_origin(&origin, PRODUCTION_ORIGIN)? {
            return Err(api_error());
        }
        if !matches!(
            class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) {
            return Err(api_error());
        }
        Ok(Self {
            routes: Routes {
                account: with_path(origin.clone(), USER_CURRENT_PATH),
                summary: with_path(origin.clone(), TOKEN_PACKS_SUMMARY_PATH),
                legacy_usage: with_path(origin.clone(), TOKEN_USAGE_PATH),
                fuel: with_path(origin, PENDING_FUEL_PATH),
            },
            class,
        })
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        EndpointPolicy::new([(
            self.routes.account.origin().ascii_serialization(),
            self.class,
        )])
        .map_err(|_| api_error())
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

impl Debug for LongCatRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LongCatRouteSet")
            .field("routes", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

struct SessionHeaders {
    account: Option<Zeroizing<String>>,
    summary: Option<Zeroizing<String>>,
    legacy_usage: Option<Zeroizing<String>>,
    fuel: Option<Zeroizing<String>>,
}

impl SessionHeaders {
    fn manual(header: &str) -> Self {
        Self {
            account: Some(Zeroizing::new(header.to_owned())),
            summary: Some(Zeroizing::new(header.to_owned())),
            legacy_usage: Some(Zeroizing::new(header.to_owned())),
            fuel: Some(Zeroizing::new(header.to_owned())),
        }
    }

    fn from_jar(
        routes: &LongCatRouteSet,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Ok(Self {
            account: browser_header(routes, jar, Route::Account, now)?,
            summary: browser_header(routes, jar, Route::Summary, now)?,
            legacy_usage: browser_header(routes, jar, Route::LegacyUsage, now)?,
            fuel: browser_header(routes, jar, Route::Fuel, now)?,
        })
    }

    fn get(&self, route: Route) -> Option<&str> {
        match route {
            Route::Account => self.account.as_ref().map(|value| value.as_str()),
            Route::Summary => self.summary.as_ref().map(|value| value.as_str()),
            Route::LegacyUsage => self.legacy_usage.as_ref().map(|value| value.as_str()),
            Route::Fuel => self.fuel.as_ref().map(|value| value.as_str()),
        }
    }

    fn is_empty(&self) -> bool {
        self.account.is_none()
            && self.summary.is_none()
            && self.legacy_usage.is_none()
            && self.fuel.is_none()
    }
}

impl Debug for SessionHeaders {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHeaders(<redacted>)")
    }
}

/// `LongCat` adapter permanently bound to one account and one credential source.
pub struct LongCatProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: LongCatRouteSet,
    sessions: Vec<SessionHeaders>,
    transport: HttpTransport,
}

impl LongCatProvider {
    /// Creates a production manual-session adapter from a Cookie header or
    /// inert copied cURL command.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential, parse, scope, or endpoint failures.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, LongCatRouteSet::production()?)
    }

    /// Creates a manual adapter with injected fixed transport routes.
    ///
    /// A captured URL must still target an exact LongCat production host; the
    /// injected route only replaces the network authority after validation.
    ///
    /// # Errors
    ///
    /// Returns stable redacted capture, scope, or configuration failures.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: LongCatRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(
            ["longcat.chat", "www.longcat.chat"],
            [CaptureHeader::Cookie],
        )
        .map_err(classify_capture_error)?
        .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Authentication::cookie(cookie.to_owned()).map_err(|_| parse_error())?;
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            routes,
            vec![SessionHeaders::manual(cookie)],
        )
    }

    /// Creates a production adapter from the pinned manual-cookie environment
    /// aliases without reading ambient process state.
    ///
    /// # Errors
    ///
    /// Returns a stable scope, capture, or configuration failure.
    pub fn from_environment(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
    ) -> Result<Option<Self>, ClassifiedError> {
        Self::from_environment_routes(scope, environment, LongCatRouteSet::production()?)
    }

    /// Creates an environment-backed adapter with injected fixed routes.
    ///
    /// # Errors
    ///
    /// Returns a stable scope, capture, or configuration failure.
    #[doc(hidden)]
    pub fn from_environment_routes(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
        routes: LongCatRouteSet,
    ) -> Result<Option<Self>, ClassifiedError> {
        if scope.provider() != ProviderId::LongCat {
            return Err(api_error());
        }
        let Some(raw) = first_environment_value(environment, &COOKIE_ENV_KEYS)
            .and_then(clean_environment_value)
        else {
            return Ok(None);
        };
        Self::from_manual_capture_routes(scope, &raw, routes).map(Some)
    }

    /// Creates a production browser-session adapter from one pre-imported jar.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, cookie, or configuration failures.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::new_browser_sessions(scope, &[jar], now)
    }

    /// Creates a production browser adapter from ordered, isolated profile
    /// jars. Profiles are attempted in caller-supplied Chrome/Firefox order.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, cookie, or configuration failures.
    pub fn new_browser_sessions(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jars_routes(scope, jars, now, LongCatRouteSet::production()?)
    }

    /// Creates a browser adapter with injected fixed transport routes.
    ///
    /// Each profile retains independent URL-scoped headers. No cookie from a
    /// later profile is merged into an earlier profile.
    ///
    /// # Errors
    ///
    /// Returns a stable failure for excessive sessions or no matching cookie.
    #[doc(hidden)]
    pub fn from_browser_jars_routes(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
        routes: LongCatRouteSet,
    ) -> Result<Self, ClassifiedError> {
        if jars.is_empty() || jars.len() > MAX_BROWSER_SESSIONS {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        let all_empty = jars.iter().all(|jar| jar.is_empty());
        let mut sessions = Vec::with_capacity(jars.len());
        for jar in jars {
            let session = SessionHeaders::from_jar(&routes, jar, now)?;
            if !session.is_empty() {
                sessions.push(session);
            }
        }
        if sessions.is_empty() {
            return Err(ClassifiedError::new(if all_empty {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        }
        Self::build(scope, ProviderSource::BrowserSession, routes, sessions)
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: LongCatRouteSet,
        sessions: Vec<SessionHeaders>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::LongCat
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
            || sessions.is_empty()
            || sessions.len() > MAX_BROWSER_SESSIONS
        {
            return Err(api_error());
        }
        let policy = routes.endpoint_policy()?;
        for route in [
            Route::Account,
            Route::Summary,
            Route::LegacyUsage,
            Route::Fuel,
        ] {
            policy
                .validate(routes.routes.get(route))
                .map_err(|_| api_error())?;
        }
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            routes,
            sessions,
            transport,
        })
    }

    /// Source to which this adapter is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Fetches `LongCat` quota at an injected wall-clock instant.
    ///
    /// Browser profiles advance only after a required credential failure. A
    /// token-pack summary or fuel-package failure remains best-effort and never
    /// erases a valid required account/legacy response.
    /// Credentialed POST redirects are rejected by the shared transport; a
    /// redirected optional summary therefore takes the canonical legacy path.
    ///
    /// # Errors
    ///
    /// Returns stable scope, credential, network, status, or parse failures.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }
        let mut last_credential_error = None;
        for session in &self.sessions {
            match self.fetch_session(context, fetched_at, session).await {
                Ok(sample) => return Ok(sample),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::MissingCredential | ErrorKind::AuthenticationExpired
                    ) =>
                {
                    last_credential_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_credential_error
            .unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }

    async fn fetch_session(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        session: &SessionHeaders,
    ) -> Result<UsageSample, ClassifiedError> {
        let account = self
            .request_object(context, session, Route::Account)
            .await?;

        let summary = self
            .request_object(context, session, Route::Summary)
            .await
            .ok();

        let legacy_usage = if active_token_lot(summary.as_ref()).is_some() {
            None
        } else {
            let usage = self
                .request_object(context, session, Route::LegacyUsage)
                .await?;
            validate_legacy_usage(&usage)?;
            Some(usage)
        };

        let fuel = self
            .request_object(context, session, Route::Fuel)
            .await
            .ok();

        normalize_payloads(
            self.scope.clone(),
            fetched_at,
            self.source,
            &account,
            summary.as_ref(),
            legacy_usage.as_ref(),
            fuel.as_ref(),
        )
    }

    async fn request_object(
        &self,
        context: &ProviderContext,
        session: &SessionHeaders,
        route: Route,
    ) -> Result<Map<String, Value>, ClassifiedError> {
        let cookie = session
            .get(route)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let request = request(self.routes.routes.get(route).clone(), route, cookie)?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(classify_transport)?;
        if response.status() != 200 {
            return Err(api_error());
        }
        let root = parse_bounded_json(response.body())?;
        envelope_object(&root)
    }
}

impl ProviderAdapter for LongCatProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::LongCat)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for LongCatProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LongCatProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("session_count", &self.sessions.len())
            .field("transport", &"<redacted>")
            .finish()
    }
}

/// Parses captured LongCat envelope bodies through the production
/// normalization contract without performing network I/O.
///
/// `token_usage_body` is required only when `summary_body` has no active,
/// positive token lot. `fuel_body` is optional but, when supplied here, must be
/// valid; production fetches deliberately discard supplemental fuel failures.
///
/// # Errors
///
/// Returns stable scope, source, envelope, shape, or bounded parse failures.
#[doc(hidden)]
pub fn parse_usage_responses(
    scope: AccountScope,
    fetched_at: Timestamp,
    source: ProviderSource,
    account_body: &[u8],
    summary_body: Option<&[u8]>,
    token_usage_body: Option<&[u8]>,
    fuel_body: Option<&[u8]>,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope_source(&scope, source)?;
    let account_root = parse_bounded_json(account_body)?;
    let account = envelope_object(&account_root)?;
    let summary = summary_body
        .map(parse_bounded_json)
        .transpose()?
        .as_ref()
        .map(envelope_object)
        .transpose()?;
    let legacy_usage = if active_token_lot(summary.as_ref()).is_some() {
        None
    } else {
        let body = token_usage_body.ok_or_else(parse_error)?;
        let root = parse_bounded_json(body)?;
        let usage = envelope_object(&root)?;
        validate_legacy_usage(&usage)?;
        Some(usage)
    };
    let fuel = fuel_body
        .map(parse_bounded_json)
        .transpose()?
        .as_ref()
        .map(envelope_object)
        .transpose()?;
    normalize_payloads(
        scope,
        fetched_at,
        source,
        &account,
        summary.as_ref(),
        legacy_usage.as_ref(),
        fuel.as_ref(),
    )
}

struct Snapshot {
    total: Option<f64>,
    used: Option<f64>,
    remaining: Option<f64>,
    fuel_total: Option<f64>,
    fuel_remaining: Option<f64>,
    nearest_fuel_expiry: Option<Timestamp>,
    account_name: Option<String>,
}

fn normalize_payloads(
    scope: AccountScope,
    fetched_at: Timestamp,
    source: ProviderSource,
    account: &Map<String, Value>,
    summary: Option<&Map<String, Value>>,
    legacy_usage: Option<&Map<String, Value>>,
    fuel: Option<&Map<String, Value>>,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope_source(&scope, source)?;
    let account_name = string_value(account.get("name"))
        .or_else(|| string_value(account.get("nickName")))
        .filter(|value| value.len() <= MAX_ACCOUNT_NAME_BYTES);
    let mut snapshot = Snapshot {
        total: None,
        used: None,
        remaining: None,
        fuel_total: None,
        fuel_remaining: None,
        nearest_fuel_expiry: None,
        account_name,
    };

    if let Some(lot) = active_token_lot(summary) {
        let total = number_value(lot.get("totalToken")).ok_or_else(parse_error)?;
        let used = number_value(lot.get("consumedToken")).unwrap_or(0.0);
        snapshot.total = Some(total);
        snapshot.used = Some(used);
        snapshot.remaining = Some(total - used);
    } else if let Some(legacy_usage) = legacy_usage {
        let usage = legacy_usage
            .get("usage")
            .and_then(Value::as_object)
            .unwrap_or(legacy_usage);
        snapshot.total = number_value(usage.get("totalToken"));
        snapshot.used = number_value(usage.get("usedToken"));
        snapshot.remaining = number_value(usage.get("availableToken"));
    }

    if let Some(fuel) = fuel {
        apply_fuel(fuel, &mut snapshot)?;
    }
    snapshot_to_sample(scope, fetched_at, source, snapshot)
}

fn snapshot_to_sample(
    scope: AccountScope,
    fetched_at: Timestamp,
    source: ProviderSource,
    snapshot: Snapshot,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .organization(snapshot.account_name)?
        .provenance(
            "longcat",
            if source == ProviderSource::ManualCookie {
                "manual_cookie"
            } else {
                "browser_session"
            },
        )?;
    if let Some(total) = snapshot.total.filter(|value| *value > 0.0) {
        let used = snapshot
            .used
            .unwrap_or_else(|| snapshot.remaining.map_or(0.0, |value| total - value))
            .max(0.0);
        builder = builder.primary(quota_window(
            used,
            total,
            None,
            format!("{}/{}", truncated_integer(used)?, truncated_integer(total)?),
        )?);
    }
    if let Some(total) = snapshot.fuel_total.filter(|value| *value > 0.0) {
        let remaining = snapshot.fuel_remaining.unwrap_or(total);
        let used = (total - remaining).max(0.0);
        builder = builder.secondary(quota_window(
            used,
            total,
            snapshot.nearest_fuel_expiry,
            format!(
                "Fuel pack: {}/{}",
                truncated_integer(remaining)?,
                truncated_integer(total)?
            ),
        )?);
    }
    builder.build()
}

fn quota_window(
    used: f64,
    total: f64,
    resets_at: Option<Timestamp>,
    description: String,
) -> Result<RateWindow, ClassifiedError> {
    let percent = (used / total * 100.0).min(100.0);
    let percent = UsagePercent::new(percent).map_err(|_| parse_error())?;
    let description = BoundedText::new(description).map_err(|_| parse_error())?;
    RateWindow::new(
        WindowUsage::known(percent),
        None,
        resets_at,
        Some(description),
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn apply_fuel(fuel: &Map<String, Value>, snapshot: &mut Snapshot) -> Result<(), ClassifiedError> {
    let total = number_value(fuel.get("totalQuota"));
    let packages = fuel
        .get("list")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if packages.len() > MAX_FUEL_PACKAGES {
        return Err(parse_error());
    }
    let mut remaining = 0.0_f64;
    let mut saw_remaining = false;
    let mut nearest = None;
    for package in packages.iter().filter_map(Value::as_object) {
        if let Some(value) = number_value(package.get("availableToken")) {
            remaining += value;
            if !remaining.is_finite() {
                return Err(parse_error());
            }
            saw_remaining = true;
        }
        if let Some(expiry) = parse_timestamp(package.get("expireTime")) {
            nearest = Some(nearest.map_or(expiry, |current: Timestamp| current.min(expiry)));
        }
    }
    if let Some(total) = total.filter(|value| *value > 0.0) {
        snapshot.fuel_total = Some(total);
        snapshot.fuel_remaining = Some(if saw_remaining { remaining } else { total });
    }
    snapshot.nearest_fuel_expiry = nearest;
    Ok(())
}

fn active_token_lot(summary: Option<&Map<String, Value>>) -> Option<&Map<String, Value>> {
    let lot = summary?.get("currentLot")?.as_object()?;
    let status = string_value(lot.get("status"))?;
    let total = number_value(lot.get("totalToken"))?;
    (status.eq_ignore_ascii_case("ACTIVE") && total > 0.0).then_some(lot)
}

fn validate_legacy_usage(usage: &Map<String, Value>) -> Result<(), ClassifiedError> {
    let canonical = usage
        .get("usage")
        .and_then(Value::as_object)
        .unwrap_or(usage);
    number_value(canonical.get("totalToken"))
        .map(|_| ())
        .ok_or_else(parse_error)
}

fn envelope_object(root: &Value) -> Result<Map<String, Value>, ClassifiedError> {
    let object = root.as_object().ok_or_else(parse_error)?;
    if let Some(code) = integer_value(object.get("code"))
        && code != 0
        && code != 200
    {
        return Err(ClassifiedError::new(if matches!(code, 401 | 403) {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::Api
        }));
    }
    object
        .get("data")
        .unwrap_or(root)
        .as_object()
        .cloned()
        .ok_or_else(parse_error)
}

fn parse_bounded_json(body: &[u8]) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| parse_error())?;
    let mut stack = vec![(&root, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(parse_error)?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(parse_error());
        }
        match value {
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                return Err(parse_error());
            }
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.keys().any(|key| key.len() > MAX_JSON_STRING_BYTES) {
                    return Err(parse_error());
                }
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(root)
}

fn request(url: Url, route: Route, cookie: &str) -> Result<HttpRequest, ClassifiedError> {
    let request = if matches!(route, Route::Summary) {
        HttpRequest::post_json(url, b"{}".to_vec()).map_err(|_| api_error())?
    } else {
        HttpRequest::get(url)
    };
    request
        .accept(RequestAccept::JsonTextAny)
        .public_header("origin", PRODUCTION_ORIGIN)
        .map_err(|_| api_error())?
        .public_header("referer", USAGE_REFERER)
        .map_err(|_| api_error())?
        .public_header("accept-language", "en-US,en;q=0.9")
        .map_err(|_| api_error())?
        .public_header("user-agent", USER_AGENT)
        .map_err(|_| api_error())
        .and_then(|request| {
            Authentication::cookie(cookie.to_owned())
                .map(|authentication| request.authentication(authentication))
                .map_err(|_| parse_error())
        })
}

fn browser_header(
    routes: &LongCatRouteSet,
    jar: &CookieJar,
    route: Route,
    now: OffsetDateTime,
) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
    let target = ValidatedCookieUrl::new(routes.routes.get(route).clone(), routes.cookie_policy())
        .map_err(|_| api_error())?;
    jar.header_for(&target, now)
        .map_err(|_| parse_error())
        .map(|header| header.map(|header| Zeroizing::new(header.expose().to_owned())))
}

fn number_value(value: Option<&Value>) -> Option<f64> {
    let value = match value? {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse::<f64>().ok(),
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }?;
    value.is_finite().then_some(value)
}

fn integer_value(value: Option<&Value>) -> Option<i64> {
    number_value(value)?.trunc().to_i64()
}

fn string_value(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(if *value { "1" } else { "0" }.to_owned()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn parse_timestamp(value: Option<&Value>) -> Option<Timestamp> {
    if let Some(mut seconds) = number_value(value) {
        if seconds > 1_000_000_000_000.0 {
            seconds /= 1_000.0;
        }
        if seconds > 1_000_000_000.0 {
            let nanos = seconds * 1_000_000_000.0;
            if let Some(nanos) = nanos.trunc().to_i128() {
                let timestamp = OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
                return Timestamp::new(timestamp).ok();
            }
        }
    }
    let Value::String(value) = value? else {
        return None;
    };
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Timestamp::new(timestamp).ok();
    }
    let format = time::format_description::parse_borrowed::<3>(
        "[year]-[month]-[day] [hour]:[minute]:[second]",
    )
    .ok()?;
    PrimitiveDateTime::parse(value, &format)
        .ok()
        .and_then(local_wall_timestamp)
}

fn local_wall_timestamp(wall: PrimitiveDateTime) -> Option<Timestamp> {
    let mut offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    for _ in 0..4 {
        let candidate = wall.assume_offset(offset);
        let observed = UtcOffset::local_offset_at(candidate).unwrap_or(offset);
        if observed == offset {
            return Timestamp::new(candidate).ok();
        }
        offset = observed;
    }
    None
}

fn truncated_integer(value: f64) -> Result<i64, ClassifiedError> {
    value.trunc().to_i64().ok_or_else(parse_error)
}

fn first_environment_value<'a>(
    environment: &'a BTreeMap<String, String>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| environment.get(*key).map(String::as_str))
}

fn clean_environment_value(raw: &str) -> Option<String> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = &value[1..value.len() - 1];
    }
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn validate_scope_source(
    scope: &AccountScope,
    source: ProviderSource,
) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::LongCat
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(api_error());
    }
    Ok(())
}

fn validate_bare_origin(url: &Url, class: EndpointClass) -> Result<(), ClassifiedError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(api_error());
    }
    EndpointPolicy::new([(url.as_str(), class)])
        .map_err(|_| api_error())
        .map(|_| ())
}

fn same_origin(url: &Url, expected: &str) -> Result<bool, ClassifiedError> {
    let expected = Url::parse(expected).map_err(|_| api_error())?;
    Ok(url.origin() == expected.origin())
}

fn with_path(mut origin: Url, path: &str) -> Url {
    origin.set_path(path);
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

fn classify_capture_error(error: ManualCaptureError) -> ClassifiedError {
    let kind = match error {
        ManualCaptureError::MissingSecret
        | ManualCaptureError::InvalidSecret
        | ManualCaptureError::DisallowedHeader => ErrorKind::MissingCredential,
        ManualCaptureError::InputTooLarge
        | ManualCaptureError::InvalidSyntax
        | ManualCaptureError::UnsafeSyntax
        | ManualCaptureError::UnsafeOption
        | ManualCaptureError::TooManyTokens
        | ManualCaptureError::TooManyHeaders
        | ManualCaptureError::DuplicateSecret
        | ManualCaptureError::ConflictingHeader
        | ManualCaptureError::DisallowedUrl => ErrorKind::Parse,
        ManualCaptureError::InvalidPolicy => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn classify_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired
        | TransportError::PermissionDenied
        | TransportError::Endpoint(_)
        | TransportError::TooManyRedirects => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        TransportError::RequestTimeout
        | TransportError::RateLimited { .. }
        | TransportError::ProviderUnavailable { .. }
        | TransportError::Api { .. } => api_error(),
        other => other.classified(),
    }
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(10),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        10,
        RetryPolicy::none(),
    )
    .map_err(|_| api_error())
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}
