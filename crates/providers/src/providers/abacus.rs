//! Abacus AI browser-session and manual-cookie usage adapter.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use serde_json::{Map, Value};
use time::{Date, Month, OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp, timestamp_from_unix};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpResponse, HttpTransport, RequestAccept, TransportConfig,
};

const PRODUCTION_ORIGIN: &str = "https://apps.abacus.ai";
const COMPUTE_POINTS_PATH: &str = "/api/_getOrganizationComputePoints";
const BILLING_INFO_PATH: &str = "/api/_getBillingInfo";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 16_384;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_JSON_KEY_BYTES: usize = 512;
const MAX_PLAN_BYTES: usize = 256;
const MAX_CREDIT_MAGNITUDE: f64 = 1_000_000_000_000_000.0;
const OPTIONAL_BILLING_BUDGET: Duration = Duration::from_secs(5);

const KNOWN_SESSION_COOKIE_NAMES: [&str; 5] = [
    "sessionid",
    "session_id",
    "session_token",
    "auth_token",
    "access_token",
];
const SESSION_COOKIE_SUBSTRINGS: [&str; 4] = ["session", "auth", "sid", "jwt"];
const EXCLUDED_COOKIE_PREFIXES: [&str; 5] = ["csrf", "_ga", "_gid", "tracking", "analytics"];

/// Fixed Abacus API routes, with a loopback-only injection seam for tests.
#[derive(Clone)]
pub struct AbacusRouteSet {
    compute_points: Url,
    billing_info: Url,
    endpoint_class: EndpointClass,
}

impl AbacusRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_origins(origin.clone(), origin, EndpointClass::PublicHttps)
    }

    /// Creates isolated loopback routes. Paths and queries on supplied URLs
    /// are replaced by the two fixed Abacus API paths.
    ///
    /// # Errors
    ///
    /// Returns an API error unless both origins are exact loopback origins.
    #[doc(hidden)]
    pub fn loopback(compute_origin: Url, billing_origin: Url) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            compute_origin,
            billing_origin,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        compute_origin: Url,
        billing_origin: Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let compute_points = fixed_url(compute_origin, COMPUTE_POINTS_PATH)?;
        let billing_info = fixed_url(billing_origin, BILLING_INFO_PATH)?;
        let routes = Self {
            compute_points,
            billing_info,
            endpoint_class,
        };
        routes.validate()?;
        Ok(routes)
    }

    fn validate(&self) -> Result<(), ClassifiedError> {
        validate_fixed_path(&self.compute_points, COMPUTE_POINTS_PATH)?;
        validate_fixed_path(&self.billing_info, BILLING_INFO_PATH)?;
        if self.endpoint_class == EndpointClass::PublicHttps {
            for endpoint in [&self.compute_points, &self.billing_info] {
                if endpoint.scheme() != "https"
                    || endpoint.port_or_known_default() != Some(443)
                    || !endpoint
                        .host_str()
                        .is_some_and(|host| host.eq_ignore_ascii_case("apps.abacus.ai"))
                {
                    return Err(ClassifiedError::new(ErrorKind::Api));
                }
            }
        } else if self.endpoint_class != EndpointClass::LoopbackDevelopment {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let policy = self.endpoint_policy()?;
        policy
            .validate(&self.compute_points)
            .and_then(|_| policy.validate(&self.billing_info))
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(())
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        let compute = self.compute_points.origin().ascii_serialization();
        let billing = self.billing_info.origin().ascii_serialization();
        let origins = if compute == billing {
            vec![(compute, self.endpoint_class)]
        } else {
            vec![
                (compute, self.endpoint_class),
                (billing, self.endpoint_class),
            ]
        };
        EndpointPolicy::new(origins).map_err(|_| ClassifiedError::new(ErrorKind::Api))
    }

    fn cookie_policy(&self) -> CookieUrlPolicy {
        match self.endpoint_class {
            EndpointClass::LoopbackDevelopment => CookieUrlPolicy::LoopbackHttp,
            EndpointClass::PublicHttps
            | EndpointClass::PrivateHttps
            | EndpointClass::PrivateHttp => CookieUrlPolicy::HttpsOnly,
        }
    }
}

impl Debug for AbacusRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AbacusRouteSet")
            .field("compute_points", &"<redacted>")
            .field("billing_info", &"<redacted>")
            .field("endpoint_class", &self.endpoint_class)
            .finish()
    }
}

/// Native Abacus adapter permanently bound to one credential source and account.
pub struct AbacusProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: AbacusRouteSet,
    compute_cookie: Zeroizing<String>,
    billing_cookie: Option<Zeroizing<String>>,
    transport: HttpTransport,
}

impl AbacusProvider {
    /// Creates the production adapter from a raw Cookie header or copied cURL.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential, parse, or configuration failures.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, AbacusRouteSet::production()?)
    }

    /// Creates a manual adapter with deterministic transport routes. A URL in
    /// the capture remains restricted to exact `apps.abacus.ai`.
    ///
    /// # Errors
    ///
    /// Returns a stable error for invalid scope, capture, or routes.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: AbacusRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(["apps.abacus.ai"], [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            routes,
            cookie,
            Some(cookie),
        )
    }

    /// Creates the production browser-session adapter from an imported jar at
    /// the injected instant.
    ///
    /// # Errors
    ///
    /// Returns stable missing/expired or configuration failures without
    /// exposing cookie data.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jar_routes(scope, jar, now, AbacusRouteSet::production()?)
    }

    /// Creates a browser adapter with deterministic routes. Cookie selection
    /// is performed independently for both exact request targets.
    ///
    /// # Errors
    ///
    /// Returns a stable error for invalid scope/routes or no usable session.
    #[doc(hidden)]
    pub fn from_browser_jar_routes(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        routes: AbacusRouteSet,
    ) -> Result<Self, ClassifiedError> {
        routes.validate()?;
        let compute_target =
            ValidatedCookieUrl::new(routes.compute_points.clone(), routes.cookie_policy())
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let billing_target =
            ValidatedCookieUrl::new(routes.billing_info.clone(), routes.cookie_policy())
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let compute_cookie = jar
            .header_for(&compute_target, now)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let billing_cookie = jar
            .header_for(&billing_target, now)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let has_session = compute_cookie
            .as_ref()
            .is_some_and(|header| contains_session_cookie(header.expose()))
            || billing_cookie
                .as_ref()
                .is_some_and(|header| contains_session_cookie(header.expose()));
        let Some(compute_cookie) = compute_cookie else {
            return Err(ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        };
        if !has_session {
            return Err(ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        }
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            routes,
            compute_cookie.expose(),
            billing_cookie
                .as_ref()
                .map(crate::cookie::CookieHeader::expose),
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: AbacusRouteSet,
        compute_cookie: &str,
        billing_cookie: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Abacus
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        routes.validate()?;
        Authentication::cookie(compute_cookie.to_owned()).map_err(|error| error.classified())?;
        if let Some(cookie) = billing_cookie {
            Authentication::cookie(cookie.to_owned()).map_err(|error| error.classified())?;
        }
        let transport = HttpTransport::new(routes.endpoint_policy()?, transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            routes,
            compute_cookie: Zeroizing::new(compute_cookie.to_owned()),
            billing_cookie: billing_cookie.map(|cookie| Zeroizing::new(cookie.to_owned())),
            transport,
        })
    }

    /// Fetches required compute points and bounded optional billing metadata.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let compute_request = self.compute_request()?;
        let compute = self
            .transport
            .send(&compute_request, context.cancellation());
        let billing = async {
            let Some(request) = self.billing_request()? else {
                return Ok::<_, ClassifiedError>(None);
            };
            Ok(tokio::time::timeout(
                OPTIONAL_BILLING_BUDGET,
                self.transport.send(&request, context.cancellation()),
            )
            .await
            .ok()
            .and_then(Result::ok))
        };
        let (compute, billing) = tokio::join!(compute, billing);
        let compute = compute.map_err(|error| error.classified())?;
        let billing = billing?;
        parse_responses(
            context.scope().clone(),
            fetched_at,
            &compute,
            billing.as_ref(),
            self.source,
        )
    }

    /// Fetches only the required compute-points response.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, or parse errors.
    #[doc(hidden)]
    pub async fn fetch_required_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let request = self.compute_request()?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(|error| error.classified())?;
        parse_responses(
            context.scope().clone(),
            fetched_at,
            &response,
            None,
            self.source,
        )
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(())
    }

    fn compute_request(&self) -> Result<HttpRequest, ClassifiedError> {
        json_request(
            self.routes.compute_points.clone(),
            false,
            self.compute_cookie.as_str(),
        )
    }

    fn billing_request(&self) -> Result<Option<HttpRequest>, ClassifiedError> {
        self.billing_cookie
            .as_ref()
            .map(|cookie| json_request(self.routes.billing_info.clone(), true, cookie.as_str()))
            .transpose()
    }
}

impl ProviderAdapter for AbacusProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Abacus)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for AbacusProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AbacusProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("compute_cookie", &"<redacted>")
            .field("has_billing_cookie", &self.billing_cookie.is_some())
            .field("transport", &"<redacted>")
            .finish()
    }
}

/// Parses required compute points and optional billing metadata into the
/// common usage model. Optional billing failures never discard valid credits.
///
/// # Errors
///
/// Returns a stable authentication or parse error for invalid required data.
pub fn parse_usage_responses(
    scope: AccountScope,
    fetched_at: Timestamp,
    compute_body: &[u8],
    billing_body: Option<&[u8]>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope_source(&scope, source)?;
    let compute = parse_envelope(compute_body, true)?;
    let billing = billing_body
        .and_then(|body| parse_envelope(body, false).ok())
        .unwrap_or_default();
    normalize_usage(scope, fetched_at, &compute, &billing, source)
}

fn parse_responses(
    scope: AccountScope,
    fetched_at: Timestamp,
    compute: &HttpResponse,
    billing: Option<&HttpResponse>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    match compute.status() {
        200 => {}
        401 | 403 => return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired)),
        _ => return Err(ClassifiedError::new(ErrorKind::Api)),
    }
    let billing_body = billing
        .filter(|response| response.status() == 200)
        .map(HttpResponse::body);
    parse_usage_responses(scope, fetched_at, compute.body(), billing_body, source)
}

fn parse_envelope(body: &[u8], required: bool) -> Result<Map<String, Value>, ClassifiedError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| parse_error())?;
    validate_json_shape(&root)?;
    let object = root.as_object().ok_or_else(parse_error)?;
    if object.get("success").and_then(Value::as_bool) != Some(true) {
        let error = object
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if required && looks_like_auth_error(error) {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        return Err(parse_error());
    }
    object
        .get("result")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(parse_error)
}

fn validate_json_shape(root: &Value) -> Result<(), ClassifiedError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
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
                if values.keys().any(|key| key.len() > MAX_JSON_KEY_BYTES) {
                    return Err(parse_error());
                }
                stack.extend(values.values().rev().map(|value| (value, depth + 1)));
            }
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                return Err(parse_error());
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    compute: &Map<String, Value>,
    billing: &Map<String, Value>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    let total = finite_credit(compute.get("totalComputePoints")).ok_or_else(parse_error)?;
    let left = finite_credit(compute.get("computePointsLeft")).ok_or_else(parse_error)?;
    let used = total - left;
    if !used.is_finite() || used.abs() > MAX_CREDIT_MAGNITUDE * 2.0 {
        return Err(parse_error());
    }
    let percent = if total > 0.0 {
        (used * 100.0 / total).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let percent = UsagePercent::new(percent).map_err(|_| parse_error())?;
    let (resets_at, duration) = if let Some((timestamp, seconds)) = billing
        .get("nextBillingDate")
        .and_then(Value::as_str)
        .and_then(parse_billing_date)
    {
        (
            Some(timestamp),
            WindowDuration::from_seconds(seconds).map_err(|_| parse_error())?,
        )
    } else {
        (None, fallback_duration()?)
    };
    let description = BoundedText::new(format!(
        "{} / {} credits",
        format_credits(used)?,
        format_credits(total)?
    ))
    .map_err(|_| parse_error())?;
    let primary = RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        resets_at,
        Some(description),
        None,
        false,
    )
    .map_err(|_| parse_error())?;
    let plan_name = billing
        .get("currentTier")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.len() > MAX_PLAN_BYTES {
                Err(parse_error())
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()?;
    let strategy = if source == ProviderSource::ManualCookie {
        "manual_cookie"
    } else {
        "browser_session"
    };
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .login_method(plan_name)?
        .provenance("abacus", strategy)?
        .build()
}

fn parse_billing_date(raw: &str) -> Option<(Timestamp, u64)> {
    if raw.len() > 128 {
        return None;
    }
    let parsed = OffsetDateTime::parse(raw, &Rfc3339).ok()?;
    let timestamp = timestamp_from_unix(parsed.unix_timestamp()).ok()?;
    let seconds = previous_month_seconds(parsed.date())?;
    Some((timestamp, seconds))
}

fn previous_month_seconds(date: Date) -> Option<u64> {
    let (year, month) = match date.month() {
        Month::January => (date.year() - 1, Month::December),
        month => (date.year(), month.previous()),
    };
    let day = date.day().min(days_in_month(year, month)?);
    let previous = Date::from_calendar_date(year, month, day).ok()?;
    let seconds = (date - previous).whole_seconds();
    u64::try_from(seconds).ok().filter(|seconds| *seconds > 0)
}

fn days_in_month(year: i32, month: Month) -> Option<u8> {
    let (next_year, next_month) = match month {
        Month::December => (year + 1, Month::January),
        month => (year, month.next()),
    };
    let first_next = Date::from_calendar_date(next_year, next_month, 1).ok()?;
    first_next.previous_day().map(Date::day)
}

fn fallback_duration() -> Result<WindowDuration, ClassifiedError> {
    WindowDuration::from_seconds(30 * 24 * 60 * 60).map_err(|_| parse_error())
}

fn finite_credit(value: Option<&Value>) -> Option<f64> {
    let value = value?.as_f64()?;
    (value.is_finite() && value.abs() <= MAX_CREDIT_MAGNITUDE).then_some(value)
}

fn format_credits(value: f64) -> Result<String, ClassifiedError> {
    if !value.is_finite() || value.abs() > MAX_CREDIT_MAGNITUDE * 2.0 {
        return Err(parse_error());
    }
    let value = if value == 0.0 { 0.0 } else { value };
    if value.abs() >= 1_000.0 {
        let rounded = format!("{value:.0}");
        return Ok(group_integer(&rounded));
    }
    let rendered = format!("{value:.1}");
    Ok(rendered
        .strip_suffix(".0")
        .map_or(rendered.clone(), str::to_owned))
}

fn group_integer(raw: &str) -> String {
    let (sign, digits) = raw
        .strip_prefix('-')
        .map_or(("", raw), |digits| ("-", digits));
    let mut grouped = String::with_capacity(raw.len() + raw.len() / 3);
    grouped.push_str(sign);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(character);
    }
    grouped
}

fn json_request(url: Url, post: bool, cookie: &str) -> Result<HttpRequest, ClassifiedError> {
    let request = if post {
        HttpRequest::post_json(url, b"{}".to_vec()).map_err(|error| error.classified())?
    } else {
        HttpRequest::get(url)
            .accept(RequestAccept::Json)
            .empty_json_content_type()
    };
    let authentication =
        Authentication::cookie(cookie.to_owned()).map_err(|error| error.classified())?;
    request
        .accepted_statuses(&[401, 403])
        .map_err(|error| error.classified())
        .map(|request| request.authentication(authentication))
}

fn fixed_url(mut origin: Url, path: &str) -> Result<Url, ClassifiedError> {
    if !origin.username().is_empty() || origin.password().is_some() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    origin.set_path(path);
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(origin)
}

fn validate_fixed_path(url: &Url, path: &str) -> Result<(), ClassifiedError> {
    if url.path() != path
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn contains_session_cookie(header: &str) -> bool {
    header.split(';').any(|part| {
        let Some((name, _)) = part.trim().split_once('=') else {
            return false;
        };
        let name = name.trim().to_ascii_lowercase();
        if EXCLUDED_COOKIE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            return false;
        }
        KNOWN_SESSION_COOKIE_NAMES.contains(&name.as_str())
            || SESSION_COOKIE_SUBSTRINGS
                .iter()
                .any(|needle| name.contains(needle))
    })
}

fn looks_like_auth_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    [
        "expired",
        "session",
        "login",
        "authenticate",
        "unauthorized",
        "unauthenticated",
        "forbidden",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

fn validate_scope_source(
    scope: &AccountScope,
    source: ProviderSource,
) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Abacus
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
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

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
