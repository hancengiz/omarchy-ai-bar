//! T3 Chat browser-session usage adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::{OffsetDateTime, UtcOffset};
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
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig,
};

const PRODUCTION_ORIGIN: &str = "https://t3.chat";
const CUSTOMER_DATA_PATH: &str = "/api/trpc/getCustomerData";
const CUSTOMER_DATA_INPUT: &str =
    r#"{"0":{"json":{"sessionId":null},"meta":{"values":{"sessionId":["undefined"]}}}}"#;
const DEFAULT_REFERER: &str = "https://t3.chat/settings/customization";
const DEFAULT_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSONL_LINES: usize = 256;
const MAX_JSONL_LINE_BYTES: usize = 512 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 32;
const MAX_FORWARDED_VALUE_BYTES: usize = 8 * 1024;

const FORWARDED_HEADERS: [&str; 15] = [
    "accept",
    "accept-language",
    "cache-control",
    "pragma",
    "priority",
    "referer",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "trpc-accept",
    "user-agent",
    "x-client-context",
    "x-deployment-id",
    "x-trpc-batch",
    "x-trpc-source",
];

const DEFAULT_HEADERS: [(&str, &str); 12] = [
    ("trpc-accept", "application/jsonl"),
    ("x-trpc-source", "web-client"),
    ("x-trpc-batch", "true"),
    ("accept-language", "en-US,en;q=0.9"),
    ("user-agent", DEFAULT_USER_AGENT),
    ("referer", DEFAULT_REFERER),
    ("sec-fetch-dest", "empty"),
    ("sec-fetch-mode", "cors"),
    ("sec-fetch-site", "same-origin"),
    ("priority", "u=4"),
    ("pragma", "no-cache"),
    ("cache-control", "no-cache"),
];

/// Native T3 Chat adapter bound to one credential source and account scope.
pub struct T3ChatProvider {
    scope: AccountScope,
    source: ProviderSource,
    endpoint: Url,
    cookie: Zeroizing<String>,
    accept: RequestAccept,
    forwarded_headers: BTreeMap<String, Zeroizing<String>>,
    transport: HttpTransport,
}

impl T3ChatProvider {
    /// Creates the production manual-cookie adapter.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or API error for an invalid
    /// capture or fixed configuration.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_manual_capture_at(scope, raw, origin, EndpointClass::PublicHttps)
    }

    /// Creates a manual-cookie adapter at an explicit exact-origin seam.
    ///
    /// The pasted cURL URL, when present, must still target exact `t3.chat`.
    /// The supplied origin is used only for isolated transport tests; its path
    /// and query are replaced by the fixed T3 request shape.
    ///
    /// # Errors
    ///
    /// Returns a stable error for malformed capture data, unsupported captured
    /// `Accept`, another provider scope, or invalid endpoint authority.
    pub fn from_manual_capture_at(
        scope: AccountScope,
        raw: &str,
        origin: Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(["t3.chat"], [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query()
            .with_forwarded_headers(FORWARDED_HEADERS)
            .map_err(classify_capture_error)?;
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let mut forwarded_headers = BTreeMap::new();
        let mut accept = RequestAccept::Any;
        for (name, value) in capture.forwarded_headers() {
            if name == "accept" {
                accept = captured_accept(value)?;
            } else {
                if value.len() > MAX_FORWARDED_VALUE_BYTES {
                    return Err(ClassifiedError::new(ErrorKind::Api));
                }
                forwarded_headers.insert(name.to_owned(), Zeroizing::new(value.to_owned()));
            }
        }
        let endpoint = customer_data_url(origin)?;
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            endpoint,
            endpoint_class,
            cookie,
            accept,
            forwarded_headers,
        )
    }

    /// Creates a production browser-session adapter from an already imported
    /// cookie jar at the injected instant.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or authentication-expired error if
    /// no applicable cookie exists, or an API error for invalid configuration.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let endpoint = customer_data_url(origin)?;
        let target = ValidatedCookieUrl::new(endpoint, CookieUrlPolicy::HttpsOnly)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_browser_jar_at(scope, jar, &target, now, EndpointClass::PublicHttps)
    }

    /// Creates a browser-session adapter from an explicit validated target and
    /// cookie jar at the injected instant.
    ///
    /// This constructor performs no discovery or filesystem access. The target
    /// must already have the exact fixed T3 path and query shape.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, or API errors without cookie text.
    pub fn from_browser_jar_at(
        scope: AccountScope,
        jar: &CookieJar,
        target: &ValidatedCookieUrl,
        now: OffsetDateTime,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        validate_customer_data_url(target.url())?;
        let cookie = jar
            .header_for(target, now)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let Some(cookie) = cookie else {
            let kind = if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            };
            return Err(ClassifiedError::new(kind));
        };
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            target.url().clone(),
            endpoint_class,
            cookie.expose(),
            RequestAccept::Any,
            BTreeMap::new(),
        )
    }

    /// Builds the exact validated cookie target for an injected origin.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for an invalid origin or cookie URL policy.
    pub fn browser_target(
        origin: Url,
        policy: CookieUrlPolicy,
    ) -> Result<ValidatedCookieUrl, ClassifiedError> {
        let endpoint = customer_data_url(origin)?;
        ValidatedCookieUrl::new(endpoint, policy).map_err(|_| ClassifiedError::new(ErrorKind::Api))
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        endpoint: Url,
        endpoint_class: EndpointClass,
        cookie: &str,
        accept: RequestAccept,
        forwarded_headers: BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::T3Chat
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_customer_data_url(&endpoint)?;
        match endpoint_class {
            EndpointClass::PublicHttps
                if endpoint.scheme() == "https"
                    && endpoint
                        .host_str()
                        .is_some_and(|host| host.eq_ignore_ascii_case("t3.chat"))
                    && endpoint.port_or_known_default() == Some(443) => {}
            EndpointClass::LoopbackDevelopment => {}
            EndpointClass::PublicHttps
            | EndpointClass::PrivateHttps
            | EndpointClass::PrivateHttp => {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
        }
        let origin = endpoint.origin().ascii_serialization();
        let endpoints = EndpointPolicy::new([(origin, endpoint_class)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        endpoints
            .validate(&endpoint)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Authentication::cookie(cookie.to_owned()).map_err(|error| error.classified())?;
        let transport = HttpTransport::new(endpoints, transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            endpoint,
            cookie: Zeroizing::new(cookie.to_owned()),
            accept,
            forwarded_headers,
            transport,
        })
    }

    /// Fetches and maps one deterministic sample timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable missing/expired/rate-limit/challenge/network/parse errors
    /// without response or credential text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let request = self.request()?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(|error| error.classified())?;
        match response.status() {
            200 => parse_json_lines(context.scope().clone(), fetched_at, response.body()),
            401 | 403 => Err(ClassifiedError::new(ErrorKind::AuthenticationExpired)),
            429 if response
                .header("x-vercel-mitigated")
                .is_some_and(|value| value.eq_ignore_ascii_case("challenge")) =>
            {
                Err(ClassifiedError::new(ErrorKind::PermissionDenied))
            }
            429 => Err(ClassifiedError::new(ErrorKind::RateLimited)),
            _ => Err(ClassifiedError::new(ErrorKind::Api)),
        }
    }

    fn request(&self) -> Result<HttpRequest, ClassifiedError> {
        let mut request = HttpRequest::get(self.endpoint.clone()).accept(self.accept);
        for (name, value) in DEFAULT_HEADERS {
            if !self.forwarded_headers.contains_key(name) {
                request = request
                    .public_header(name, value)
                    .map_err(|error| error.classified())?;
            }
        }
        for (name, value) in &self.forwarded_headers {
            request = request
                .sensitive_header(name, value.as_str().to_owned())
                .map_err(|error| error.classified())?;
        }
        request = request
            .public_header("origin", PRODUCTION_ORIGIN)
            .map_err(|error| error.classified())?
            .accepted_statuses(&[401, 403, 429])
            .map_err(|error| error.classified())?
            .response_headers(&["x-vercel-mitigated"])
            .map_err(|error| error.classified())?
            .authentication(
                Authentication::cookie(self.cookie.as_str().to_owned())
                    .map_err(|error| error.classified())?,
            );
        Ok(request)
    }
}

impl ProviderAdapter for T3ChatProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::T3Chat)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for T3ChatProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("T3ChatProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("endpoint", &"<redacted>")
            .field("cookie", &"<redacted>")
            .field("accept", &self.accept)
            .field("forwarded_header_count", &self.forwarded_headers.len())
            .field("transport", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomerData {
    sub_tier: Option<String>,
    subscription: Option<Subscription>,
    usage_band: Option<String>,
    usage_four_hour_percentage: Option<f64>,
    usage_month_percentage: Option<f64>,
    usage_four_hour_next_reset_at: Option<f64>,
    usage_period_percentage: Option<f64>,
    usage_window_next_reset_at: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    product_name: Option<String>,
    current_period_end: Option<f64>,
}

/// Parses a bounded T3 JSONL response and maps the baseline two usage lanes.
///
/// # Errors
///
/// Returns a stable parse error for invalid UTF-8, excessive lines/nodes/depth,
/// malformed customer data, or missing customer data.
pub fn parse_json_lines(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
) -> Result<UsageSample, ClassifiedError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let text = std::str::from_utf8(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    for (line_index, line) in text.lines().enumerate() {
        if line_index == MAX_JSONL_LINES || line.len() > MAX_JSONL_LINE_BYTES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
    }
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(root) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        validate_json_shape(&root)?;
        let Some(customer) = find_customer_data(&root)? else {
            continue;
        };
        let customer: CustomerData = serde_json::from_value(Value::Object(customer.clone()))
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        return normalize_customer(scope, fetched_at, &customer);
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn validate_json_shape(root: &Value) -> Result<(), ClassifiedError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().rev().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                stack.extend(values.values().rev().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn find_customer_data(root: &Value) -> Result<Option<&Map<String, Value>>, ClassifiedError> {
    let mut stack = vec![root];
    let mut nodes = 0_usize;
    while let Some(value) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        if nodes > MAX_JSON_NODES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        match value {
            Value::Object(values) => {
                if values.contains_key("usageFourHourPercentage")
                    || values.contains_key("usageMonthPercentage")
                    || (values.contains_key("subscription") && values.contains_key("usageBand"))
                {
                    return Ok(Some(values));
                }
                stack.extend(values.values().rev());
            }
            Value::Array(values) => stack.extend(values.iter().rev()),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(None)
}

fn normalize_customer(
    scope: AccountScope,
    fetched_at: Timestamp,
    customer: &CustomerData,
) -> Result<UsageSample, ClassifiedError> {
    let primary_percent = normalized_percent(customer.usage_four_hour_percentage)?;
    let secondary_percent = normalized_percent(
        customer
            .usage_month_percentage
            .or(customer.usage_period_percentage),
    )?;
    let primary_reset = provider_timestamp(customer.usage_four_hour_next_reset_at)?
        .or(provider_timestamp(customer.usage_window_next_reset_at)?);
    let secondary_reset = provider_timestamp(
        customer
            .subscription
            .as_ref()
            .and_then(|subscription| subscription.current_period_end),
    )?;
    let description = primary_description(customer.usage_band.as_deref())?;
    let primary = RateWindow::new(
        WindowUsage::known(primary_percent),
        Some(
            WindowDuration::from_provider_minutes(4 * 60)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        primary_reset,
        Some(description),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let secondary = RateWindow::new(
        WindowUsage::known(secondary_percent),
        None,
        secondary_reset,
        Some(BoundedText::new("Overage").map_err(|_| ClassifiedError::new(ErrorKind::Parse))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let plan_name = customer
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.product_name.as_deref())
        .or(customer.sub_tier.as_deref())
        .and_then(format_plan_name);
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .secondary(secondary)
        .login_method(plan_name)?
        .provenance("t3chat", "web")?
        .build()
}

fn normalized_percent(raw: Option<f64>) -> Result<UsagePercent, ClassifiedError> {
    let value = raw.unwrap_or(0.0);
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    UsagePercent::new(value.clamp(0.0, 100.0)).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn provider_timestamp(raw: Option<f64>) -> Result<Option<Timestamp>, ClassifiedError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if !raw.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if raw <= 0.0 {
        return Ok(None);
    }
    let seconds = if raw > 10_000_000_000.0 {
        raw / 1_000.0
    } else {
        raw
    };
    let whole_seconds = Decimal::from_f64(seconds)
        .and_then(|value| value.trunc().to_i64())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let timestamp = OffsetDateTime::from_unix_timestamp(whole_seconds)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        .to_offset(UtcOffset::UTC);
    Timestamp::new(timestamp)
        .map(Some)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn primary_description(usage_band: Option<&str>) -> Result<BoundedText<120>, ClassifiedError> {
    let usage_band = usage_band.map(str::trim).filter(|value| !value.is_empty());
    let description = usage_band.map_or_else(
        || "Base".to_owned(),
        |usage_band| format!("Base - {usage_band}"),
    );
    BoundedText::new(description).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_plan_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    Some(
        raw.split('-')
            .filter(|part| !part.is_empty())
            .map(|part| {
                let mut characters = part.chars();
                let Some(first) = characters.next() else {
                    return String::new();
                };
                first.to_uppercase().chain(characters).collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn customer_data_url(mut origin: Url) -> Result<Url, ClassifiedError> {
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.host_str().is_none()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    origin.set_path(CUSTOMER_DATA_PATH);
    origin.set_query(None);
    origin
        .query_pairs_mut()
        .append_pair("batch", "1")
        .append_pair("input", CUSTOMER_DATA_INPUT);
    validate_customer_data_url(&origin)?;
    Ok(origin)
}

fn validate_customer_data_url(url: &Url) -> Result<(), ClassifiedError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.path() != CUSTOMER_DATA_PATH
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let pairs = url.query_pairs().collect::<Vec<_>>();
    if pairs.len() != 2
        || pairs[0].0.as_ref() != "batch"
        || pairs[0].1.as_ref() != "1"
        || pairs[1].0.as_ref() != "input"
        || pairs[1].1.as_ref() != CUSTOMER_DATA_INPUT
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn captured_accept(value: &str) -> Result<RequestAccept, ClassifiedError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("*/*") {
        Ok(RequestAccept::Any)
    } else if value.eq_ignore_ascii_case("application/json") {
        Ok(RequestAccept::Json)
    } else if value.eq_ignore_ascii_case("text/html,application/xhtml+xml") {
        Ok(RequestAccept::Html)
    } else {
        Err(ClassifiedError::new(ErrorKind::Api))
    }
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
