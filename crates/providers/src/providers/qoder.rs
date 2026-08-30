//! Qoder big-model-credit usage from an explicitly supplied web session.

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use futures_util::StreamExt;
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use reqwest::header::{ACCEPT, ACCEPT_LANGUAGE, COOKIE, HeaderValue, ORIGIN, REFERER, USER_AGENT};
use reqwest::{Client, StatusCode};
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;

const INTERNATIONAL_ORIGIN: &str = "https://qoder.com";
const CHINA_ORIGIN: &str = "https://qoder.com.cn";
const USAGE_PATH: &str = "/api/v2/me/usages/big_model_credits";
const ACCEPT_VALUE: &str = "application/json, text/plain, */*";
const ACCEPT_LANGUAGE_VALUE: &str = "en-US,en;q=0.9";
const USER_AGENT_VALUE: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_CAPTURE_TOKENS: usize = 256;
const MAX_CAPTURE_TOKEN_BYTES: usize = 32 * 1024;
const MAX_CAPTURE_LINES: usize = 256;
const MAX_COOKIE_HEADER_BYTES: usize = 64 * 1024;
const MAX_COOKIE_PAIRS: usize = 512;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_UNIT_BYTES: usize = 128;
const MAX_QUOTA_MAGNITUDE: f64 = 1_000_000_000_000_000.0;

/// One of Qoder's two pinned first-party web properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QoderSite {
    /// The international `qoder.com` property.
    International,
    /// The mainland-China `qoder.com.cn` property.
    China,
}

impl QoderSite {
    const ALL: [Self; 2] = [Self::International, Self::China];

    const fn origin(self) -> &'static str {
        match self {
            Self::International => INTERNATIONAL_ORIGIN,
            Self::China => CHINA_ORIGIN,
        }
    }
}

/// Exact network routes for the two Qoder properties.
///
/// Production constructors use the fixed HTTPS origins. The loopback seam
/// changes only network authorities; cookie selection and browser metadata
/// remain bound to the real Qoder hosts.
pub struct QoderRouteSet {
    international: Url,
    china: Url,
    endpoint_class: EndpointClass,
}

impl QoderRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Ok(Self {
            international: production_endpoint(QoderSite::International)?,
            china: production_endpoint(QoderSite::China)?,
            endpoint_class: EndpointClass::PublicHttps,
        })
    }

    /// Creates exact loopback endpoints for deterministic transport tests.
    ///
    /// # Errors
    ///
    /// Returns a stable API error unless both values are bare loopback origins.
    #[doc(hidden)]
    pub fn loopback(international: Url, china: Url) -> Result<Self, ClassifiedError> {
        let international =
            endpoint_from_origin(international, EndpointClass::LoopbackDevelopment)?;
        let china = endpoint_from_origin(china, EndpointClass::LoopbackDevelopment)?;
        Ok(Self {
            international,
            china,
            endpoint_class: EndpointClass::LoopbackDevelopment,
        })
    }

    fn endpoint(&self, site: QoderSite) -> &Url {
        match site {
            QoderSite::International => &self.international,
            QoderSite::China => &self.china,
        }
    }

    fn cookie_target(site: QoderSite, www: bool) -> Result<ValidatedCookieUrl, ClassifiedError> {
        let mut endpoint = production_endpoint(site)?;
        if www {
            endpoint
                .set_host(Some(match site {
                    QoderSite::International => "www.qoder.com",
                    QoderSite::China => "www.qoder.com.cn",
                }))
                .map_err(|_| api_error())?;
        }
        ValidatedCookieUrl::new(endpoint, CookieUrlPolicy::HttpsOnly).map_err(|_| api_error())
    }

    fn policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        let policy = EndpointPolicy::new([
            (
                self.international.origin().ascii_serialization(),
                self.endpoint_class,
            ),
            (
                self.china.origin().ascii_serialization(),
                self.endpoint_class,
            ),
        ])
        .map_err(|_| api_error())?;
        for endpoint in [&self.international, &self.china] {
            policy.validate(endpoint).map_err(|_| api_error())?;
        }
        Ok(policy)
    }
}

impl Debug for QoderRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QoderRouteSet")
            .field("international", &"<redacted>")
            .field("china", &"<redacted>")
            .field("endpoint_class", &self.endpoint_class)
            .finish()
    }
}

struct QoderCredential {
    site: QoderSite,
    cookie: Zeroizing<String>,
}

/// Qoder adapter permanently bound to one account and credential source.
pub struct QoderProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: QoderRouteSet,
    credentials: Vec<QoderCredential>,
    transport: QoderTransport,
}

impl QoderProvider {
    /// Creates a production adapter from a raw Cookie header, copied cURL, or
    /// copied HTTP request.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, scope, or endpoint error.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_at(scope, raw, &QoderRouteSet::production()?)
    }

    /// Creates a manual adapter against explicit exact loopback routes.
    ///
    /// The capture itself is still authorized only for exact Qoder domains;
    /// the injected routes replace network authorities after authorization.
    ///
    /// # Errors
    ///
    /// Returns stable redacted capture, cookie, scope, or endpoint failures.
    #[doc(hidden)]
    pub fn from_manual_capture_at(
        scope: AccountScope,
        raw: &str,
        routes: &QoderRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let site = manual_site(raw)?;
        let raw_cookie = if looks_like_curl_capture(raw) {
            extract_curl_cookie(raw)?
        } else if looks_like_http_request(raw) {
            extract_http_cookie(raw)?
        } else {
            Zeroizing::new(raw.to_owned())
        };
        let cookie = normalize_manual_cookie(raw_cookie.as_str())?;
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            clone_routes(routes),
            vec![QoderCredential { site, cookie }],
        )
    }

    /// Creates a production adapter from one already imported browser jar.
    ///
    /// No profile discovery, browser I/O, global cache, or ambient credential
    /// source is consulted.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential, scope, or endpoint error.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jar_at(scope, jar, now, &QoderRouteSet::production()?)
    }

    /// Creates a browser adapter against explicit exact loopback routes.
    ///
    /// Cookie selection remains separately bound to the fixed HTTPS Qoder
    /// targets, so loopback transport cannot broaden cookie authority.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential, scope, or endpoint error.
    #[doc(hidden)]
    pub fn from_browser_jar_at(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        routes: &QoderRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let mut credentials = Vec::with_capacity(QoderSite::ALL.len());
        for site in QoderSite::ALL {
            let mut selected = Vec::new();
            for www in [false, true] {
                let target = QoderRouteSet::cookie_target(site, www)?;
                if let Some(header) = jar.header_for(&target, now).map_err(|_| api_error())? {
                    selected.push(Zeroizing::new(header.expose().to_owned()));
                }
            }
            if let Some(cookie) = merge_browser_cookie_headers(&selected)? {
                credentials.push(QoderCredential { site, cookie });
            }
        }
        if credentials.is_empty() {
            return Err(ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        }
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            clone_routes(routes),
            credentials,
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: QoderRouteSet,
        credentials: Vec<QoderCredential>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Qoder
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
            || credentials.is_empty()
            || credentials.len() > QoderSite::ALL.len()
        {
            return Err(api_error());
        }
        for credential in &credentials {
            secret_header(credential.cookie.as_str())?;
        }
        let transport = QoderTransport::new(routes.policy()?)?;
        Ok(Self {
            scope,
            source,
            routes,
            credentials,
            transport,
        })
    }

    /// Fetches the first valid candidate, retrying browser candidates in
    /// international-then-China order exactly like the pinned importer.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, API, or parse
    /// failures. Manual credentials are never retried against another domain.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let retry_candidates = self.source == ProviderSource::BrowserSession;
        let mut saw_auth = false;
        let mut terminal_non_auth = None;
        for credential in &self.credentials {
            let result = self
                .transport
                .send(
                    self.routes.endpoint(credential.site),
                    credential.site,
                    credential.cookie.as_str(),
                    context.cancellation(),
                )
                .await
                .and_then(|body| {
                    parse_usage_response(context.scope().clone(), fetched_at, &body, self.source)
                });
            match result {
                Ok(sample) => return Ok(sample),
                Err(error) if !retry_candidates || context.cancellation().is_cancelled() => {
                    return Err(error);
                }
                Err(error) if error.kind() == ErrorKind::AuthenticationExpired => {
                    saw_auth = true;
                }
                Err(error) => terminal_non_auth = Some(error),
            }
        }
        Err(terminal_non_auth
            .or_else(|| saw_auth.then(|| ClassifiedError::new(ErrorKind::AuthenticationExpired)))
            .unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }
        Ok(())
    }
}

impl ProviderAdapter for QoderProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Qoder)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for QoderProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QoderProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("credential_count", &self.credentials.len())
            .field("credentials", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

struct QoderTransport {
    client: Client,
    policy: EndpointPolicy,
}

impl QoderTransport {
    fn new(policy: EndpointPolicy) -> Result<Self, ClassifiedError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| api_error())?;
        Ok(Self { client, policy })
    }

    async fn send(
        &self,
        endpoint: &Url,
        site: QoderSite,
        cookie: &str,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<Vec<u8>, ClassifiedError> {
        let endpoint = self.policy.validate(endpoint).map_err(|_| api_error())?;
        let cookie = secret_header(cookie)?;
        let origin = site.origin();
        let request = self
            .client
            .get(endpoint.url().clone())
            .header(COOKIE, cookie)
            .header(ACCEPT, ACCEPT_VALUE)
            .header(ACCEPT_LANGUAGE, ACCEPT_LANGUAGE_VALUE)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(ORIGIN, origin)
            .header(REFERER, format!("{origin}/account/usage"))
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Bx-V", "2.5.35");
        let future = async {
            let response = request
                .send()
                .await
                .map_err(|_| ClassifiedError::new(ErrorKind::Network))?;
            read_response(response).await
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ClassifiedError::new(ErrorKind::Network)),
            result = tokio::time::timeout(REQUEST_TIMEOUT, future) => {
                result.unwrap_or_else(|_| Err(ClassifiedError::new(ErrorKind::Network)))
            }
        }
    }
}

impl Debug for QoderTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("QoderTransport(<redacted>)")
    }
}

async fn read_response(response: reqwest::Response) -> Result<Vec<u8>, ClassifiedError> {
    let status = response.status();
    if !status.is_success() {
        return Err(ClassifiedError::new(
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                ErrorKind::AuthenticationExpired
            } else {
                ErrorKind::Api
            },
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(parse_error());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ClassifiedError::new(ErrorKind::Network))?;
        let next = body
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= MAX_RESPONSE_BYTES)
            .ok_or_else(parse_error)?;
        body.reserve(next.saturating_sub(body.len()));
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Parses one bounded Qoder quota payload and maps it to the single primary
/// credit window exposed by the pinned provider.
///
/// # Errors
///
/// Returns a stable parse error for malformed, excessive, negative, missing,
/// non-finite, or arithmetically impossible quota data.
pub fn parse_usage_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Qoder
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(api_error());
    }
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| parse_error())?;
    validate_json_shape(&root)?;
    let object = root.as_object().ok_or_else(parse_error)?;
    let base = quota_summary(object_alias(object, "totalQuota", "total_quota")?)?;
    let shared = optional_object_alias(object, "sharedQuota", "shared_quota")?
        .map(optional_quota_summary)
        .transpose()?
        .flatten();
    let merged = merge_quota(base, shared)?;
    let reset = optional_alias(object, "nextResetAt", "next_reset_at").and_then(parse_reset);
    let description = BoundedText::new(format!(
        "{} / {} credits",
        format_credits(merged.used),
        format_credits(merged.total)
    ))
    .map_err(|_| parse_error())?;
    let percent =
        UsagePercent::new(merged.percentage.clamp(0.0, 100.0)).map_err(|_| parse_error())?;
    let primary = RateWindow::new(
        WindowUsage::known(percent),
        None,
        reset,
        Some(description),
        None,
        false,
    )
    .map_err(|_| parse_error())?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .provenance(
            "qoder",
            if source == ProviderSource::ManualCookie {
                "manual_cookie"
            } else {
                "browser_session"
            },
        )?
        .build()
}

#[derive(Clone, Copy)]
struct QuotaSummary {
    used: f64,
    total: f64,
    remaining: Option<f64>,
    percentage: Option<f64>,
}

#[derive(Clone, Copy)]
struct MergedQuota {
    used: f64,
    total: f64,
    percentage: f64,
}

fn quota_summary(container: &Value) -> Result<QuotaSummary, ClassifiedError> {
    let container = container.as_object().ok_or_else(parse_error)?;
    let summary = object_alias(container, "quotaSummary", "quota_summary")?;
    parse_quota_summary(summary)
}

fn optional_quota_summary(container: &Value) -> Result<Option<QuotaSummary>, ClassifiedError> {
    let container = container.as_object().ok_or_else(parse_error)?;
    optional_alias(container, "quotaSummary", "quota_summary")
        .map(parse_quota_summary)
        .transpose()
}

fn parse_quota_summary(summary: &Value) -> Result<QuotaSummary, ClassifiedError> {
    let summary = summary.as_object().ok_or_else(parse_error)?;
    let used = required_number_alias(summary, "usedValue", "used_value")?;
    let total = required_number_alias(summary, "limitValue", "limit_value")?;
    let remaining = optional_number_alias(summary, "remainingValue", "remaining_value")?;
    let percentage = optional_number_alias(summary, "usagePercentage", "usage_percentage")?;
    if let Some(unit) = summary.get("unit").filter(|value| !value.is_null()) {
        let unit = unit.as_str().ok_or_else(parse_error)?;
        if unit.len() > MAX_UNIT_BYTES || unit.chars().any(char::is_control) {
            return Err(parse_error());
        }
    }
    Ok(QuotaSummary {
        used,
        total,
        remaining,
        percentage,
    })
}

fn merge_quota(
    base: QuotaSummary,
    shared: Option<QuotaSummary>,
) -> Result<MergedQuota, ClassifiedError> {
    let base_remaining = remaining(base)?;
    let Some(shared) = shared else {
        return Ok(MergedQuota {
            used: base.used,
            total: base.total,
            percentage: percentage(base.used, base.total, base_remaining, base.percentage)?,
        });
    };
    let shared_remaining = remaining(shared)?;
    let used = checked_quota_add(base.used, shared.used)?;
    let total = checked_quota_add(base.total, shared.total)?;
    let remaining = checked_quota_add(base_remaining, shared_remaining)?;
    Ok(MergedQuota {
        used,
        total,
        percentage: percentage(used, total, remaining, None)?,
    })
}

fn remaining(summary: QuotaSummary) -> Result<f64, ClassifiedError> {
    if summary.used < 0.0
        || summary.total < 0.0
        || summary.remaining.is_some_and(|value| value < 0.0)
    {
        return Err(parse_error());
    }
    Ok(summary
        .remaining
        .unwrap_or_else(|| (summary.total - summary.used).max(0.0)))
}

fn percentage(
    used: f64,
    total: f64,
    remaining: f64,
    provided: Option<f64>,
) -> Result<f64, ClassifiedError> {
    if used < 0.0 || total < 0.0 || remaining < 0.0 {
        return Err(parse_error());
    }
    if total == 0.0 {
        if used != 0.0 || remaining != 0.0 {
            return Err(parse_error());
        }
        return Ok(provided.unwrap_or(100.0));
    }
    Ok(provided.unwrap_or((used / total) * 100.0))
}

fn checked_quota_add(left: f64, right: f64) -> Result<f64, ClassifiedError> {
    let value = left + right;
    if value.is_finite() && value <= MAX_QUOTA_MAGNITUDE {
        Ok(value)
    } else {
        Err(parse_error())
    }
}

fn required_number_alias(
    object: &Map<String, Value>,
    camel: &str,
    snake: &str,
) -> Result<f64, ClassifiedError> {
    let value = object_alias(object, camel, snake)?;
    bounded_number(value)
}

fn optional_number_alias(
    object: &Map<String, Value>,
    camel: &str,
    snake: &str,
) -> Result<Option<f64>, ClassifiedError> {
    optional_alias(object, camel, snake)
        .map(bounded_number)
        .transpose()
}

fn bounded_number(value: &Value) -> Result<f64, ClassifiedError> {
    let value = value.as_f64().ok_or_else(parse_error)?;
    if value.is_finite() && value.abs() <= MAX_QUOTA_MAGNITUDE {
        Ok(value)
    } else {
        Err(parse_error())
    }
}

fn object_alias<'a>(
    object: &'a Map<String, Value>,
    camel: &str,
    snake: &str,
) -> Result<&'a Value, ClassifiedError> {
    optional_alias(object, camel, snake).ok_or_else(parse_error)
}

fn optional_object_alias<'a>(
    object: &'a Map<String, Value>,
    camel: &str,
    snake: &str,
) -> Result<Option<&'a Value>, ClassifiedError> {
    let value = optional_alias(object, camel, snake);
    if value.is_some_and(|candidate| !candidate.is_object()) {
        return Err(parse_error());
    }
    Ok(value)
}

fn optional_alias<'a>(
    object: &'a Map<String, Value>,
    camel: &str,
    snake: &str,
) -> Option<&'a Value> {
    object
        .get(camel)
        .filter(|value| !value.is_null())
        .or_else(|| object.get(snake).filter(|value| !value.is_null()))
}

fn parse_reset(value: &Value) -> Option<Timestamp> {
    if let Some(value) = value.as_str() {
        return Timestamp::parse(value).ok();
    }
    let value = value.as_f64()?;
    if !value.is_finite() {
        return None;
    }
    let seconds = if value > 10_000_000_000.0 {
        value / 1000.0
    } else {
        value
    };
    let nanos = Decimal::from_f64(seconds)?
        .checked_mul(Decimal::from(1_000_000_000_u64))?
        .round()
        .to_i128()?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|value| Timestamp::new(value).ok())
}

fn format_credits(value: f64) -> String {
    let rounded = (value * 100.0).round() / 100.0;
    let mut raw = if rounded.fract() == 0.0 {
        format!("{rounded:.0}")
    } else {
        let mut value = format!("{rounded:.2}");
        while value.ends_with('0') {
            value.pop();
        }
        value
    };
    let fraction = raw.find('.').map(|index| raw.split_off(index));
    let mut grouped = String::with_capacity(raw.len() + raw.len() / 3 + 3);
    for (index, byte) in raw.bytes().enumerate() {
        if index > 0 && (raw.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    if let Some(fraction) = fraction {
        grouped.push_str(&fraction);
    }
    grouped
}

fn validate_json_shape(value: &Value) -> Result<(), ClassifiedError> {
    fn visit(
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        string_bytes: &mut usize,
    ) -> Result<(), ClassifiedError> {
        if depth > MAX_JSON_DEPTH || *nodes >= MAX_JSON_NODES {
            return Err(parse_error());
        }
        *nodes += 1;
        match value {
            Value::Array(values) => {
                for value in values {
                    visit(value, depth + 1, nodes, string_bytes)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    *string_bytes = string_bytes
                        .checked_add(key.len())
                        .filter(|size| *size <= MAX_JSON_STRING_BYTES)
                        .ok_or_else(parse_error)?;
                    visit(value, depth + 1, nodes, string_bytes)?;
                }
            }
            Value::String(value) => {
                *string_bytes = string_bytes
                    .checked_add(value.len())
                    .filter(|size| *size <= MAX_JSON_STRING_BYTES)
                    .ok_or_else(parse_error)?;
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }

    visit(value, 0, &mut 0, &mut 0)
}

/// Resolves the authoritative Qoder site from a bounded manual capture.
///
/// Cookie values are never scanned for domain-looking substrings. Only an
/// exact cURL URL, HTTP request target/Host, or plain `Domain` attribute can
/// select China.
///
/// # Errors
///
/// Returns authentication-expired semantics for an authoritative but invalid
/// route, and a parse error for excessive or control-bearing input.
#[doc(hidden)]
pub fn manual_site(raw: &str) -> Result<QoderSite, ClassifiedError> {
    if raw.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    if raw.len() > MAX_CAPTURE_BYTES {
        return Err(parse_error());
    }
    if raw
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
    {
        return Err(parse_error());
    }
    if looks_like_curl_capture(raw) {
        return curl_site(raw).map_err(|_| authentication_error());
    }
    if let Some(site) = http_site(raw).map_err(|_| authentication_error())? {
        return Ok(site);
    }
    plain_cookie_site(raw).map_err(|_| authentication_error())
}

fn plain_cookie_site(raw: &str) -> Result<QoderSite, ClassifiedError> {
    if raw.chars().any(char::is_control) {
        return Err(parse_error());
    }
    let mut routed = None;
    for (index, part) in raw.split(';').enumerate() {
        if index >= MAX_CAPTURE_TOKENS {
            return Err(parse_error());
        }
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("domain") {
            continue;
        }
        let site = site_for_host(value).ok_or_else(parse_error)?;
        if routed.is_some_and(|existing| existing != site) {
            return Err(parse_error());
        }
        routed = Some(site);
    }
    Ok(routed.unwrap_or(QoderSite::International))
}

fn http_site(raw: &str) -> Result<Option<QoderSite>, ClassifiedError> {
    let mut request_site = None;
    let mut saw_request = false;
    let mut host_sites = Vec::new();
    for (line_count, line) in raw.lines().enumerate() {
        if line_count >= MAX_CAPTURE_LINES {
            return Err(parse_error());
        }
        let line = line.trim();
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
        {
            host_sites.push(site_for_host(value).ok_or_else(parse_error)?);
        }
        let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        let method = parts[0];
        let supported = matches!(
            method.to_ascii_lowercase().as_str(),
            "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
        );
        let known_unsupported = matches!(method.to_ascii_lowercase().as_str(), "trace" | "connect");
        let versioned = parts
            .get(2)
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("http/"));
        if !supported {
            if known_unsupported
                || (versioned && method.bytes().all(|byte| byte.is_ascii_alphabetic()))
            {
                return Err(parse_error());
            }
            continue;
        }
        if saw_request {
            return Err(parse_error());
        }
        saw_request = true;
        request_site = if parts[1].starts_with('/') {
            None
        } else {
            Some(site_for_url(parts[1]).ok_or_else(parse_error)?)
        };
    }
    if !saw_request {
        return Ok(None);
    }
    if host_sites
        .iter()
        .skip(1)
        .any(|site| Some(site) != host_sites.first())
    {
        return Err(parse_error());
    }
    match request_site {
        Some(site) => {
            if host_sites.first().is_some_and(|host| *host != site) {
                return Err(parse_error());
            }
            Ok(Some(site))
        }
        None => host_sites
            .first()
            .copied()
            .map(Some)
            .ok_or_else(parse_error),
    }
}

fn extract_http_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let mut found = None;
    for (line_count, line) in raw.lines().enumerate() {
        if line_count >= MAX_CAPTURE_LINES {
            return Err(parse_error());
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("cookie") {
            continue;
        }
        if found.is_some() {
            continue;
        }
        if value.trim().is_empty() {
            return Err(parse_error());
        }
        found = Some(Zeroizing::new(value.trim().to_owned()));
    }
    found.ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
}

fn extract_curl_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let tokens = shell_tokens(raw)?;
    let mut curl_index = 0;
    while tokens
        .get(curl_index)
        .is_some_and(|token| is_shell_assignment(token.as_str()))
    {
        curl_index += 1;
    }
    if !tokens
        .get(curl_index)
        .is_some_and(|token| is_curl_token(token.as_str()))
    {
        return Err(parse_error());
    }
    let mut found = None;
    let mut index = curl_index + 1;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        let lower = token.to_ascii_lowercase();
        let candidate = if lower == "--header" || token == "-H" {
            index += 1;
            cookie_from_header(tokens.get(index).ok_or_else(parse_error)?.as_str())?
        } else if lower.starts_with("--header=") {
            cookie_from_header(&token["--header=".len()..])?
        } else if let Some(short) = short_header_value(token)? {
            match short {
                ShortHeader::Attached(value) => cookie_from_header(value)?,
                ShortHeader::Following => {
                    index += 1;
                    cookie_from_header(tokens.get(index).ok_or_else(parse_error)?.as_str())?
                }
            }
        } else if lower == "--cookie" || token == "-b" {
            index += 1;
            Some(tokens.get(index).ok_or_else(parse_error)?.as_str())
        } else if lower.starts_with("--cookie=") {
            Some(&token["--cookie=".len()..])
        } else if token.starts_with("-b") && !token.starts_with("--") && token.len() > 2 {
            Some(&token[2..])
        } else {
            None
        };
        if let Some(candidate) = candidate {
            if found.is_some() {
                index += 1;
                continue;
            }
            if candidate.is_empty() || candidate.starts_with('@') {
                return Err(parse_error());
            }
            found = Some(Zeroizing::new(candidate.to_owned()));
        }
        index += 1;
    }
    found.ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
}

fn cookie_from_header(header: &str) -> Result<Option<&str>, ClassifiedError> {
    if header.is_empty() || header.starts_with('@') {
        return Err(parse_error());
    }
    let Some((name, value)) = header.split_once(':') else {
        return Ok(None);
    };
    if !name.trim().eq_ignore_ascii_case("cookie") {
        return Ok(None);
    }
    let value = value.trim();
    if value.is_empty() {
        return Err(parse_error());
    }
    Ok(Some(value))
}

fn looks_like_http_request(raw: &str) -> bool {
    raw.lines().any(|line| {
        let mut parts = line.split_ascii_whitespace();
        let Some(method) = parts.next() else {
            return false;
        };
        let Some(_target) = parts.next() else {
            return false;
        };
        matches!(
            method.to_ascii_lowercase().as_str(),
            "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace" | "connect"
        ) || parts
            .next()
            .is_some_and(|version| version.to_ascii_lowercase().starts_with("http/"))
    })
}

fn looks_like_curl_capture(raw: &str) -> bool {
    raw.split(|character: char| character.is_ascii_whitespace() || character == ';')
        .any(|token| is_curl_token(token.trim_matches(['\'', '"', '\\'])))
}

fn curl_site(raw: &str) -> Result<QoderSite, ClassifiedError> {
    let tokens = shell_tokens(raw)?;
    let mut curl_index = 0;
    while tokens
        .get(curl_index)
        .is_some_and(|token| is_shell_assignment(token.as_str()))
    {
        curl_index += 1;
    }
    if !tokens
        .get(curl_index)
        .is_some_and(|token| is_curl_token(token.as_str()))
        || tokens
            .iter()
            .enumerate()
            .any(|(index, token)| index != curl_index && is_curl_token(token.as_str()))
    {
        return Err(parse_error());
    }
    let mut explicit = Vec::new();
    let mut url_targets = Vec::new();
    let mut index = curl_index + 1;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token.eq_ignore_ascii_case("--url") {
            let value_index = index + 1;
            let value = tokens.get(value_index).ok_or_else(parse_error)?;
            explicit.push((
                value_index,
                site_for_url(value.as_str()).ok_or_else(parse_error)?,
            ));
            index += 2;
            continue;
        }
        if token
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("--url="))
        {
            explicit.push((index, site_for_url(&token[6..]).ok_or_else(parse_error)?));
        }
        if starts_with_http_scheme(token) {
            url_targets.push((index, site_for_url(token).ok_or_else(parse_error)?));
        }
        index += 1;
    }
    let indices = explicit
        .iter()
        .chain(&url_targets)
        .map(|(index, _)| *index)
        .collect::<BTreeSet<_>>();
    if indices.len() != 1 {
        return Err(parse_error());
    }
    let target_index = *indices.first().ok_or_else(parse_error)?;
    let target_site =
        if let Some((_, site)) = explicit.iter().find(|(index, _)| *index == target_index) {
            *site
        } else if target_index == curl_index + 1 {
            url_targets
                .iter()
                .find(|(index, _)| *index == target_index)
                .map(|(_, site)| *site)
                .ok_or_else(parse_error)?
        } else {
            return Err(parse_error());
        };
    for site in curl_header_sites(&tokens, curl_index + 1)? {
        if site != target_site {
            return Err(parse_error());
        }
    }
    Ok(target_site)
}

fn curl_header_sites(
    tokens: &[Zeroizing<String>],
    mut index: usize,
) -> Result<Vec<QoderSite>, ClassifiedError> {
    let mut sites = Vec::new();
    while index < tokens.len() {
        let token = tokens[index].as_str();
        let lower = token.to_ascii_lowercase();
        if lower == "--config"
            || lower.starts_with("--config=")
            || lower.starts_with("--expand-")
            || lower == "--location-trusted"
            || short_options_contain(token, 'K')
        {
            return Err(parse_error());
        }
        let header = if lower == "--header" {
            index += 1;
            Some(tokens.get(index).ok_or_else(parse_error)?.as_str())
        } else if lower.starts_with("--header=") {
            Some(&token["--header=".len()..])
        } else {
            match short_header_value(token)? {
                Some(ShortHeader::Attached(value)) => Some(value),
                Some(ShortHeader::Following) => {
                    index += 1;
                    Some(tokens.get(index).ok_or_else(parse_error)?.as_str())
                }
                None => None,
            }
        };
        if let Some(header) = header
            && let Some(site) = inspect_host_header(header)?
        {
            sites.push(site);
        }
        index += 1;
    }
    Ok(sites)
}

enum ShortHeader<'a> {
    Attached(&'a str),
    Following,
}

fn short_header_value(token: &str) -> Result<Option<ShortHeader<'_>>, ClassifiedError> {
    if !token.starts_with('-') || token.starts_with("--") {
        return Ok(None);
    }
    let options = &token[1..];
    let Some(position) = options.find('H') else {
        return Ok(None);
    };
    if !options[..position]
        .bytes()
        .all(|byte| matches!(byte, b'f' | b's' | b'S' | b'L'))
    {
        return Err(parse_error());
    }
    let attached = &options[position + 1..];
    Ok(Some(if attached.is_empty() {
        ShortHeader::Following
    } else {
        ShortHeader::Attached(attached)
    }))
}

fn inspect_host_header(header: &str) -> Result<Option<QoderSite>, ClassifiedError> {
    let header = header.trim();
    if header.is_empty() || header.starts_with('@') {
        return Err(parse_error());
    }
    let Some((name, value)) = header.split_once(':') else {
        if header.to_ascii_lowercase().starts_with("host") {
            return Err(parse_error());
        }
        return Ok(None);
    };
    if !name.trim().eq_ignore_ascii_case("host") {
        return Ok(None);
    }
    site_for_host(value).map(Some).ok_or_else(parse_error)
}

fn short_options_contain(token: &str, option: char) -> bool {
    token.starts_with('-') && !token.starts_with("--") && token[1..].contains(option)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShellQuote {
    Single,
    Double,
}

fn shell_tokens(raw: &str) -> Result<Vec<Zeroizing<String>>, ClassifiedError> {
    let mut tokens = Vec::new();
    let mut token = Zeroizing::new(String::new());
    let mut quote = None;
    let mut started = false;
    let mut chars = raw.chars().peekable();
    while let Some(character) = chars.next() {
        match quote {
            Some(ShellQuote::Single) => {
                if character == '\'' {
                    quote = None;
                } else if character.is_control() {
                    return Err(parse_error());
                } else {
                    push_capture_char(&mut token, character)?;
                }
            }
            Some(ShellQuote::Double) => match character {
                '"' => quote = None,
                '$' | '`' => return Err(parse_error()),
                '\\' => {
                    let escaped = chars.next().ok_or_else(parse_error)?;
                    if !matches!(escaped, '"' | '\\') {
                        return Err(parse_error());
                    }
                    push_capture_char(&mut token, escaped)?;
                }
                value if value.is_control() => return Err(parse_error()),
                value => push_capture_char(&mut token, value)?,
            },
            None => match character {
                value if value.is_control() => return Err(parse_error()),
                value if value.is_whitespace() => {
                    finish_capture_token(&mut tokens, &mut token, &mut started)?;
                }
                '\'' => {
                    quote = Some(ShellQuote::Single);
                    started = true;
                }
                '"' => {
                    quote = Some(ShellQuote::Double);
                    started = true;
                }
                '$' | '`' | ';' | '|' | '&' | '<' | '>' => return Err(parse_error()),
                '\\' => {
                    let escaped = chars.next().ok_or_else(parse_error)?;
                    if escaped == '\r' {
                        if chars.peek() == Some(&'\n') {
                            chars.next();
                        } else {
                            return Err(parse_error());
                        }
                    } else if escaped != '\n' {
                        if escaped.is_control() {
                            return Err(parse_error());
                        }
                        push_capture_char(&mut token, escaped)?;
                        started = true;
                    }
                }
                value => {
                    push_capture_char(&mut token, value)?;
                    started = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err(parse_error());
    }
    finish_capture_token(&mut tokens, &mut token, &mut started)?;
    Ok(tokens)
}

fn push_capture_char(token: &mut String, value: char) -> Result<(), ClassifiedError> {
    if token.len() + value.len_utf8() > MAX_CAPTURE_TOKEN_BYTES {
        return Err(parse_error());
    }
    token.push(value);
    Ok(())
}

fn finish_capture_token(
    tokens: &mut Vec<Zeroizing<String>>,
    token: &mut Zeroizing<String>,
    started: &mut bool,
) -> Result<(), ClassifiedError> {
    if !*started {
        return Ok(());
    }
    if tokens.len() >= MAX_CAPTURE_TOKENS {
        return Err(parse_error());
    }
    tokens.push(Zeroizing::new(token.as_str().to_owned()));
    token.zeroize();
    *started = false;
    Ok(())
}

fn is_shell_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn is_curl_token(token: &str) -> bool {
    !token.contains('=')
        && !token.contains("://")
        && token
            .rsplit('/')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("curl"))
}

fn starts_with_http_scheme(value: &str) -> bool {
    value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn site_for_url(raw: &str) -> Option<QoderSite> {
    if !starts_with_http_scheme(raw) {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    site_for_host(url.host_str()?)
}

fn site_for_host(raw: &str) -> Option<QoderSite> {
    let raw = raw.trim().trim_matches(['\'', '"']);
    let raw = raw.strip_prefix('.').unwrap_or(raw);
    let mut host = raw.to_ascii_lowercase();
    if host.is_empty() || host.chars().any(char::is_control) {
        return None;
    }
    if let Some(separator) = host.rfind(':') {
        let port = &host[separator + 1..];
        let name = &host[..separator];
        if name.contains(':')
            || port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || !(1..=65_535).contains(&port.parse::<u32>().ok()?)
        {
            return None;
        }
        host.truncate(separator);
    }
    match host.as_str() {
        "qoder.com" | "www.qoder.com" => Some(QoderSite::International),
        "qoder.com.cn" | "www.qoder.com.cn" => Some(QoderSite::China),
        _ => None,
    }
}

fn normalize_manual_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let mut value = raw.trim();
    if let Some((name, candidate)) = value.split_once(':')
        && name.trim().eq_ignore_ascii_case("cookie")
    {
        value = candidate.trim();
    }
    if value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"')))
    {
        value = value[1..value.len() - 1].trim();
    }
    if value.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    if value.len() > MAX_COOKIE_HEADER_BYTES || !value.contains('=') {
        return Err(parse_error());
    }
    secret_header(value)?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn merge_browser_cookie_headers(
    headers: &[Zeroizing<String>],
) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
    let mut pairs = Vec::<Zeroizing<String>>::new();
    for header in headers {
        for raw_pair in header.split(';') {
            let pair = raw_pair.trim();
            if pair.is_empty() || !pair.contains('=') {
                return Err(api_error());
            }
            if pairs.iter().any(|existing| existing.as_str() == pair) {
                continue;
            }
            if pairs.len() >= MAX_COOKIE_PAIRS {
                return Err(api_error());
            }
            pairs.push(Zeroizing::new(pair.to_owned()));
        }
    }
    if pairs.is_empty() {
        return Ok(None);
    }
    let mut merged = Zeroizing::new(String::new());
    for (index, pair) in pairs.iter().enumerate() {
        if index > 0 {
            merged.push_str("; ");
        }
        let current = merged.len();
        let next = current
            .checked_add(pair.len())
            .filter(|length| *length <= MAX_COOKIE_HEADER_BYTES)
            .ok_or_else(api_error)?;
        merged.reserve(next.saturating_sub(current));
        merged.push_str(pair);
    }
    secret_header(merged.as_str())?;
    Ok(Some(merged))
}

fn secret_header(value: &str) -> Result<HeaderValue, ClassifiedError> {
    let mut header = HeaderValue::from_str(value).map_err(|_| parse_error())?;
    header.set_sensitive(true);
    Ok(header)
}

fn production_endpoint(site: QoderSite) -> Result<Url, ClassifiedError> {
    let origin = Url::parse(site.origin()).map_err(|_| api_error())?;
    endpoint_from_origin(origin, EndpointClass::PublicHttps)
}

fn endpoint_from_origin(
    mut origin: Url,
    endpoint_class: EndpointClass,
) -> Result<Url, ClassifiedError> {
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.host_str().is_none()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(api_error());
    }
    let policy = EndpointPolicy::new([(origin.origin().ascii_serialization(), endpoint_class)])
        .map_err(|_| api_error())?;
    policy.validate(&origin).map_err(|_| api_error())?;
    origin.set_path(USAGE_PATH);
    policy.validate(&origin).map_err(|_| api_error())?;
    Ok(origin)
}

fn clone_routes(routes: &QoderRouteSet) -> QoderRouteSet {
    QoderRouteSet {
        international: routes.international.clone(),
        china: routes.china.clone(),
        endpoint_class: routes.endpoint_class,
    }
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn authentication_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::AuthenticationExpired)
}
