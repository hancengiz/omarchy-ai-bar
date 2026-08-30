//! Native Qwen Cloud individual token-plan adapter.

use std::fmt::{self, Debug, Formatter, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime, PrimitiveDateTime, Time};
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
    Authentication, HttpRequest, HttpResponse, HttpTransport, RequestAccept, RequestContentType,
    TransportConfig, TransportError,
};

const DASHBOARD_ORIGIN: &str = "https://home.qwencloud.com";
const DATA_ORIGIN: &str = "https://cs-data.qwencloud.com";
const DASHBOARD_PATH: &str = "/billing/subscription/token-plan-individual";
const USER_INFO_PATH: &str = "/tool/user/info.json";
const DATA_PATH: &str = "/data/api.json";
const CONSOLE_ACTION: &str = "IntlBroadScopeAspnGateway";
const CONSOLE_PRODUCT: &str = "sfm_bailian";
const PRODUCT_CODE: &str = "sfm_tokenplansolo_public_intl";
const REGION: &str = "ap-southeast-1";
const LANGUAGE: &str = "en-US";
const USAGE_API: &str = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage";
const SUBSCRIPTION_API: &str = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/subscription";
const QUOTA_CONFIG_API: &str = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/quota-config";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_EMBEDDED_JSON_LAYERS: usize = 6;
const MAX_COOKIE_HEADER_BYTES: usize = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_PLAN_BYTES: usize = 256;
const AUTH_TICKET_COOKIE_NAMES: [&str; 3] = [
    "login_aliyunid_ticket",
    "login_qwencloud_ticket",
    "qwen_sso_ticket",
];
const PROBE_STATUSES: [u16; 12] = [400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504];

static TRACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Routes {
    dashboard: Url,
    user_info: Url,
    usage: Url,
    subscription: Url,
    quota_config: Url,
}

/// Fixed Qwen Cloud dashboard and data-gateway routing.
///
/// Production construction pins the two baseline HTTPS origins. The loopback
/// constructor is an injected, typed seam for isolated transport tests only.
pub struct QwenCloudRouteSet {
    routes: Routes,
    class: EndpointClass,
}

impl QwenCloudRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origins(
            Url::parse(DASHBOARD_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            Url::parse(DATA_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates an exact two-origin loopback route table for HTTP tests.
    ///
    /// # Errors
    ///
    /// Rejects non-origin, credential-bearing, or non-loopback URLs.
    #[doc(hidden)]
    pub fn loopback(dashboard_origin: Url, data_origin: Url) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            dashboard_origin,
            data_origin,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        dashboard_origin: Url,
        data_origin: Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        validate_bare_origin(&dashboard_origin, class)?;
        validate_bare_origin(&data_origin, class)?;
        if class == EndpointClass::PublicHttps
            && (!same_origin(&dashboard_origin, DASHBOARD_ORIGIN)?
                || !same_origin(&data_origin, DATA_ORIGIN)?)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        if !matches!(
            class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let dashboard = with_path(dashboard_origin.clone(), DASHBOARD_PATH);
        let user_info = with_path(dashboard_origin, USER_INFO_PATH);
        let usage = api_url(data_origin.clone(), USAGE_API);
        let subscription = api_url(data_origin.clone(), SUBSCRIPTION_API);
        let quota_config = api_url(data_origin, QUOTA_CONFIG_API);
        Ok(Self {
            routes: Routes {
                dashboard,
                user_info,
                usage,
                subscription,
                quota_config,
            },
            class,
        })
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        let dashboard = self.routes.dashboard.origin().ascii_serialization();
        let data = self.routes.usage.origin().ascii_serialization();
        EndpointPolicy::new([(dashboard, self.class), (data, self.class)])
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

impl Debug for QwenCloudRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QwenCloudRouteSet")
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

fn api_url(origin: Url, api: &str) -> Url {
    let mut url = with_path(origin, DATA_PATH);
    url.query_pairs_mut().clear().extend_pairs([
        ("action", CONSOLE_ACTION),
        ("product", CONSOLE_PRODUCT),
        ("api", api),
        ("_v", "undefined"),
    ]);
    url
}

struct SessionHeaders {
    dashboard: Option<Zeroizing<String>>,
    user_info: Option<Zeroizing<String>>,
    api: Zeroizing<String>,
}

impl SessionHeaders {
    fn manual(cookie: &str) -> Result<Self, ClassifiedError> {
        validate_cookie_header(cookie)?;
        Ok(Self {
            dashboard: Some(Zeroizing::new(cookie.to_owned())),
            user_info: Some(Zeroizing::new(cookie.to_owned())),
            api: Zeroizing::new(cookie.to_owned()),
        })
    }

    fn browser(
        routes: &Routes,
        policy: CookieUrlPolicy,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        let dashboard = cookie_for(jar, &routes.dashboard, policy, now)?;
        let user_info = cookie_for(jar, &routes.user_info, policy, now)?;
        let api = cookie_for(jar, &routes.usage, policy, now)?.ok_or_else(|| {
            ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            })
        })?;
        if !has_qwen_auth_ticket(&api) {
            return Err(ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        }
        let dashboard = dashboard.ok_or_else(|| {
            ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            })
        })?;
        Ok(Self {
            dashboard: Some(dashboard),
            user_info,
            api,
        })
    }
}

impl Debug for SessionHeaders {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionHeaders")
            .field("dashboard", &self.dashboard.is_some())
            .field("user_info", &self.user_info.is_some())
            .field("api", &"<redacted>")
            .finish()
    }
}

fn cookie_for(
    jar: &CookieJar,
    url: &Url,
    policy: CookieUrlPolicy,
    now: OffsetDateTime,
) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
    let target = ValidatedCookieUrl::new(url.clone(), policy)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let header = jar
        .header_for(&target, now)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    header
        .map(|header| {
            validate_cookie_header(header.expose())?;
            Ok(Zeroizing::new(header.expose().to_owned()))
        })
        .transpose()
}

fn validate_cookie_header(cookie: &str) -> Result<(), ClassifiedError> {
    if cookie.len() > MAX_COOKIE_HEADER_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Authentication::cookie(cookie.to_owned())
        .map(|_| ())
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn has_qwen_auth_ticket(header: &str) -> bool {
    header.split(';').any(|part| {
        let Some((name, value)) = part.trim().split_once('=') else {
            return false;
        };
        AUTH_TICKET_COOKIE_NAMES.contains(&name.trim()) && valid_token(value.trim())
    })
}

/// Qwen Cloud adapter bound to one account and one explicit web-session source.
pub struct QwenCloudProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: QwenCloudRouteSet,
    cookies: SessionHeaders,
    transport: HttpTransport,
}

impl QwenCloudProvider {
    /// Creates the production manual-cookie adapter.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or API error for an invalid
    /// capture, provider scope, or fixed configuration.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, QwenCloudRouteSet::production()?)
    }

    /// Creates a manual adapter with injected, fixed transport routes.
    ///
    /// A cURL URL, when present, must still target an exact production Qwen
    /// Cloud host. Injected routes are used only after capture authorization.
    ///
    /// # Errors
    ///
    /// Returns stable redacted capture or configuration failures.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: QwenCloudRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(
            ["home.qwencloud.com", "cs-data.qwencloud.com"],
            [CaptureHeader::Cookie],
        )
        .map_err(classify_capture_error)?
        .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let cookies = SessionHeaders::manual(cookie)?;
        Self::build(scope, ProviderSource::ManualCookie, routes, cookies)
    }

    /// Creates the production browser-session adapter from an injected jar.
    ///
    /// Cookie selection happens once for each exact dashboard, user-info, and
    /// data-gateway target at `now`; no discovery, cache, or ambient cookie
    /// store is consulted.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, or configuration failures.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jar_routes(scope, jar, now, QwenCloudRouteSet::production()?)
    }

    /// Creates a browser-session adapter with injected, fixed routes.
    ///
    /// # Errors
    ///
    /// Returns a stable failure if the data endpoint has no active matching
    /// cookie or any target violates its typed URL policy.
    #[doc(hidden)]
    pub fn from_browser_jar_routes(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        routes: QwenCloudRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let cookies = SessionHeaders::browser(&routes.routes, routes.cookie_policy(), jar, now)?;
        Self::build(scope, ProviderSource::BrowserSession, routes, cookies)
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: QwenCloudRouteSet,
        cookies: SessionHeaders,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::QwenCloud
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let policy = routes.endpoint_policy()?;
        for endpoint in [
            &routes.routes.dashboard,
            &routes.routes.user_info,
            &routes.routes.usage,
            &routes.routes.subscription,
            &routes.routes.quota_config,
        ] {
            policy
                .validate(endpoint)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        }
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            routes,
            cookies,
            transport,
        })
    }

    /// Source to which this provider instance is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Fetches usage at an injected wall-clock instant.
    ///
    /// # Errors
    ///
    /// Returns stable account, credential, network, rate-limit, API, or parse
    /// failures with no response or session text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let sec_token = self.resolve_sec_token(context).await?;
        let usage = self
            .fetch_api(
                context,
                &self.routes.routes.usage,
                USAGE_API,
                None,
                &sec_token,
                fetched_at,
            )
            .await
            .map_err(classify_api_transport)?;
        let subscription = match self
            .fetch_api(
                context,
                &self.routes.routes.subscription,
                SUBSCRIPTION_API,
                Some(("commodityCode", PRODUCT_CODE)),
                &sec_token,
                fetched_at,
            )
            .await
        {
            Ok(body) => Some(body),
            Err(TransportError::Cancelled) => {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            Err(_) => None,
        };
        let quota_config = match self
            .fetch_api(
                context,
                &self.routes.routes.quota_config,
                QUOTA_CONFIG_API,
                None,
                &sec_token,
                fetched_at,
            )
            .await
        {
            Ok(body) => Some(body),
            Err(TransportError::Cancelled) => {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            Err(_) => None,
        };
        parse_usage_responses(
            self.scope.clone(),
            fetched_at,
            &usage,
            subscription.as_deref(),
            quota_config.as_deref(),
            self.source,
        )
    }

    async fn resolve_sec_token(
        &self,
        context: &ProviderContext,
    ) -> Result<Zeroizing<String>, ClassifiedError> {
        let mut dashboard_failure = None;
        if let Some(cookie) = self.cookies.dashboard.as_deref() {
            match self
                .send_probe(
                    context,
                    &self.routes.routes.dashboard,
                    cookie,
                    RequestAccept::Html,
                )
                .await
            {
                Ok(response) if response.status() == 200 => {
                    if let Ok(html) = std::str::from_utf8(response.body())
                        && !looks_like_login_page(html)
                        && let Some(token) = extract_html_token(html)
                    {
                        return Ok(token);
                    }
                }
                Ok(response) if response.status() >= 500 => {
                    dashboard_failure = Some(ClassifiedError::new(ErrorKind::Network));
                }
                Ok(_) => {}
                Err(error) => dashboard_failure = Some(classify_probe_transport(&error)),
            }

            if let Some(token) =
                preferred_cookie_value(cookie, "sec_token", self.routes.routes.dashboard.host_str())
            {
                return Ok(Zeroizing::new(token.to_owned()));
            }
        }

        if let Some(cookie) = self.cookies.user_info.as_deref() {
            let response = self
                .send_probe(
                    context,
                    &self.routes.routes.user_info,
                    cookie,
                    RequestAccept::Json,
                )
                .await
                .map_err(|error| classify_probe_transport(&error))?;
            if response.status() == 200
                && let Ok(root) = parse_bounded_json(response.body())
            {
                for key in ["secToken", "sec_token", "csrfToken", "token"] {
                    if let Some(value) = find_first_string_for_key(&root, key)
                        && valid_token(value)
                    {
                        return Ok(Zeroizing::new(value.to_owned()));
                    }
                }
            }
        }

        Err(dashboard_failure
            .unwrap_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired)))
    }

    async fn send_probe(
        &self,
        context: &ProviderContext,
        url: &Url,
        cookie: &str,
        accept: RequestAccept,
    ) -> Result<HttpResponse, TransportError> {
        let request = HttpRequest::get(url.clone())
            .accept(accept)
            .accepted_statuses(&PROBE_STATUSES)?
            .authentication(Authentication::cookie(cookie.to_owned())?);
        self.transport.send(&request, context.cancellation()).await
    }

    async fn fetch_api(
        &self,
        context: &ProviderContext,
        url: &Url,
        api: &str,
        data_parameter: Option<(&str, &str)>,
        sec_token: &str,
        fetched_at: Timestamp,
    ) -> Result<Vec<u8>, TransportError> {
        let body = api_request_body(
            api,
            data_parameter,
            sec_token,
            &self.routes.routes.dashboard,
            &self.cookies.api,
            fetched_at,
        )?;
        let origin = self.routes.routes.dashboard.origin().ascii_serialization();
        let mut request = HttpRequest::post(url.clone(), body)?
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::FormUrlEncoded)
            .public_header("origin", origin)?
            .public_header("referer", self.routes.routes.dashboard.as_str())?
            .public_header("x-requested-with", "XMLHttpRequest")?
            .authentication(Authentication::cookie(self.cookies.api.to_string())?);
        if let Some(csrf) = cookie_value(&self.cookies.api, "login_aliyunid_csrf")
            .or_else(|| cookie_value(&self.cookies.api, "csrf"))
        {
            request = request
                .sensitive_header("x-xsrf-token", csrf.to_owned())?
                .sensitive_header("x-csrf-token", csrf.to_owned())?;
        }
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

impl ProviderAdapter for QwenCloudProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::QwenCloud)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for QwenCloudProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QwenCloudProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("cookies", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(10),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))
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

fn classify_api_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::PermissionDenied | TransportError::AuthenticationExpired => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        other => other.classified(),
    }
}

fn classify_probe_transport(error: &TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired
        | TransportError::PermissionDenied
        | TransportError::Api { .. } => ClassifiedError::new(ErrorKind::AuthenticationExpired),
        TransportError::ProviderUnavailable { .. }
        | TransportError::RateLimited { .. }
        | TransportError::RequestTimeout
        | TransportError::Timeout
        | TransportError::Network
        | TransportError::Cancelled => ClassifiedError::new(ErrorKind::Network),
        TransportError::ResponseTooLarge
        | TransportError::MalformedResponse
        | TransportError::TooManyRedirects => ClassifiedError::new(ErrorKind::Parse),
        TransportError::Endpoint(_) | TransportError::InvalidConfiguration => {
            ClassifiedError::new(ErrorKind::Api)
        }
    }
}

fn api_request_body(
    api: &str,
    data_parameter: Option<(&str, &str)>,
    sec_token: &str,
    dashboard: &Url,
    api_cookie: &str,
    fetched_at: Timestamp,
) -> Result<Vec<u8>, TransportError> {
    if !valid_token(sec_token) {
        return Err(TransportError::InvalidConfiguration);
    }
    let mut cornerstone = json!({
        "feTraceId": trace_id(fetched_at),
        "feURL": dashboard.as_str(),
        "protocol": "V2",
        "console": "ONE_CONSOLE",
        "productCode": "p_efm",
        "domain": dashboard.host_str().unwrap_or("home.qwencloud.com"),
        "consoleSite": "QWENCLOUD",
        "userNickName": "",
        "userPrincipalName": "",
        "xsp_lang": LANGUAGE,
    });
    if let Some(anonymous_id) = cookie_value(api_cookie, "cna") {
        cornerstone
            .as_object_mut()
            .ok_or(TransportError::InvalidConfiguration)?
            .insert(
                "X-Anonymous-Id".to_owned(),
                Value::String(anonymous_id.to_owned()),
            );
    }
    let mut data = Map::new();
    if let Some((name, value)) = data_parameter {
        data.insert(name.to_owned(), Value::String(value.to_owned()));
    }
    data.insert("cornerstoneParam".to_owned(), cornerstone);
    let params = serde_json::to_string(&json!({
        "Api": api,
        "V": "1.0",
        "Data": data,
    }))
    .map_err(|_| TransportError::InvalidConfiguration)?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("product", CONSOLE_PRODUCT)
        .append_pair("action", CONSOLE_ACTION)
        .append_pair("sec_token", sec_token)
        .append_pair("region", REGION)
        .append_pair("language", LANGUAGE)
        .append_pair("params", &params);
    let encoded = Zeroizing::new(serializer.finish());
    Ok(encoded.as_bytes().to_vec())
}

fn trace_id(fetched_at: Timestamp) -> String {
    let sequence = TRACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(fetched_at.unix_timestamp().to_le_bytes());
    hasher.update(sequence.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn cookie_value<'a>(header: &'a str, expected: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name.trim().eq_ignore_ascii_case(expected) && valid_token(value.trim()))
            .then_some(value.trim())
    })
}

fn preferred_cookie_value<'a>(
    header: &'a str,
    expected: &str,
    host: Option<&str>,
) -> Option<&'a str> {
    let mut fallback = None;
    for part in header.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        if !name.trim().eq_ignore_ascii_case(expected) || !valid_token(value) {
            continue;
        }
        if host.is_some_and(|host| value.contains(host)) {
            return Some(value);
        }
        fallback = Some(value);
    }
    fallback
}

fn valid_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TOKEN_BYTES && !value.chars().any(char::is_control)
}

fn looks_like_login_page(html: &str) -> bool {
    let lowered = html.to_ascii_lowercase();
    lowered.contains("passport.alibabacloud.com")
        || lowered.contains("signin.aliyun.com")
        || lowered.contains("account.alibabacloud.com/login")
        || lowered.contains("login.qwencloud.com")
        || (lowered.contains("login")
            && lowered.contains("password")
            && lowered.contains("sign in"))
}

fn extract_html_token(html: &str) -> Option<Zeroizing<String>> {
    for key in ["secToken", "sec_token", "csrfToken"] {
        for (offset, _) in html.match_indices(key) {
            if !identifier_boundary(html, offset, key.len()) {
                continue;
            }
            let mut rest = &html[offset + key.len()..];
            rest = rest.trim_start_matches(|character: char| character.is_ascii_whitespace());
            if let Some(stripped) = rest.strip_prefix(['\'', '"']) {
                rest = stripped;
            }
            rest = rest.trim_start_matches(|character: char| character.is_ascii_whitespace());
            let Some(stripped) = rest.strip_prefix([':', '=']) else {
                continue;
            };
            rest = stripped.trim_start_matches(|character: char| character.is_ascii_whitespace());
            let Some(quote) = rest
                .chars()
                .next()
                .filter(|quote| matches!(quote, '\'' | '"'))
            else {
                continue;
            };
            let rest = &rest[quote.len_utf8()..];
            let Some(end) = rest.find(quote) else {
                continue;
            };
            let token = rest[..end].trim();
            if valid_token(token) {
                return Some(Zeroizing::new(token.to_owned()));
            }
        }
    }
    None
}

fn identifier_boundary(text: &str, offset: usize, length: usize) -> bool {
    let before = text[..offset].chars().next_back();
    let after = text[offset + length..].chars().next();
    !before.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
        && !after.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
}

struct ParsedWindow {
    percent: Decimal,
    duration_minutes: i64,
    resets_at: Option<Timestamp>,
    description: Option<String>,
}

struct ParsedUsage {
    plan_name: Option<String>,
    primary: Option<ParsedWindow>,
    secondary: Option<ParsedWindow>,
}

/// Parses one required usage response without optional plan metadata.
///
/// # Errors
///
/// Returns stable scope, authentication, API, or bounded parse failures.
pub fn parse_usage_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    parse_usage_responses(scope, fetched_at, body, None, None, source)
}

/// Parses the required usage response and optional subscription/quota metadata.
///
/// Malformed optional responses are ignored as in the pinned fetch pipeline;
/// each is still parsed under the same byte, depth, node, string, and embedded
/// JSON bounds.
///
/// # Errors
///
/// Returns stable scope, authentication, API, or bounded parse failures from
/// the required usage response and normalized output.
#[doc(hidden)]
pub fn parse_usage_responses(
    scope: AccountScope,
    fetched_at: Timestamp,
    usage_body: &[u8],
    subscription_body: Option<&[u8]>,
    quota_config_body: Option<&[u8]>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::QwenCloud
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    if looks_like_login_html(usage_body) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let usage = parse_bounded_json(usage_body)?;
    validate_payload_status(&usage)?;
    let subscription = subscription_body.and_then(|body| parse_bounded_json(body).ok());
    let quota_config = quota_config_body.and_then(|body| parse_bounded_json(body).ok());
    let parsed = parse_current(&usage, subscription.as_ref(), quota_config.as_ref())
        .or_else(|| parse_legacy(&usage))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    normalize_usage(scope, fetched_at, parsed)
}

fn parse_current(
    usage_root: &Value,
    subscription_root: Option<&Value>,
    quota_root: Option<&Value>,
) -> Option<ParsedUsage> {
    let usage =
        find_object_containing_any(usage_root, &["per5HourPercentage", "per1WeekPercentage"])?;
    let five_hour = usage
        .get("per5HourPercentage")
        .and_then(scalar_decimal)
        .map(percentage_points);
    let weekly = usage
        .get("per1WeekPercentage")
        .and_then(scalar_decimal)
        .map(percentage_points);
    if five_hour.is_none() && weekly.is_none() {
        return None;
    }
    let plan_code = subscription_root.and_then(plan_code);
    let plan_name = plan_code.as_deref().map(display_plan_name);
    let totals = quota_root
        .zip(plan_code.as_deref())
        .and_then(|(root, code)| quota_totals(root, code));
    let primary = five_hour.map(|percent| ParsedWindow {
        percent,
        duration_minutes: 5 * 60,
        resets_at: usage.get("per5HourResetTime").and_then(scalar_timestamp),
        description: totals
            .as_ref()
            .and_then(|(five_hour, _)| *five_hour)
            .filter(|total| *total > Decimal::ZERO)
            .map(|total| quota_description(percent, total)),
    });
    let secondary = weekly.map(|percent| ParsedWindow {
        percent,
        duration_minutes: 7 * 24 * 60,
        resets_at: usage.get("per1WeekResetTime").and_then(scalar_timestamp),
        description: totals
            .as_ref()
            .and_then(|(_, weekly)| *weekly)
            .filter(|total| *total > Decimal::ZERO)
            .map(|total| quota_description(percent, total)),
    });
    Some(ParsedUsage {
        plan_name,
        primary,
        secondary,
    })
}

fn plan_code(root: &Value) -> Option<String> {
    let object =
        find_object_containing_any(root, &["specCode", "spec_code", "planName", "plan_name"])?;
    for key in ["specCode", "spec_code", "planName", "plan_name"] {
        if let Some(value) = object.get(key).and_then(scalar_string) {
            return Some(value.to_ascii_lowercase());
        }
    }
    None
}

fn display_plan_name(code: &str) -> String {
    match code {
        "lite" => "Lite".to_owned(),
        "standard" => "Standard".to_owned(),
        "pro" => "Pro".to_owned(),
        "max" => "Max".to_owned(),
        _ => code.to_owned(),
    }
}

fn quota_totals(root: &Value, plan_code: &str) -> Option<(Option<Decimal>, Option<Decimal>)> {
    let value = find_first_value_for_key(root, plan_code)?;
    let quota = value.as_object()?;
    let five_hour = quota
        .get("five_hour")
        .or_else(|| quota.get("fiveHour"))
        .and_then(scalar_decimal);
    let weekly = quota.get("weekly").and_then(scalar_decimal);
    (five_hour.is_some() || weekly.is_some()).then_some((five_hour, weekly))
}

fn quota_description(percent: Decimal, total: Decimal) -> String {
    let used = total * percent / Decimal::from(100_u8);
    format!(
        "{} / {} credits used",
        format_decimal(used),
        format_decimal(total)
    )
}

fn parse_legacy(root: &Value) -> Option<ParsedUsage> {
    let summary = find_legacy_summary(root)?;
    let total = any_decimal(summary, TOTAL_KEYS);
    let remaining = any_decimal(summary, REMAINING_KEYS);
    let used = any_decimal(summary, USED_KEYS).or_else(|| {
        total
            .zip(remaining)
            .map(|(total, remaining)| (total - remaining).max(Decimal::ZERO))
    });
    let reset =
        any_timestamp(summary, RESET_KEYS).or_else(|| find_first_timestamp(root, RESET_KEYS));
    let total_count = any_decimal(summary, COUNT_KEYS);
    let plan_name = any_string(summary, PLAN_KEYS)
        .map(str::to_owned)
        .or_else(|| find_first_string(root, PLAN_KEYS).map(str::to_owned))
        .or_else(|| {
            ((total_count.unwrap_or(Decimal::ZERO) > Decimal::ZERO) || total.is_some())
                .then(|| "TOKEN PLAN".to_owned())
        });
    if plan_name.is_none()
        && total.is_none()
        && used.is_none()
        && remaining.is_none()
        && total_count.is_none()
    {
        return None;
    }
    let primary = total
        .filter(|total| *total > Decimal::ZERO)
        .and_then(|total| {
            used.or_else(|| remaining.map(|remaining| total - remaining))
                .map(|used| (used.max(Decimal::ZERO).min(total), total))
        })
        .map(|(used, total)| ParsedWindow {
            percent: used * Decimal::from(100_u8) / total,
            duration_minutes: 30 * 24 * 60,
            resets_at: reset,
            description: Some(format!(
                "{} / {} credits used",
                format_decimal(used),
                format_decimal(total)
            )),
        });
    Some(ParsedUsage {
        plan_name,
        primary,
        secondary: None,
    })
}

const PLAN_KEYS: &[&str] = &[
    "planName",
    "plan_name",
    "packageName",
    "package_name",
    "commodityName",
    "commodity_name",
    "specType",
    "SpecType",
    "instanceName",
    "instance_name",
    "displayName",
    "display_name",
    "ProductName",
    "productName",
    "name",
    "title",
    "planType",
    "plan_type",
];
const USED_KEYS: &[&str] = &[
    "usedQuota",
    "used_quota",
    "usedCredits",
    "usedCredit",
    "consumedCredits",
    "usage",
    "used",
    "usedAmount",
    "consumeAmount",
    "usedValue",
    "UsedValue",
    "consumedValue",
    "ConsumedValue",
];
const TOTAL_KEYS: &[&str] = &[
    "totalQuota",
    "total_quota",
    "totalCredits",
    "totalCredit",
    "quota",
    "creditLimit",
    "creditsTotal",
    "monthlyTotalQuota",
    "amount",
    "totalValue",
    "TotalValue",
    "cycleTotalValue",
    "CycleTotalValue",
];
const REMAINING_KEYS: &[&str] = &[
    "remainingQuota",
    "remainQuota",
    "remainingCredits",
    "remainingCredit",
    "availableCredits",
    "balance",
    "remaining",
    "availableAmount",
    "remainAmount",
    "totalSurplusValue",
    "TotalSurplusValue",
    "surplusValue",
    "SurplusValue",
    "cycleSurplusValue",
    "CycleSurplusValue",
];
const COUNT_KEYS: &[&str] = &[
    "totalCount",
    "TotalCount",
    "subscriptionTotalNumber",
    "SubscriptionTotalNumber",
];
const RESET_KEYS: &[&str] = &[
    "nextRefreshTime",
    "resetTime",
    "periodEndTime",
    "billingCycleEnd",
    "billCycleEndTime",
    "expireTime",
    "expirationTime",
    "endTime",
    "validEndTime",
    "instanceEndTime",
    "EndTime",
    "cycleEndTime",
    "CycleEndTime",
    "nearestExpireDate",
    "NearestExpireDate",
];

fn find_legacy_summary(root: &Value) -> Option<&Map<String, Value>> {
    let quota_keys = USED_KEYS
        .iter()
        .chain(TOTAL_KEYS)
        .chain(REMAINING_KEYS)
        .copied()
        .collect::<Vec<_>>();
    if let Some(data) = find_first_object_value(
        root,
        &["Data", "data", "successResponse", "success_response"],
    ) && contains_any_key(
        data,
        &quota_keys
            .iter()
            .chain(COUNT_KEYS)
            .copied()
            .collect::<Vec<_>>(),
    ) {
        if contains_any_key(data, &quota_keys) {
            return Some(data);
        }
        if let Some(nested) = find_object_in_map_containing_any(data, &quota_keys) {
            return Some(nested);
        }
        return Some(data);
    }
    find_object_containing_any(
        root,
        &quota_keys
            .iter()
            .chain(COUNT_KEYS)
            .copied()
            .collect::<Vec<_>>(),
    )
}

fn find_object_in_map_containing_any<'a>(
    root: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    if contains_any_key(root, keys) {
        return Some(root);
    }
    let mut stack = root.values().rev().collect::<Vec<_>>();
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value
            && contains_any_key(object, keys)
        {
            return Some(object);
        }
        push_children(&mut stack, value);
    }
    None
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    parsed: ParsedUsage,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(primary) = parsed.primary {
        builder = builder.primary(normalize_window(primary)?);
    }
    if let Some(secondary) = parsed.secondary {
        builder = builder.secondary(normalize_window(secondary)?);
    }
    let plan_name = parsed.plan_name.and_then(|value| {
        let value = value.trim();
        (!value.is_empty() && value.len() <= MAX_PLAN_BYTES).then(|| value.to_owned())
    });
    builder
        .login_method(plan_name)?
        .provenance("qwencloud", "web")?
        .build()
}

fn normalize_window(parsed: ParsedWindow) -> Result<RateWindow, ClassifiedError> {
    let percent = parsed
        .percent
        .clamp(Decimal::ZERO, Decimal::from(100_u8))
        .to_f64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let percent = UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let duration = WindowDuration::from_provider_minutes(parsed.duration_minutes)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let description = parsed
        .description
        .map(BoundedText::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        parsed.resets_at,
        description,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_decimal(value: Decimal) -> String {
    let rounded = value.round_dp(2).normalize();
    let raw = rounded.to_string();
    let (sign, unsigned) = raw
        .strip_prefix('-')
        .map_or(("", raw.as_str()), |value| ("-", value));
    let (integer, fraction) = unsigned
        .split_once('.')
        .map_or((unsigned, None), |(integer, fraction)| {
            (integer, Some(fraction))
        });
    let mut output = String::with_capacity(raw.len() + raw.len() / 3);
    output.push_str(sign);
    for (index, character) in integer.chars().enumerate() {
        if index > 0 && (integer.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    if let Some(fraction) = fraction {
        output.push('.');
        output.push_str(fraction);
    }
    output
}

fn validate_payload_status(root: &Value) -> Result<(), ClassifiedError> {
    let Some(root_map) = root.as_object() else {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    };
    if root_map.get("successResponse").and_then(scalar_bool) == Some(false) {
        return classify_error_frame(root_map, None);
    }
    if let Some(frame) = find_failing_success_frame(root) {
        return classify_error_frame(frame, Some(root));
    }
    if let Some(status) = find_first_i64(root, &["statusCode", "status_code", "code"])
        && !matches!(status, 0 | 200)
    {
        return Err(ClassifiedError::new(if matches!(status, 401 | 403) {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::Api
        }));
    }
    let code = find_first_string(root, &["errorCode", "code", "status", "statusCode"]);
    let message = find_first_string(root, &["errorMsg", "message", "msg", "statusMessage"]);
    classify_text_signals(code, message)
}

fn classify_error_frame(
    frame: &Map<String, Value>,
    fallback_root: Option<&Value>,
) -> Result<(), ClassifiedError> {
    let value = Value::Object(frame.clone());
    let status = find_first_i64(&value, &["statusCode", "status_code", "code"]);
    if matches!(status, Some(401 | 403)) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let code = find_first_string(&value, &["errorCode", "Code", "code", "status"]).or_else(|| {
        fallback_root.and_then(|root| {
            find_first_string(root, &["errorCode", "Code", "code", "status", "statusCode"])
        })
    });
    let message = find_first_string(
        &value,
        &["errorMsg", "Message", "message", "msg", "statusMessage"],
    )
    .or_else(|| {
        fallback_root.and_then(|root| {
            find_first_string(
                root,
                &[
                    "errorMsg",
                    "Message",
                    "message",
                    "msg",
                    "statusMessage",
                    "Code",
                    "code",
                ],
            )
        })
    });
    classify_text_signals(code, message)?;
    Err(ClassifiedError::new(ErrorKind::Api))
}

fn classify_text_signals(code: Option<&str>, message: Option<&str>) -> Result<(), ClassifiedError> {
    let combined = [code, message]
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    if combined.contains("workspace.notauthorised") || combined.contains("workspace.notauthorized")
    {
        return Ok(());
    }
    if combined.contains("needlogin")
        || combined.contains("login")
        || combined.contains("postonlyortokenerror")
        || combined.contains("tokenerror")
        || combined.contains("request has expired")
        || combined.contains("refresh page")
        || combined.contains("请求已经过期")
        || combined.contains("notauthorised")
        || combined.contains("notauthorized")
        || combined.contains("not authorised")
        || combined.contains("not authorized")
        || combined.contains("unauthorised")
        || combined.contains("unauthorized")
        || combined.contains("access denied")
        || combined.contains("forbidden")
    {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    Ok(())
}

fn find_failing_success_frame(root: &Value) -> Option<&Map<String, Value>> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value
            && (object.get("success").and_then(scalar_bool) == Some(false)
                || object.get("Success").and_then(scalar_bool) == Some(false))
        {
            return Some(object);
        }
        push_children(&mut stack, value);
    }
    None
}

fn looks_like_login_html(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let text = text.to_ascii_lowercase();
    text.contains("<html")
        && (text.contains("login") || text.contains("sign in") || text.contains("signin"))
}

fn percentage_points(ratio: Decimal) -> Decimal {
    ratio.clamp(Decimal::ZERO, Decimal::ONE) * Decimal::from(100_u8)
}

fn contains_any_key(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter().any(|key| object.contains_key(*key))
}

fn any_decimal(object: &Map<String, Value>, keys: &[&str]) -> Option<Decimal> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_decimal))
}

fn any_string<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_string))
}

fn any_timestamp(object: &Map<String, Value>, keys: &[&str]) -> Option<Timestamp> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_timestamp))
}

fn find_first_string<'a>(root: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(value) = find_first_string_for_key(root, key) {
            return Some(value);
        }
    }
    None
}

fn find_first_string_for_key<'a>(root: &'a Value, expected: &str) -> Option<&'a str> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value {
            for (key, candidate) in object {
                if key.eq_ignore_ascii_case(expected)
                    && let Some(candidate) = scalar_string(candidate)
                {
                    return Some(candidate);
                }
            }
        }
        push_children(&mut stack, value);
    }
    None
}

fn find_first_value_for_key<'a>(root: &'a Value, expected: &str) -> Option<&'a Value> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value {
            for (key, candidate) in object {
                if key.eq_ignore_ascii_case(expected) {
                    return Some(candidate);
                }
            }
        }
        push_children(&mut stack, value);
    }
    None
}

fn find_first_i64(root: &Value, keys: &[&str]) -> Option<i64> {
    for key in keys {
        if let Some(value) = find_first_i64_for_key(root, key) {
            return Some(value);
        }
    }
    None
}

fn find_first_i64_for_key(root: &Value, expected: &str) -> Option<i64> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value {
            for (key, candidate) in object {
                if key.eq_ignore_ascii_case(expected)
                    && let Some(candidate) = scalar_i64(candidate)
                {
                    return Some(candidate);
                }
            }
        }
        push_children(&mut stack, value);
    }
    None
}

fn find_first_timestamp(root: &Value, keys: &[&str]) -> Option<Timestamp> {
    for key in keys {
        if let Some(value) = find_first_timestamp_for_key(root, key) {
            return Some(value);
        }
    }
    None
}

fn find_first_timestamp_for_key(root: &Value, expected: &str) -> Option<Timestamp> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value {
            for (key, candidate) in object {
                if key.eq_ignore_ascii_case(expected)
                    && let Some(candidate) = scalar_timestamp(candidate)
                {
                    return Some(candidate);
                }
            }
        }
        push_children(&mut stack, value);
    }
    None
}

fn find_first_object_value<'a>(root: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value {
            for key in keys {
                if let Some(Value::Object(found)) = object.get(*key) {
                    return Some(found);
                }
            }
        }
        push_children(&mut stack, value);
    }
    None
}

fn find_object_containing_any<'a>(
    root: &'a Value,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(object) = value
            && keys.iter().any(|key| object.contains_key(*key))
        {
            return Some(object);
        }
        push_children(&mut stack, value);
    }
    None
}

fn push_children<'a>(stack: &mut Vec<&'a Value>, value: &'a Value) {
    match value {
        Value::Array(values) => stack.extend(values.iter().rev()),
        Value::Object(values) => stack.extend(values.values().rev()),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn scalar_decimal(value: &Value) -> Option<Decimal> {
    match value {
        Value::Number(value) => value.to_string().parse().ok(),
        Value::String(value) => value.trim().replace(',', "").parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

fn scalar_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(value) => Some(i64::from(*value)),
        Value::Number(_) | Value::String(_) => scalar_decimal(value)?.trunc().to_i64(),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn scalar_string(value: &Value) -> Option<&str> {
    let Value::String(value) = value else {
        return None;
    };
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_TOKEN_BYTES.max(MAX_PLAN_BYTES)).then_some(value)
}

fn scalar_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value
            .to_string()
            .parse::<Decimal>()
            .ok()
            .map(|value| !value.is_zero()),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "active" | "valid" | "normal" => Some(true),
            "false" | "0" | "no" | "inactive" | "invalid" | "expired" => Some(false),
            _ => None,
        },
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn scalar_timestamp(value: &Value) -> Option<Timestamp> {
    if let Some(number) = scalar_decimal(value)
        && number > Decimal::ZERO
    {
        let seconds = if number >= Decimal::from(1_000_000_000_000_i64) {
            number / Decimal::from(1_000_u16)
        } else {
            number
        };
        let nanos = (seconds * Decimal::from(1_000_000_000_u64))
            .trunc()
            .to_i128()?;
        return OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .ok()
            .and_then(|value| Timestamp::new(value).ok());
    }
    let Value::String(value) = value else {
        return None;
    };
    let value = value.trim();
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Timestamp::new(timestamp).ok();
    }
    for pattern in [
        "[year]-[month]-[day] [hour]:[minute]:[second]",
        "[year]-[month]-[day] [hour]:[minute]",
    ] {
        let format = time::format_description::parse_borrowed::<3>(pattern).ok()?;
        if let Ok(timestamp) = PrimitiveDateTime::parse(value, &format) {
            return Timestamp::new(timestamp.assume_utc()).ok();
        }
    }
    let format = time::format_description::parse_borrowed::<3>("[year]-[month]-[day]").ok()?;
    Date::parse(value, &format).ok().and_then(|date| {
        Timestamp::new(PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc()).ok()
    })
}

enum ExpandTask {
    Visit {
        value: Value,
        depth: usize,
        embedded_layers: usize,
    },
    FinishArray(usize),
    FinishObject(Vec<String>),
}

fn parse_bounded_json(body: &[u8]) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let mut tasks = vec![ExpandTask::Visit {
        value: root,
        depth: 0,
        embedded_layers: 0,
    }];
    let mut results = Vec::new();
    let mut nodes = 0_usize;
    while let Some(task) = tasks.pop() {
        match task {
            ExpandTask::Visit {
                value,
                depth,
                embedded_layers,
            } => {
                nodes = nodes
                    .checked_add(1)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                match value {
                    Value::String(value) => {
                        if value.len() > MAX_JSON_STRING_BYTES {
                            return Err(ClassifiedError::new(ErrorKind::Parse));
                        }
                        let trimmed = value.trim();
                        if matches!(trimmed.as_bytes().first(), Some(b'{' | b'[')) {
                            if embedded_layers == MAX_EMBEDDED_JSON_LAYERS {
                                return Err(ClassifiedError::new(ErrorKind::Parse));
                            }
                            if let Ok(expanded) = serde_json::from_str::<Value>(trimmed) {
                                tasks.push(ExpandTask::Visit {
                                    value: expanded,
                                    depth,
                                    embedded_layers: embedded_layers + 1,
                                });
                                continue;
                            }
                        }
                        results.push(Value::String(value));
                    }
                    Value::Array(values) => {
                        let length = values.len();
                        tasks.push(ExpandTask::FinishArray(length));
                        tasks.extend(values.into_iter().rev().map(|value| ExpandTask::Visit {
                            value,
                            depth: depth + 1,
                            embedded_layers,
                        }));
                    }
                    Value::Object(values) => {
                        if values.keys().any(|key| key.len() > MAX_JSON_STRING_BYTES) {
                            return Err(ClassifiedError::new(ErrorKind::Parse));
                        }
                        let (keys, nested): (Vec<_>, Vec<_>) = values.into_iter().unzip();
                        tasks.push(ExpandTask::FinishObject(keys));
                        tasks.extend(nested.into_iter().rev().map(|value| ExpandTask::Visit {
                            value,
                            depth: depth + 1,
                            embedded_layers,
                        }));
                    }
                    Value::Null | Value::Bool(_) | Value::Number(_) => results.push(value),
                }
            }
            ExpandTask::FinishArray(length) => {
                let start = results
                    .len()
                    .checked_sub(length)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                let values = results.split_off(start);
                results.push(Value::Array(values));
            }
            ExpandTask::FinishObject(keys) => {
                let start = results
                    .len()
                    .checked_sub(keys.len())
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                let values = results.split_off(start);
                results.push(Value::Object(keys.into_iter().zip(values).collect()));
            }
        }
    }
    if results.len() != 1 {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    results
        .pop()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}
