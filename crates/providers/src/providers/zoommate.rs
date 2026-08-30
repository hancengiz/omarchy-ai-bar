//! `ZoomMate` credit status, browser-session token minting, and credit history.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage,
    CostUsageDailyBucket, CostUsageMetrics, CostUsageSnapshot, CostUsageTokenMix, DetailChart,
    DetailChartKind, DetailChartPoint, DetailRow, DetailSection, DetailSensitivity, ErrorKind,
    ExactDecimal, FiniteNumber, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample,
    WindowUsage,
};
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION, COOKIE, HeaderMap, HeaderName, HeaderValue, ORIGIN,
    REFERER, USER_AGENT,
};
use reqwest::{Client, StatusCode};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration as TimeDuration, OffsetDateTime, UtcOffset};
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{
    CookieImport, CookieImportOrder, CookieJar, CookieSourceId, CookieUrlPolicy, ValidatedCookieUrl,
};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;

const WEB_ORIGIN: &str = "https://zoommate.zoom.us";
const PRIMARY_API_ORIGIN: &str = "https://ai.zoom.us";
const ALTERNATE_API_ORIGIN: &str = "https://zoommate.zoom.us";
const STATUS_PATH: &str = "/ai-computer/api/v1/credits/status";
const HISTORY_PATH: &str = "/ai-computer/api/v1/credits/history";
const LOGIN_PATH: &str = "/ai-computer/api/v1/login/";
const USER_AGENT_VALUE: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const ACCEPT_VALUE: &str = "application/json, text/plain, */*";
const ACCEPT_LANGUAGE_VALUE: &str = "en-US,en;q=0.9";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_JSON_KEY_BYTES: usize = 512;
const MAX_CREDIT_MAGNITUDE: i64 = 1_000_000_000_000_000;
const MAX_RECORD_TEXT_BYTES: usize = 4 * 1024;
const HISTORY_DAYS: u16 = 30;
const HISTORY_PAGE_LIMIT: usize = 50;
const MAX_HISTORY_PAGES: usize = 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
const TOKEN_REFRESH_SKEW_SECONDS: i64 = 60;
const MAX_BROWSER_SESSIONS: usize = 64;

const FORWARDED_MANUAL_HEADERS: [&str; 6] = [
    "accept",
    "accept-language",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "user-agent",
];

#[derive(Clone)]
struct ApiRoutes {
    origin: Url,
    status: Url,
    history: Url,
    login: Url,
}

impl ApiRoutes {
    fn new(origin: Url) -> Result<Self, ClassifiedError> {
        let origin = bare_origin(origin)?;
        let status = fixed_path(origin.clone(), STATUS_PATH)?;
        let history = fixed_path(origin.clone(), HISTORY_PATH)?;
        let mut login = fixed_path(origin.clone(), LOGIN_PATH)?;
        login
            .query_pairs_mut()
            .append_pair("continue", "https://zoommate.zoom.us/");
        Ok(Self {
            origin,
            status,
            history,
            login,
        })
    }
}

/// Fixed `ZoomMate` endpoint table. Production construction accepts only the two
/// first-party HTTPS origins; the loopback constructor is an isolated test seam.
#[derive(Clone)]
pub struct ZoomMateRouteSet {
    hosts: [ApiRoutes; 2],
    class: EndpointClass,
}

impl ZoomMateRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origins(
            Url::parse(PRIMARY_API_ORIGIN).map_err(|_| api_error())?,
            Url::parse(ALTERNATE_API_ORIGIN).map_err(|_| api_error())?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates an exact two-origin loopback route table for deterministic tests.
    /// Supplied paths, queries, and fragments are discarded.
    ///
    /// # Errors
    ///
    /// Returns a stable API error unless both inputs are valid loopback origins.
    #[doc(hidden)]
    pub fn loopback(primary_origin: Url, alternate_origin: Url) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            primary_origin,
            alternate_origin,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        primary_origin: Url,
        alternate_origin: Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let routes = Self {
            hosts: [
                ApiRoutes::new(primary_origin)?,
                ApiRoutes::new(alternate_origin)?,
            ],
            class,
        };
        routes.validate()?;
        Ok(routes)
    }

    fn validate(&self) -> Result<(), ClassifiedError> {
        if !matches!(
            self.class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) || self.hosts[0].origin.origin() == self.hosts[1].origin.origin()
        {
            return Err(api_error());
        }
        if self.class == EndpointClass::PublicHttps
            && (!same_origin(&self.hosts[0].origin, PRIMARY_API_ORIGIN)?
                || !same_origin(&self.hosts[1].origin, ALTERNATE_API_ORIGIN)?)
        {
            return Err(api_error());
        }
        let policy = self.endpoint_policy()?;
        for host in &self.hosts {
            if host.status.path() != STATUS_PATH
                || host.history.path() != HISTORY_PATH
                || host.login.path() != LOGIN_PATH
                || host.status.query().is_some()
                || host.history.query().is_some()
                || host.login.query_pairs().count() != 1
            {
                return Err(api_error());
            }
            policy
                .validate(&host.status)
                .and_then(|_| policy.validate(&host.history))
                .and_then(|_| policy.validate(&host.login))
                .map_err(|_| api_error())?;
            self.cookie_target(&host.status)?;
            self.cookie_target(&host.history)?;
            self.cookie_target(&host.login)?;
        }
        Ok(())
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        EndpointPolicy::new(
            self.hosts
                .iter()
                .map(|host| (host.origin.origin().ascii_serialization(), self.class)),
        )
        .map_err(|_| api_error())
    }

    fn cookie_target(&self, url: &Url) -> Result<ValidatedCookieUrl, ClassifiedError> {
        let policy = if self.class == EndpointClass::LoopbackDevelopment {
            CookieUrlPolicy::LoopbackHttp
        } else {
            CookieUrlPolicy::HttpsOnly
        };
        ValidatedCookieUrl::new(url.clone(), policy).map_err(|_| api_error())
    }
}

impl Debug for ZoomMateRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZoomMateRouteSet")
            .field("hosts", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

struct ForwardedHeader {
    name: HeaderName,
    value: Zeroizing<String>,
}

struct BrowserCredential {
    sessions: Vec<BrowserSessionCredential>,
}

struct BrowserSessionCredential {
    cookies: [BrowserHostCookies; 2],
    cache: Mutex<Option<CachedBearer>>,
}

struct BrowserHostCookies {
    login: Option<Zeroizing<String>>,
    status: Option<Zeroizing<String>>,
    history: Option<Zeroizing<String>>,
}

#[derive(Clone, Copy)]
enum RequestKind {
    Login,
    Status,
    History,
}

struct CachedBearer {
    token: Zeroizing<String>,
    email: Option<String>,
    expires_at: OffsetDateTime,
}

enum Credential {
    Manual {
        token: Zeroizing<String>,
        cookies: [Option<Zeroizing<String>>; 2],
        forwarded_headers: Vec<ForwardedHeader>,
        preferred_host: usize,
    },
    Browser(BrowserCredential),
}

impl Credential {
    fn cookie(&self, host: usize, _request: RequestKind) -> Option<&str> {
        match self {
            Self::Manual { cookies, .. } => cookies[host].as_ref().map(|cookie| cookie.as_str()),
            Self::Browser(_) => None,
        }
    }

    fn browser_cookie(&self, session: usize, host: usize, request: RequestKind) -> Option<&str> {
        let Self::Browser(browser) = self else {
            return None;
        };
        let cookies = &browser.sessions.get(session)?.cookies[host];
        match request {
            RequestKind::Login => cookies.login.as_ref().map(|cookie| cookie.as_str()),
            RequestKind::Status => cookies.status.as_ref().map(|cookie| cookie.as_str()),
            RequestKind::History => cookies.history.as_ref().map(|cookie| cookie.as_str()),
        }
    }

    fn forwarded_headers(&self) -> &[ForwardedHeader] {
        match self {
            Self::Manual {
                forwarded_headers, ..
            } => forwarded_headers,
            Self::Browser(_) => &[],
        }
    }

    fn host_order(&self) -> [usize; 2] {
        match self {
            Self::Manual { preferred_host, .. } if *preferred_host == 1 => [1, 0],
            Self::Manual { .. } | Self::Browser(_) => [0, 1],
        }
    }
}

struct ResolvedBearer {
    token: Zeroizing<String>,
    email: Option<String>,
    browser_session: Option<usize>,
}

/// `ZoomMate` adapter permanently bound to one account and one credential source.
pub struct ZoomMateProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: ZoomMateRouteSet,
    credential: Credential,
    transport: ZoomMateTransport,
}

impl ZoomMateProvider {
    /// Creates a production adapter from an exact `ZoomMate` `credits/status`
    /// cURL capture containing an Authorization header.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, capture, scope, or endpoint error.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, ZoomMateRouteSet::production()?)
    }

    /// Creates a manual adapter using an injected route table.
    ///
    /// # Errors
    ///
    /// Returns the same stable errors as [`Self::new_manual`].
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: ZoomMateRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(
            ["ai.zoom.us", "zoommate.zoom.us"],
            [CaptureHeader::Authorization, CaptureHeader::Cookie],
        )
        .map_err(classify_capture_error)?
        .with_forwarded_headers(FORWARDED_MANUAL_HEADERS)
        .map_err(classify_capture_error)?;
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let captured_url = capture.url().ok_or_else(parse_error)?;
        if captured_url.path() != STATUS_PATH || captured_url.query().is_some() {
            return Err(parse_error());
        }
        let preferred_host = match captured_url.host_str() {
            Some(host) if host.eq_ignore_ascii_case("ai.zoom.us") => 0,
            Some(host) if host.eq_ignore_ascii_case("zoommate.zoom.us") => 1,
            _ => return Err(parse_error()),
        };
        let token = capture
            .header(CaptureHeader::Authorization)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let token = normalize_bearer_token(token)?;
        let mut cookies: [Option<Zeroizing<String>>; 2] = [None, None];
        if let Some(raw_cookie) = capture.header(CaptureHeader::Cookie) {
            let target = ValidatedCookieUrl::new(captured_url.clone(), CookieUrlPolicy::HttpsOnly)
                .map_err(|_| parse_error())?;
            cookies[preferred_host] = Some(normalize_manual_cookie(raw_cookie, &target)?);
        }
        let forwarded_headers = capture
            .forwarded_headers()
            .map(|(name, value)| {
                let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| parse_error())?;
                HeaderValue::from_str(value).map_err(|_| parse_error())?;
                Ok(ForwardedHeader {
                    name,
                    value: Zeroizing::new(value.to_owned()),
                })
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            routes,
            Credential::Manual {
                token,
                cookies,
                forwarded_headers,
                preferred_host,
            },
        )
    }

    /// Creates a production adapter from one already imported Linux browser
    /// cookie jar. Browser discovery and decryption remain host-owned.
    ///
    /// # Errors
    ///
    /// Returns missing-credential for an empty jar and authentication-expired
    /// when no active cookie reaches either fixed API host.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::new_browser_sessions(scope, &[jar], now)
    }

    /// Creates a production browser adapter from isolated profile jars in
    /// deterministic preference order.
    ///
    /// # Errors
    ///
    /// Returns stable bounded-session, cookie, scope, or endpoint failures.
    pub fn new_browser_sessions(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jars_routes(scope, jars, now, ZoomMateRouteSet::production()?)
    }

    /// Creates a browser adapter using an injected route table.
    ///
    /// # Errors
    ///
    /// Returns stable cookie, source, scope, or endpoint failures.
    #[doc(hidden)]
    pub fn from_browser_jar_routes(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        routes: ZoomMateRouteSet,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jars_routes(scope, &[jar], now, routes)
    }

    /// Creates a browser adapter from isolated profile jars and injected routes.
    /// A rejected login advances to the next profile; other failures remain
    /// terminal so another account cannot hide them.
    ///
    /// # Errors
    ///
    /// Returns stable bounded-session, cookie, scope, or endpoint failures.
    #[doc(hidden)]
    pub fn from_browser_jars_routes(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
        routes: ZoomMateRouteSet,
    ) -> Result<Self, ClassifiedError> {
        if jars.len() > MAX_BROWSER_SESSIONS {
            return Err(api_error());
        }
        let any_records = jars.iter().any(|jar| !jar.is_empty());
        let mut sessions = Vec::with_capacity(jars.len());
        for jar in jars {
            let cookies = [
                browser_host_cookies(&routes, &routes.hosts[0], jar, now)?,
                browser_host_cookies(&routes, &routes.hosts[1], jar, now)?,
            ];
            if cookies.iter().any(|cookies| cookies.login.is_some()) {
                sessions.push(BrowserSessionCredential {
                    cookies,
                    cache: Mutex::new(None),
                });
            }
        }
        if sessions.is_empty() {
            return Err(ClassifiedError::new(if any_records {
                ErrorKind::AuthenticationExpired
            } else {
                ErrorKind::MissingCredential
            }));
        }
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            routes,
            Credential::Browser(BrowserCredential { sessions }),
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: ZoomMateRouteSet,
        credential: Credential,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::ZoomMate
            || !matches!(
                (&credential, source),
                (Credential::Manual { .. }, ProviderSource::ManualCookie)
                    | (Credential::Browser(_), ProviderSource::BrowserSession)
            )
        {
            return Err(api_error());
        }
        routes.validate()?;
        let transport = ZoomMateTransport::new(routes.endpoint_policy()?)?;
        Ok(Self {
            scope,
            source,
            routes,
            credential,
            transport,
        })
    }

    /// Credential source permanently bound to this adapter.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Fetches the required credit status and best-effort 30-day history.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, API, or bounded
    /// parse failures. History failures do not discard valid current status;
    /// cooperative cancellation always wins.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.fetch_at_with_timeout(context, fetched_at, TOTAL_TIMEOUT)
            .await
    }

    /// Fetches with an injected total deadline for deterministic tests.
    ///
    /// # Errors
    ///
    /// Returns the same stable errors as [`Self::fetch_at`].
    #[doc(hidden)]
    pub async fn fetch_at_with_timeout(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        timeout: Duration,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source || timeout.is_zero() {
            return Err(api_error());
        }
        if context.cancellation().is_cancelled() {
            return Err(network_error());
        }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(api_error)?;
        let bearer = self.resolve_bearer(context, fetched_at, deadline).await?;
        let status = match self
            .fetch_status(context, &bearer.token, bearer.browser_session, deadline)
            .await
        {
            Ok(status) => status,
            Err(error) => {
                if error.kind() == ErrorKind::AuthenticationExpired {
                    self.invalidate_cached_bearer(bearer.browser_session).await;
                }
                return Err(error);
            }
        };

        let history = match self
            .fetch_history(
                context,
                &bearer.token,
                bearer.browser_session,
                fetched_at,
                deadline,
            )
            .await
        {
            Ok(history) => Some(history),
            Err(error) if context.cancellation().is_cancelled() => return Err(error),
            Err(error) => {
                if error.kind() == ErrorKind::AuthenticationExpired {
                    self.invalidate_cached_bearer(bearer.browser_session).await;
                }
                None
            }
        };
        normalize_usage(
            self.scope.clone(),
            fetched_at,
            self.source,
            &status,
            history.as_ref(),
            bearer.email,
            None,
        )
    }

    async fn resolve_bearer(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        deadline: Instant,
    ) -> Result<ResolvedBearer, ClassifiedError> {
        match &self.credential {
            Credential::Manual { token, .. } => Ok(ResolvedBearer {
                token: token.clone(),
                email: None,
                browser_session: None,
            }),
            Credential::Browser(browser) => {
                let now = fetched_at.as_offset_date_time();
                for (session_index, session) in browser.sessions.iter().enumerate() {
                    let mut cache = session.cache.lock().await;
                    if let Some(entry) = cache.as_ref() {
                        let refresh_boundary = entry
                            .expires_at
                            .checked_sub(TimeDuration::seconds(TOKEN_REFRESH_SKEW_SECONDS));
                        if refresh_boundary.is_some_and(|boundary| boundary > now) {
                            return Ok(ResolvedBearer {
                                token: entry.token.clone(),
                                email: entry.email.clone(),
                                browser_session: Some(session_index),
                            });
                        }
                    }
                    *cache = None;
                    drop(cache);

                    match self.mint_bearer(context, deadline, session_index).await {
                        Ok(mut minted) => {
                            minted.browser_session = Some(session_index);
                            if let Some(expires_at) = expiry_from_jwt(minted.token.as_str()) {
                                *session.cache.lock().await = Some(CachedBearer {
                                    token: minted.token.clone(),
                                    email: minted.email.clone(),
                                    expires_at,
                                });
                            }
                            return Ok(minted);
                        }
                        Err(error) if error.kind() == ErrorKind::AuthenticationExpired => {
                            if context.cancellation().is_cancelled() {
                                return Err(network_error());
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(ClassifiedError::new(ErrorKind::AuthenticationExpired))
            }
        }
    }

    async fn invalidate_cached_bearer(&self, session: Option<usize>) {
        if let (Credential::Browser(browser), Some(session)) = (&self.credential, session)
            && let Some(session) = browser.sessions.get(session)
        {
            *session.cache.lock().await = None;
        }
    }

    fn request_cookie(
        &self,
        browser_session: Option<usize>,
        host: usize,
        request: RequestKind,
    ) -> Option<&str> {
        match &self.credential {
            Credential::Manual { .. } => self.credential.cookie(host, request),
            Credential::Browser(_) => browser_session
                .and_then(|session| self.credential.browser_cookie(session, host, request)),
        }
    }

    async fn mint_bearer(
        &self,
        context: &ProviderContext,
        deadline: Instant,
        browser_session: usize,
    ) -> Result<ResolvedBearer, ClassifiedError> {
        let mut last_error = None;
        for index in self.credential.host_order() {
            let host = &self.routes.hosts[index];
            let result = self
                .transport
                .get(
                    host.login.clone(),
                    None,
                    self.credential
                        .browser_cookie(browser_session, index, RequestKind::Login),
                    self.credential.forwarded_headers(),
                    context,
                    deadline,
                )
                .await;
            match result {
                Ok(body) => return parse_login_response(&body),
                Err(error) if no_host_fallback(&error, context) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(api_error))
    }

    async fn fetch_status(
        &self,
        context: &ProviderContext,
        bearer: &str,
        browser_session: Option<usize>,
        deadline: Instant,
    ) -> Result<CreditStatus, ClassifiedError> {
        let mut last_error = None;
        for index in self.credential.host_order() {
            let host = &self.routes.hosts[index];
            let result = self
                .transport
                .get(
                    host.status.clone(),
                    Some(bearer),
                    self.request_cookie(browser_session, index, RequestKind::Status),
                    self.credential.forwarded_headers(),
                    context,
                    deadline,
                )
                .await;
            match result {
                Ok(body) => return parse_status_response(&body),
                Err(error) if no_host_fallback(&error, context) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(api_error))
    }

    async fn fetch_history(
        &self,
        context: &ProviderContext,
        bearer: &str,
        browser_session: Option<usize>,
        fetched_at: Timestamp,
        deadline: Instant,
    ) -> Result<HistorySnapshot, ClassifiedError> {
        let mut last_error = None;
        for index in self.credential.host_order() {
            match self
                .fetch_history_from_host(
                    context,
                    bearer,
                    browser_session,
                    fetched_at,
                    deadline,
                    index,
                )
                .await
            {
                Ok(history) => return Ok(history),
                Err(error) if no_host_fallback(&error, context) => return Err(error),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(api_error))
    }

    async fn fetch_history_from_host(
        &self,
        context: &ProviderContext,
        bearer: &str,
        browser_session: Option<usize>,
        fetched_at: Timestamp,
        deadline: Instant,
        host_index: usize,
    ) -> Result<HistorySnapshot, ClassifiedError> {
        let host = &self.routes.hosts[host_index];
        let end = fetched_at.as_offset_date_time();
        let start = end
            .checked_sub(TimeDuration::days(i64::from(HISTORY_DAYS)))
            .ok_or_else(parse_error)?;
        let start_text = start.format(&Rfc3339).map_err(|_| parse_error())?;
        let end_text = end.format(&Rfc3339).map_err(|_| parse_error())?;
        let mut records = Vec::new();
        let mut total = i64::MAX;
        let mut page = 0_usize;
        let mut coverage_established = true;

        while page
            .checked_mul(HISTORY_PAGE_LIMIT)
            .and_then(|offset| i64::try_from(offset).ok())
            .is_some_and(|offset| offset < total)
            && page < MAX_HISTORY_PAGES
        {
            let mut url = host.history.clone();
            url.query_pairs_mut().extend_pairs([
                ("app_id", "demo_app".to_owned()),
                ("limit", HISTORY_PAGE_LIMIT.to_string()),
                ("page", page.to_string()),
                ("sort_by", "time".to_owned()),
                ("sort_order", "desc".to_owned()),
                ("start_time", start_text.clone()),
                ("end_time", end_text.clone()),
            ]);
            let body = self
                .transport
                .get(
                    url,
                    Some(bearer),
                    self.request_cookie(browser_session, host_index, RequestKind::History),
                    self.credential.forwarded_headers(),
                    context,
                    deadline,
                )
                .await?;
            let parsed = parse_history_page(&body)?;
            if records
                .len()
                .checked_add(parsed.records.len())
                .is_none_or(|count| count > MAX_HISTORY_PAGES * HISTORY_PAGE_LIMIT)
            {
                return Err(parse_error());
            }
            let page_is_empty = parsed.records.is_empty();
            let all_older = !page_is_empty
                && parsed.records.iter().all(|record| {
                    record
                        .time
                        .as_deref()
                        .and_then(parse_record_time)
                        .is_some_and(|timestamp| timestamp < start)
                });
            records.extend(parsed.records);
            total = parsed
                .total
                .unwrap_or(i64::try_from(records.len()).map_err(|_| parse_error())?);
            if page_is_empty || all_older {
                break;
            }
            page = page.checked_add(1).ok_or_else(parse_error)?;
        }
        if page == MAX_HISTORY_PAGES
            && page
                .checked_mul(HISTORY_PAGE_LIMIT)
                .and_then(|offset| i64::try_from(offset).ok())
                .is_some_and(|offset| offset < total)
        {
            coverage_established = false;
        }
        Ok(HistorySnapshot {
            records,
            coverage_established,
        })
    }
}

impl ProviderAdapter for ZoomMateProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::ZoomMate)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for ZoomMateProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZoomMateProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("credential", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

fn browser_host_cookies(
    routes: &ZoomMateRouteSet,
    host: &ApiRoutes,
    jar: &CookieJar,
    now: OffsetDateTime,
) -> Result<BrowserHostCookies, ClassifiedError> {
    Ok(BrowserHostCookies {
        login: browser_cookie_for(routes, &host.login, jar, now)?,
        status: browser_cookie_for(routes, &host.status, jar, now)?,
        history: browser_cookie_for(routes, &host.history, jar, now)?,
    })
}

fn browser_cookie_for(
    routes: &ZoomMateRouteSet,
    url: &Url,
    jar: &CookieJar,
    now: OffsetDateTime,
) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
    let target = routes.cookie_target(url)?;
    jar.header_for(&target, now)
        .map(|header| header.map(|value| Zeroizing::new(value.expose().to_owned())))
        .map_err(|_| api_error())
}

struct ZoomMateTransport {
    client: Client,
    policy: EndpointPolicy,
}

impl ZoomMateTransport {
    fn new(policy: EndpointPolicy) -> Result<Self, ClassifiedError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.error("ZoomMate redirect limit exceeded");
                }
                let same_origin = attempt
                    .previous()
                    .first()
                    .is_some_and(|original| original.origin() == attempt.url().origin());
                if same_origin {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|_| api_error())?;
        Ok(Self { client, policy })
    }

    #[allow(clippy::too_many_arguments)]
    async fn get(
        &self,
        url: Url,
        bearer: Option<&str>,
        cookie: Option<&str>,
        forwarded_headers: &[ForwardedHeader],
        context: &ProviderContext,
        deadline: Instant,
    ) -> Result<Vec<u8>, ClassifiedError> {
        let endpoint = self.policy.validate(&url).map_err(|_| api_error())?;
        let mut headers = default_headers();
        for header in forwarded_headers {
            headers.insert(
                header.name.clone(),
                HeaderValue::from_str(header.value.as_str()).map_err(|_| parse_error())?,
            );
        }
        headers.insert(ORIGIN, HeaderValue::from_static(WEB_ORIGIN));
        headers.insert(REFERER, HeaderValue::from_static(WEB_ORIGIN));
        if let Some(bearer) = bearer {
            let value = Zeroizing::new(format!("Bearer {bearer}"));
            headers.insert(AUTHORIZATION, sensitive_header(value.as_str())?);
        }
        if let Some(cookie) = cookie {
            headers.insert(COOKIE, sensitive_header(cookie)?);
        }
        let request = self.client.get(endpoint.url().clone()).headers(headers);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(network_error());
        }
        let request_timeout = remaining.min(REQUEST_TIMEOUT);
        let future = async {
            let response = request.send().await.map_err(|_| network_error())?;
            classify_and_read(response).await
        };
        tokio::select! {
            biased;
            () = context.cancellation().cancelled() => Err(network_error()),
            result = tokio::time::timeout(request_timeout, future) => {
                result.unwrap_or_else(|_| Err(network_error()))
            }
        }
    }
}

async fn classify_and_read(response: reqwest::Response) -> Result<Vec<u8>, ClassifiedError> {
    let status = response.status();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if status != StatusCode::OK {
        return Err(api_error());
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
        let chunk = chunk.map_err(|_| network_error())?;
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

fn default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_VALUE));
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static(ACCEPT_LANGUAGE_VALUE),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    for (name, value) in [
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-site"),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers
}

#[derive(Clone)]
struct CreditStatus {
    budget_cap: Option<Decimal>,
    used_credit: Option<Decimal>,
    _remaining_credit: Option<Decimal>,
    _overage_credit: Option<Decimal>,
    _allow_overage: Option<bool>,
    cycle_start_millis: Option<i64>,
    cycle_end_millis: Option<i64>,
    _quota_available: Option<bool>,
    unlimited: Option<bool>,
}

struct HistoryRecord {
    _session_id: Option<String>,
    _title: Option<String>,
    cost: Option<Decimal>,
    time: Option<String>,
    _running: Option<bool>,
    deleted: Option<bool>,
}

struct HistoryPage {
    records: Vec<HistoryRecord>,
    total: Option<i64>,
}

struct HistorySnapshot {
    records: Vec<HistoryRecord>,
    coverage_established: bool,
}

struct DailyCredits {
    amount: Decimal,
    record_count: u64,
}

struct HistoryNormalization {
    today: Decimal,
    total: Decimal,
    daily: Vec<(String, DailyCredits)>,
    cost_usage: CostUsageSnapshot,
}

/// Parses deterministic status and optional single-page history fixtures with
/// the same normalization used by the network adapter.
///
/// # Errors
///
/// Returns stable scope, source, bounded-JSON, or domain-normalization errors.
pub fn parse_zoommate_responses(
    scope: AccountScope,
    fetched_at: Timestamp,
    status_body: &[u8],
    history_body: Option<&[u8]>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    parse_zoommate_responses_with_optional_offset(
        scope,
        fetched_at,
        status_body,
        history_body,
        source,
        None,
    )
}

/// Parses deterministic responses using a fixed local-calendar offset.
/// This is a test seam for timezone-boundary behavior; production fetches use
/// the operating system timezone at each record instant.
///
/// # Errors
///
/// Returns the same stable failures as [`parse_zoommate_responses`].
#[doc(hidden)]
pub fn parse_zoommate_responses_with_calendar_offset(
    scope: AccountScope,
    fetched_at: Timestamp,
    status_body: &[u8],
    history_body: Option<&[u8]>,
    source: ProviderSource,
    calendar_offset: UtcOffset,
) -> Result<UsageSample, ClassifiedError> {
    parse_zoommate_responses_with_optional_offset(
        scope,
        fetched_at,
        status_body,
        history_body,
        source,
        Some(calendar_offset),
    )
}

fn parse_zoommate_responses_with_optional_offset(
    scope: AccountScope,
    fetched_at: Timestamp,
    status_body: &[u8],
    history_body: Option<&[u8]>,
    source: ProviderSource,
    calendar_offset: Option<UtcOffset>,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope_source(&scope, source)?;
    let status = parse_status_response(status_body)?;
    let history = history_body
        .map(parse_history_page)
        .transpose()?
        .map(|page| {
            let coverage_established = page.total.is_none_or(|total| {
                i64::try_from(page.records.len()).is_ok_and(|count| count >= total)
            });
            HistorySnapshot {
                records: page.records,
                coverage_established,
            }
        });
    normalize_usage(
        scope,
        fetched_at,
        source,
        &status,
        history.as_ref(),
        None,
        calendar_offset,
    )
}

fn parse_status_response(body: &[u8]) -> Result<CreditStatus, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let root = root.as_object().ok_or_else(parse_error)?;
    validate_optional_integer(root, "status_code")?;
    validate_optional_text(root, "error_message")?;
    let status = root
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("credit_status"))
        .and_then(Value::as_object)
        .ok_or_else(parse_error)?;
    Ok(CreditStatus {
        budget_cap: optional_number(status, "budget_cap")?,
        used_credit: optional_number(status, "used_credit")?,
        _remaining_credit: optional_number(status, "remaining_credit")?,
        _overage_credit: optional_number(status, "overage_credit")?,
        _allow_overage: optional_bool(status, "allow_overage")?,
        cycle_start_millis: optional_integer(status, "cycle_start_date")?,
        cycle_end_millis: optional_integer(status, "cycle_end_date")?,
        _quota_available: optional_bool(status, "is_quota_available")?,
        unlimited: optional_bool(status, "is_unlimited")?,
    })
}

fn parse_login_response(body: &[u8]) -> Result<ResolvedBearer, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let root = root.as_object().ok_or_else(parse_error)?;
    validate_optional_bool(root, "success")?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(parse_error)?;
    let raw_token = data
        .get("nak")
        .and_then(Value::as_str)
        .ok_or_else(parse_error)?;
    let token = normalize_bearer_token(raw_token).map_err(|_| parse_error())?;
    let profile = match data.get("user_profile") {
        None | Some(Value::Null) => None,
        Some(Value::Object(profile)) => Some(profile),
        Some(_) => return Err(parse_error()),
    };
    let email = profile
        .map(|profile| optional_text(profile, "email"))
        .transpose()?
        .flatten()
        .map(|email| email.trim().to_owned())
        .filter(|email| !email.is_empty());
    if email.as_ref().is_some_and(|email| email.len() > 256) {
        return Err(parse_error());
    }
    Ok(ResolvedBearer {
        token,
        email,
        browser_session: None,
    })
}

fn parse_history_page(body: &[u8]) -> Result<HistoryPage, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let root = root.as_object().ok_or_else(parse_error)?;
    validate_optional_integer(root, "status_code")?;
    validate_optional_text(root, "error_message")?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(parse_error)?;
    let records = match data.get("records") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(records)) => {
            if records.len() > HISTORY_PAGE_LIMIT {
                return Err(parse_error());
            }
            records
                .iter()
                .map(parse_history_record)
                .collect::<Result<Vec<_>, _>>()?
        }
        Some(_) => return Err(parse_error()),
    };
    let total = optional_integer(data, "total")?;
    Ok(HistoryPage { records, total })
}

fn parse_history_record(value: &Value) -> Result<HistoryRecord, ClassifiedError> {
    let object = value.as_object().ok_or_else(parse_error)?;
    Ok(HistoryRecord {
        _session_id: optional_text(object, "session_id")?,
        _title: optional_text(object, "title")?,
        cost: optional_number(object, "cost")?,
        time: optional_text(object, "time")?,
        _running: optional_bool(object, "is_running")?,
        deleted: optional_bool(object, "is_deleted")?,
    })
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    source: ProviderSource,
    status: &CreditStatus,
    history: Option<&HistorySnapshot>,
    email: Option<String>,
    calendar_offset: Option<UtcOffset>,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope_source(&scope, source)?;
    let budget = status.budget_cap.unwrap_or(Decimal::ZERO);
    let used = status.used_credit.unwrap_or(Decimal::ZERO);
    let unlimited = status.unlimited.unwrap_or(false);
    let percent = if unlimited || budget <= Decimal::ZERO {
        Decimal::ZERO
    } else {
        used.checked_mul(Decimal::from(100_u8))
            .and_then(|value| value.checked_div(budget))
            .ok_or_else(parse_error)?
            .clamp(Decimal::ZERO, Decimal::from(100_u8))
    };
    let resets_at = if unlimited || budget <= Decimal::ZERO {
        None
    } else {
        status.cycle_end_millis.and_then(timestamp_from_millis)
    };
    let primary = RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent.to_f64().ok_or_else(parse_error)?)
                .map_err(|_| parse_error())?,
        ),
        None,
        resets_at,
        Some(BoundedText::new("Credits").map_err(|_| parse_error())?),
        None,
        false,
    )
    .map_err(|_| parse_error())?;

    let normalized_history = history
        .map(|history| normalize_history(history, fetched_at, calendar_offset))
        .transpose()?;
    let mut details = Vec::new();
    if let Some(history) = &normalized_history {
        let mut rows = vec![
            detail_row("Today", format_credits(history.today))?,
            detail_row("30d credits", format_credits(history.total))?,
        ];
        if let Some(pace) = pacing_text(status, fetched_at) {
            rows.push(detail_row("Pace", pace)?);
        }
        let chart = if history.daily.is_empty() {
            None
        } else {
            let points = history
                .daily
                .iter()
                .map(|(day, value)| {
                    let value = value.amount.to_f64().ok_or_else(parse_error)?;
                    DetailChartPoint::new(
                        day.clone(),
                        FiniteNumber::new(value).map_err(|_| parse_error())?,
                    )
                    .map_err(|_| parse_error())
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some(
                DetailChart::new(
                    DetailChartKind::Bars,
                    Some("Daily credits".to_owned()),
                    Some("credits".to_owned()),
                    points,
                )
                .map_err(|_| parse_error())?,
            )
        };
        details.push(
            DetailSection::new(Some("Credit history".to_owned()), rows, chart)
                .map_err(|_| parse_error())?,
        );
    }

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .email(email.clone())?
        .login_method(email.map(|_| "Cookie".to_owned()))?
        .detail_sections(details)
        .provenance(
            "zoommate",
            if source == ProviderSource::ManualCookie {
                "manual_cookie"
            } else {
                "browser_session"
            },
        )?;
    if let Some(history) = normalized_history {
        builder = builder.cost_usage(history.cost_usage);
    }
    builder.build()
}

fn normalize_history(
    history: &HistorySnapshot,
    fetched_at: Timestamp,
    calendar_offset: Option<UtcOffset>,
) -> Result<HistoryNormalization, ClassifiedError> {
    let fetched_instant = fetched_at.as_offset_date_time();
    let fetched_offset = calendar_offset
        .unwrap_or_else(|| UtcOffset::local_offset_at(fetched_instant).unwrap_or(UtcOffset::UTC));
    let today = fetched_instant.to_offset(fetched_offset).date();
    let since = today
        .checked_sub(TimeDuration::days(i64::from(HISTORY_DAYS - 1)))
        .ok_or_else(parse_error)?;
    let mut daily = BTreeMap::<Date, DailyCredits>::new();
    for record in &history.records {
        if record.deleted == Some(true) {
            continue;
        }
        let Some(cost) = record.cost.filter(|cost| *cost >= Decimal::ZERO) else {
            continue;
        };
        let Some(instant) = record.time.as_deref().and_then(parse_record_time) else {
            continue;
        };
        let offset = calendar_offset
            .unwrap_or_else(|| UtcOffset::local_offset_at(instant).unwrap_or(fetched_offset));
        let day = instant.to_offset(offset).date();
        if day < since {
            continue;
        }
        let entry = daily.entry(day).or_insert(DailyCredits {
            amount: Decimal::ZERO,
            record_count: 0,
        });
        entry.amount = entry.amount.checked_add(cost).ok_or_else(parse_error)?;
        entry.record_count = entry.record_count.checked_add(1).ok_or_else(parse_error)?;
    }
    let today_amount = daily
        .get(&today)
        .map_or(Decimal::ZERO, |value| value.amount);
    let total = daily.values().try_fold(Decimal::ZERO, |total, value| {
        total.checked_add(value.amount).ok_or_else(parse_error)
    })?;
    let total_records = daily.values().try_fold(0_u64, |total, value| {
        total
            .checked_add(value.record_count)
            .ok_or_else(parse_error)
    })?;
    let today_records = daily.get(&today).map_or(0, |value| value.record_count);

    let daily = daily
        .into_iter()
        .map(|(day, value)| (day.to_string(), value))
        .collect::<Vec<_>>();
    let buckets = daily
        .iter()
        .map(|(day, value)| {
            CostUsageDailyBucket::new(
                day,
                None,
                credit_metrics(value.amount, value.record_count)?,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .map_err(|_| parse_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cost_usage = CostUsageSnapshot::new(
        CostUnit::provider("credits").map_err(|_| parse_error())?,
        credit_metrics(today_amount, today_records)?,
        credit_metrics(total, total_records)?,
        Some(ExactDecimal::new(total)),
        HISTORY_DAYS,
        history.coverage_established,
        Some(if history.coverage_established {
            "Last 30 days".to_owned()
        } else {
            "Last 30 days (partial)".to_owned()
        }),
        None,
        buckets,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        fetched_at,
        CostProvenance::VendorMetered,
    )
    .map_err(|_| parse_error())?;
    Ok(HistoryNormalization {
        today: today_amount,
        total,
        daily,
        cost_usage,
    })
}

fn credit_metrics(amount: Decimal, record_count: u64) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::default(),
        None,
        Some(record_count),
        Some(ExactDecimal::new(amount)),
        CostUsageCoverage::new(record_count, 0, 0, 0).map_err(|_| parse_error())?,
    )
    .map_err(|_| parse_error())
}

fn pacing_text(status: &CreditStatus, fetched_at: Timestamp) -> Option<String> {
    let budget = status.budget_cap.filter(|budget| *budget > Decimal::ZERO)?;
    if status.unlimited == Some(true) {
        return None;
    }
    let start = timestamp_from_millis(status.cycle_start_millis?)?.as_offset_date_time();
    let end = timestamp_from_millis(status.cycle_end_millis?)?.as_offset_date_time();
    if end <= start {
        return None;
    }
    let cycle_minutes = (end - start).whole_seconds() / 60;
    if cycle_minutes <= 0 {
        return None;
    }
    let duration_seconds = cycle_minutes.checked_mul(60)?;
    let remaining_seconds = (end - fetched_at.as_offset_date_time()).whole_seconds();
    if remaining_seconds <= 0 || remaining_seconds > duration_seconds {
        return None;
    }
    let elapsed_seconds = duration_seconds.checked_sub(remaining_seconds)?;
    let actual = status
        .used_credit
        .unwrap_or(Decimal::ZERO)
        .checked_mul(Decimal::from(100_u8))?
        .checked_div(budget)?
        .clamp(Decimal::ZERO, Decimal::from(100_u8));
    if elapsed_seconds == 0 && actual > Decimal::ZERO {
        return None;
    }
    let expected = Decimal::from(elapsed_seconds)
        .checked_mul(Decimal::from(100_u8))?
        .checked_div(Decimal::from(duration_seconds))?
        .clamp(Decimal::ZERO, Decimal::from(100_u8));
    let delta = actual.checked_sub(expected)?.to_f64()?;
    if delta.abs() <= 2.0 {
        return Some("On track".to_owned());
    }
    let rounded = delta.abs().round();
    let rounded = rounded.to_i64()?;
    if delta > 0.0 {
        Some(if rounded == 0 {
            "Ahead of budget".to_owned()
        } else {
            format!("{rounded}% ahead of budget")
        })
    } else {
        Some(if rounded == 0 {
            "Behind budget".to_owned()
        } else {
            format!("{rounded}% behind budget")
        })
    }
}

fn parse_bounded_json(body: &[u8]) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| parse_error())?;
    let mut stack = vec![(&root, 0_usize)];
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
    Ok(root)
}

fn optional_number(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<Decimal>, ClassifiedError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            let text = number.to_string();
            let value = text
                .parse::<Decimal>()
                .or_else(|_| Decimal::from_scientific(&text))
                .map_err(|_| parse_error())?;
            if value.abs() > Decimal::from(MAX_CREDIT_MAGNITUDE) {
                return Err(parse_error());
            }
            Ok(Some(value))
        }
        Some(_) => Err(parse_error()),
    }
}

fn validate_optional_integer(
    object: &Map<String, Value>,
    key: &str,
) -> Result<(), ClassifiedError> {
    optional_integer(object, key).map(drop)
}

fn validate_optional_bool(object: &Map<String, Value>, key: &str) -> Result<(), ClassifiedError> {
    optional_bool(object, key).map(drop)
}

fn validate_optional_text(object: &Map<String, Value>, key: &str) -> Result<(), ClassifiedError> {
    optional_text(object, key).map(drop)
}

fn optional_integer(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, ClassifiedError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().ok_or_else(parse_error).map(Some),
    }
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, ClassifiedError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_bool().ok_or_else(parse_error).map(Some),
    }
}

fn optional_text(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, ClassifiedError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= MAX_RECORD_TEXT_BYTES => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(parse_error()),
    }
}

fn parse_record_time(value: &str) -> Option<OffsetDateTime> {
    if value.len() > 128 || value != value.trim() {
        return None;
    }
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn timestamp_from_millis(value: i64) -> Option<Timestamp> {
    if value <= 0 {
        return None;
    }
    let nanos = i128::from(value).checked_mul(1_000_000)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|timestamp| Timestamp::new(timestamp).ok())
}

fn expiry_from_jwt(token: &str) -> Option<OffsetDateTime> {
    let token = token.trim();
    let token = token
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))
        .map_or(token, |_| &token[7..]);
    let payload = token.split('.').nth(1)?;
    if payload.is_empty() || payload.len() > 16 * 1024 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    if decoded.len() > 16 * 1024 {
        return None;
    }
    let root: Value = serde_json::from_slice(&decoded).ok()?;
    let exp = root.as_object()?.get("exp")?.as_f64()?;
    if !exp.is_finite() || exp <= 0.0 {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(exp.trunc().to_i64()?).ok()
}

fn normalize_bearer_token(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let trimmed = raw.trim();
    let token = trimmed
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))
        .map_or(trimmed, |_| &trimmed[7..]);
    if token.is_empty() || token.len() > 16 * 1024 || token.contains(['\r', '\n']) {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    Ok(Zeroizing::new(token.to_owned()))
}

fn normalize_manual_cookie(
    raw: &str,
    target: &ValidatedCookieUrl,
) -> Result<Zeroizing<String>, ClassifiedError> {
    let import = CookieImport::from_host_only_capture(CookieSourceId::MANUAL, raw, target, None)
        .map_err(|_| parse_error())?;
    let order = CookieImportOrder::new([CookieSourceId::MANUAL]).map_err(|_| api_error())?;
    let jar = CookieJar::from_imports(&order, [import]).map_err(|_| parse_error())?;
    let header = jar
        .header_for(target, OffsetDateTime::UNIX_EPOCH)
        .map_err(|_| parse_error())?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    Ok(Zeroizing::new(header.expose().to_owned()))
}

fn sensitive_header(value: &str) -> Result<HeaderValue, ClassifiedError> {
    let mut header = HeaderValue::from_str(value).map_err(|_| api_error())?;
    header.set_sensitive(true);
    Ok(header)
}

fn detail_row(label: &str, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Public).map_err(|_| parse_error())
}

fn format_credits(value: Decimal) -> String {
    let plain = value.round_dp(2).normalize().to_string();
    let (integer, fraction) = plain
        .split_once('.')
        .map_or((plain.as_str(), None), |(integer, fraction)| {
            (integer, Some(fraction))
        });
    let (sign, digits) = integer
        .strip_prefix('-')
        .map_or(("", integer), |digits| ("-", digits));
    let mut grouped = String::with_capacity(plain.len() + plain.len() / 3);
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

fn no_host_fallback(error: &ClassifiedError, context: &ProviderContext) -> bool {
    context.cancellation().is_cancelled()
        || matches!(
            error.kind(),
            ErrorKind::AuthenticationExpired | ErrorKind::PermissionDenied | ErrorKind::Parse
        )
}

fn validate_scope_source(
    scope: &AccountScope,
    source: ProviderSource,
) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::ZoomMate
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(api_error());
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

fn bare_origin(mut url: Url) -> Result<Url, ClassifiedError> {
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(api_error());
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn fixed_path(mut origin: Url, path: &str) -> Result<Url, ClassifiedError> {
    if origin.host_str().is_none() || !path.starts_with('/') {
        return Err(api_error());
    }
    origin.set_path(path);
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(origin)
}

fn same_origin(url: &Url, expected: &str) -> Result<bool, ClassifiedError> {
    let expected = Url::parse(expected).map_err(|_| api_error())?;
    Ok(url.origin() == expected.origin())
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn network_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Network)
}
