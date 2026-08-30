//! GitHub Copilot OAuth usage and quota normalization.
//!
//! Optional web-budget enrichment is restricted to public GitHub OAuth accounts.
//! Enterprise-host tokens are never rebound to `api.github.com`; they retain the
//! successful base sample and skip all public GitHub identity and cookie traffic.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, NamedRateWindow, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample,
    WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    ChromiumCookieDecryptor, import_browser_cookie_stores_with_decryptor,
};
use crate::browser_profile::BrowserProfileDiscovery;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{
    CookieHeaderNormalizer, CookieImport, CookieImportOrder, CookieJar, CookieSourceId,
    CookieUrlPolicy, ValidatedCookieUrl,
};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
    TransportError,
};

const DEFAULT_HOST: &str = "github.com";
const TOKEN_KEY: &str = "COPILOT_API_TOKEN";
const DEVICE_CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";
const DEVICE_SCOPE: &str = "read:user";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_QUOTA_SNAPSHOTS: usize = 512;
const MAX_HOST_BYTES: usize = 512;
const MAX_DEVICE_CODE_BYTES: usize = 16 * 1024;
const MAX_USER_CODE_BYTES: usize = 256;
const MAX_VERIFICATION_URL_BYTES: usize = 8 * 1024;
const MAX_DEVICE_FLOW_LIFETIME: Duration = Duration::from_hours(24);
const MAX_DEVICE_POLL_INTERVAL: Duration = Duration::from_mins(5);
const SLOW_DOWN_DELAY: Duration = Duration::from_secs(5);
const BUDGET_SETTINGS_URL: &str = "https://github.com/settings/billing/budgets";
const BUDGET_ORIGIN: &str = "https://github.com";
const BUDGET_USER_AGENT: &str = "omarchy-ai-bar";
const MAX_BUDGET_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUDGET_JSON_DEPTH: usize = 32;
const MAX_BUDGET_JSON_NODES: usize = 16 * 1024;
const MAX_BUDGET_OBJECT_FIELDS: usize = 256;
const MAX_BUDGET_ARRAY_ITEMS: usize = 2_048;
const MAX_BUDGET_STRING_BYTES: usize = 64 * 1024;
const MAX_BUDGET_FIELD_BYTES: usize = 8 * 1024;
const MAX_BUDGETS_PER_PAGE: usize = 100;
const MAX_BUDGET_PAGES: usize = 20;
const MAX_TOTAL_BUDGETS: usize = MAX_BUDGETS_PER_PAGE * MAX_BUDGET_PAGES;
const MAX_BUDGET_WINDOWS: usize = 16;
const MAX_BROWSER_PROFILES: usize = 64;
const MAX_BROWSER_SESSIONS: usize = 16;
const MAX_HTML_META_TAGS: usize = 512;
const MAX_HTML_ATTRIBUTES: usize = 64;
const MAX_NONCE_BYTES: usize = 8 * 1024;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_NAMED_WINDOW_ID_BYTES: usize = 128;
const BROWSER_COOKIE_SOURCE: CookieSourceId = CookieSourceId::new(61);
const BROWSER_ROOT_COOKIE_SOURCE: CookieSourceId = CookieSourceId::new(62);
const SESSION_COOKIE_NAMES: [&str; 5] = [
    "user_session",
    "__Host-user_session_same_site",
    "_gh_sess",
    "logged_in",
    "dotcom_user",
];

/// Monotonic time boundary used by the device authorization state machine.
///
/// The public trait keeps polling tests deterministic without relaxing the
/// production constructor's exact-origin HTTPS policy.
pub trait DeviceFlowClock: Send + Sync {
    /// Returns a duration from an arbitrary, stable monotonic origin.
    fn monotonic_now(&self) -> Duration;

    /// Sleeps for the requested bounded polling delay.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Runs one token request only while its challenge lifetime remains.
    fn run_before_timeout<'a, F, T>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Option<T>> + Send + 'a>>
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a;
}

/// Tokio-backed production clock for Copilot device authorization.
#[derive(Debug)]
pub struct TokioDeviceFlowClock {
    origin: Instant,
}

impl Default for TokioDeviceFlowClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl DeviceFlowClock for TokioDeviceFlowClock {
    fn monotonic_now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn run_before_timeout<'a, F, T>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Option<T>> + Send + 'a>>
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        Box::pin(async move { tokio::time::timeout(duration, future).await.ok() })
    }
}

/// Validated device-code challenge displayed while GitHub authorization is pending.
pub struct CopilotDeviceCode {
    device_code: Zeroizing<String>,
    token_endpoint: Url,
    issuer: Arc<()>,
    user_code: BoundedText<MAX_USER_CODE_BYTES>,
    verification_uri: Url,
    verification_uri_complete: Option<Url>,
    issued_at: Duration,
    expires_in: Duration,
    interval: Duration,
}

impl CopilotDeviceCode {
    /// Short code the user enters on GitHub's verification page.
    #[must_use]
    pub fn user_code(&self) -> &str {
        self.user_code.as_str()
    }

    /// Preferred verification URL, falling back to the base URI when GitHub
    /// does not return a pre-populated URL.
    #[must_use]
    pub fn verification_url_to_open(&self) -> &Url {
        self.verification_uri_complete
            .as_ref()
            .unwrap_or(&self.verification_uri)
    }

    /// Server-issued authorization lifetime.
    #[must_use]
    pub const fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// Server-issued delay required before each token poll.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }
}

impl Debug for CopilotDeviceCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CopilotDeviceCode")
            .field("device_code", &"<redacted>")
            .field("token_endpoint", &"<redacted>")
            .field("issuer", &"<redacted>")
            .field("user_code", &"<redacted>")
            .field("verification_uri", &"<redacted>")
            .field("verification_uri_complete", &"<redacted>")
            .field("issued_at", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// Exact-origin GitHub device authorization client.
pub struct CopilotDeviceFlow<C = TokioDeviceFlowClock> {
    transport: HttpTransport,
    device_code_url: Url,
    access_token_url: Url,
    issuer: Arc<()>,
    clock: C,
}

impl CopilotDeviceFlow<TokioDeviceFlowClock> {
    /// Creates a production device flow for GitHub or GitHub Enterprise.
    ///
    /// The configured origin must use HTTPS and cannot be loopback. Credentials
    /// are never attached to redirects or origins outside the exact policy.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for an invalid or insecure enterprise host.
    pub fn new(enterprise_host: Option<&str>) -> Result<Self, ClassifiedError> {
        let base_url = device_base_url(enterprise_host)?;
        let endpoint_class =
            classify_https_endpoint(&base_url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if endpoint_class == EndpointClass::LoopbackDevelopment {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let endpoints =
            EndpointPolicy::new([(base_url.origin().ascii_serialization(), endpoint_class)])
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport = HttpTransport::new(endpoints, device_transport_config()?)
            .map_err(|error| error.classified())?;
        Self::build(&base_url, transport, TokioDeviceFlowClock::default())
    }
}

impl<C: DeviceFlowClock> CopilotDeviceFlow<C> {
    /// Builds a flow around an explicitly supplied transport and clock.
    ///
    /// This seam exists for isolated loopback tests. The transport still owns
    /// and enforces its endpoint policy before every request.
    ///
    /// # Errors
    ///
    /// Returns a stable API error unless `base_url` is a credential-free bare
    /// origin URL.
    #[doc(hidden)]
    pub fn with_test_transport(
        base_url: &Url,
        transport: HttpTransport,
        clock: C,
    ) -> Result<Self, ClassifiedError> {
        Self::build(base_url, transport, clock)
    }

    fn build(base_url: &Url, transport: HttpTransport, clock: C) -> Result<Self, ClassifiedError> {
        if base_url.host_str().is_none()
            || !matches!(base_url.scheme(), "http" | "https")
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.path() != "/"
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let device_code_url = base_url
            .join("login/device/code")
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let access_token_url = base_url
            .join("login/oauth/access_token")
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self {
            transport,
            device_code_url,
            access_token_url,
            issuer: Arc::new(()),
            clock,
        })
    }

    /// Exact endpoint used to request the user-facing authorization challenge.
    #[must_use]
    pub const fn device_code_url(&self) -> &Url {
        &self.device_code_url
    }

    /// Exact endpoint used to poll for the resulting access token.
    #[must_use]
    pub const fn access_token_url(&self) -> &Url {
        &self.access_token_url
    }

    /// Requests and validates one bounded device authorization challenge.
    ///
    /// # Errors
    ///
    /// Returns stable transport or parse errors without exposing response text
    /// or the server-issued device code.
    pub async fn request_device_code(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<CopilotDeviceCode, ClassifiedError> {
        let body = form_body(&[("client_id", DEVICE_CLIENT_ID), ("scope", DEVICE_SCOPE)]);
        let issued_at = self.clock.monotonic_now();
        let request = HttpRequest::post(self.device_code_url.clone(), body)
            .map_err(|error| error.classified())?
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::FormUrlEncoded);
        let response = self
            .transport
            .send(&request, cancellation)
            .await
            .map_err(|error| error.classified())?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let wire: DeviceCodeWire = response.json()?;
        CopilotDeviceCode::from_wire(
            wire,
            self.access_token_url.clone(),
            Arc::clone(&self.issuer),
            issued_at,
        )
    }

    /// Polls GitHub until the challenge succeeds, expires, is cancelled, or is
    /// denied, returning a bounded redacted credential on success.
    ///
    /// GitHub's required interval is slept before every request. A `slow_down`
    /// response inserts the provider-mandated additional five-second delay.
    ///
    /// # Errors
    ///
    /// Returns authentication-expired for challenge expiry, permission-denied
    /// for an explicit user denial, network for cancellation, and stable
    /// transport/parse errors for other failures.
    pub async fn poll_for_token(
        &self,
        challenge: &CopilotDeviceCode,
        cancellation: &CancellationToken,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        if challenge.token_endpoint != self.access_token_url
            || !Arc::ptr_eq(&challenge.issuer, &self.issuer)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let body = form_body(&[
            ("client_id", DEVICE_CLIENT_ID),
            ("device_code", challenge.device_code.as_str()),
            ("grant_type", DEVICE_GRANT_TYPE),
        ]);
        let request = HttpRequest::post(self.access_token_url.clone(), body)
            .map_err(|error| error.classified())?
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::FormUrlEncoded)
            .accepted_statuses(&[400])
            .map_err(|error| error.classified())?;
        let started_at = challenge.issued_at;

        loop {
            self.sleep_with_deadline(
                challenge.interval,
                started_at,
                challenge.expires_in,
                cancellation,
            )
            .await?;
            let remaining = self.remaining(started_at, challenge.expires_in)?;
            let response = self
                .clock
                .run_before_timeout(remaining, self.transport.send(&request, cancellation))
                .await
                .ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))?
                .map_err(|error| error.classified())?;
            self.remaining(started_at, challenge.expires_in)?;

            let wire: AccessTokenWire = response.json()?;
            if let Some(error) = wire.error.as_deref() {
                match error {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        self.sleep_with_deadline(
                            SLOW_DOWN_DELAY,
                            started_at,
                            challenge.expires_in,
                            cancellation,
                        )
                        .await?;
                        continue;
                    }
                    "access_denied" => {
                        return Err(ClassifiedError::new(ErrorKind::PermissionDenied));
                    }
                    "expired_token" => {
                        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
                    }
                    _ => return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired)),
                }
            }
            if response.status() != 200 {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            let token = wire
                .access_token
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            let _token_type = wire
                .token_type
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            let _scope = wire
                .scope
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            return ApiKeyCredential::new(token.as_str())
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse));
        }
    }

    async fn sleep_with_deadline(
        &self,
        requested: Duration,
        started_at: Duration,
        expires_in: Duration,
        cancellation: &CancellationToken,
    ) -> Result<(), ClassifiedError> {
        let remaining = self.remaining(started_at, expires_in)?;
        let delay = requested.min(remaining);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(ClassifiedError::new(ErrorKind::Network)),
            () = self.clock.sleep(delay) => {}
        }
        if requested >= remaining {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        self.remaining(started_at, expires_in).map(|_| ())
    }

    fn remaining(
        &self,
        started_at: Duration,
        expires_in: Duration,
    ) -> Result<Duration, ClassifiedError> {
        let elapsed = self
            .clock
            .monotonic_now()
            .checked_sub(started_at)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))?;
        expires_in
            .checked_sub(elapsed)
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))
    }
}

#[derive(Deserialize)]
struct DeviceCodeWire {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

impl CopilotDeviceCode {
    fn from_wire(
        wire: DeviceCodeWire,
        token_endpoint: Url,
        issuer: Arc<()>,
        issued_at: Duration,
    ) -> Result<Self, ClassifiedError> {
        if wire.device_code.is_empty()
            || wire.device_code.len() > MAX_DEVICE_CODE_BYTES
            || wire.device_code.chars().any(char::is_control)
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let user_code = BoundedText::new(&wire.user_code)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let expires_in = bounded_duration(wire.expires_in, MAX_DEVICE_FLOW_LIFETIME)?;
        let interval = bounded_duration(wire.interval, MAX_DEVICE_POLL_INTERVAL)?;
        let verification_uri = verification_url(&wire.verification_uri)?;
        let verification_uri_complete = wire
            .verification_uri_complete
            .as_deref()
            .map(verification_url)
            .transpose()?;
        Ok(Self {
            device_code: Zeroizing::new(wire.device_code),
            token_endpoint,
            issuer,
            user_code,
            verification_uri,
            verification_uri_complete,
            issued_at,
            expires_in,
            interval,
        })
    }
}

#[derive(Deserialize)]
struct AccessTokenWire {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

fn bounded_duration(seconds: u64, maximum: Duration) -> Result<Duration, ClassifiedError> {
    let duration = Duration::from_secs(seconds);
    if duration.is_zero() || duration > maximum {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(duration)
}

fn verification_url(value: &str) -> Result<Url, ClassifiedError> {
    if value.is_empty() || value.len() > MAX_VERIFICATION_URL_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let url = Url::parse(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.scheme() != "https"
        || url.host_str().is_none()
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(url)
}

fn form_body(parameters: &[(&str, &str)]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(parameters.iter().copied());
    serializer.finish().into_bytes()
}

/// Fixed GitHub billing-settings route used by optional Copilot budget enrichment.
pub struct CopilotBudgetRouteSet {
    settings: Url,
    endpoints: EndpointPolicy,
}

impl CopilotBudgetRouteSet {
    /// Creates the pinned public GitHub budget route.
    ///
    /// # Errors
    ///
    /// Returns a stable API error only if the compile-time route contract is invalid.
    pub fn production() -> Result<Self, ClassifiedError> {
        let settings =
            Url::parse(BUDGET_SETTINGS_URL).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let endpoints = EndpointPolicy::new([(BUDGET_ORIGIN, EndpointClass::PublicHttps)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::new(settings, endpoints)
    }

    /// Creates an exact loopback billing-settings route for deterministic tests.
    ///
    /// # Errors
    ///
    /// Rejects non-loopback, credential-bearing, queried, or incorrectly pathed URLs.
    #[doc(hidden)]
    pub fn loopback(settings: Url) -> Result<Self, ClassifiedError> {
        let origin = settings.origin().ascii_serialization();
        let endpoints = EndpointPolicy::new([(origin, EndpointClass::LoopbackDevelopment)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::new(settings, endpoints)
    }

    fn new(settings: Url, endpoints: EndpointPolicy) -> Result<Self, ClassifiedError> {
        if !settings.username().is_empty()
            || settings.password().is_some()
            || settings.path() != "/settings/billing/budgets"
            || settings.query().is_some()
            || settings.fragment().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        endpoints
            .validate(&settings)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self {
            settings,
            endpoints,
        })
    }

    fn page(&self, page: usize) -> Url {
        let mut url = self.settings.clone();
        url.query_pairs_mut()
            .append_pair("page", &page.to_string())
            .append_pair("page_size", "10")
            .append_pair("scope", "customer");
        url
    }
}

impl Debug for CopilotBudgetRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CopilotBudgetRouteSet")
            .field("origin", &self.settings.origin().ascii_serialization())
            .field("path", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BudgetCookieMode {
    Manual,
    Browser,
}

struct BudgetWebSession {
    cookie: Zeroizing<String>,
}

impl Debug for BudgetWebSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("BudgetWebSession(<redacted>)")
    }
}

/// Explicit, optional GitHub web-budget configuration attached to an OAuth provider.
///
/// This object never becomes the provider's authentication source. It only adds
/// best-effort quota windows after the OAuth usage request has succeeded and the
/// same OAuth credential has identified its GitHub account through `/user`.
pub struct CopilotBudgetEnrichment {
    mode: BudgetCookieMode,
    routes: CopilotBudgetRouteSet,
    sessions: Vec<BudgetWebSession>,
    transport: HttpTransport,
    local_offset: Option<UtcOffset>,
}

impl CopilotBudgetEnrichment {
    /// Parses a manual Cookie header or non-executed cURL capture for GitHub budgets.
    ///
    /// Only the pinned session-cookie names are retained. A captured URL, when
    /// present, must be the exact GitHub billing-budgets path.
    ///
    /// # Errors
    ///
    /// Returns stable missing-credential, parse, or route errors without retaining
    /// input text in diagnostics.
    pub fn manual(raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(raw, CopilotBudgetRouteSet::production()?)
    }

    /// Builds browser enrichment from explicitly enabled Linux profile discovery.
    ///
    /// Chromium Network and root stores become separate candidates in that order;
    /// Firefox and Zen use one shared SQLite candidate. Profiles stay isolated and
    /// duplicate sessions are removed.
    ///
    /// # Errors
    ///
    /// Returns stable bounded discovery, cookie, or route errors. An empty profile
    /// set is valid because enrichment is optional.
    pub fn browser(
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_routes(
            discovery,
            decryptor,
            now,
            CopilotBudgetRouteSet::production()?,
        )
    }

    /// Injects a route while retaining production manual-capture authority.
    ///
    /// # Errors
    ///
    /// Returns stable capture, cookie, or transport configuration errors.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        raw: &str,
        routes: CopilotBudgetRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(["github.com"], [CaptureHeader::Cookie])
            .map_err(classify_budget_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_budget_capture_error)?;
        if capture.url().is_some_and(|url| {
            !url.host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case("github.com"))
                || url.path() != "/settings/billing/budgets"
        }) {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let raw_cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let cookie = normalized_budget_cookie(raw_cookie)?;
        Self::build(
            BudgetCookieMode::Manual,
            routes,
            vec![BudgetWebSession { cookie }],
        )
    }

    /// Injects a route for deterministic browser-profile and HTTP tests.
    ///
    /// # Errors
    ///
    /// Returns stable bounded discovery, cookie, or transport errors. Individual
    /// unreadable profiles are skipped like the pinned browser rotation.
    #[doc(hidden)]
    pub fn from_browser_routes(
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
        routes: CopilotBudgetRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let sessions = budget_browser_sessions(discovery, decryptor, now)?;
        Self::build(BudgetCookieMode::Browser, routes, sessions)
    }

    fn build(
        mode: BudgetCookieMode,
        routes: CopilotBudgetRouteSet,
        sessions: Vec<BudgetWebSession>,
    ) -> Result<Self, ClassifiedError> {
        if sessions.len() > MAX_BROWSER_SESSIONS {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let transport = HttpTransport::new(routes.endpoints.clone(), budget_transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            mode,
            routes,
            sessions,
            transport,
            local_offset: None,
        })
    }

    /// Uses one fixed local-calendar offset at both fetch and reset time.
    ///
    /// This deterministic seam intentionally disables production DST resolution.
    #[must_use]
    pub const fn with_local_offset(mut self, offset: UtcOffset) -> Self {
        self.local_offset = Some(offset);
        self
    }
}

impl Debug for CopilotBudgetEnrichment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CopilotBudgetEnrichment")
            .field("mode", &self.mode)
            .field("routes", &self.routes)
            .field("session_count", &self.sessions.len())
            .field("local_offset", &self.local_offset)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BudgetFailure {
    NoSession,
    NotLoggedIn,
    AccountMismatch,
    Status,
    InvalidResponse,
    Network,
}

impl From<ClassifiedError> for BudgetFailure {
    fn from(error: ClassifiedError) -> Self {
        match error.kind() {
            ErrorKind::AuthenticationExpired | ErrorKind::PermissionDenied => Self::NotLoggedIn,
            ErrorKind::Network => Self::Network,
            ErrorKind::Api
            | ErrorKind::Parse
            | ErrorKind::MissingCredential
            | ErrorKind::RateLimited
            | ErrorKind::ProviderUnavailable => Self::InvalidResponse,
        }
    }
}

struct GitHubOAuthIdentity {
    id: String,
    _login: String,
}

struct GitHubWebIdentity {
    id: Option<String>,
    _login: Option<String>,
}

struct BudgetPageMetadata {
    nonce: Option<Zeroizing<String>>,
    identity: Option<GitHubWebIdentity>,
}

struct BudgetPage {
    budgets: Vec<BudgetRecord>,
    has_next_page: bool,
}

struct BudgetRecord {
    id: Option<String>,
    name: Option<String>,
    budget_type: Option<String>,
    product_skus: Vec<String>,
    _scope: Option<String>,
    entity_name: Option<String>,
    budget_amount: f64,
    current_amount: f64,
}

impl BudgetRecord {
    fn selectors(&self) -> BTreeSet<String> {
        self.product_skus
            .iter()
            .map(String::as_str)
            .chain(self.budget_type.as_deref())
            .chain(self.entity_name.as_deref())
            .chain(self.name.as_deref())
            .filter_map(normalized_billing_identifier)
            .collect()
    }
}

impl CopilotBudgetEnrichment {
    async fn fetch_for_identity(
        &self,
        cancellation: &CancellationToken,
        expected: &GitHubOAuthIdentity,
        fetched_at: Timestamp,
    ) -> Result<Vec<NamedRateWindow>, BudgetFailure> {
        if self.sessions.is_empty() {
            return Err(BudgetFailure::NoSession);
        }
        for session in &self.sessions {
            match self
                .fetch_session(cancellation, session, expected, fetched_at)
                .await
            {
                Ok(windows) => return Ok(windows),
                Err(BudgetFailure::NotLoggedIn | BudgetFailure::AccountMismatch)
                    if self.mode == BudgetCookieMode::Browser => {}
                Err(error) => return Err(error),
            }
        }
        Err(BudgetFailure::NoSession)
    }

    async fn fetch_session(
        &self,
        cancellation: &CancellationToken,
        session: &BudgetWebSession,
        expected: &GitHubOAuthIdentity,
        fetched_at: Timestamp,
    ) -> Result<Vec<NamedRateWindow>, BudgetFailure> {
        let metadata = self.fetch_metadata(cancellation, session).await?;
        let Some(actual) = metadata.identity else {
            return Err(BudgetFailure::AccountMismatch);
        };
        if actual.id.as_deref() != Some(expected.id.as_str()) {
            return Err(BudgetFailure::AccountMismatch);
        }

        let mut records = Vec::new();
        let mut page = 1_usize;
        let mut should_continue = true;
        while should_continue && page <= MAX_BUDGET_PAGES {
            let response = self
                .fetch_page(
                    cancellation,
                    session,
                    metadata.nonce.as_ref().map(|nonce| nonce.as_str()),
                    page,
                )
                .await?;
            if records.len().saturating_add(response.budgets.len()) > MAX_TOTAL_BUDGETS {
                return Err(BudgetFailure::InvalidResponse);
            }
            records.extend(response.budgets);
            should_continue = response.has_next_page;
            page = page.saturating_add(1);
        }
        budget_windows_from_records(&records, fetched_at, self.local_offset)
            .map_err(BudgetFailure::from)
    }

    async fn fetch_metadata(
        &self,
        cancellation: &CancellationToken,
        session: &BudgetWebSession,
    ) -> Result<BudgetPageMetadata, BudgetFailure> {
        let authentication = Authentication::cookie(session.cookie.as_str().to_owned())
            .map_err(|_| BudgetFailure::InvalidResponse)?;
        let request = HttpRequest::get(self.routes.settings.clone())
            .accept(RequestAccept::Html)
            .authentication(authentication)
            .public_header("user-agent", BUDGET_USER_AGENT)
            .map_err(|_| BudgetFailure::InvalidResponse)?;
        let response = self
            .transport
            .send(&request, cancellation)
            .await
            .map_err(|error| classify_budget_transport_error(&error))?;
        if response.status() != 200 {
            return Err(BudgetFailure::Status);
        }
        let html =
            std::str::from_utf8(response.body()).map_err(|_| BudgetFailure::InvalidResponse)?;
        parse_budget_page_metadata(html)
    }

    async fn fetch_page(
        &self,
        cancellation: &CancellationToken,
        session: &BudgetWebSession,
        nonce: Option<&str>,
        page: usize,
    ) -> Result<BudgetPage, BudgetFailure> {
        let authentication = Authentication::cookie(session.cookie.as_str().to_owned())
            .map_err(|_| BudgetFailure::InvalidResponse)?;
        let mut request = HttpRequest::get(self.routes.page(page))
            .accept(RequestAccept::Json)
            .authentication(authentication)
            .public_header("user-agent", BUDGET_USER_AGENT)
            .map_err(|_| BudgetFailure::InvalidResponse)?
            .public_header("referer", self.routes.settings.as_str())
            .map_err(|_| BudgetFailure::InvalidResponse)?
            .public_header("x-requested-with", "XMLHttpRequest")
            .map_err(|_| BudgetFailure::InvalidResponse)?
            .public_header("github-verified-fetch", "true")
            .map_err(|_| BudgetFailure::InvalidResponse)?;
        if let Some(nonce) = nonce.filter(|nonce| !nonce.is_empty()) {
            request = request
                .sensitive_header("x-fetch-nonce", nonce.to_owned())
                .map_err(|_| BudgetFailure::InvalidResponse)?;
        }
        let response = self
            .transport
            .send(&request, cancellation)
            .await
            .map_err(|error| classify_budget_transport_error(&error))?;
        if response.status() != 200 {
            return Err(BudgetFailure::Status);
        }
        if std::str::from_utf8(response.body()).is_ok_and(looks_like_github_login) {
            return Err(BudgetFailure::NotLoggedIn);
        }
        parse_budget_page(response.body())
    }
}

fn classify_budget_transport_error(error: &TransportError) -> BudgetFailure {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            BudgetFailure::NotLoggedIn
        }
        TransportError::Cancelled
        | TransportError::Timeout
        | TransportError::Network
        | TransportError::RequestTimeout => BudgetFailure::Network,
        TransportError::Endpoint(_)
        | TransportError::InvalidConfiguration
        | TransportError::ResponseTooLarge
        | TransportError::MalformedResponse
        | TransportError::TooManyRedirects
        | TransportError::RateLimited { .. }
        | TransportError::ProviderUnavailable { .. }
        | TransportError::Api { .. } => BudgetFailure::Status,
    }
}

fn classify_budget_capture_error(error: ManualCaptureError) -> ClassifiedError {
    let kind = match error {
        ManualCaptureError::MissingSecret
        | ManualCaptureError::InvalidSecret
        | ManualCaptureError::DisallowedHeader => ErrorKind::MissingCredential,
        ManualCaptureError::InvalidPolicy => ErrorKind::Api,
        ManualCaptureError::InputTooLarge
        | ManualCaptureError::InvalidSyntax
        | ManualCaptureError::UnsafeSyntax
        | ManualCaptureError::UnsafeOption
        | ManualCaptureError::TooManyTokens
        | ManualCaptureError::TooManyHeaders
        | ManualCaptureError::DuplicateSecret
        | ManualCaptureError::ConflictingHeader
        | ManualCaptureError::DisallowedUrl => ErrorKind::Parse,
    };
    ClassifiedError::new(kind)
}

fn normalized_budget_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let target = ValidatedCookieUrl::parse(BUDGET_SETTINGS_URL, CookieUrlPolicy::HttpsOnly)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    normalized_budget_cookie_for_target(raw, &target)
}

fn normalized_budget_cookie_for_target(
    raw: &str,
    target: &ValidatedCookieUrl,
) -> Result<Zeroizing<String>, ClassifiedError> {
    let normalized = CookieHeaderNormalizer::filtered(Some(raw), &SESSION_COOKIE_NAMES)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let import =
        CookieImport::from_normalized_host_only(CookieSourceId::MANUAL, normalized, target, None)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let order = CookieImportOrder::new([CookieSourceId::MANUAL])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let jar = CookieJar::from_imports(&order, [import])
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let header = jar
        .header_for(target, OffsetDateTime::UNIX_EPOCH)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    Ok(Zeroizing::new(header.expose().to_owned()))
}

fn budget_browser_sessions(
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: OffsetDateTime,
) -> Result<Vec<BudgetWebSession>, ClassifiedError> {
    let allowlist = BrowserCookieDomainAllowlist::new([BrowserCookieDomainRule {
        domain: "github.com",
        policy: BrowserCookieDomainPolicy::Exact,
    }])
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let target = ValidatedCookieUrl::parse(BUDGET_SETTINGS_URL, CookieUrlPolicy::HttpsOnly)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let report = discovery.discover();
    if report.profiles().len() > MAX_BROWSER_PROFILES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut sessions = Vec::new();
    let mut seen = BTreeSet::<[u8; 32]>::new();
    for profile in report.profiles() {
        let Ok(imports) = import_browser_cookie_stores_with_decryptor(
            profile,
            [BROWSER_COOKIE_SOURCE, BROWSER_ROOT_COOKIE_SOURCE],
            &allowlist,
            decryptor,
        ) else {
            continue;
        };
        for import in imports {
            let order = CookieImportOrder::new([BROWSER_COOKIE_SOURCE, BROWSER_ROOT_COOKIE_SOURCE])
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
            let jar = CookieJar::from_imports(&order, [import])
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            let Some(header) = jar
                .header_for(&target, now)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
            else {
                continue;
            };
            let Ok(cookie) = normalized_budget_cookie_for_target(header.expose(), &target) else {
                continue;
            };
            let digest: [u8; 32] = Sha256::digest(cookie.as_bytes()).into();
            if seen.insert(digest) {
                sessions.push(BudgetWebSession { cookie });
                if sessions.len() > MAX_BROWSER_SESSIONS {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
            }
        }
    }
    Ok(sessions)
}

fn budget_transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_BUDGET_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn parse_oauth_identity(body: &[u8]) -> Result<GitHubOAuthIdentity, BudgetFailure> {
    let value: Value = serde_json::from_slice(body).map_err(|_| BudgetFailure::InvalidResponse)?;
    validate_budget_json(&value).map_err(BudgetFailure::from)?;
    let object = value.as_object().ok_or(BudgetFailure::InvalidResponse)?;
    let id = flexible_identifier(object.get("id"))
        .filter(|value| !value.is_empty() && value.len() <= MAX_IDENTITY_BYTES)
        .ok_or(BudgetFailure::InvalidResponse)?;
    let login = object
        .get("login")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= MAX_IDENTITY_BYTES)
        .ok_or(BudgetFailure::InvalidResponse)?
        .to_owned();
    Ok(GitHubOAuthIdentity { id, _login: login })
}

fn parse_budget_page_metadata(html: &str) -> Result<BudgetPageMetadata, BudgetFailure> {
    if html.len() > MAX_BUDGET_RESPONSE_BYTES {
        return Err(BudgetFailure::InvalidResponse);
    }
    let tags = meta_attributes(html)?;
    let id = first_meta_content(
        &tags,
        &["octolytics-actor-id", "analytics-user-id", "user-id"],
    );
    let login = first_meta_content(
        &tags,
        &[
            "user-login",
            "octolytics-actor-login",
            "analytics-user-login",
        ],
    );
    let identity = if id.is_some() || login.is_some() {
        Some(GitHubWebIdentity { id, _login: login })
    } else {
        None
    };
    if identity.is_none() && looks_like_github_login(html) {
        return Err(BudgetFailure::NotLoggedIn);
    }
    let nonce = first_meta_content(&tags, &["x-fetch-nonce"])
        .or_else(|| quoted_assignment(html, "X-Fetch-Nonce"))
        .or_else(|| quoted_assignment(html, "fetchNonce"))
        .or_else(|| quoted_assignment(html, "data-fetch-nonce"))
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_NONCE_BYTES
                && !value.chars().any(char::is_control)
        })
        .map(Zeroizing::new);
    Ok(BudgetPageMetadata { nonce, identity })
}

fn looks_like_github_login(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("sign in to github")
        || lower.contains("action=\"/session\"")
        || lower.contains("action='/session'")
        || lower.contains("/login?return_to=")
}

fn meta_attributes(html: &str) -> Result<Vec<BTreeMap<String, String>>, BudgetFailure> {
    let bytes = html.as_bytes();
    let mut output = Vec::new();
    let mut cursor = 0_usize;
    while let Some(start) = find_ascii_case_insensitive(bytes, b"<meta", cursor) {
        let boundary = bytes.get(start + 5).copied();
        if boundary.is_some_and(|byte| !byte.is_ascii_whitespace() && byte != b'>' && byte != b'/')
        {
            cursor = start.saturating_add(5);
            continue;
        }
        if output.len() == MAX_HTML_META_TAGS {
            return Err(BudgetFailure::InvalidResponse);
        }
        let relative_end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'>')
            .ok_or(BudgetFailure::InvalidResponse)?;
        let end = start.saturating_add(relative_end).saturating_add(1);
        let tag =
            std::str::from_utf8(&bytes[start..end]).map_err(|_| BudgetFailure::InvalidResponse)?;
        output.push(parse_meta_attributes(tag)?);
        cursor = end;
    }
    Ok(output)
}

fn parse_meta_attributes(tag: &str) -> Result<BTreeMap<String, String>, BudgetFailure> {
    let bytes = tag.as_bytes();
    let mut attributes = BTreeMap::new();
    let mut cursor = 5_usize;
    while cursor < bytes.len() {
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_whitespace() || matches!(bytes[cursor], b'/' | b'>'))
        {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        let key_start = cursor;
        while cursor < bytes.len() && is_html_attribute_name_byte(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == key_start {
            cursor += 1;
            continue;
        }
        let key = tag[key_start..cursor].to_ascii_lowercase();
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let Some(quote @ (b'\'' | b'"')) = bytes.get(cursor).copied() else {
            continue;
        };
        cursor += 1;
        let value_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != quote {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            return Err(BudgetFailure::InvalidResponse);
        }
        if attributes.len() == MAX_HTML_ATTRIBUTES && !attributes.contains_key(&key) {
            return Err(BudgetFailure::InvalidResponse);
        }
        let value = tag[value_start..cursor].to_owned();
        if value.len() > MAX_BUDGET_FIELD_BYTES {
            return Err(BudgetFailure::InvalidResponse);
        }
        attributes.insert(key, value);
        cursor += 1;
    }
    Ok(attributes)
}

const fn is_html_attribute_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
        .map(|position| position + start)
}

fn first_meta_content(tags: &[BTreeMap<String, String>], names: &[&str]) -> Option<String> {
    for name in names {
        for tag in tags {
            if tag
                .get("name")
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
                && let Some(content) = tag.get("content").map(|value| value.trim())
                && !content.is_empty()
            {
                return Some(content.to_owned());
            }
        }
    }
    None
}

fn quoted_assignment(haystack: &str, key: &str) -> Option<String> {
    let bytes = haystack.as_bytes();
    let start = find_ascii_case_insensitive(bytes, key.as_bytes(), 0)? + key.len();
    let tail = bytes.get(start..)?;
    let operator = tail.iter().position(|byte| matches!(byte, b':' | b'='))?;
    if operator > 32 {
        return None;
    }
    let mut cursor = start + operator + 1;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let quote @ (b'\'' | b'"') = *bytes.get(cursor)? else {
        return None;
    };
    cursor += 1;
    let end = bytes[cursor..].iter().position(|byte| *byte == quote)? + cursor;
    let value = std::str::from_utf8(&bytes[cursor..end]).ok()?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn parse_budget_page(body: &[u8]) -> Result<BudgetPage, BudgetFailure> {
    let value: Value = serde_json::from_slice(body).map_err(|_| BudgetFailure::InvalidResponse)?;
    validate_budget_json(&value).map_err(BudgetFailure::from)?;
    let mut current = &value;
    for _ in 0..=MAX_BUDGET_JSON_DEPTH {
        let object = current.as_object().ok_or(BudgetFailure::InvalidResponse)?;
        if let Some(payload) = object.get("payload").filter(|payload| !payload.is_null()) {
            current = payload;
            continue;
        }
        let budgets = match object.get("budgets") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(values)) if values.len() <= MAX_BUDGETS_PER_PAGE => values
                .iter()
                .map(parse_budget_record)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(BudgetFailure::InvalidResponse),
        };
        let pagination = match object.get("hasNextPage") {
            None | Some(Value::Null) => object.get("has_next_page"),
            value => value,
        };
        let has_next_page = match pagination {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(BudgetFailure::InvalidResponse),
        };
        return Ok(BudgetPage {
            budgets,
            has_next_page,
        });
    }
    Err(BudgetFailure::InvalidResponse)
}

#[cfg(test)]
mod budget_page_tests {
    use super::*;

    #[test]
    fn null_camel_pagination_falls_back_to_true_snake_value() {
        let page = parse_budget_page(br#"{"budgets":[],"hasNextPage":null,"has_next_page":true}"#)
            .expect("null camel pagination must inspect snake fallback");

        assert!(page.has_next_page);
    }
}

fn validate_budget_json(value: &Value) -> Result<(), ClassifiedError> {
    let mut nodes = 0_usize;
    validate_budget_json_node(value, 0, &mut nodes)
}

fn validate_budget_json_node(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ClassifiedError> {
    if depth > MAX_BUDGET_JSON_DEPTH || *nodes >= MAX_BUDGET_JSON_NODES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    *nodes += 1;
    match value {
        Value::Object(object) => {
            if object.len() > MAX_BUDGET_OBJECT_FIELDS {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            for (key, child) in object {
                if key.len() > MAX_BUDGET_FIELD_BYTES {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                validate_budget_json_node(child, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            if array.len() > MAX_BUDGET_ARRAY_ITEMS {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            for child in array {
                validate_budget_json_node(child, depth + 1, nodes)?;
            }
        }
        Value::String(value) if value.len() > MAX_BUDGET_STRING_BYTES => {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn parse_budget_record(value: &Value) -> Result<BudgetRecord, BudgetFailure> {
    let object = value.as_object().ok_or(BudgetFailure::InvalidResponse)?;
    Ok(BudgetRecord {
        id: first_flexible_string(object, &["id", "uuid", "budget_id", "budgetId"]),
        name: first_flexible_string(object, &["name", "display_name", "displayName", "title"]),
        budget_type: first_flexible_string(
            object,
            &[
                "budget_type",
                "budgetType",
                "type",
                "pricing_target_type",
                "pricingTargetType",
            ],
        ),
        product_skus: first_string_array(
            object,
            &[
                "budget_product_skus",
                "budgetProductSkus",
                "budget_product_sku",
                "budgetProductSku",
                "product_skus",
                "productSkus",
                "skus",
                "sku",
                "product",
                "product_name",
                "productName",
                "pricing_target_id",
                "pricingTargetId",
            ],
        ),
        _scope: first_flexible_string(object, &["budget_scope", "budgetScope", "scope"]),
        entity_name: first_flexible_string(
            object,
            &[
                "budget_entity_name",
                "budgetEntityName",
                "entity_name",
                "entityName",
                "target_name",
                "targetName",
            ],
        ),
        budget_amount: first_amount(
            object,
            &[
                "budget_amount",
                "budgetAmount",
                "target_amount",
                "targetAmount",
                "spending_limit",
                "spendingLimit",
                "limit",
                "amount",
                "max",
            ],
        )
        .unwrap_or(0.0),
        current_amount: first_amount(
            object,
            &[
                "current_usage",
                "currentUsage",
                "current_amount",
                "currentAmount",
                "usage_amount",
                "usageAmount",
                "usage",
                "spent",
                "amount_used",
                "amountUsed",
            ],
        )
        .unwrap_or(0.0),
    })
}

fn first_flexible_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let value = object.get(*key)?;
        let value = flexible_identifier(Some(value))?;
        (!value.is_empty() && value.len() <= MAX_BUDGET_FIELD_BYTES).then_some(value)
    })
}

fn flexible_identifier(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) if value.is_i64() || value.is_u64() => Some(value.to_string()),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            None
        }
    }
}

fn first_string_array(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };
        if let Value::Array(values) = value {
            let strings = values.iter().map(Value::as_str).collect::<Option<Vec<_>>>();
            if let Some(strings) = strings.filter(|strings| !strings.is_empty()) {
                return strings
                    .into_iter()
                    .filter(|value| !value.is_empty() && value.len() <= MAX_BUDGET_FIELD_BYTES)
                    .map(str::to_owned)
                    .collect();
            }
            let objects = values
                .iter()
                .map(Value::as_object)
                .collect::<Option<Vec<_>>>();
            if let Some(objects) = objects.filter(|objects| !objects.is_empty()) {
                return objects
                    .into_iter()
                    .flat_map(product_sku_selectors)
                    .collect();
            }
        }
        if let Some(value) = value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= MAX_BUDGET_FIELD_BYTES)
        {
            return vec![value.to_owned()];
        }
    }
    Vec::new()
}

fn product_sku_selectors(object: &serde_json::Map<String, Value>) -> Vec<String> {
    [
        "sku",
        "name",
        "display_name",
        "displayName",
        "product",
        "product_name",
        "productName",
    ]
    .into_iter()
    .filter_map(|key| {
        object
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= MAX_BUDGET_FIELD_BYTES)
            .map(str::to_owned)
    })
    .collect()
}

fn first_amount(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(|value| amount_value(value, key)))
}

fn amount_value(value: &Value, key: &str) -> Option<f64> {
    match value {
        Value::Number(number) => {
            number
                .as_f64()
                .filter(|number| number.is_finite())
                .map(|number| {
                    if key == "cents" {
                        number / 100.0
                    } else {
                        number
                    }
                })
        }
        Value::String(value) => parse_budget_amount(value),
        Value::Object(object) => ["amount", "value", "total", "cents", "formatted"]
            .into_iter()
            .find_map(|nested| {
                object
                    .get(nested)
                    .and_then(|value| amount_value(value, nested))
            }),
        Value::Null | Value::Bool(_) | Value::Array(_) => None,
    }
}

fn parse_budget_amount(value: &str) -> Option<f64> {
    let trimmed = value.trim();
    let negative = trimmed.starts_with('-');
    let unsigned_source = trimmed.strip_prefix('-').unwrap_or(trimmed);
    if unsigned_source.contains('-') {
        return None;
    }
    let mut unsigned = String::new();
    for character in unsigned_source.chars() {
        if character.is_ascii_digit() || character == '.' {
            unsigned.push(character);
        }
    }
    if unsigned.is_empty() {
        return None;
    }
    let candidate = if negative {
        format!("-{unsigned}")
    } else {
        unsigned
    };
    candidate
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

/// Normalizes a GitHub billing selector to the pinned Copilot budget vocabulary.
#[must_use]
#[doc(hidden)]
pub fn normalized_billing_identifier(value: &str) -> Option<String> {
    let slug = slug(value);
    if slug.is_empty() {
        return None;
    }
    let underscored = slug.replace('-', "_");
    let normalized = if underscored == "copilot" {
        "copilot"
    } else if matches!(underscored.as_str(), "premium_request" | "premium_requests") {
        "copilot_premium_request"
    } else if underscored == "coding_agent_premium_request"
        || underscored == "coding_agent_premium_requests"
    {
        "copilot_agent_premium_request"
    } else if underscored.contains("spark")
        && underscored.contains("premium")
        && underscored.contains("request")
    {
        "spark_premium_request"
    } else if (underscored.contains("cloud") || underscored.contains("coding"))
        && underscored.contains("agent")
        && underscored.contains("premium")
        && underscored.contains("request")
    {
        "copilot_agent_premium_request"
    } else if underscored.contains("bundled")
        && underscored.contains("premium")
        && underscored.contains("request")
    {
        "copilot_premium_request"
    } else if underscored.contains("copilot")
        && underscored.contains("agent")
        && underscored.contains("premium")
        && underscored.contains("request")
    {
        "copilot_agent_premium_request"
    } else if underscored.contains("copilot")
        && underscored.contains("premium")
        && underscored.contains("request")
    {
        "copilot_premium_request"
    } else {
        return Some(underscored);
    };
    Some(normalized.to_owned())
}

fn budget_windows_from_records(
    records: &[BudgetRecord],
    now: Timestamp,
    fixed_local_offset: Option<UtcOffset>,
) -> Result<Vec<NamedRateWindow>, ClassifiedError> {
    const SELECTORS: [&str; 4] = [
        "copilot",
        "copilot_premium_request",
        "copilot_agent_premium_request",
        "spark_premium_request",
    ];
    let reset = approximate_next_month_reset(now, fixed_local_offset);
    let mut used_ids = BTreeSet::new();
    let mut windows = Vec::new();
    for record in records {
        let selectors = record.selectors();
        if record.budget_amount <= 0.0
            || selectors
                .iter()
                .all(|selector| !SELECTORS.contains(&selector.as_str()))
        {
            continue;
        }
        if windows.len() == MAX_BUDGET_WINDOWS {
            break;
        }
        let percentage = (record.current_amount / record.budget_amount * 100.0).clamp(0.0, 999.0);
        if !percentage.is_finite() {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let usage =
            UsagePercent::new(percentage).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let window = RateWindow::new(WindowUsage::known(usage), None, reset, None, None, false)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let title = budget_window_title(record, &selectors);
        let id = unique_budget_window_id(record, &title, &mut used_ids);
        windows.push(NamedRateWindow::new(
            BoundedText::new(id).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            BoundedText::new(title).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            window,
        ));
    }
    Ok(windows)
}

fn budget_window_title(record: &BudgetRecord, selectors: &BTreeSet<String>) -> String {
    let label = if selectors.len() == 1 && selectors.contains("copilot") {
        "Copilot"
    } else if selectors.contains("copilot_agent_premium_request") {
        "Copilot Agent Premium Requests"
    } else if selectors.contains("spark_premium_request") {
        "Spark Premium Requests"
    } else if selectors.contains("copilot_premium_request") {
        "All Premium Request SKUs"
    } else {
        record
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("Copilot Premium Requests")
    };
    format!("Budget - {label}")
}

fn unique_budget_window_id(
    record: &BudgetRecord,
    title: &str,
    used: &mut BTreeSet<String>,
) -> String {
    let source = record
        .id
        .as_deref()
        .filter(|value| !value.is_empty())
        .map_or_else(|| record.product_skus.join("-"), str::to_owned);
    let slug = slug(if source.is_empty() { title } else { &source });
    let base = if slug.is_empty() {
        "copilot-budget".to_owned()
    } else {
        let maximum = MAX_NAMED_WINDOW_ID_BYTES.saturating_sub("copilot-budget-".len());
        format!("copilot-budget-{}", truncate_utf8(&slug, maximum))
    };
    let mut candidate = base.clone();
    let mut suffix = 2_usize;
    while !used.insert(candidate.clone()) {
        let suffix_text = format!("-{suffix}");
        let maximum = MAX_NAMED_WINDOW_ID_BYTES.saturating_sub(suffix_text.len());
        candidate = format!("{}{}", truncate_utf8(&base, maximum), suffix_text);
        suffix = suffix.saturating_add(1);
    }
    candidate
}

fn slug(value: &str) -> String {
    let mut result = String::new();
    let mut last_was_dash = false;
    for character in value.to_lowercase().chars() {
        if character.is_alphanumeric() {
            result.push(character);
            last_was_dash = false;
        } else if !last_was_dash {
            result.push('-');
            last_was_dash = true;
        }
    }
    result.trim_matches('-').to_owned()
}

fn truncate_utf8(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut boundary = maximum;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    &value[..boundary]
}

fn approximate_next_month_reset(
    now: Timestamp,
    fixed_local_offset: Option<UtcOffset>,
) -> Option<Timestamp> {
    let fallback_offset = fixed_local_offset.unwrap_or(UtcOffset::UTC);
    if fixed_local_offset.is_some() {
        return approximate_next_month_reset_with_resolver(now, fallback_offset, |_| None);
    }
    approximate_next_month_reset_with_resolver(now, fallback_offset, |instant| {
        UtcOffset::local_offset_at(instant).ok()
    })
}

fn approximate_next_month_reset_with_resolver(
    now: Timestamp,
    fallback_offset: UtcOffset,
    mut resolve_offset: impl FnMut(OffsetDateTime) -> Option<UtcOffset>,
) -> Option<Timestamp> {
    let local_offset = resolve_offset(now.as_offset_date_time()).unwrap_or(fallback_offset);
    let local = now.as_offset_date_time().to_offset(local_offset);
    let (year, month) = if local.month() == Month::December {
        (local.year().checked_add(1)?, Month::January)
    } else {
        (local.year(), local.month().next())
    };
    let date = Date::from_calendar_date(year, month, 1).ok()?;
    let local_midnight = PrimitiveDateTime::new(date, Time::MIDNIGHT);
    let mut target_offset = local_offset;
    for _ in 0..4 {
        let candidate = local_midnight.assume_offset(target_offset);
        let observed = resolve_offset(candidate).unwrap_or(target_offset);
        if observed == target_offset {
            return Timestamp::new(candidate).ok();
        }
        target_offset = observed;
    }
    None
}

#[cfg(test)]
mod reset_tests {
    use super::*;

    #[test]
    fn production_calendar_resolves_offset_at_future_month_boundary() {
        let fetched_at = Timestamp::parse("2026-03-01T12:00:00Z").expect("fetch timestamp");
        let transition = Timestamp::parse("2026-03-08T07:00:00Z")
            .expect("transition timestamp")
            .as_offset_date_time();
        let standard = UtcOffset::from_hms(-5, 0, 0).expect("standard offset");
        let daylight = UtcOffset::from_hms(-4, 0, 0).expect("daylight offset");

        let reset = approximate_next_month_reset_with_resolver(fetched_at, standard, |instant| {
            Some(if instant < transition {
                standard
            } else {
                daylight
            })
        })
        .expect("DST-aware reset");

        assert_eq!(
            reset,
            Timestamp::parse("2026-04-01T04:00:00Z").expect("expected daylight reset")
        );
    }

    #[test]
    fn fixed_offset_seam_stays_stable_across_future_dst_transition() {
        let fetched_at = Timestamp::parse("2026-03-01T12:00:00Z").expect("fetch timestamp");
        let standard = UtcOffset::from_hms(-5, 0, 0).expect("fixed standard offset");

        let reset =
            approximate_next_month_reset(fetched_at, Some(standard)).expect("fixed-offset reset");

        assert_eq!(
            reset,
            Timestamp::parse("2026-04-01T05:00:00Z").expect("expected fixed-offset reset")
        );
    }
}

/// Parses one bounded GitHub budget page into normalized extra quota windows.
///
/// # Errors
///
/// Returns a stable parse error for malformed, excessive, or incompatible JSON.
#[doc(hidden)]
pub fn parse_budget_windows(
    body: &[u8],
    now: Timestamp,
    local_offset: UtcOffset,
) -> Result<Vec<NamedRateWindow>, ClassifiedError> {
    let page = parse_budget_page(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    budget_windows_from_records(&page.budgets, now, Some(local_offset))
}

/// Native GitHub Copilot usage adapter.
pub struct CopilotProvider {
    client: FixedApiClient,
    budget_identity_allowed: bool,
    budget: Option<CopilotBudgetEnrichment>,
}

fn is_public_github_or_loopback(url: &Url) -> bool {
    if url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("api.github.com"))
    {
        return true;
    }
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

impl CopilotProvider {
    /// Resolves the explicit environment token supported by the pinned provider.
    ///
    /// Device-flow and Secret Service precedence are orchestrated above this
    /// adapter so environment credentials remain ephemeral.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for an unusable token.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &[TOKEN_KEY])
    }

    /// Creates an exact-origin OAuth-token client for GitHub or GitHub Enterprise.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for an invalid enterprise host or transport.
    pub fn new(
        scope: AccountScope,
        credential: ApiKeyCredential,
        enterprise_host: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        let base_url = usage_base_url(enterprise_host)?;
        let endpoint_class =
            classify_https_endpoint(&base_url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if endpoint_class == EndpointClass::LoopbackDevelopment {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let client = FixedApiClient::new_authorization_scheme(
            scope,
            base_url,
            endpoint_class,
            "token",
            credential,
            transport_config()?,
        )?
        .with_source(ProviderSource::OAuth)?;
        Self::from_client(client)
    }

    /// Wraps an already validated OAuth-bound account client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider or
    /// is not bound to Copilot's OAuth source.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Copilot
            || client.source() != ProviderSource::OAuth
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let budget_identity_allowed = is_public_github_or_loopback(client.base_url());
        Ok(Self {
            client,
            budget_identity_allowed,
            budget: None,
        })
    }

    /// Reports whether this client's OAuth origin may perform public GitHub
    /// identity binding for optional web-budget enrichment.
    #[must_use]
    #[doc(hidden)]
    pub const fn public_budget_identity_allowed(&self) -> bool {
        self.budget_identity_allowed
    }

    /// Disables public GitHub identity binding for a deterministic security-policy seam.
    #[must_use]
    #[doc(hidden)]
    pub const fn without_public_budget_identity(mut self) -> Self {
        self.budget_identity_allowed = false;
        self
    }

    /// Attaches optional GitHub web-budget enrichment to this OAuth account.
    ///
    /// The adapter and [`ProviderContext`] remain OAuth-bound. Manual cookies
    /// and browser sessions are auxiliary inputs and cannot authorize the base
    /// usage request or alter its account scope. Enterprise-host accounts skip
    /// enrichment because their token is never forwarded to public GitHub.
    #[must_use]
    pub fn with_budget_enrichment(mut self, enrichment: CopilotBudgetEnrichment) -> Self {
        self.budget = Some(enrichment);
        self
    }

    /// Fetches and normalizes one deterministic Copilot usage snapshot.
    ///
    /// # Errors
    ///
    /// Returns stable authentication, transport, or parse errors without
    /// exposing the OAuth token or provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("copilot_internal/user")?;
        let response = self
            .client
            .get_json_with_public_headers_and_status_map(
                context,
                url,
                &[
                    ("editor-version", "vscode/1.96.2"),
                    ("editor-plugin-version", "copilot-chat/0.26.7"),
                    ("user-agent", "GitHubCopilotChat/0.26.7"),
                    ("x-github-api-version", "2025-04-01"),
                ],
                |status| (status == 403).then_some(ErrorKind::AuthenticationExpired),
            )
            .await?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let payload: Value = response.json()?;
        let base = normalize(context.scope().clone(), fetched_at, &payload, Vec::new())?;
        let Some(enrichment) = &self.budget else {
            return Ok(base);
        };
        if !self.budget_identity_allowed {
            return Ok(base);
        }
        let extras = match self
            .fetch_budget_windows(context, enrichment, fetched_at)
            .await
        {
            Ok(extras) if !extras.is_empty() => extras,
            Ok(_) | Err(_) => return Ok(base),
        };
        normalize(context.scope().clone(), fetched_at, &payload, extras).or(Ok(base))
    }

    async fn fetch_budget_windows(
        &self,
        context: &ProviderContext,
        enrichment: &CopilotBudgetEnrichment,
        fetched_at: Timestamp,
    ) -> Result<Vec<oab_domain::NamedRateWindow>, BudgetFailure> {
        let identity_url = self.client.url("user").map_err(BudgetFailure::from)?;
        let response = self
            .client
            .get_json_with_status_map(context, identity_url, |status| {
                matches!(status, 401 | 403).then_some(ErrorKind::AuthenticationExpired)
            })
            .await
            .map_err(BudgetFailure::from)?;
        if response.status() != 200 {
            return Err(BudgetFailure::Status);
        }
        let identity = parse_oauth_identity(response.body())?;
        enrichment
            .fetch_for_identity(context.cancellation(), &identity, fetched_at)
            .await
    }
}

impl ProviderAdapter for CopilotProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Copilot)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Clone)]
struct QuotaSnapshot {
    entitlement: f64,
    remaining: f64,
    credits_used: Option<f64>,
    percent_remaining: f64,
    has_percent_remaining: bool,
    unlimited: bool,
    decoded: DecodedQuotaFields,
}

#[derive(Clone, Copy)]
struct DecodedQuotaFields {
    entitlement: bool,
    remaining: bool,
}

impl QuotaSnapshot {
    fn parse(value: &Value) -> Result<Self, ClassifiedError> {
        let root = value
            .as_object()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let entitlement = optional_number(root.get("entitlement"))?;
        let remaining = optional_number(root.get("remaining"))?;
        let credits_used = optional_number(root.get("credits_used"))?;
        let decoded_percent = optional_number(root.get("percent_remaining"))?;
        let unlimited = match root.get("unlimited") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
        };
        if root
            .get("quota_id")
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let (percent_remaining, has_percent_remaining) = if unlimited {
            (100.0, true)
        } else if let Some(percent) = decoded_percent {
            (percent, true)
        } else if let (Some(entitlement), Some(remaining)) = (entitlement, remaining) {
            if entitlement > 0.0 {
                let percent = remaining / entitlement * 100.0;
                if !percent.is_finite() {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                (percent, true)
            } else {
                (0.0, false)
            }
        } else {
            (0.0, false)
        };
        Ok(Self {
            entitlement: entitlement.unwrap_or(0.0),
            remaining: remaining.unwrap_or(0.0),
            credits_used,
            percent_remaining,
            has_percent_remaining,
            unlimited,
            decoded: DecodedQuotaFields {
                entitlement: entitlement.is_some(),
                remaining: remaining.is_some(),
            },
        })
    }

    fn is_placeholder(&self) -> bool {
        if self.unlimited {
            return false;
        }
        (!self.has_percent_remaining
            && self.entitlement == 0.0
            && self.remaining == 0.0
            && self.percent_remaining == 0.0)
            || (self.decoded.entitlement
                && self.decoded.remaining
                && self.entitlement == 0.0
                && self.remaining == 0.0)
    }

    fn usable(&self) -> bool {
        !self.is_placeholder() && self.has_percent_remaining
    }

    fn with_credits(mut self, credits: Option<f64>) -> Self {
        self.credits_used = credits;
        self
    }
}

#[derive(Default)]
struct QuotaSnapshots {
    premium: Option<QuotaSnapshot>,
    chat: Option<QuotaSnapshot>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: &Value,
    extra_windows: Vec<oab_domain::NamedRateWindow>,
) -> Result<UsageSample, ClassifiedError> {
    let root = payload
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let direct = parse_direct_snapshots(root.get("quota_snapshots"))?;
    let monthly = parse_quota_counts(root.get("monthly_quotas"))?;
    let limited = parse_quota_counts(root.get("limited_user_quotas"))?;
    let fallback = monthly_snapshots(monthly.as_ref(), limited.as_ref())?;

    let selected_premium = preferred_snapshot(direct.premium.as_ref(), fallback.premium);
    let selected_chat = preferred_snapshot(direct.chat.as_ref(), fallback.chat);
    let snapshots = if selected_premium.is_some() || selected_chat.is_some() {
        QuotaSnapshots {
            premium: selected_premium,
            chat: selected_chat,
        }
    } else {
        direct
    };

    validate_optional_string(root.get("assigned_date"))?;
    let reset = match root.get("quota_reset_date") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => parse_reset(value),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let primary = snapshots
        .premium
        .as_ref()
        .map(|snapshot| make_window(snapshot, reset))
        .transpose()?
        .flatten();
    let secondary = snapshots
        .chat
        .as_ref()
        .map(|snapshot| make_window(snapshot, reset))
        .transpose()?
        .flatten();
    let token_billing = match root.get("token_based_billing") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let has_unlimited = snapshots
        .premium
        .as_ref()
        .is_some_and(|snapshot| snapshot.unlimited)
        || snapshots
            .chat
            .as_ref()
            .is_some_and(|snapshot| snapshot.unlimited);
    if primary.is_none() && secondary.is_none() && !token_billing && !has_unlimited {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let credits = snapshots
        .premium
        .as_ref()
        .and_then(|snapshot| snapshot.credits_used)
        .or_else(|| {
            snapshots
                .chat
                .as_ref()
                .and_then(|snapshot| snapshot.credits_used)
        });
    let details = credits
        .map(|credits| credits_section(credits, reset))
        .transpose()?
        .into_iter()
        .collect();
    let plan = match root.get("copilot_plan") {
        None | Some(Value::Null) => "Unknown".to_owned(),
        Some(Value::String(value)) => capitalize(value),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .extra_windows(extra_windows)
        .login_method(Some(plan))?
        .detail_sections(details);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder.provenance("copilot", "oauth")?.build()
}

fn parse_direct_snapshots(value: Option<&Value>) -> Result<QuotaSnapshots, ClassifiedError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(QuotaSnapshots::default());
    };
    let root = value
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if root.len() > MAX_QUOTA_SNAPSHOTS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut premium = root
        .get("premium_interactions")
        .map(QuotaSnapshot::parse)
        .transpose()?;
    let mut chat = root.get("chat").map(QuotaSnapshot::parse).transpose()?;
    if premium
        .as_ref()
        .is_some_and(|snapshot| snapshot.is_placeholder() && snapshot.credits_used.is_none())
    {
        premium = None;
    }
    if chat
        .as_ref()
        .is_some_and(|snapshot| snapshot.is_placeholder() && snapshot.credits_used.is_none())
    {
        chat = None;
    }

    if premium.is_none() || chat.is_none() {
        let mut keys = root.keys().collect::<Vec<_>>();
        keys.sort();
        let mut fallback_premium = None;
        let mut fallback_chat = None;
        let mut first_usable = None;
        for key in keys {
            let Ok(snapshot) = QuotaSnapshot::parse(&root[key]) else {
                continue;
            };
            if snapshot.is_placeholder() && snapshot.credits_used.is_none() {
                continue;
            }
            first_usable.get_or_insert_with(|| snapshot.clone());
            let name = key.to_ascii_lowercase();
            if fallback_chat.is_none() && name.contains("chat") {
                fallback_chat = Some(snapshot);
                continue;
            }
            if fallback_premium.is_none()
                && (name.contains("premium")
                    || name.contains("completion")
                    || name.contains("code"))
            {
                fallback_premium = Some(snapshot);
            }
        }
        premium = premium.or(fallback_premium);
        chat = chat.or(fallback_chat);
        if premium.is_none() && chat.is_none() {
            chat = first_usable;
        }
    }
    Ok(QuotaSnapshots { premium, chat })
}

#[derive(Default)]
struct QuotaCounts {
    chat: Option<f64>,
    completions: Option<f64>,
}

fn parse_quota_counts(value: Option<&Value>) -> Result<Option<QuotaCounts>, ClassifiedError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let root = value
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(Some(QuotaCounts {
        chat: optional_number(root.get("chat"))?,
        completions: optional_number(root.get("completions"))?,
    }))
}

fn monthly_snapshots(
    monthly: Option<&QuotaCounts>,
    limited: Option<&QuotaCounts>,
) -> Result<QuotaSnapshots, ClassifiedError> {
    Ok(QuotaSnapshots {
        premium: monthly_snapshot(
            monthly.and_then(|counts| counts.completions),
            limited.and_then(|counts| counts.completions),
        )?,
        chat: monthly_snapshot(
            monthly.and_then(|counts| counts.chat),
            limited.and_then(|counts| counts.chat),
        )?,
    })
}

fn monthly_snapshot(
    monthly: Option<f64>,
    limited: Option<f64>,
) -> Result<Option<QuotaSnapshot>, ClassifiedError> {
    let (Some(monthly), Some(limited)) = (monthly, limited) else {
        return Ok(None);
    };
    let entitlement = monthly.max(0.0);
    if entitlement <= 0.0 {
        return Ok(None);
    }
    let remaining = limited.max(0.0);
    let percent_remaining = (remaining / entitlement * 100.0).clamp(0.0, 100.0);
    if !percent_remaining.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(Some(QuotaSnapshot {
        entitlement,
        remaining,
        credits_used: None,
        percent_remaining,
        has_percent_remaining: true,
        unlimited: false,
        decoded: DecodedQuotaFields {
            entitlement: true,
            remaining: true,
        },
    }))
}

fn preferred_snapshot(
    direct: Option<&QuotaSnapshot>,
    fallback: Option<QuotaSnapshot>,
) -> Option<QuotaSnapshot> {
    if direct.is_some_and(|snapshot| snapshot.unlimited)
        && fallback.as_ref().is_some_and(QuotaSnapshot::usable)
    {
        return fallback.map(|snapshot| {
            snapshot.with_credits(direct.and_then(|snapshot| snapshot.credits_used))
        });
    }
    if let Some(direct) = direct.filter(|snapshot| snapshot.usable()) {
        return Some(direct.clone());
    }
    let fallback = fallback.filter(QuotaSnapshot::usable)?;
    Some(
        if direct.is_some_and(|snapshot| snapshot.credits_used.is_some()) {
            fallback.with_credits(direct.and_then(|snapshot| snapshot.credits_used))
        } else {
            fallback
        },
    )
}

fn make_window(
    snapshot: &QuotaSnapshot,
    resets_at: Option<Timestamp>,
) -> Result<Option<RateWindow>, ClassifiedError> {
    if snapshot.unlimited || snapshot.is_placeholder() || !snapshot.has_percent_remaining {
        return Ok(None);
    }
    let used = (100.0 - snapshot.percent_remaining).max(0.0);
    let used = UsagePercent::new(used).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let description = (used.get() > 100.0)
        .then(|| BoundedText::new(format!("{:.0}% used", used.get())))
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(used),
        None,
        resets_at,
        description,
        None,
        false,
    )
    .map(Some)
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn credits_section(
    credits: f64,
    resets_at: Option<Timestamp>,
) -> Result<DetailSection, ClassifiedError> {
    let secondary = resets_at.map(|reset| format!("Resets {reset}"));
    let row = DetailRow::new(
        "Credits used",
        format_credits(credits)?,
        secondary,
        DetailSensitivity::Public,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    DetailSection::new(Some("Credits".to_owned()), vec![row], None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn optional_number(value: Option<&Value>) -> Result<Option<f64>, ClassifiedError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse::<f64>().ok(),
        _ => None,
    };
    match parsed {
        Some(value) if value.is_finite() => Ok(Some(value)),
        Some(_) => Err(ClassifiedError::new(ErrorKind::Parse)),
        None => Ok(None),
    }
}

fn validate_optional_string(value: Option<&Value>) -> Result<(), ClassifiedError> {
    match value {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        Some(_) => Err(ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn parse_reset(value: &str) -> Option<Timestamp> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Timestamp::parse(value).ok().or_else(|| {
        (value.len() == 10)
            .then(|| Timestamp::parse(&format!("{value}T00:00:00Z")).ok())
            .flatten()
    })
}

fn format_credits(value: f64) -> Result<String, ClassifiedError> {
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let decimal = Decimal::from_f64(value)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .round_dp(2)
        .normalize();
    let raw = decimal.to_string();
    let (sign, raw) = raw
        .strip_prefix('-')
        .map_or(("", raw.as_str()), |digits| ("-", digits));
    let (integer, fraction) = raw
        .split_once('.')
        .map_or((raw, None), |(integer, fraction)| (integer, Some(fraction)));
    let mut output = String::with_capacity(raw.len() + raw.len() / 3 + sign.len());
    output.push_str(sign);
    for (index, byte) in integer.bytes().enumerate() {
        if index > 0 && (integer.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(char::from(byte));
    }
    if let Some(fraction) = fraction {
        output.push('.');
        output.push_str(fraction);
    }
    Ok(output)
}

fn capitalize(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut word_start = true;
    for character in value.chars() {
        if word_start {
            output.extend(character.to_uppercase());
        } else {
            output.extend(character.to_lowercase());
        }
        word_start = !character.is_alphanumeric();
    }
    output
}

/// Normalizes the pinned GitHub/GitHub Enterprise host input.
///
/// # Errors
///
/// Returns a stable API error for malformed, credential-bearing, or unbounded
/// host text.
pub fn normalize_enterprise_host(raw: Option<&str>) -> Result<String, ClassifiedError> {
    let raw = raw.map(str::trim).filter(|value| !value.is_empty());
    let Some(raw) = raw else {
        return Ok(DEFAULT_HOST.to_owned());
    };
    if raw.len() > MAX_HOST_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let host = url
        .host_str()
        .map(|host| host.trim_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if host.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(url
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

fn usage_base_url(enterprise_host: Option<&str>) -> Result<Url, ClassifiedError> {
    let host = normalize_enterprise_host(enterprise_host)?;
    let (hostname, port) = split_host_port(&host);
    let api_host = if hostname.starts_with("api.") {
        hostname.to_owned()
    } else if hostname == DEFAULT_HOST {
        "api.github.com".to_owned()
    } else {
        format!("api.{hostname}")
    };
    let authority = port.map_or(api_host.clone(), |port| format!("{api_host}:{port}"));
    Url::parse(&format!("https://{authority}/")).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn device_base_url(enterprise_host: Option<&str>) -> Result<Url, ClassifiedError> {
    let host = normalize_enterprise_host(enterprise_host)?;
    Url::parse(&format!("https://{host}/")).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

/// Returns the exact Copilot usage endpoint for a normalized enterprise host.
///
/// # Errors
///
/// Returns a stable API error when the host cannot form an approved HTTPS URL.
pub fn usage_url(enterprise_host: Option<&str>) -> Result<Url, ClassifiedError> {
    usage_base_url(enterprise_host)?
        .join("copilot_internal/user")
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn split_host_port(host: &str) -> (&str, Option<u16>) {
    host.rsplit_once(':').map_or((host, None), |(host, port)| {
        port.parse::<u16>()
            .map_or((host, None), |port| (host, Some(port)))
    })
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn device_transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
