//! Amp Free, subscription, and credit usage through CLI, bearer API, or web session.

use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, NamedRateWindow, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample,
    WindowDuration, WindowUsage,
};
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, COOKIE, HeaderValue, LOCATION, ORIGIN, REFERER, USER_AGENT,
};
use reqwest::{Client, StatusCode};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::{Decimal, RoundingStrategy};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    ChromiumCookieDecryptor, import_browser_cookie_stores_with_decryptor,
};
use crate::browser_profile::BrowserProfileDiscovery;
use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{
    CookieImportOrder, CookieJar, CookieSourceId, CookieUrlPolicy, MAX_COOKIE_HEADER_BYTES,
    ValidatedCookieUrl,
};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::executable::{ExecutablePath, resolve_executable};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{StderrClassifier, SubprocessError, SubprocessRequest};
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
};

const API_ENDPOINT: &str = "https://ampcode.com/api/internal?userDisplayBalanceInfo";
const SETTINGS_ENDPOINT: &str = "https://ampcode.com/settings";
const APP_ORIGIN: &str = "https://app.ampcode.com";
const WWW_ORIGIN: &str = "https://www.ampcode.com";
const API_TOKEN_KEY: &str = "AMP_API_KEY";
const CLI_OVERRIDE: &str = "OMARCHY_AI_BAR_AMP_PATH";
const PINNED_CLI_OVERRIDE: &str = "AMP_CLI_PATH";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_HTML_OBJECT_DEPTH: usize = 64;
const MAX_HTML_FIELDS: usize = 4_096;
const MAX_HTML_STRING_BYTES: usize = 128 * 1024;
const MAX_BROWSER_PROFILES: usize = 64;
const MAX_BROWSER_SESSIONS: usize = 16;
const MAX_NAVIGATION_REDIRECTS: usize = 5;
const MAX_NAVIGATION_URL_BYTES: usize = 16 * 1024;
const MAX_DISPLAY_TEXT_BYTES: usize = 256 * 1024;
const MAX_DISPLAY_LINES: usize = 4_096;
const MAX_WORKSPACES: usize = 23;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_PLAN_BYTES: usize = 256;
const MAX_WORKSPACE_NAME_BYTES: usize = 110;
const CLI_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_STDOUT_BYTES: usize = MAX_DISPLAY_TEXT_BYTES;
const CLI_STDERR_BYTES: usize = MAX_DISPLAY_TEXT_BYTES;
const MAX_CLI_CUSTOM_VALUE_BYTES: usize = 4 * 1024;
const AUTH_STDERR_TAG: u8 = 1;
const MONTHLY_SECONDS: u64 = 30 * 24 * 60 * 60;
const WEB_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const WEB_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const WEB_ORIGIN: &str = "https://ampcode.com";
const WEB_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);

/// A bounded Amp access token which is zeroized on drop.
#[derive(Clone)]
pub struct AmpApiCredential {
    value: Zeroizing<String>,
}

impl AmpApiCredential {
    /// Resolves `AMP_API_KEY`, preserving the baseline trim-and-unquote behavior.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for absent or unsafe values.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        environment
            .get(API_TOKEN_KEY)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
            .and_then(Self::new)
    }

    /// Validates one explicitly selected Amp access token.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for empty, oversized, or
    /// line-breaking values.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ClassifiedError> {
        let value = clean_setting(value.as_ref())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        if value.len() > MAX_TOKEN_BYTES || value.contains(['\r', '\n']) {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        Ok(Self {
            value: Zeroizing::new(value.to_owned()),
        })
    }

    fn authentication(&self) -> Result<Authentication, ClassifiedError> {
        Authentication::bearer(self.value.as_str().to_owned()).map_err(|error| error.classified())
    }
}

impl Debug for AmpApiCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AmpApiCredential(<redacted>)")
    }
}

/// Resolved shell-free Amp CLI configuration.
pub struct AmpCliSettings {
    executable: ExecutablePath,
    environment: Vec<(String, String)>,
    api_token: Option<Zeroizing<String>>,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl AmpCliSettings {
    /// Resolves the Amp executable from the application override, absolute
    /// `PATH` entries, and bounded Linux install locations.
    ///
    /// # Errors
    ///
    /// Returns missing-credential when no executable is installed and API for
    /// an invalid or unavailable authoritative override.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let executable = resolve_amp(environment)?;
        Self::from_executable(executable, environment)
    }

    /// Creates CLI settings from one explicit absolute executable path.
    ///
    /// # Errors
    ///
    /// Returns API for a relative/non-executable path or unsafe environment.
    pub fn new(
        executable: impl Into<PathBuf>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let executable = executable.into();
        let configured = executable
            .to_str()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        let executable = resolve_executable("amp", Some(configured), None, &[])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_executable(executable, environment)
    }

    fn from_executable(
        executable: ExecutablePath,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let sanitized = sanitized_cli_environment(environment, executable.as_path())?;
        let api_token = environment
            .get(API_TOKEN_KEY)
            .and_then(|value| clean_setting(value))
            .map(AmpApiCredential::new)
            .transpose()?
            .map(|credential| credential.value);
        Ok(Self {
            executable,
            environment: sanitized,
            api_token,
            timeout: CLI_TIMEOUT,
            max_stdout_bytes: CLI_STDOUT_BYTES,
            max_stderr_bytes: CLI_STDERR_BYTES,
        })
    }

    /// Returns the resolved executable for setup diagnostics.
    #[must_use]
    pub fn executable(&self) -> &Path {
        self.executable.as_path()
    }

    /// Overrides resource limits for deterministic subprocess tests.
    ///
    /// # Errors
    ///
    /// Rejects zero or production-exceeding values.
    #[doc(hidden)]
    pub fn with_test_limits(
        mut self,
        timeout: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, ClassifiedError> {
        if timeout.is_zero()
            || timeout > CLI_TIMEOUT
            || max_stdout_bytes == 0
            || max_stdout_bytes > CLI_STDOUT_BYTES
            || max_stderr_bytes == 0
            || max_stderr_bytes > CLI_STDERR_BYTES
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        self.timeout = timeout;
        self.max_stdout_bytes = max_stdout_bytes;
        self.max_stderr_bytes = max_stderr_bytes;
        Ok(self)
    }
}

impl Debug for AmpCliSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmpCliSettings")
            .field("executable", &"<redacted>")
            .field("environment_entries", &self.environment.len())
            .field("api_token", &"<redacted>")
            .field("timeout", &self.timeout)
            .field("max_stdout_bytes", &self.max_stdout_bytes)
            .field("max_stderr_bytes", &self.max_stderr_bytes)
            .finish()
    }
}

/// Fixed Amp settings route plus the exact origins a navigation may use.
pub struct AmpWebRouteSet {
    settings: Url,
    endpoints: EndpointPolicy,
}

impl AmpWebRouteSet {
    /// Creates Amp's production settings route and known cookie-bearing origins.
    ///
    /// # Errors
    ///
    /// Returns API only if the compile-time route contract is invalid.
    #[doc(hidden)]
    pub fn production() -> Result<Self, ClassifiedError> {
        let settings = Url::parse(SETTINGS_ENDPOINT).map_err(|_| api_error())?;
        let endpoints = EndpointPolicy::new([
            (WEB_ORIGIN, EndpointClass::PublicHttps),
            (WWW_ORIGIN, EndpointClass::PublicHttps),
            (APP_ORIGIN, EndpointClass::PublicHttps),
        ])
        .map_err(|_| api_error())?;
        Self::new(settings, endpoints)
    }

    /// Reports whether a complete URL may receive the Amp session cookie.
    #[must_use]
    #[doc(hidden)]
    pub fn allows_cookie_target(&self, url: &Url) -> bool {
        self.endpoints.validate(url).is_ok() && !is_amp_login_redirect(url) && !is_login_route(url)
    }

    /// Creates an exact loopback route for deterministic HTTP tests.
    ///
    /// # Errors
    ///
    /// Rejects non-loopback, credential-bearing, queried, or non-settings URLs.
    #[doc(hidden)]
    pub fn loopback(settings: Url) -> Result<Self, ClassifiedError> {
        let origin = settings.origin().ascii_serialization();
        let endpoints = EndpointPolicy::new([(origin, EndpointClass::LoopbackDevelopment)])
            .map_err(|_| api_error())?;
        Self::new(settings, endpoints)
    }

    fn new(settings: Url, endpoints: EndpointPolicy) -> Result<Self, ClassifiedError> {
        if !settings.username().is_empty()
            || settings.password().is_some()
            || settings.path() != "/settings"
            || settings.query().is_some()
            || settings.fragment().is_some()
        {
            return Err(api_error());
        }
        endpoints.validate(&settings).map_err(|_| api_error())?;
        Ok(Self {
            settings,
            endpoints,
        })
    }
}

impl Debug for AmpWebRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmpWebRouteSet")
            .field(
                "settings_origin",
                &self.settings.origin().ascii_serialization(),
            )
            .field("settings_path", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct WebSession {
    cookie: Zeroizing<String>,
}

impl Debug for WebSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSession(<redacted>)")
    }
}

struct WebBackend {
    source: ProviderSource,
    routes: AmpWebRouteSet,
    sessions: Vec<WebSession>,
    transport: AmpWebTransport,
}

/// Amp adapter permanently bound to one account and one explicit source.
pub struct AmpProvider {
    scope: AccountScope,
    backend: Backend,
}

enum Backend {
    Api(ApiBackend),
    Cli(AmpCliSettings),
    Web(Box<WebBackend>),
}

struct ApiBackend {
    credential: AmpApiCredential,
    endpoint: Url,
    transport: HttpTransport,
}

impl AmpProvider {
    /// Resolves and constructs only sources whose credentials fit the injected
    /// environment. Manual and browser sources use their explicit constructors.
    ///
    /// # Errors
    ///
    /// Returns a stable error for unsupported sources or unusable credentials.
    pub fn resolve(
        scope: AccountScope,
        source: ProviderSource,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        match source {
            ProviderSource::ApiKey => Self::new_api(scope, AmpApiCredential::resolve(environment)?),
            ProviderSource::Cli => Self::new_cli(scope, AmpCliSettings::resolve(environment)?),
            ProviderSource::BrowserSession
            | ProviderSource::ManualCookie
            | ProviderSource::CloudCredentials
            | ProviderSource::ConfigurableEndpoint
            | ProviderSource::OAuth
            | ProviderSource::LocalData => Err(ClassifiedError::new(ErrorKind::Api)),
        }
    }

    /// Creates the production fixed-origin bearer API adapter.
    ///
    /// # Errors
    ///
    /// Returns API for a wrong provider scope or invalid transport setup.
    pub fn new_api(
        scope: AccountScope,
        credential: AmpApiCredential,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        let endpoint =
            Url::parse(API_ENDPOINT).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let policy = EndpointPolicy::new([(
            endpoint.origin().ascii_serialization(),
            EndpointClass::PublicHttps,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Self::from_api_transport(scope, credential, endpoint, transport)
    }

    /// Creates the shell-free Amp CLI adapter.
    ///
    /// # Errors
    ///
    /// Returns API for a wrong provider scope.
    pub fn new_cli(scope: AccountScope, settings: AmpCliSettings) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        Ok(Self {
            scope,
            backend: Backend::Cli(settings),
        })
    }

    /// Creates a production adapter from a manual Cookie header or cURL capture.
    ///
    /// Only exact known Amp web hosts and the case-sensitive `session` cookie
    /// are retained.
    ///
    /// # Errors
    ///
    /// Returns stable missing, parse, scope, or route errors.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, AmpWebRouteSet::production()?)
    }

    /// Creates an injected-route manual-session adapter for HTTP tests.
    ///
    /// A cURL URL, when present, remains restricted to exact production Amp
    /// hosts. The route changes only the already-authorized network target.
    ///
    /// # Errors
    ///
    /// Returns stable capture, credential, scope, or route errors.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: AmpWebRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(
            ["ampcode.com", "www.ampcode.com", "app.ampcode.com"],
            [CaptureHeader::Cookie],
        )
        .map_err(classify_capture_error)?
        .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(missing_credential)?;
        let session = session_cookie_header(cookie)?;
        Self::build_web(
            scope,
            ProviderSource::ManualCookie,
            routes,
            vec![WebSession { cookie: session }],
        )
    }

    /// Creates a production adapter from ordered Linux browser profiles.
    ///
    /// Chromium-family root/Network stores and Firefox/Zen SQLite stores are
    /// read through the shared snapshot boundary. Profiles never share jars.
    ///
    /// # Errors
    ///
    /// Returns stable missing, bounded local-data, decryption, scope, or route errors.
    pub fn new_browser(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        let routes = AmpWebRouteSet::production()?;
        Self::from_browser_routes(scope, discovery, decryptor, now, routes)
    }

    /// Creates an injected-route browser adapter for deterministic profile tests.
    ///
    /// # Errors
    ///
    /// Returns stable missing, bounded local-data, decryption, scope, or route errors.
    #[doc(hidden)]
    pub fn from_browser_routes(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
        routes: AmpWebRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let sessions = browser_sessions(discovery, decryptor, now)?;
        Self::build_web(scope, ProviderSource::BrowserSession, routes, sessions)
    }

    fn build_web(
        scope: AccountScope,
        source: ProviderSource,
        routes: AmpWebRouteSet,
        sessions: Vec<WebSession>,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        if !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        ) || sessions.is_empty()
            || sessions.len() > MAX_BROWSER_SESSIONS
        {
            return Err(api_error());
        }
        let transport = AmpWebTransport::new(routes.endpoints.clone())?;
        Ok(Self {
            scope,
            backend: Backend::Web(Box::new(WebBackend {
                source,
                routes,
                sessions,
                transport,
            })),
        })
    }

    /// Deterministic loopback seam retaining transport-owned endpoint policy.
    ///
    /// # Errors
    ///
    /// Rejects wrong-provider scopes and malformed balance endpoints.
    #[doc(hidden)]
    pub fn from_api_transport(
        scope: AccountScope,
        credential: AmpApiCredential,
        endpoint: Url,
        transport: HttpTransport,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        validate_api_endpoint(&endpoint)?;
        Ok(Self {
            scope,
            backend: Backend::Api(ApiBackend {
                credential,
                endpoint,
                transport,
            }),
        })
    }

    /// Source to which this adapter is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        match &self.backend {
            Backend::Api(_) => ProviderSource::ApiKey,
            Backend::Cli(_) => ProviderSource::Cli,
            Backend::Web(web) => web.source,
        }
    }

    /// Fetches one sample at an injected wall-clock instant.
    ///
    /// # Errors
    ///
    /// Returns only stable scope, credential, subprocess, transport, or parse
    /// classifications without provider-controlled text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        match &self.backend {
            Backend::Api(backend) => fetch_api(backend, context, fetched_at).await,
            Backend::Cli(settings) => fetch_cli(settings, context, fetched_at).await,
            Backend::Web(web) => fetch_web(web, context, fetched_at).await,
        }
    }
}

impl Debug for AmpProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmpProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source())
            .finish_non_exhaustive()
    }
}

impl ProviderAdapter for AmpProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Amp)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

async fn fetch_api(
    backend: &ApiBackend,
    context: &ProviderContext,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let body = serde_json::to_vec(&serde_json::json!({
        "method": "userDisplayBalanceInfo",
        "params": {},
    }))
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let request = HttpRequest::post_json(backend.endpoint.clone(), body)
        .map_err(|error| error.classified())?
        .accept(RequestAccept::Json)
        .content_type(RequestContentType::Json)
        .authentication(backend.credential.authentication()?)
        .accepted_statuses(&[401, 403])
        .map_err(|error| error.classified())?;
    let response = backend
        .transport
        .send(&request, context.cancellation())
        .await
        .map_err(|error| error.classified())?;
    if matches!(response.status(), 401 | 403) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if response.status() != 200 {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let wire: UsageApiResponse = response.json()?;
    if !wire.ok {
        return Err(ClassifiedError::new(
            if wire.error.as_ref().and_then(|error| error.code.as_deref()) == Some("auth-required")
            {
                ErrorKind::AuthenticationExpired
            } else {
                ErrorKind::Api
            },
        ));
    }
    let display_text = wire
        .result
        .map(|result| result.display_text)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    parse_display_text(
        context.scope().clone(),
        fetched_at,
        &display_text,
        ProviderSource::ApiKey,
    )
}

async fn fetch_cli(
    settings: &AmpCliSettings,
    context: &ProviderContext,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let classifier = StderrClassifier::ascii_case_insensitive([
        (AUTH_STDERR_TAG, "not logged in"),
        (AUTH_STDERR_TAG, "not authenticated"),
        (AUTH_STDERR_TAG, "authentication required"),
        (AUTH_STDERR_TAG, "login required"),
        (AUTH_STDERR_TAG, "please login"),
        (AUTH_STDERR_TAG, "please log in"),
        (AUTH_STDERR_TAG, "sign in"),
    ])
    .map_err(map_subprocess_error)?;
    let mut request = SubprocessRequest::new(
        settings.executable.as_path(),
        ["usage"],
        settings.timeout,
        settings.max_stdout_bytes,
        settings.max_stderr_bytes,
    )
    .map_err(map_subprocess_error)?
    .with_cleared_environment()
    .with_stderr_classifier(classifier);
    for (name, value) in &settings.environment {
        request = request
            .with_environment(name, value)
            .map_err(map_subprocess_error)?;
    }
    if let Some(api_token) = &settings.api_token {
        request = request
            .with_environment(API_TOKEN_KEY, api_token.as_str())
            .map_err(map_subprocess_error)?;
    }
    request = request
        .with_environment("NO_COLOR", "1")
        .map_err(map_subprocess_error)?
        .with_environment("TERM", "dumb")
        .map_err(map_subprocess_error)?;
    let output = request
        .run(context.cancellation())
        .await
        .map_err(map_subprocess_error)?;
    let bytes = if output
        .stdout()
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        output.stdout()
    } else {
        output.stderr()
    };
    let text = std::str::from_utf8(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if text.trim().is_empty() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    parse_display_text(
        context.scope().clone(),
        fetched_at,
        text,
        ProviderSource::Cli,
    )
}

async fn fetch_web(
    backend: &WebBackend,
    context: &ProviderContext,
    fetched_at: Timestamp,
) -> Result<UsageSample, ClassifiedError> {
    let mut last_error = None;
    for session in &backend.sessions {
        let result = backend
            .transport
            .fetch(&backend.routes.settings, session, context.cancellation())
            .await
            .and_then(|body| {
                let html = std::str::from_utf8(&body).map_err(|_| parse_error(()))?;
                parse_html(context.scope().clone(), fetched_at, html, backend.source)
            });
        match result {
            Ok(sample) => return Ok(sample),
            Err(error)
                if backend.source == ProviderSource::BrowserSession
                    && error.kind() == ErrorKind::AuthenticationExpired =>
            {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(missing_credential))
}

struct AmpWebTransport {
    client: Client,
    endpoints: EndpointPolicy,
}

impl AmpWebTransport {
    fn new(endpoints: EndpointPolicy) -> Result<Self, ClassifiedError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| api_error())?;
        Ok(Self { client, endpoints })
    }

    async fn fetch(
        &self,
        settings: &Url,
        session: &WebSession,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, ClassifiedError> {
        let mut current = settings.clone();
        let mut referer = SETTINGS_ENDPOINT.to_owned();
        for redirect_count in 0..=MAX_NAVIGATION_REDIRECTS {
            if current.as_str().len() > MAX_NAVIGATION_URL_BYTES {
                return Err(parse_error(()));
            }
            if is_amp_login_redirect(&current) {
                return Err(authentication_expired());
            }
            let endpoint = self
                .endpoints
                .validate(&current)
                .map_err(|_| parse_error(()))?;
            if is_login_route(&current) {
                return Err(authentication_expired());
            }
            let cookie = sensitive_header(session.cookie.as_str())?;
            let request = self
                .client
                .get(endpoint.url().clone())
                .header(ACCEPT, WEB_ACCEPT)
                .header(ACCEPT_LANGUAGE, WEB_ACCEPT_LANGUAGE)
                .header(USER_AGENT, WEB_USER_AGENT)
                .header(ORIGIN, WEB_ORIGIN)
                .header(REFERER, &referer)
                .header(COOKIE, cookie);
            let response = tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(network_error()),
                response = request.send() => response.map_err(|_| network_error())?,
            };
            if response.status().is_redirection() {
                if redirect_count == MAX_NAVIGATION_REDIRECTS {
                    return Err(parse_error(()));
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| parse_error(()))?;
                if location.as_bytes().len() > MAX_NAVIGATION_URL_BYTES {
                    return Err(parse_error(()));
                }
                let location = location.to_str().map_err(parse_error)?;
                let target = current.join(location).map_err(parse_error)?;
                if target.as_str().len() > MAX_NAVIGATION_URL_BYTES {
                    return Err(parse_error(()));
                }
                if is_amp_login_redirect(&target) {
                    return Err(authentication_expired());
                }
                self.endpoints
                    .validate(&target)
                    .map_err(|_| parse_error(()))?;
                if is_login_route(&target) {
                    return Err(authentication_expired());
                }
                referer = current.as_str().to_owned();
                current = target;
                continue;
            }
            classify_web_status(response.status())?;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
            {
                return Err(parse_error(()));
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            loop {
                let next = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return Err(network_error()),
                    next = stream.next() => next,
                };
                let Some(chunk) = next else {
                    break;
                };
                let chunk = chunk.map_err(|_| network_error())?;
                let length = body
                    .len()
                    .checked_add(chunk.len())
                    .filter(|length| *length <= MAX_RESPONSE_BYTES)
                    .ok_or_else(|| parse_error(()))?;
                body.reserve(length.saturating_sub(body.len()));
                body.extend_from_slice(&chunk);
            }
            return Ok(body);
        }
        Err(parse_error(()))
    }
}

impl Debug for AmpWebTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AmpWebTransport(<redacted>)")
    }
}

fn classify_web_status(status: StatusCode) -> Result<(), ClassifiedError> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(authentication_expired()),
        StatusCode::REQUEST_TIMEOUT => Err(network_error()),
        StatusCode::TOO_MANY_REQUESTS => Err(ClassifiedError::new(ErrorKind::RateLimited)),
        status if status.is_server_error() => {
            Err(ClassifiedError::new(ErrorKind::ProviderUnavailable))
        }
        _ => Err(api_error()),
    }
}

fn sensitive_header(value: &str) -> Result<HeaderValue, ClassifiedError> {
    if value.is_empty() || value.len() > MAX_COOKIE_HEADER_BYTES {
        return Err(api_error());
    }
    let mut value = HeaderValue::from_str(value).map_err(|_| api_error())?;
    value.set_sensitive(true);
    Ok(value)
}

/// Reports whether a URL is one of Amp's pinned sign-in redirect shapes.
#[must_use]
#[doc(hidden)]
pub fn is_amp_login_redirect(url: &Url) -> bool {
    if !is_amp_host(url.host_str()) {
        return false;
    }
    url.host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("auth.ampcode.com"))
        || is_login_route(url)
}

fn is_amp_host(host: Option<&str>) -> bool {
    host.is_some_and(|host| {
        host.eq_ignore_ascii_case("ampcode.com")
            || host
                .to_ascii_lowercase()
                .strip_suffix(".ampcode.com")
                .is_some_and(|prefix| !prefix.is_empty())
    })
}

fn is_login_route(url: &Url) -> bool {
    let components = url
        .path_segments()
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| matches!(component.as_str(), "login" | "signin" | "sign-in"))
    {
        return true;
    }
    if components.iter().any(|component| component == "auth") {
        let query = url.query().unwrap_or_default().to_ascii_lowercase();
        return ["returnto=", "redirect=", "redirectto="]
            .iter()
            .any(|needle| query.contains(needle));
    }
    false
}

fn browser_sessions(
    discovery: &BrowserProfileDiscovery,
    decryptor: &dyn ChromiumCookieDecryptor,
    now: OffsetDateTime,
) -> Result<Vec<WebSession>, ClassifiedError> {
    let allowlist = BrowserCookieDomainAllowlist::new([BrowserCookieDomainRule {
        domain: "ampcode.com",
        policy: BrowserCookieDomainPolicy::DomainAndSubdomains,
    }])
    .map_err(|_| parse_error(()))?;
    let target = ValidatedCookieUrl::parse(SETTINGS_ENDPOINT, CookieUrlPolicy::HttpsOnly)
        .map_err(|_| api_error())?;
    let report = discovery.discover();
    if report.profiles().len() > MAX_BROWSER_PROFILES {
        return Err(parse_error(()));
    }
    let mut sessions = Vec::new();
    let mut seen = HashSet::<[u8; 32]>::new();
    for (index, profile) in report.profiles().iter().enumerate() {
        let first = index
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| parse_error(()))?;
        let store_sources = [CookieSourceId::new(first), CookieSourceId::new(first + 1)];
        let Ok(imports) = import_browser_cookie_stores_with_decryptor(
            profile,
            store_sources,
            &allowlist,
            decryptor,
        ) else {
            continue;
        };
        let order = CookieImportOrder::new(store_sources).map_err(|_| parse_error(()))?;
        for import in imports {
            let jar = CookieJar::from_imports(&order, [import]).map_err(|_| parse_error(()))?;
            let Some(header) = jar.header_for(&target, now).map_err(|_| parse_error(()))? else {
                continue;
            };
            let Ok(cookie) = session_cookie_header(header.expose()) else {
                continue;
            };
            let digest: [u8; 32] = Sha256::digest(cookie.as_bytes()).into();
            if seen.insert(digest) {
                sessions.push(WebSession { cookie });
                if sessions.len() > MAX_BROWSER_SESSIONS {
                    return Err(parse_error(()));
                }
            }
            break;
        }
    }
    if sessions.is_empty() {
        Err(missing_credential())
    } else {
        Ok(sessions)
    }
}

fn session_cookie_header(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    if raw.len() > MAX_COOKIE_HEADER_BYTES || raw.contains(['\r', '\n']) {
        return Err(parse_error(()));
    }
    let mut output = Zeroizing::new(String::new());
    for part in raw.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            return Err(parse_error(()));
        };
        let name = name.trim();
        let value = value.trim();
        if name != "session" {
            continue;
        }
        if value.is_empty() || value.len() > MAX_TOKEN_BYTES {
            return Err(missing_credential());
        }
        if !output.is_empty() {
            output.push_str("; ");
        }
        output.push_str("session=");
        output.push_str(value);
    }
    if output.is_empty() {
        return Err(missing_credential());
    }
    sensitive_header(output.as_str())?;
    Ok(output)
}

/// Parses Amp's complete CLI/API display-text format into the shared domain.
///
/// This includes legacy rolling free-tier balances, current daily percentages,
/// both subscription syntaxes, individual credits, workspace credits, ANSI
/// output, Markdown-bold labels, account identity, and reset metadata.
///
/// # Errors
///
/// Returns a stable parse/authentication error for malformed, signed-out, or
/// resource-excessive text. Only Amp API-key and CLI sources are accepted.
pub fn parse_display_text(
    scope: AccountScope,
    fetched_at: Timestamp,
    display_text: &str,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope(&scope)?;
    let strategy = match source {
        ProviderSource::ApiKey => "api",
        ProviderSource::Cli => "cli",
        ProviderSource::BrowserSession
        | ProviderSource::ManualCookie
        | ProviderSource::CloudCredentials
        | ProviderSource::ConfigurableEndpoint
        | ProviderSource::OAuth
        | ProviderSource::LocalData => return Err(ClassifiedError::new(ErrorKind::Api)),
    };
    let parsed = ParsedUsage::parse(display_text, fetched_at)?;
    parsed.normalize(scope, fetched_at, strategy)
}

/// Parses Amp's settings-page Svelte payload into the shared usage domain.
///
/// The pinned page exposes either `freeTierUsage` or the prefetched
/// `getFreeTierUsage` key. Parsing is bounded and does not execute page code.
///
/// # Errors
///
/// Returns stable scope, source, signed-out, or bounded parse failures. Only
/// manual-cookie and browser-session sources are accepted.
pub fn parse_html(
    scope: AccountScope,
    fetched_at: Timestamp,
    html: &str,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope(&scope)?;
    let strategy = match source {
        ProviderSource::ManualCookie => "manual_cookie",
        ProviderSource::BrowserSession => "browser_session",
        ProviderSource::ApiKey
        | ProviderSource::ConfigurableEndpoint
        | ProviderSource::OAuth
        | ProviderSource::Cli
        | ProviderSource::LocalData
        | ProviderSource::CloudCredentials => return Err(api_error()),
    };
    if html.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error(()));
    }
    let Some(free) = parse_html_free_usage(html)? else {
        return Err(if looks_signed_out(html) {
            authentication_expired()
        } else {
            parse_error(())
        });
    };
    ParsedUsage {
        free: Some(free),
        subscription: None,
        individual_credits: None,
        workspaces: Vec::new(),
        email: None,
        organization: None,
    }
    .normalize(scope, fetched_at, strategy)
}

#[derive(Deserialize)]
struct UsageApiResponse {
    ok: bool,
    result: Option<UsageApiResult>,
    error: Option<UsageApiError>,
}

#[derive(Deserialize)]
struct UsageApiResult {
    #[serde(rename = "displayText")]
    display_text: String,
}

#[derive(Deserialize)]
struct UsageApiError {
    code: Option<String>,
}

struct ParsedUsage {
    free: Option<FreeUsage>,
    subscription: Option<SubscriptionUsage>,
    individual_credits: Option<Decimal>,
    workspaces: Vec<WorkspaceBalance>,
    email: Option<String>,
    organization: Option<String>,
}

struct FreeUsage {
    quota: Decimal,
    used: Decimal,
    hourly_replenishment: Decimal,
    duration_seconds: Option<u64>,
    reset_kind: FreeReset,
}

#[derive(Clone, Copy)]
enum FreeReset {
    Rolling,
    Daily,
    None,
}

struct SubscriptionUsage {
    plan: String,
    other_used_percent: f64,
    orb_used_percent: f64,
    resets_at: Timestamp,
    reset_description: String,
}

struct WorkspaceBalance {
    name: String,
    remaining: Decimal,
}

impl ParsedUsage {
    fn parse(text: &str, fetched_at: Timestamp) -> Result<Self, ClassifiedError> {
        if text.len() > MAX_DISPLAY_TEXT_BYTES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let stripped = strip_ansi(text)?;
        let stripped = stripped.replace("**", "");
        if stripped.lines().count() > MAX_DISPLAY_LINES {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }

        let mut identity = None;
        let mut legacy_free = None;
        let mut daily_free = None;
        let mut subscription = None;
        let mut individual_credits = None;
        let mut workspaces = Vec::new();

        for raw_line in stripped.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if identity.is_none() {
                identity = parse_identity(line)?;
            }
            if let Some(body) = strip_prefix_ascii_case(line, "Amp Free:") {
                if legacy_free.is_none() {
                    legacy_free = parse_legacy_free(body)?;
                }
                if daily_free.is_none() {
                    daily_free = parse_daily_free(body);
                }
                continue;
            }
            if subscription.is_none() {
                subscription = parse_subscription(line, fetched_at)?;
                if subscription.is_some() {
                    continue;
                }
            }
            if individual_credits.is_none()
                && let Some(body) = strip_prefix_ascii_case(line, "Individual credits:")
            {
                individual_credits = parse_remaining_amount(body);
                continue;
            }
            if let Some(body) =
                strip_prefix_ascii_case(line, "Workspace").and_then(strip_required_ascii_whitespace)
            {
                if workspaces.len() == MAX_WORKSPACES {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                if let Some((name, remaining)) = parse_workspace(body)? {
                    workspaces.push(WorkspaceBalance { name, remaining });
                }
            }
        }

        let (email, organization) = identity.map_or((None, None), |(email, organization)| {
            (Some(email), organization)
        });
        if email.is_none() && looks_signed_out(&stripped) {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        let free = legacy_free.or(daily_free);
        if free.is_none()
            && subscription.is_none()
            && individual_credits.is_none()
            && workspaces.is_empty()
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(Self {
            free,
            subscription,
            individual_credits,
            workspaces,
            email,
            organization,
        })
    }

    fn normalize(
        self,
        scope: AccountScope,
        fetched_at: Timestamp,
        strategy: &'static str,
    ) -> Result<UsageSample, ClassifiedError> {
        let free_window = self
            .free
            .as_ref()
            .map(|free| free.rate_window(fetched_at))
            .transpose()?;
        let mut builder = UsageSampleBuilder::new(scope, fetched_at)
            .email(self.email)?
            .organization(self.organization)?;

        if let Some(subscription) = self.subscription {
            let primary = subscription_window(
                subscription.other_used_percent,
                subscription.resets_at,
                &subscription.reset_description,
            )?;
            let secondary = subscription_window(
                subscription.orb_used_percent,
                subscription.resets_at,
                &subscription.reset_description,
            )?;
            builder = builder
                .primary(primary)
                .secondary(secondary)
                .login_method(Some(subscription.plan))?;
            if let Some(free_window) = free_window {
                builder = builder.extra_windows(vec![NamedRateWindow::new(
                    bounded("amp-free")?,
                    bounded("Amp Free")?,
                    free_window,
                )]);
            }
        } else {
            builder = builder.login_method(Some(if free_window.is_some() {
                "Amp Free".to_owned()
            } else {
                "Amp".to_owned()
            }))?;
            if let Some(free_window) = free_window {
                builder = builder.primary(free_window);
            }
        }

        let mut rows = Vec::new();
        if let Some(credits) = self.individual_credits {
            rows.push(detail_row(
                "Individual credits".to_owned(),
                format_usd(credits),
            )?);
        }
        for workspace in self.workspaces {
            rows.push(detail_row(
                format!("Workspace {}", workspace.name),
                format_usd(workspace.remaining),
            )?);
        }
        if !rows.is_empty() {
            builder = builder.detail_sections(vec![
                DetailSection::new(Some("Credits".to_owned()), rows, None)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ]);
        }
        builder.provenance("amp", strategy)?.build()
    }
}

impl FreeUsage {
    fn rate_window(&self, fetched_at: Timestamp) -> Result<RateWindow, ClassifiedError> {
        let quota = self.quota.max(Decimal::ZERO);
        let used = self.used.max(Decimal::ZERO);
        let percent = if quota > Decimal::ZERO {
            (used * Decimal::from(100_u8) / quota)
                .to_f64()
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
                .clamp(0.0, 100.0)
        } else {
            0.0
        };
        let (resets_at, description) = match self.reset_kind {
            FreeReset::Daily => (
                Some(next_eastern_daily_reset(fetched_at)?),
                Some(bounded("resets daily")?),
            ),
            FreeReset::Rolling
                if quota > Decimal::ZERO && self.hourly_replenishment > Decimal::ZERO =>
            {
                let nanoseconds = (used / self.hourly_replenishment
                    * Decimal::from(3_600_000_000_000_u64))
                .round_dp(0)
                .to_i128()
                .filter(|nanoseconds| {
                    *nanoseconds >= 0 && *nanoseconds <= i128::from(i64::MAX) * 1_000_000_000
                })
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                let reset = fetched_at
                    .as_offset_date_time()
                    .checked_add(time::Duration::nanoseconds_i128(nanoseconds))
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
                (
                    Some(
                        Timestamp::new(reset)
                            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                    ),
                    None,
                )
            }
            FreeReset::Rolling | FreeReset::None => (None, None),
        };
        RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            self.duration_seconds
                .map(WindowDuration::from_seconds)
                .transpose()
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            resets_at,
            description,
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
    }
}

fn parse_html_free_usage(html: &str) -> Result<Option<FreeUsage>, ClassifiedError> {
    for token in ["freeTierUsage", "getFreeTierUsage"] {
        let Some(object) = extract_html_object(token, html)? else {
            continue;
        };
        let Some(quota) = html_number_for("quota", object)? else {
            continue;
        };
        let Some(used) = html_number_for("used", object)? else {
            continue;
        };
        let Some(hourly_replenishment) = html_number_for("hourlyReplenishment", object)? else {
            continue;
        };
        let duration_seconds = html_number_for("windowHours", object)?
            .filter(|hours| *hours > Decimal::ZERO)
            .map(|hours| {
                (hours * Decimal::from(60_u8))
                    .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
                    .to_u64()
                    .and_then(|minutes| minutes.checked_mul(60))
                    .ok_or_else(|| parse_error(()))
            })
            .transpose()?;
        return Ok(Some(FreeUsage {
            quota,
            used,
            hourly_replenishment,
            duration_seconds,
            reset_kind: if hourly_replenishment > Decimal::ZERO {
                FreeReset::Rolling
            } else {
                FreeReset::None
            },
        }));
    }
    Ok(None)
}

fn extract_html_object<'a>(token: &str, html: &'a str) -> Result<Option<&'a str>, ClassifiedError> {
    let Some(token_start) = html.find(token) else {
        return Ok(None);
    };
    let search_start = token_start
        .checked_add(token.len())
        .ok_or_else(|| parse_error(()))?;
    let Some(relative_brace) = html[search_start..].find('{') else {
        return Ok(None);
    };
    let brace = search_start
        .checked_add(relative_brace)
        .ok_or_else(|| parse_error(()))?;
    let bytes = html.as_bytes();
    let mut depth = 0_usize;
    let mut fields = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut string_bytes = 0_usize;
    for (index, byte) in bytes.iter().copied().enumerate().skip(brace) {
        if in_string {
            string_bytes = string_bytes
                .checked_add(1)
                .filter(|length| *length <= MAX_HTML_STRING_BYTES)
                .ok_or_else(|| parse_error(()))?;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                string_bytes = 0;
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                string_bytes = 0;
            }
            b'{' => {
                depth = depth
                    .checked_add(1)
                    .filter(|depth| *depth <= MAX_HTML_OBJECT_DEPTH)
                    .ok_or_else(|| parse_error(()))?;
            }
            b'}' => {
                depth = depth.checked_sub(1).ok_or_else(|| parse_error(()))?;
                if depth == 0 {
                    return Ok(Some(&html[brace..=index]));
                }
            }
            b':' => {
                fields = fields
                    .checked_add(1)
                    .filter(|fields| *fields <= MAX_HTML_FIELDS)
                    .ok_or_else(|| parse_error(()))?;
            }
            _ => {}
        }
    }
    if in_string || depth != 0 {
        return Err(parse_error(()));
    }
    Ok(None)
}

fn html_number_for(key: &str, object: &str) -> Result<Option<Decimal>, ClassifiedError> {
    let mut offset = 0_usize;
    while let Some(relative) = object[offset..].find(key) {
        let start = offset
            .checked_add(relative)
            .ok_or_else(|| parse_error(()))?;
        let end = start
            .checked_add(key.len())
            .ok_or_else(|| parse_error(()))?;
        let left_is_word = start > 0 && is_html_word_byte(object.as_bytes()[start - 1]);
        let right_is_word = object
            .as_bytes()
            .get(end)
            .is_some_and(|byte| is_html_word_byte(*byte));
        if !left_is_word && !right_is_word {
            let suffix = object[end..].trim_start_matches(char::is_whitespace);
            if let Some(suffix) = suffix.strip_prefix(':') {
                let suffix = suffix.trim_start_matches(char::is_whitespace);
                let digit_count = suffix.bytes().take_while(u8::is_ascii_digit).count();
                if digit_count > 0 {
                    let mut number_end = digit_count;
                    if suffix.as_bytes().get(number_end) == Some(&b'.') {
                        let fraction = suffix[number_end + 1..]
                            .bytes()
                            .take_while(u8::is_ascii_digit)
                            .count();
                        if fraction == 0 {
                            return Ok(None);
                        }
                        number_end = number_end
                            .checked_add(1 + fraction)
                            .ok_or_else(|| parse_error(()))?;
                    }
                    if number_end > 64 {
                        return Err(parse_error(()));
                    }
                    return Decimal::from_str(&suffix[..number_end])
                        .map(Some)
                        .map_err(parse_error);
                }
            }
        }
        offset = end;
    }
    Ok(None)
}

const fn is_html_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn parse_identity(line: &str) -> Result<Option<(String, Option<String>)>, ClassifiedError> {
    let Some(body) =
        strip_prefix_ascii_case(line, "Signed in as").and_then(strip_required_ascii_whitespace)
    else {
        return Ok(None);
    };
    let body = body.trim();
    if body.is_empty() {
        return Ok(None);
    }
    let (email, organization) = if body.ends_with(')') && body.contains('(') {
        let Some(open) = body.rfind('(') else {
            return Ok(None);
        };
        let email_with_space = &body[..open];
        let email = trim_ascii_whitespace_end(email_with_space);
        if email.len() == email_with_space.len() {
            return Ok(None);
        }
        let organization = body[open + 1..body.len() - 1].trim();
        if organization.contains(')') {
            return Ok(None);
        }
        (email, organization)
    } else {
        if body.contains('(') {
            return Ok(None);
        }
        (body, "")
    };
    let email = clean_parser_text(email, MAX_IDENTITY_BYTES)?;
    if email.split_whitespace().count() != 1 || email.contains('(') {
        return Ok(None);
    }
    let organization = if organization.is_empty() {
        None
    } else {
        Some(clean_parser_text(organization, MAX_IDENTITY_BYTES)?)
    };
    Ok(Some((email, organization)))
}

fn parse_legacy_free(body: &str) -> Result<Option<FreeUsage>, ClassifiedError> {
    let Some((remaining, rest)) = take_amount(body) else {
        return Ok(None);
    };
    let Some(rest) = trim_ascii_whitespace_start(rest).strip_prefix('/') else {
        return Ok(None);
    };
    let Some((quota, rest)) = take_amount(rest) else {
        return Ok(None);
    };
    let Some(after_remaining) = strip_required_ascii_token(rest, "remaining") else {
        return Ok(None);
    };
    let hourly = parse_hourly_replenishment(after_remaining).unwrap_or(Decimal::ZERO);
    let duration_seconds = if hourly > Decimal::ZERO {
        let hours = (quota / hourly)
            .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
            .to_u64()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .max(1);
        Some(
            hours
                .checked_mul(3_600)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
        )
    } else {
        None
    };
    Ok(Some(FreeUsage {
        quota,
        used: (quota - remaining).max(Decimal::ZERO),
        hourly_replenishment: hourly,
        duration_seconds,
        reset_kind: if hourly > Decimal::ZERO {
            FreeReset::Rolling
        } else {
            FreeReset::None
        },
    }))
}

fn parse_hourly_replenishment(after_remaining: &str) -> Option<Decimal> {
    let metadata = trim_ascii_whitespace_start(after_remaining).strip_prefix('(')?;
    let metadata = trim_ascii_whitespace_start(strip_prefix_ascii_case(metadata, "replenishes")?);
    let metadata = metadata.strip_prefix('+')?;
    let metadata = metadata.strip_prefix('$').unwrap_or(metadata);
    if metadata.len() != trim_ascii_whitespace_start(metadata).len() {
        return None;
    }
    let (hourly, metadata) = take_decimal(metadata)?;
    let metadata = trim_ascii_whitespace_start(metadata).strip_prefix('/')?;
    let metadata = trim_ascii_whitespace_start(metadata);
    let metadata = strip_prefix_ascii_case(metadata, "hour")?;
    metadata.starts_with(')').then_some(hourly)
}

fn parse_daily_free(body: &str) -> Option<FreeUsage> {
    let (remaining, rest) = take_decimal(body)?;
    let rest = trim_ascii_whitespace_start(rest).strip_prefix('%')?;
    let rest = strip_required_ascii_token(rest, "remaining")?;
    let remaining = remaining.clamp(Decimal::ZERO, Decimal::from(100_u8));
    Some(FreeUsage {
        quota: Decimal::from(100_u8),
        used: Decimal::from(100_u8) - remaining,
        hourly_replenishment: Decimal::ZERO,
        duration_seconds: Some(24 * 60 * 60),
        reset_kind: if has_exact_daily_reset(rest) {
            FreeReset::Daily
        } else {
            FreeReset::None
        },
    })
}

fn has_exact_daily_reset(after_remaining: &str) -> bool {
    let mut metadata = after_remaining;
    if let Some(after_space) = strip_required_ascii_whitespace(metadata)
        && let Some(after_today) = strip_prefix_ascii_case(after_space, "today")
    {
        metadata = after_today;
    }
    let metadata = trim_ascii_whitespace_start(metadata);
    let Some(metadata) = metadata.strip_prefix('(') else {
        return false;
    };
    let Some(metadata) = strip_prefix_ascii_case(metadata, "resets") else {
        return false;
    };
    let Some(metadata) = strip_required_ascii_whitespace(metadata) else {
        return false;
    };
    strip_prefix_ascii_case(metadata, "daily)").is_some()
}

fn parse_subscription(
    line: &str,
    fetched_at: Timestamp,
) -> Result<Option<SubscriptionUsage>, ClassifiedError> {
    let (plan, suffix) = if let Some(body) =
        strip_prefix_ascii_case(line, "Subscription").and_then(strip_required_ascii_whitespace)
    {
        let Some(colon) = body.find(':') else {
            return Ok(None);
        };
        (&body[..colon], &body[colon + 1..])
    } else if let Some(body) =
        strip_prefix_ascii_case(line, "Amp").and_then(strip_required_ascii_whitespace)
    {
        let Some((plan, suffix)) = split_before_required_ascii_token(body, "Subscription:") else {
            return Ok(None);
        };
        (plan, suffix)
    } else {
        return Ok(None);
    };
    let plan = clean_parser_text(plan, MAX_PLAN_BYTES)?;
    let Some((other_remaining, rest)) = take_decimal(suffix) else {
        return Ok(None);
    };
    let Some(rest) = trim_ascii_whitespace_start(rest).strip_prefix('%') else {
        return Ok(None);
    };
    let Some(rest) = strip_required_ascii_token(rest, "other")
        .and_then(|rest| strip_required_ascii_token(rest, "usage"))
        .and_then(|rest| strip_required_ascii_token(rest, "and"))
        .and_then(strip_required_ascii_whitespace)
    else {
        return Ok(None);
    };
    let Some((orb_remaining, rest)) = take_decimal(rest) else {
        return Ok(None);
    };
    let Some(rest) = trim_ascii_whitespace_start(rest).strip_prefix('%') else {
        return Ok(None);
    };
    let Some(rest) = strip_required_ascii_token(rest, "orb")
        .and_then(|rest| strip_required_ascii_token(rest, "usage"))
        .and_then(|rest| strip_required_ascii_token(rest, "remaining"))
    else {
        return Ok(None);
    };
    let Some(rest) = strip_subscription_reset_prefix(rest) else {
        return Ok(None);
    };
    let Some((value, unit)) = take_unsigned_integer(rest) else {
        return Ok(None);
    };
    let Some(unit) = strip_required_ascii_whitespace(unit) else {
        return Ok(None);
    };
    let (resets_at, singular, suffix) = if let Some(suffix) =
        strip_prefix_ascii_case(unit, "months").or_else(|| strip_prefix_ascii_case(unit, "month"))
    {
        (add_calendar_months(fetched_at, value)?, "month", suffix)
    } else if let Some(suffix) =
        strip_prefix_ascii_case(unit, "days").or_else(|| strip_prefix_ascii_case(unit, "day"))
    {
        let days = i64::from(value);
        let at = fetched_at
            .as_offset_date_time()
            .checked_add(time::Duration::days(days))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        (
            Timestamp::new(at).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            "day",
            suffix,
        )
    } else {
        return Ok(None);
    };
    if !valid_subscription_link_suffix(suffix) {
        return Ok(None);
    }
    let other_remaining = decimal_percent(other_remaining)?;
    let orb_remaining = decimal_percent(orb_remaining)?;
    Ok(Some(SubscriptionUsage {
        plan,
        other_used_percent: 100.0 - other_remaining,
        orb_used_percent: 100.0 - orb_remaining,
        resets_at,
        reset_description: format!(
            "renews in {value} {singular}{}",
            if value == 1 { "" } else { "s" }
        ),
    }))
}

fn strip_subscription_reset_prefix(rest: &str) -> Option<&str> {
    let rest = trim_ascii_whitespace_start(rest).strip_prefix('-')?;
    let rest = trim_ascii_whitespace_start(rest);
    let rest = strip_prefix_ascii_case(rest, "resets")?;
    let rest = strip_required_ascii_whitespace(rest)?;
    let rest = strip_prefix_ascii_case(rest, "upon")?;
    let rest = strip_required_ascii_whitespace(rest)?;
    let rest = strip_prefix_ascii_case(rest, "renewal")?;
    let rest = strip_required_ascii_whitespace(rest)?;
    let rest = strip_prefix_ascii_case(rest, "in")?;
    strip_required_ascii_whitespace(rest)
}

fn valid_subscription_link_suffix(suffix: &str) -> bool {
    if suffix.trim().is_empty() {
        return true;
    }
    let Some(suffix) = strip_required_ascii_whitespace(suffix) else {
        return false;
    };
    let Some(suffix) = suffix.strip_prefix('-') else {
        return false;
    };
    let Some(url) = strip_required_ascii_whitespace(suffix) else {
        return false;
    };
    let url = url.trim_end();
    let target = strip_prefix_ascii_case(url, "https://")
        .or_else(|| strip_prefix_ascii_case(url, "http://"));
    target.is_some_and(|target| !target.is_empty() && !url.chars().any(char::is_whitespace))
}

fn parse_remaining_amount(body: &str) -> Option<Decimal> {
    let (value, rest) = take_amount(body)?;
    strip_required_ascii_token(rest, "remaining").map(|_| value)
}

fn parse_workspace(body: &str) -> Result<Option<(String, Decimal)>, ClassifiedError> {
    let Some(colon) = body.find(':') else {
        return Ok(None);
    };
    let name = clean_parser_text(&body[..colon], MAX_WORKSPACE_NAME_BYTES)?;
    Ok(parse_remaining_amount(&body[colon + 1..]).map(|remaining| (name, remaining)))
}

fn subscription_window(
    percent: f64,
    resets_at: Timestamp,
    description: &str,
) -> Result<RateWindow, ClassifiedError> {
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(
            WindowDuration::from_seconds(MONTHLY_SECONDS)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(resets_at),
        Some(bounded(description)?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn decimal_percent(value: Decimal) -> Result<f64, ClassifiedError> {
    value
        .clamp(Decimal::ZERO, Decimal::from(100_u8))
        .to_f64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn take_amount(value: &str) -> Option<(Decimal, &str)> {
    let value = trim_ascii_whitespace_start(value);
    take_decimal(value.strip_prefix('$').unwrap_or(value))
}

fn take_decimal(value: &str) -> Option<(Decimal, &str)> {
    let value = trim_ascii_whitespace_start(value);
    let end = value
        .bytes()
        .take_while(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'.'))
        .count();
    if end == 0 || end > 64 {
        return None;
    }
    let raw = &value[..end];
    if raw.starts_with([',', '.'])
        || raw.ends_with([',', '.'])
        || raw.matches('.').count() > 1
        || !valid_grouping(raw)
    {
        return None;
    }
    let canonical = raw.replace(',', "");
    Decimal::from_str(&canonical)
        .ok()
        .filter(|decimal| *decimal >= Decimal::ZERO)
        .map(|decimal| (decimal, &value[end..]))
}

fn valid_grouping(raw: &str) -> bool {
    let whole = raw.split('.').next().unwrap_or(raw);
    if !whole.contains(',') {
        return whole.bytes().all(|byte| byte.is_ascii_digit());
    }
    let mut groups = whole.split(',');
    let Some(first) = groups.next() else {
        return false;
    };
    !first.is_empty()
        && first.len() <= 3
        && first.bytes().all(|byte| byte.is_ascii_digit())
        && groups.all(|group| group.len() == 3 && group.bytes().all(|byte| byte.is_ascii_digit()))
}

fn take_unsigned_integer(value: &str) -> Option<(u32, &str)> {
    let value = trim_ascii_whitespace_start(value);
    let end = value
        .bytes()
        .take_while(|byte| byte.is_ascii_digit() || *byte == b',')
        .count();
    if end == 0 || end > 16 || !valid_grouping(&value[..end]) {
        return None;
    }
    value[..end]
        .replace(',', "")
        .parse()
        .ok()
        .map(|number| (number, &value[end..]))
}

fn strip_ansi(value: &str) -> Result<String, ClassifiedError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != 0x1b {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        if index >= bytes.len() {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        match bytes[index] {
            b'[' => {
                index += 1;
                while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                    index += 1;
                }
                if index == bytes.len() {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                index += 1;
            }
            b']' => {
                index += 1;
                let mut terminated = false;
                while index < bytes.len() {
                    if bytes[index] == 0x07 {
                        index += 1;
                        terminated = true;
                        break;
                    }
                    if bytes[index] == 0x1b && bytes.get(index + 1).copied() == Some(b'\\') {
                        index += 2;
                        terminated = true;
                        break;
                    }
                    index += 1;
                }
                if !terminated {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
            }
            _ => index += 1,
        }
    }
    String::from_utf8(output).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn next_eastern_daily_reset(fetched_at: Timestamp) -> Result<Timestamp, ClassifiedError> {
    let utc = fetched_at.as_offset_date_time();
    let offset = eastern_offset_at_utc(utc)?;
    let local = utc.to_offset(offset);
    let mut date = local.date();
    if local.time() >= Time::from_hms(20, 0, 0).map_err(parse_error)? {
        date = date
            .next_day()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    }
    let wall = PrimitiveDateTime::new(date, Time::from_hms(20, 0, 0).map_err(parse_error)?);
    let target_offset = eastern_offset_for_local_date(date)?;
    Timestamp::new(wall.assume_offset(target_offset))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn eastern_offset_at_utc(utc: OffsetDateTime) -> Result<UtcOffset, ClassifiedError> {
    let year = utc.year();
    let start_date = nth_weekday(year, Month::March, Weekday::Sunday, 2)?;
    let end_date = nth_weekday(year, Month::November, Weekday::Sunday, 1)?;
    let start = PrimitiveDateTime::new(start_date, Time::from_hms(7, 0, 0).map_err(parse_error)?)
        .assume_utc();
    let end = PrimitiveDateTime::new(end_date, Time::from_hms(6, 0, 0).map_err(parse_error)?)
        .assume_utc();
    offset(if utc >= start && utc < end { -4 } else { -5 })
}

fn eastern_offset_for_local_date(date: Date) -> Result<UtcOffset, ClassifiedError> {
    let start = nth_weekday(date.year(), Month::March, Weekday::Sunday, 2)?;
    let end = nth_weekday(date.year(), Month::November, Weekday::Sunday, 1)?;
    offset(if date >= start && date < end { -4 } else { -5 })
}

fn nth_weekday(
    year: i32,
    month: Month,
    weekday: Weekday,
    ordinal: u8,
) -> Result<Date, ClassifiedError> {
    let first = Date::from_calendar_date(year, month, 1).map_err(parse_error)?;
    let delta =
        (weekday.number_days_from_monday() + 7 - first.weekday().number_days_from_monday()) % 7;
    first
        .checked_add(time::Duration::days(i64::from(
            delta + 7 * ordinal.saturating_sub(1),
        )))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn offset(hours: i8) -> Result<UtcOffset, ClassifiedError> {
    UtcOffset::from_hms(hours, 0, 0).map_err(parse_error)
}

fn add_calendar_months(fetched_at: Timestamp, months: u32) -> Result<Timestamp, ClassifiedError> {
    let instant = fetched_at.as_offset_date_time();
    let local_offset = UtcOffset::local_offset_at(instant).unwrap_or(UtcOffset::UTC);
    let local = instant.to_offset(local_offset);
    let month_index = i64::from(local.year())
        .checked_mul(12)
        .and_then(|total| total.checked_add(i64::from(u8::from(local.month()) - 1)))
        .and_then(|total| total.checked_add(i64::from(months)))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let year = i32::try_from(month_index.div_euclid(12))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let month = Month::try_from(u8::try_from(month_index.rem_euclid(12) + 1).map_err(parse_error)?)
        .map_err(parse_error)?;
    let day = local.day().min(days_in_month(year, month)?);
    let date = Date::from_calendar_date(year, month, day).map_err(parse_error)?;
    let wall = PrimitiveDateTime::new(date, local.time());
    let mut target_offset = local_offset;
    for _ in 0..4 {
        let candidate = wall.assume_offset(target_offset);
        let observed = UtcOffset::local_offset_at(candidate).unwrap_or(target_offset);
        if observed == target_offset {
            return Timestamp::new(candidate).map_err(parse_error);
        }
        target_offset = observed;
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn days_in_month(year: i32, month: Month) -> Result<u8, ClassifiedError> {
    let (next_year, next_month) = if month == Month::December {
        (
            year.checked_add(1)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?,
            Month::January,
        )
    } else {
        (
            year,
            Month::try_from(u8::from(month) + 1).map_err(parse_error)?,
        )
    };
    let next = Date::from_calendar_date(next_year, next_month, 1).map_err(parse_error)?;
    Ok(next
        .previous_day()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .day())
}

fn looks_signed_out(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("sign in")
        || lower.contains("log in")
        || lower.contains("login")
        || lower.contains("/login")
}

fn clean_parser_text(value: &str, maximum: usize) -> Result<String, ClassifiedError> {
    let value = value.trim();
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(value.to_owned())
}

fn bounded<const MAX: usize>(value: impl AsRef<str>) -> Result<BoundedText<MAX>, ClassifiedError> {
    BoundedText::new(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn detail_row(label: String, value: String) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, None, DetailSensitivity::Personal)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_usd(value: Decimal) -> String {
    let fixed = format!("{value:.2}");
    let (whole, fraction) = fixed.split_once('.').unwrap_or((&fixed, "00"));
    let mut grouped = String::with_capacity(fixed.len() + fixed.len() / 3 + 1);
    for (index, byte) in whole.bytes().enumerate() {
        if index > 0 && (whole.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    format!("${grouped}.{fraction}")
}

fn starts_with_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    starts_with_ascii_case(value, prefix).then(|| &value[prefix.len()..])
}

fn trim_ascii_whitespace_start(value: &str) -> &str {
    let whitespace = value.bytes().take_while(u8::is_ascii_whitespace).count();
    &value[whitespace..]
}

fn trim_ascii_whitespace_end(value: &str) -> &str {
    let whitespace = value
        .bytes()
        .rev()
        .take_while(u8::is_ascii_whitespace)
        .count();
    &value[..value.len() - whitespace]
}

fn strip_required_ascii_whitespace(value: &str) -> Option<&str> {
    let trimmed = trim_ascii_whitespace_start(value);
    (trimmed.len() < value.len()).then_some(trimmed)
}

fn strip_required_ascii_token<'a>(value: &'a str, token: &str) -> Option<&'a str> {
    strip_prefix_ascii_case(strip_required_ascii_whitespace(value)?, token)
}

fn split_before_required_ascii_token<'a>(
    value: &'a str,
    token: &str,
) -> Option<(&'a str, &'a str)> {
    let mut offset = 0_usize;
    while let Some(relative) = find_ascii_case_insensitive(&value[offset..], token) {
        let start = offset.checked_add(relative)?;
        let plan_with_space = &value[..start];
        let plan = trim_ascii_whitespace_end(plan_with_space);
        if !plan.is_empty() && plan.len() < plan_with_space.len() {
            return Some((plan, &value[start + token.len()..]));
        }
        offset = start.checked_add(1)?;
    }
    None
}

fn find_ascii_case_insensitive(value: &str, needle: &str) -> Option<usize> {
    value
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn missing_credential() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::MissingCredential)
}

fn authentication_expired() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::AuthenticationExpired)
}

fn network_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Network)
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

fn map_subprocess_error(error: SubprocessError) -> ClassifiedError {
    let kind = match error {
        SubprocessError::NonZero {
            stderr_tag: Some(AUTH_STDERR_TAG),
            ..
        } => ErrorKind::AuthenticationExpired,
        SubprocessError::Spawn => ErrorKind::MissingCredential,
        SubprocessError::Cancelled | SubprocessError::Timeout | SubprocessError::Wait => {
            ErrorKind::Network
        }
        SubprocessError::StdoutTooLarge
        | SubprocessError::StderrTooLarge
        | SubprocessError::OutputRead => ErrorKind::Parse,
        SubprocessError::InvalidConfiguration | SubprocessError::NonZero { .. } => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn resolve_amp(environment: &BTreeMap<String, String>) -> Result<ExecutablePath, ClassifiedError> {
    let configured = environment
        .get(CLI_OVERRIDE)
        .and_then(|value| clean_setting(value))
        .or_else(|| {
            environment
                .get(PINNED_CLI_OVERRIDE)
                .and_then(|value| clean_setting(value))
        });
    let path = environment.get("PATH").map(String::as_ref);
    let mut fallbacks = Vec::new();
    if let Some(home) = environment
        .get("HOME")
        .and_then(|value| clean_setting(value))
    {
        let home = Path::new(home);
        if home.is_absolute() {
            fallbacks.push(home.join(".local/bin/amp"));
            fallbacks.push(home.join(".amp/bin/amp"));
        }
    }
    fallbacks.extend([
        PathBuf::from("/usr/local/bin/amp"),
        PathBuf::from("/usr/bin/amp"),
    ]);
    let resolved = resolve_executable("amp", configured, path, &fallbacks)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    resolved.ok_or_else(|| {
        if configured.is_some() {
            ClassifiedError::new(ErrorKind::Api)
        } else {
            ClassifiedError::new(ErrorKind::MissingCredential)
        }
    })
}

fn sanitized_cli_environment(
    source: &BTreeMap<String, String>,
    executable: &Path,
) -> Result<Vec<(String, String)>, ClassifiedError> {
    const ALLOWED: [&str; 19] = [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "PATH",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ];
    let mut environment = Vec::new();
    for name in ALLOWED {
        if let Some(value) = source.get(name) {
            if value.contains('\0') || value.len() > 64 * 1024 {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            environment.push((name.to_owned(), value.clone()));
        }
    }
    if let Some(value) = validated_amp_url(source)? {
        environment.push(("AMP_URL".to_owned(), value));
    }
    for name in ["AMP_HOME", "AMP_SETTINGS_FILE"] {
        if let Some(value) = validated_amp_path(source, name)? {
            environment.push((name.to_owned(), value));
        }
    }
    let mut paths = Vec::new();
    if let Some(parent) = executable.parent().filter(|path| path.is_absolute()) {
        paths.push(parent.to_path_buf());
    }
    if let Some(raw) = source.get("PATH") {
        for path in std::env::split_paths(raw)
            .filter(|path| path.is_absolute())
            .take(256)
        {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    for path in ["/usr/local/bin", "/usr/bin", "/bin"].map(PathBuf::from) {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    let path = std::env::join_paths(paths).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let path = path
        .into_string()
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if path.len() > 64 * 1024 {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    if let Some(existing) = environment.iter_mut().find(|(name, _)| name == "PATH") {
        existing.1 = path;
    } else {
        environment.push(("PATH".to_owned(), path));
    }
    Ok(environment)
}

fn validated_amp_url(source: &BTreeMap<String, String>) -> Result<Option<String>, ClassifiedError> {
    let Some(value) = validated_amp_custom_value(source, "AMP_URL")? else {
        return Ok(None);
    };
    let endpoint = ConfiguredEndpoint::parse(value, ConfiguredHttpPolicy::LoopbackHttp)?;
    Ok(Some(endpoint.url().as_str().to_owned()))
}

fn validated_amp_path(
    source: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<String>, ClassifiedError> {
    validated_amp_custom_value(source, name).map(|value| value.map(str::to_owned))
}

fn validated_amp_custom_value<'a>(
    source: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<Option<&'a str>, ClassifiedError> {
    let Some(raw) = source.get(name) else {
        return Ok(None);
    };
    if raw.len() > MAX_CLI_CUSTOM_VALUE_BYTES || raw.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let Some(value) = clean_setting(raw) else {
        return Ok(None);
    };
    Ok(Some(value))
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(20),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn validate_scope(scope: &AccountScope) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Amp {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_api_endpoint(endpoint: &Url) -> Result<(), ClassifiedError> {
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/api/internal"
        || endpoint.query() != Some("userDisplayBalanceInfo")
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn parse_error<T>(_: T) -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
