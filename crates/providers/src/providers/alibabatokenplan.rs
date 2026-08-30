//! Native Alibaba Token Plan Team, Personal/Solo, and Bailian CLI adapter.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::{self, Debug, Formatter, Write as _};
use std::path::{Path, PathBuf};
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
use crate::cookie::{CookieHeaderNormalizer, CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::executable::{ExecutablePath, resolve_executable};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{StderrClassifier, SubprocessError, SubprocessRequest};
use crate::transport::{
    Authentication, HttpRequest, HttpResponse, HttpTransport, RequestAccept, RequestContentType,
    TransportConfig, TransportError,
};

const INTERNATIONAL_GATEWAY: &str = "https://modelstudio.console.alibabacloud.com";
const INTERNATIONAL_PERSONAL_API: &str = "https://bailian-singapore-cs.alibabacloud.com";
const CHINA_GATEWAY: &str = "https://bailian.console.aliyun.com";
const CHINA_PERSONAL_API: &str = "https://bailian-cs.console.aliyun.com";
const DATA_PATH: &str = "/data/api.json";
const USER_INFO_PATH: &str = "/tool/user/info.json";
const BSS_PRODUCT: &str = "BssOpenAPI-V3";
const SUMMARY_ACTION: &str = "GetSubscriptionSummary";
const PERSONAL_PRODUCT: &str = "sfm_bailian";
const PERSONAL_USAGE_API: &str = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage";
const PERSONAL_SUBSCRIPTION_API: &str =
    "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/subscription";
const PERSONAL_QUOTA_API: &str = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/quota-config";
const LANGUAGE: &str = "en-US";
const BROWSER_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const SAFARI_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Safari/605.1.15"
);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_EMBEDDED_JSON_LAYERS: usize = 6;
const MAX_COOKIE_HEADER_BYTES: usize = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_PLAN_BYTES: usize = 256;
const PERSONAL_ATTEMPTS: usize = 3;
const PERSONAL_RETRY_DELAY: Duration = Duration::from_millis(400);
const MAX_NAVIGATION_REDIRECTS: u8 = 3;
const CLI_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_STDOUT_BYTES: usize = 64 * 1024;
const CLI_STDERR_BYTES: usize = 64 * 1024;
const AUTH_STDERR_TAG: u8 = 1;
const AUTH_TICKET_COOKIE: &str = "login_aliyunid_ticket";
const AUTH_ACCOUNT_COOKIES: [&str; 3] = ["login_aliyunid_pk", "login_current_pk", "login_aliyunid"];
const CAPTURE_HOSTS: [&str; 4] = [
    "modelstudio.console.alibabacloud.com",
    "bailian-singapore-cs.alibabacloud.com",
    "bailian.console.aliyun.com",
    "bailian-cs.console.aliyun.com",
];
const CLI_ENVIRONMENT_ALLOWLIST: [&str; 14] = [
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

static TRACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Alibaba Token Plan gateway and plan-family selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlibabaTokenPlanRegion {
    /// International Team plan through Model Studio.
    InternationalTeam,
    /// China-mainland Team plan through Bailian.
    ChinaTeam,
    /// International Personal/Solo rolling-window plan.
    InternationalPersonal,
    /// China-mainland Personal/Solo rolling-window plan.
    ChinaPersonal,
}

impl AlibabaTokenPlanRegion {
    const fn is_personal(self) -> bool {
        matches!(self, Self::InternationalPersonal | Self::ChinaPersonal)
    }

    const fn is_international(self) -> bool {
        matches!(self, Self::InternationalTeam | Self::InternationalPersonal)
    }

    const fn region_id(self) -> &'static str {
        if self.is_international() {
            "ap-southeast-1"
        } else {
            "cn-beijing"
        }
    }

    const fn cli_site(self) -> &'static str {
        if self.is_international() {
            "international"
        } else {
            "domestic"
        }
    }

    const fn personal_action(self) -> &'static str {
        if self.is_international() {
            "IntlBroadScopeAspnGateway"
        } else {
            "BroadScopeAspnGateway"
        }
    }

    const fn personal_console_site(self) -> &'static str {
        if self.is_international() {
            // Alibaba's live contract intentionally contains this spelling.
            "MODELSTUDIO_ALBABACLOUD"
        } else {
            "BAILIAN_ALIYUN"
        }
    }

    const fn product_code(self) -> &'static str {
        match self {
            Self::InternationalTeam => "sfm_tokenplanteams_dp_intl",
            Self::ChinaTeam => "sfm_tokenplanteams_dp_cn",
            Self::InternationalPersonal => "sfm_tokenplansolo_public_intl",
            Self::ChinaPersonal => "sfm_tokenplansolo_public_cn",
        }
    }

    const fn dashboard_path(self) -> &'static str {
        if self.is_international() {
            "/ap-southeast-1/"
        } else {
            "/cn-beijing"
        }
    }
}

struct RegionRoutes {
    dashboard: Url,
    user_info: Url,
    usage: Url,
    subscription: Url,
    quota_config: Url,
}

/// Fixed Alibaba Token Plan routing for all four baseline variants.
pub struct AlibabaTokenPlanRouteSet {
    international_team: RegionRoutes,
    china_team: RegionRoutes,
    international_personal: RegionRoutes,
    china_personal: RegionRoutes,
    class: EndpointClass,
}

impl AlibabaTokenPlanRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origins(
            Url::parse(INTERNATIONAL_GATEWAY).map_err(|_| api_error())?,
            Url::parse(INTERNATIONAL_PERSONAL_API).map_err(|_| api_error())?,
            Url::parse(CHINA_GATEWAY).map_err(|_| api_error())?,
            Url::parse(CHINA_PERSONAL_API).map_err(|_| api_error())?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates an exact four-origin loopback table for isolated HTTP tests.
    ///
    /// # Errors
    ///
    /// Rejects non-origin, credential-bearing, or non-loopback URLs.
    #[doc(hidden)]
    pub fn loopback(
        international_gateway: Url,
        international_personal_api: Url,
        china_gateway: Url,
        china_personal_api: Url,
    ) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            international_gateway,
            international_personal_api,
            china_gateway,
            china_personal_api,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        international_gateway: Url,
        international_personal_api: Url,
        china_gateway: Url,
        china_personal_api: Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let origins = [
            international_gateway,
            international_personal_api,
            china_gateway,
            china_personal_api,
        ];
        for origin in &origins {
            validate_bare_origin(origin, class)?;
        }
        if class == EndpointClass::PublicHttps
            && (!same_origin(&origins[0], INTERNATIONAL_GATEWAY)?
                || !same_origin(&origins[1], INTERNATIONAL_PERSONAL_API)?
                || !same_origin(&origins[2], CHINA_GATEWAY)?
                || !same_origin(&origins[3], CHINA_PERSONAL_API)?)
        {
            return Err(api_error());
        }
        if !matches!(
            class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) {
            return Err(api_error());
        }
        Ok(Self {
            international_team: build_routes(
                AlibabaTokenPlanRegion::InternationalTeam,
                origins[0].clone(),
                origins[1].clone(),
            ),
            china_team: build_routes(
                AlibabaTokenPlanRegion::ChinaTeam,
                origins[2].clone(),
                origins[3].clone(),
            ),
            international_personal: build_routes(
                AlibabaTokenPlanRegion::InternationalPersonal,
                origins[0].clone(),
                origins[1].clone(),
            ),
            china_personal: build_routes(
                AlibabaTokenPlanRegion::ChinaPersonal,
                origins[2].clone(),
                origins[3].clone(),
            ),
            class,
        })
    }

    const fn region(&self, region: AlibabaTokenPlanRegion) -> &RegionRoutes {
        match region {
            AlibabaTokenPlanRegion::InternationalTeam => &self.international_team,
            AlibabaTokenPlanRegion::ChinaTeam => &self.china_team,
            AlibabaTokenPlanRegion::InternationalPersonal => &self.international_personal,
            AlibabaTokenPlanRegion::ChinaPersonal => &self.china_personal,
        }
    }

    fn endpoint_policy_for(&self, url: &Url) -> Result<EndpointPolicy, ClassifiedError> {
        let origin = url.origin().ascii_serialization();
        EndpointPolicy::new([(origin.as_str(), self.class)]).map_err(|_| api_error())
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

impl Debug for AlibabaTokenPlanRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlibabaTokenPlanRouteSet")
            .field("routes", &"<redacted>")
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
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
    EndpointPolicy::new([(url.as_str(), class)]).map_err(|_| api_error())?;
    Ok(())
}

fn same_origin(actual: &Url, expected: &str) -> Result<bool, ClassifiedError> {
    Ok(actual.origin() == Url::parse(expected).map_err(|_| api_error())?.origin())
}

fn with_path(mut origin: Url, path: &str) -> Url {
    origin.set_path(path);
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

fn build_routes(region: AlibabaTokenPlanRegion, gateway: Url, personal_api: Url) -> RegionRoutes {
    let mut dashboard = with_path(gateway.clone(), region.dashboard_path());
    dashboard.query_pairs_mut().append_pair("tab", "plan");
    let user_info = with_path(gateway.clone(), USER_INFO_PATH);
    if region.is_personal() {
        RegionRoutes {
            dashboard,
            user_info,
            usage: personal_url(personal_api.clone(), region, PERSONAL_USAGE_API),
            subscription: personal_url(personal_api.clone(), region, PERSONAL_SUBSCRIPTION_API),
            quota_config: personal_url(personal_api, region, PERSONAL_QUOTA_API),
        }
    } else {
        let mut summary = with_path(gateway, DATA_PATH);
        summary.query_pairs_mut().extend_pairs([
            ("action", SUMMARY_ACTION),
            ("product", BSS_PRODUCT),
            ("_tag", ""),
        ]);
        RegionRoutes {
            dashboard,
            user_info,
            usage: summary.clone(),
            subscription: summary.clone(),
            quota_config: summary,
        }
    }
}

fn personal_url(origin: Url, region: AlibabaTokenPlanRegion, api: &str) -> Url {
    let mut url = with_path(origin, DATA_PATH);
    url.query_pairs_mut().extend_pairs([
        ("action", region.personal_action()),
        ("product", PERSONAL_PRODUCT),
        ("api", api),
        ("_v", "undefined"),
    ]);
    url
}

struct SessionHeaders {
    dashboard: Zeroizing<String>,
    user_info: Option<Zeroizing<String>>,
    api: Zeroizing<String>,
}

impl SessionHeaders {
    fn manual(raw: &str) -> Result<Self, ClassifiedError> {
        let normalized = normalize_manual_cookie(raw)?;
        Ok(Self {
            dashboard: normalized.clone(),
            user_info: Some(normalized.clone()),
            api: normalized,
        })
    }

    fn browser(
        routes: &RegionRoutes,
        policy: CookieUrlPolicy,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        let dashboard = cookie_for(jar, &routes.dashboard, policy, now)?.ok_or_else(|| {
            ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            })
        })?;
        let user_info = cookie_for(jar, &routes.user_info, policy, now)?;
        let api = cookie_for(jar, &routes.usage, policy, now)?.ok_or_else(|| {
            ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            })
        })?;
        let headers = [&*dashboard, &*api];
        let has_ticket = headers
            .iter()
            .any(|header| cookie_value(header, AUTH_TICKET_COOKIE).is_some());
        let has_account = headers.iter().any(|header| {
            AUTH_ACCOUNT_COOKIES
                .iter()
                .any(|name| cookie_value(header, name).is_some())
        });
        if !has_ticket || !has_account {
            return Err(ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        }
        Ok(Self {
            dashboard,
            user_info,
            api,
        })
    }
}

impl Debug for SessionHeaders {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionHeaders")
            .field("dashboard", &"<redacted>")
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
    let target = ValidatedCookieUrl::new(url.clone(), policy).map_err(|_| api_error())?;
    jar.header_for(&target, now)
        .map_err(|_| api_error())?
        .map(|header| normalize_manual_cookie(header.expose()))
        .transpose()
}

fn normalize_manual_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    if raw.len() > MAX_COOKIE_HEADER_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    CookieHeaderNormalizer::normalize(Some(raw))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let normalized = raw.split(';').map(str::trim).collect::<Vec<_>>().join("; ");
    Authentication::cookie(normalized.clone())
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(Zeroizing::new(normalized))
}

/// Bounded signed-in Bailian CLI configuration.
pub struct AlibabaTokenPlanCliSettings {
    executable: ExecutablePath,
    environment: Vec<(String, String)>,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl AlibabaTokenPlanCliSettings {
    /// Resolves `bl` from absolute PATH entries and narrows its child environment.
    ///
    /// # Errors
    ///
    /// Returns missing-credential when `bl` is unavailable and API for unsafe discovery input.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let path = environment.get("PATH").map(String::as_str).map(OsStr::new);
        let executable = resolve_executable("bl", None, path, &[])
            .map_err(|_| api_error())?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::from_executable(executable, environment)
    }

    /// Creates settings from one exact executable `bl` path.
    ///
    /// # Errors
    ///
    /// Rejects relative, missing, non-executable, or non-`bl` paths.
    pub fn new(
        executable: impl Into<PathBuf>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let executable = executable.into();
        let configured = executable.to_str().ok_or_else(api_error)?;
        let executable = resolve_executable("bl", Some(configured), None, &[])
            .map_err(|_| api_error())?
            .ok_or_else(api_error)?;
        Self::from_executable(executable, environment)
    }

    fn from_executable(
        executable: ExecutablePath,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let selected = environment
            .iter()
            .filter(|(name, _)| CLI_ENVIRONMENT_ALLOWLIST.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        let mut validation = SubprocessRequest::new(
            executable.as_path(),
            ["--version"],
            Duration::from_secs(1),
            1,
            1,
        )
        .map_err(map_subprocess_error)?
        .with_cleared_environment();
        for (name, value) in &selected {
            validation = validation
                .with_environment(name, value)
                .map_err(map_subprocess_error)?;
        }
        drop(validation);
        Ok(Self {
            executable,
            environment: selected,
            timeout: CLI_TIMEOUT,
            max_stdout_bytes: CLI_STDOUT_BYTES,
            max_stderr_bytes: CLI_STDERR_BYTES,
        })
    }

    /// Resolved executable used for setup diagnostics.
    #[must_use]
    pub fn executable(&self) -> &Path {
        self.executable.as_path()
    }

    /// Overrides production resource ceilings for deterministic tests.
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
            return Err(api_error());
        }
        self.timeout = timeout;
        self.max_stdout_bytes = max_stdout_bytes;
        self.max_stderr_bytes = max_stderr_bytes;
        Ok(self)
    }
}

impl Debug for AlibabaTokenPlanCliSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlibabaTokenPlanCliSettings")
            .field("executable", &"<redacted>")
            .field("environment_entries", &self.environment.len())
            .field("timeout", &self.timeout)
            .field("max_stdout_bytes", &self.max_stdout_bytes)
            .field("max_stderr_bytes", &self.max_stderr_bytes)
            .finish()
    }
}

struct WebBackend {
    source: ProviderSource,
    routes: AlibabaTokenPlanRouteSet,
    cookies: SessionHeaders,
    dashboard_transport: HttpTransport,
    api_transport: HttpTransport,
}

enum Backend {
    Web(Box<WebBackend>),
    Cli(AlibabaTokenPlanCliSettings),
}

/// Alibaba Token Plan adapter bound to one account, region, and explicit source.
pub struct AlibabaTokenPlanProvider {
    scope: AccountScope,
    region: AlibabaTokenPlanRegion,
    backend: Backend,
}

impl AlibabaTokenPlanProvider {
    /// Creates a production manual-cookie adapter.
    ///
    /// # Errors
    ///
    /// Returns stable missing, capture, scope, or fixed-route failures.
    pub fn new_manual(
        scope: AccountScope,
        region: AlibabaTokenPlanRegion,
        raw: &str,
    ) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(
            scope,
            region,
            raw,
            AlibabaTokenPlanRouteSet::production()?,
        )
    }

    /// Creates a manual-cookie adapter with injected loopback routes.
    ///
    /// Captured cURL URLs remain restricted to exact production Alibaba hosts.
    ///
    /// # Errors
    ///
    /// Returns stable redacted capture, scope, or route failures.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        region: AlibabaTokenPlanRegion,
        raw: &str,
        routes: AlibabaTokenPlanRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(CAPTURE_HOSTS, [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::build_web(
            scope,
            region,
            ProviderSource::ManualCookie,
            routes,
            SessionHeaders::manual(cookie)?,
        )
    }

    /// Creates a production browser-session adapter from an imported cookie jar.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, scope, or fixed-route failures.
    pub fn new_browser(
        scope: AccountScope,
        region: AlibabaTokenPlanRegion,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jar_routes(
            scope,
            region,
            jar,
            now,
            AlibabaTokenPlanRouteSet::production()?,
        )
    }

    /// Creates a browser-session adapter with injected loopback routes.
    ///
    /// # Errors
    ///
    /// Returns stable missing, expired, scope, or route failures.
    #[doc(hidden)]
    pub fn from_browser_jar_routes(
        scope: AccountScope,
        region: AlibabaTokenPlanRegion,
        jar: &CookieJar,
        now: OffsetDateTime,
        routes: AlibabaTokenPlanRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let cookies =
            SessionHeaders::browser(routes.region(region), routes.cookie_policy(), jar, now)?;
        Self::build_web(
            scope,
            region,
            ProviderSource::BrowserSession,
            routes,
            cookies,
        )
    }

    /// Creates a strict signed-in Bailian CLI adapter.
    ///
    /// # Errors
    ///
    /// Rejects another provider scope.
    pub fn new_cli(
        scope: AccountScope,
        region: AlibabaTokenPlanRegion,
        settings: AlibabaTokenPlanCliSettings,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        Ok(Self {
            scope,
            region,
            backend: Backend::Cli(settings),
        })
    }

    fn build_web(
        scope: AccountScope,
        region: AlibabaTokenPlanRegion,
        source: ProviderSource,
        routes: AlibabaTokenPlanRouteSet,
        cookies: SessionHeaders,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        if !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        ) {
            return Err(api_error());
        }
        let selected = routes.region(region);
        let dashboard_policy = routes.endpoint_policy_for(&selected.dashboard)?;
        for endpoint in [&selected.dashboard, &selected.user_info] {
            dashboard_policy
                .validate(endpoint)
                .map_err(|_| api_error())?;
        }
        let api_policy = routes.endpoint_policy_for(&selected.usage)?;
        for endpoint in [
            &selected.usage,
            &selected.subscription,
            &selected.quota_config,
        ] {
            api_policy.validate(endpoint).map_err(|_| api_error())?;
        }
        let dashboard_transport = HttpTransport::new(
            dashboard_policy,
            transport_config(MAX_NAVIGATION_REDIRECTS)?,
        )
        .map_err(|error| error.classified())?;
        // API requests are credentialed POSTs. The shared transport rejects
        // their redirects before resolving or authenticating the target.
        let api_transport = HttpTransport::new(api_policy, transport_config(0)?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            region,
            backend: Backend::Web(Box::new(WebBackend {
                source,
                routes,
                cookies,
                dashboard_transport,
                api_transport,
            })),
        })
    }

    /// Source to which this instance is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        match &self.backend {
            Backend::Web(web) => web.source,
            Backend::Cli(_) => ProviderSource::Cli,
        }
    }

    /// Fetches at an injected wall-clock instant.
    ///
    /// # Errors
    ///
    /// Returns stable redacted source, credential, network, API, or parse failures.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let source = self.source();
        if context.scope() != &self.scope || context.source() != source {
            return Err(api_error());
        }
        match &self.backend {
            Backend::Cli(settings) => fetch_cli(settings, self.region, context, fetched_at).await,
            Backend::Web(web) => self.fetch_web(web, context, fetched_at, source).await,
        }
    }

    async fn fetch_web(
        &self,
        web: &WebBackend,
        context: &ProviderContext,
        fetched_at: Timestamp,
        source: ProviderSource,
    ) -> Result<UsageSample, ClassifiedError> {
        let routes = web.routes.region(self.region);
        let sec_token = resolve_sec_token(web, routes, context).await?;
        let sec_token = sec_token.as_ref().map(|value| value.as_str());
        if self.region.is_personal() {
            let personal = PersonalFetch {
                web,
                routes,
                context,
                region: self.region,
                sec_token,
                fetched_at,
            };
            let subscription = personal
                .optional(
                    PERSONAL_SUBSCRIPTION_API,
                    Some(("commodityCode", self.region.product_code())),
                )
                .await?;
            let quota_config = personal.optional(PERSONAL_QUOTA_API, None).await?;
            for attempt in 0..PERSONAL_ATTEMPTS {
                if attempt > 0 {
                    tokio::select! {
                        biased;
                        () = context.cancellation().cancelled() => {
                            return Err(ClassifiedError::new(ErrorKind::Network));
                        }
                        () = tokio::time::sleep(PERSONAL_RETRY_DELAY) => {}
                    }
                }
                let usage = personal.required(PERSONAL_USAGE_API, None).await?;
                match parse_personal_parts(
                    self.scope.clone(),
                    fetched_at,
                    &usage,
                    subscription.as_deref(),
                    quota_config.as_deref(),
                    source,
                ) {
                    Ok(sample) => return Ok(sample),
                    Err(PersonalParseFailure::Unavailable) => {}
                    Err(PersonalParseFailure::Classified(error)) => return Err(error),
                }
            }
            Err(ClassifiedError::new(ErrorKind::Parse))
        } else {
            let body = summary_request_body(self.region, sec_token)?;
            let response = send_api_request(
                web,
                context,
                &routes.usage,
                &routes.dashboard,
                &web.cookies.api,
                body,
                false,
            )
            .await?;
            parse_team_usage_response(self.scope.clone(), fetched_at, response.body(), source)
        }
    }
}

impl ProviderAdapter for AlibabaTokenPlanProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::AlibabaTokenPlan)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for AlibabaTokenPlanProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlibabaTokenPlanProvider")
            .field("scope", &"<redacted>")
            .field("region", &self.region)
            .field("backend", &"<redacted>")
            .field("source", &self.source())
            .finish()
    }
}

fn validate_scope(scope: &AccountScope) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::AlibabaTokenPlan {
        return Err(api_error());
    }
    Ok(())
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn transport_config(max_redirects: u8) -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(10),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        max_redirects,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn classify_capture_error(error: ManualCaptureError) -> ClassifiedError {
    let kind = match error {
        ManualCaptureError::MissingSecret => ErrorKind::MissingCredential,
        ManualCaptureError::InputTooLarge
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
        ManualCaptureError::InvalidPolicy => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

fn classify_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        other => other.classified(),
    }
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

/// Exact shell-free argument vector used for one Bailian region.
#[must_use]
pub fn cli_arguments(region: AlibabaTokenPlanRegion) -> [&'static str; 8] {
    [
        "usage",
        "token-plan",
        "--console-region",
        region.region_id(),
        "--console-site",
        region.cli_site(),
        "--output",
        "json",
    ]
}

async fn fetch_cli(
    settings: &AlibabaTokenPlanCliSettings,
    region: AlibabaTokenPlanRegion,
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
        cli_arguments(region),
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
    let output = request
        .run(context.cancellation())
        .await
        .map_err(map_subprocess_error)?;
    parse_cli_usage_response(
        context.scope().clone(),
        fetched_at,
        output.stdout(),
        ProviderSource::Cli,
    )
}

async fn resolve_sec_token(
    web: &WebBackend,
    routes: &RegionRoutes,
    context: &ProviderContext,
) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
    let dashboard_request = HttpRequest::get(routes.dashboard.clone())
        .accept(RequestAccept::Html)
        .public_header("user-agent", SAFARI_USER_AGENT)
        .map_err(classify_transport)?
        .public_header("referer", routes.dashboard.origin().ascii_serialization())
        .map_err(classify_transport)?
        .public_header("sec-fetch-site", "same-origin")
        .map_err(classify_transport)?
        .public_header("sec-fetch-mode", "navigate")
        .map_err(classify_transport)?
        .public_header("sec-fetch-dest", "document")
        .map_err(classify_transport)?
        .public_header("accept-language", "zh-CN,zh;q=0.9,en;q=0.8")
        .map_err(classify_transport)?
        .authentication(
            Authentication::cookie(web.cookies.dashboard.as_str().to_owned())
                .map_err(classify_transport)?,
        );
    match web
        .dashboard_transport
        .send(&dashboard_request, context.cancellation())
        .await
    {
        Ok(response) if response.status() == 200 => {
            if let Ok(html) = std::str::from_utf8(response.body())
                && !looks_like_login_page(html)
                && let Some(token) = extract_html_token(html)
            {
                return Ok(Some(token));
            }
        }
        Err(TransportError::Cancelled) => {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }
        Ok(_) | Err(_) => {}
    }

    if let Some(cookie) = web.cookies.user_info.as_deref() {
        let request = HttpRequest::get(routes.user_info.clone())
            .accept(RequestAccept::JsonTextAny)
            .public_header("user-agent", SAFARI_USER_AGENT)
            .map_err(classify_transport)?
            .public_header("referer", routes.dashboard.origin().ascii_serialization())
            .map_err(classify_transport)?
            .authentication(Authentication::cookie(cookie.to_owned()).map_err(classify_transport)?);
        match web
            .dashboard_transport
            .send(&request, context.cancellation())
            .await
        {
            Ok(response) if response.status() == 200 => {
                if let Ok(root) = parse_bounded_json(response.body())
                    && let Some(token) = find_first_string(&root, &["secToken", "sec_token"])
                        .filter(|value| valid_token(value))
                {
                    return Ok(Some(Zeroizing::new(token.to_owned())));
                }
            }
            Err(TransportError::Cancelled) => {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            Ok(_) | Err(_) => {}
        }
    }

    Ok(cookie_value(&web.cookies.dashboard, "sec_token")
        .or_else(|| cookie_value(&web.cookies.api, "sec_token"))
        .map(|token| Zeroizing::new(token.to_owned())))
}

struct PersonalFetch<'a> {
    web: &'a WebBackend,
    routes: &'a RegionRoutes,
    context: &'a ProviderContext,
    region: AlibabaTokenPlanRegion,
    sec_token: Option<&'a str>,
    fetched_at: Timestamp,
}

impl PersonalFetch<'_> {
    async fn optional(
        &self,
        api: &str,
        data_parameter: Option<(&str, &str)>,
    ) -> Result<Option<Vec<u8>>, ClassifiedError> {
        match self.required(api, data_parameter).await {
            Ok(body) => Ok(Some(body)),
            Err(error) if self.context.cancellation().is_cancelled() => Err(error),
            Err(_) => Ok(None),
        }
    }

    async fn required(
        &self,
        api: &str,
        data_parameter: Option<(&str, &str)>,
    ) -> Result<Vec<u8>, ClassifiedError> {
        let url = match api {
            PERSONAL_USAGE_API => &self.routes.usage,
            PERSONAL_SUBSCRIPTION_API => &self.routes.subscription,
            PERSONAL_QUOTA_API => &self.routes.quota_config,
            _ => return Err(api_error()),
        };
        let body = personal_request_body(
            self.region,
            api,
            data_parameter,
            self.sec_token,
            &self.routes.dashboard,
            &self.web.cookies.api,
            self.fetched_at,
        )?;
        let response = send_api_request(
            self.web,
            self.context,
            url,
            &self.routes.dashboard,
            &self.web.cookies.api,
            body,
            true,
        )
        .await?;
        Ok(response.body().to_vec())
    }
}

async fn send_api_request(
    web: &WebBackend,
    context: &ProviderContext,
    url: &Url,
    dashboard: &Url,
    cookie: &str,
    body: Vec<u8>,
    personal: bool,
) -> Result<HttpResponse, ClassifiedError> {
    let accept = if personal {
        RequestAccept::JsonTextAny
    } else {
        RequestAccept::Any
    };
    let referer = dashboard_reference(dashboard, personal);
    let mut request = HttpRequest::post(url.clone(), body)
        .map_err(classify_transport)?
        .accept(accept)
        .content_type(RequestContentType::FormUrlEncoded)
        .public_header("x-requested-with", "XMLHttpRequest")
        .map_err(classify_transport)?
        .public_header("user-agent", BROWSER_USER_AGENT)
        .map_err(classify_transport)?
        .public_header("origin", dashboard.origin().ascii_serialization())
        .map_err(classify_transport)?
        .public_header("referer", referer)
        .map_err(classify_transport)?;
    if let Some(csrf) =
        cookie_value(cookie, "login_aliyunid_csrf").or_else(|| cookie_value(cookie, "csrf"))
    {
        request = request
            .sensitive_header("x-xsrf-token", csrf.to_owned())
            .map_err(classify_transport)?
            .sensitive_header("x-csrf-token", csrf.to_owned())
            .map_err(classify_transport)?;
    }
    request = request
        .authentication(Authentication::cookie(cookie.to_owned()).map_err(classify_transport)?);
    let response = web
        .api_transport
        .send(&request, context.cancellation())
        .await
        .map_err(classify_transport)?;
    if response.status() != 200 {
        return Err(api_error());
    }
    Ok(response)
}

fn summary_request_body(
    region: AlibabaTokenPlanRegion,
    sec_token: Option<&str>,
) -> Result<Vec<u8>, ClassifiedError> {
    let params = serde_json::to_string(&json!({"ProductCode": region.product_code()}))
        .map_err(|_| api_error())?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("product", BSS_PRODUCT)
        .append_pair("action", SUMMARY_ACTION)
        .append_pair("params", &params)
        .append_pair("region", region.region_id());
    if let Some(token) = sec_token {
        serializer.append_pair("sec_token", token);
    }
    Ok(serializer.finish().into_bytes())
}

fn personal_request_body(
    region: AlibabaTokenPlanRegion,
    api: &str,
    data_parameter: Option<(&str, &str)>,
    sec_token: Option<&str>,
    dashboard: &Url,
    api_cookie: &str,
    fetched_at: Timestamp,
) -> Result<Vec<u8>, ClassifiedError> {
    let dashboard_reference = dashboard_reference(dashboard, true);
    let mut cornerstone = json!({
        "feTraceId": trace_id(fetched_at),
        "feURL": dashboard_reference,
        "protocol": "V2",
        "console": "ONE_CONSOLE",
        "productCode": "p_efm",
        "switchUserType": 3,
        "domain": dashboard.host_str().unwrap_or_default(),
        "consoleSite": region.personal_console_site(),
        "userNickName": "",
        "userPrincipalName": "",
        "xsp_lang": LANGUAGE,
    });
    if let Some(anonymous_id) = cookie_value(api_cookie, "cna") {
        cornerstone.as_object_mut().ok_or_else(api_error)?.insert(
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
    .map_err(|_| api_error())?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("product", PERSONAL_PRODUCT)
        .append_pair("action", region.personal_action())
        .append_pair("region", region.region_id())
        .append_pair("language", LANGUAGE)
        .append_pair("params", &params);
    if let Some(token) = sec_token {
        serializer.append_pair("sec_token", token);
    }
    Ok(serializer.finish().into_bytes())
}

fn dashboard_reference(dashboard: &Url, personal: bool) -> String {
    format!(
        "{}#/efm/subscription/token-plan{}",
        dashboard.as_str(),
        if personal { "/personal" } else { "" }
    )
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

fn valid_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TOKEN_BYTES && !value.chars().any(char::is_control)
}

fn looks_like_login_page(html: &str) -> bool {
    let lowered = html.to_ascii_lowercase();
    lowered.contains("passport.alibabacloud.com")
        || lowered.contains("signin.aliyun.com")
        || lowered.contains("account.alibabacloud.com/login")
        || (lowered.contains("login")
            && lowered.contains("password")
            && lowered.contains("sign in"))
}

/// Extracts a bounded `OneConsole` `sec_token` from the dashboard shell.
#[must_use]
pub fn extract_sec_token(html: &str) -> Option<Zeroizing<String>> {
    extract_html_token(html)
}

fn extract_html_token(html: &str) -> Option<Zeroizing<String>> {
    for key in ["SEC_TOKEN", "secToken", "sec_token"] {
        for (offset, _) in html.match_indices(key) {
            if !identifier_boundary(html, offset, key.len()) {
                continue;
            }
            let mut rest = &html[offset + key.len()..];
            rest = rest.trim_start_matches(char::is_whitespace);
            if let Some(stripped) = rest.strip_prefix(['\'', '"']) {
                rest = stripped;
            }
            rest = rest.trim_start_matches(char::is_whitespace);
            let Some(stripped) = rest.strip_prefix([':', '=']) else {
                continue;
            };
            rest = stripped.trim_start_matches(char::is_whitespace);
            let Some(quote) = rest
                .chars()
                .next()
                .filter(|value| matches!(value, '\'' | '"'))
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
    !before.is_some_and(|value| value.is_ascii_alphanumeric() || value == '_')
        && !after.is_some_and(|value| value.is_ascii_alphanumeric() || value == '_')
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

enum PersonalParseFailure {
    Unavailable,
    Classified(ClassifiedError),
}

/// Parses one Team subscription-summary response.
///
/// # Errors
///
/// Returns stable bounded scope, authentication, API, or parse failures.
pub fn parse_team_usage_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    validate_parse_source(&scope, source, false)?;
    if looks_like_login_html(body) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let root = parse_bounded_json(body)?;
    validate_payload_status(&root)?;
    let parsed = parse_team(&root).ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    normalize_usage(scope, fetched_at, parsed, source)
}

/// Parses the required Personal/Solo response and optional plan metadata.
///
/// Malformed optional responses are ignored, while the required usage body is
/// parsed under the complete response, JSON-depth, node, string, and embedded
/// JSON bounds.
///
/// # Errors
///
/// Returns stable bounded scope, authentication, API, or parse failures.
pub fn parse_personal_usage_responses(
    scope: AccountScope,
    fetched_at: Timestamp,
    usage_body: &[u8],
    subscription_body: Option<&[u8]>,
    quota_config_body: Option<&[u8]>,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    match parse_personal_parts(
        scope,
        fetched_at,
        usage_body,
        subscription_body,
        quota_config_body,
        source,
    ) {
        Ok(sample) => Ok(sample),
        Err(PersonalParseFailure::Unavailable) => Err(ClassifiedError::new(ErrorKind::Parse)),
        Err(PersonalParseFailure::Classified(error)) => Err(error),
    }
}

fn parse_personal_parts(
    scope: AccountScope,
    fetched_at: Timestamp,
    usage_body: &[u8],
    subscription_body: Option<&[u8]>,
    quota_config_body: Option<&[u8]>,
    source: ProviderSource,
) -> Result<UsageSample, PersonalParseFailure> {
    validate_parse_source(&scope, source, false).map_err(PersonalParseFailure::Classified)?;
    if looks_like_login_html(usage_body) {
        return Err(PersonalParseFailure::Classified(ClassifiedError::new(
            ErrorKind::AuthenticationExpired,
        )));
    }
    let usage = parse_bounded_json(usage_body).map_err(PersonalParseFailure::Classified)?;
    validate_payload_status(&usage).map_err(PersonalParseFailure::Classified)?;
    let subscription = subscription_body.and_then(|body| parse_bounded_json(body).ok());
    let quota_config = quota_config_body.and_then(|body| parse_bounded_json(body).ok());
    let parsed = parse_personal(&usage, subscription.as_ref(), quota_config.as_ref())
        .ok_or(PersonalParseFailure::Unavailable)?;
    normalize_usage(scope, fetched_at, parsed, source).map_err(PersonalParseFailure::Classified)
}

/// Parses the exact top-level Bailian CLI rolling-window response.
///
/// # Errors
///
/// Returns stable bounded scope or parse failures.
pub fn parse_cli_usage_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    validate_parse_source(&scope, source, true)?;
    if body.len() > CLI_STDOUT_BYTES
        || body.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let root = parse_bounded_json(body)?;
    let object = root
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let five_hour = object.get("per5HourPercentage").and_then(strict_cli_ratio);
    let weekly = object.get("per1WeekPercentage").and_then(strict_cli_ratio);
    if five_hour.is_none() && weekly.is_none() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let primary = five_hour.map(|ratio| ParsedWindow {
        percent: ratio * Decimal::from(100_u8),
        duration_minutes: 5 * 60,
        resets_at: object.get("per5HourResetTime").and_then(scalar_timestamp),
        description: None,
    });
    let secondary = weekly.map(|ratio| ParsedWindow {
        percent: ratio * Decimal::from(100_u8),
        duration_minutes: 7 * 24 * 60,
        resets_at: object.get("per1WeekResetTime").and_then(scalar_timestamp),
        description: None,
    });
    normalize_usage(
        scope,
        fetched_at,
        ParsedUsage {
            plan_name: Some("Token Plan".to_owned()),
            primary,
            secondary,
        },
        source,
    )
}

fn validate_parse_source(
    scope: &AccountScope,
    source: ProviderSource,
    cli_only: bool,
) -> Result<(), ClassifiedError> {
    validate_scope(scope)?;
    let valid = if cli_only {
        source == ProviderSource::Cli
    } else {
        matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    };
    if !valid {
        return Err(api_error());
    }
    Ok(())
}

fn strict_cli_ratio(value: &Value) -> Option<Decimal> {
    let Value::Number(number) = value else {
        return None;
    };
    let ratio = number.to_string().parse::<Decimal>().ok()?;
    (Decimal::ZERO..=Decimal::ONE)
        .contains(&ratio)
        .then_some(ratio)
}

fn parse_personal(
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
    let plan_name = plan_code
        .as_deref()
        .map(display_plan_name)
        .or_else(|| Some("Personal".to_owned()));
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

fn parse_team(root: &Value) -> Option<ParsedUsage> {
    let summary = find_team_summary(root)?;
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

fn find_team_summary(root: &Value) -> Option<&Map<String, Value>> {
    let quota_keys = USED_KEYS
        .iter()
        .chain(TOTAL_KEYS)
        .chain(REMAINING_KEYS)
        .copied()
        .collect::<Vec<_>>();
    let all_keys = quota_keys
        .iter()
        .chain(COUNT_KEYS)
        .copied()
        .collect::<Vec<_>>();
    if let Some(data) = find_first_object_value(
        root,
        &["Data", "data", "successResponse", "success_response"],
    ) && contains_any_key(data, &all_keys)
    {
        if contains_any_key(data, &quota_keys) {
            return Some(data);
        }
        if let Some(nested) = find_object_in_map_containing_any(data, &quota_keys) {
            return Some(nested);
        }
        return Some(data);
    }
    find_object_containing_any(root, &all_keys)
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
    source: ProviderSource,
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
    let source_label = if source == ProviderSource::Cli {
        "cli"
    } else {
        "web"
    };
    builder
        .login_method(plan_name)?
        .provenance("alibabatokenplan", source_label)?
        .build()
}

fn normalize_window(parsed: ParsedWindow) -> Result<RateWindow, ClassifiedError> {
    let percent = parsed
        .percent
        .clamp(Decimal::ZERO, Decimal::from(100_u8))
        .to_f64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let usage = UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let duration = WindowDuration::from_provider_minutes(parsed.duration_minutes)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let description = parsed
        .description
        .map(BoundedText::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(usage),
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
    Err(api_error())
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
