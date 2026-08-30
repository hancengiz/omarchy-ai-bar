//! `MiniMax` Token Plan usage through API keys or isolated Linux web sessions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary, CostUnit,
    CostUsageCoverage, CostUsageDailyBucket, CostUsageMetrics, CostUsageModelBreakdown,
    CostUsageSnapshot, CostUsageTokenMix, DetailChart, DetailChartKind, DetailChartPoint,
    DetailRow, DetailSection, DetailSensitivity, ErrorKind, ExactDecimal, FiniteNumber,
    NamedRateWindow, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowDuration,
    WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::{Date, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};
use url::Url;
use zeroize::Zeroizing;

use crate::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    ChromiumCookieDecryptor, DisabledChromiumCookieDecryptor,
    import_browser_cookies_merging_chromium_stores_with_decryptor,
};
use crate::browser_profile::{BrowserKind, BrowserProfile, BrowserProfileDiscovery};
use crate::chromium_leveldb::{ChromiumHttpsOrigin, ChromiumLevelDbReader};
use crate::configured_endpoint::{ConfiguredEndpoint, ConfiguredHttpPolicy, clean_setting};
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{
    CookieHeaderNormalizer, CookieImportOrder, CookieJar, CookieSourceId, CookieUrlPolicy,
    ValidatedCookieUrl,
};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, format_integer, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig, TransportError,
};

const GLOBAL_PLATFORM: &str = "https://platform.minimax.io";
const GLOBAL_API: &str = "https://api.minimax.io";
const GLOBAL_WEB: &str = "https://www.minimax.io";
const CHINA_PLATFORM: &str = "https://platform.minimaxi.com";
const CHINA_API: &str = "https://api.minimaxi.com";
const CHINA_WEB: &str = "https://www.minimaxi.com";
const CODING_PLAN_PATH: &str = "/user-center/payment/coding-plan";
const CODING_PLAN_REFERER_PATH: &str = "/user-center/payment/coding-plan";
const CODING_PLAN_REMAINS_PATH: &str = "/v1/api/openplatform/coding_plan/remains";
const TOKEN_PLAN_REMAINS_PATH: &str = "/v1/token_plan/remains";
const BILLING_HISTORY_PATH: &str = "/account/amount";
const COMBO_PATH: &str = "/v1/api/openplatform/charge/combo/cycle_audio_resource_package";
const LOCAL_STORAGE_DIRECTORY: &str = "Local Storage/leveldb";
const SESSION_STORAGE_DIRECTORY: &str = "Session Storage";
const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ",
    "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const BILLING_PAGE_LIMIT: usize = 100;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_JSON_NODES: usize = 65_536;
const MAX_JSON_DEPTH: usize = 48;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_JSON_AGGREGATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_CONFIGURED_ENDPOINT_BYTES: usize = 16 * 1024;
const MAX_PLAN_BYTES: usize = 256;
const MAX_SERVICE_TEXT_BYTES: usize = 120;
const MAX_SERVICES: usize = 19;
const MAX_BROWSER_PROFILES: usize = 128;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_STORAGE_TOKENS: usize = 64;
const MAX_STORAGE_VALUE_BYTES: usize = 256 * 1024;
const MAX_INDEXED_DB_DIRECTORIES: usize = 64;
const MAX_BILLING_PAGES: usize = 64;
const MAX_BILLING_RECORDS: usize = 6_400;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(18);

/// `MiniMax`'s two independent Token Plan regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiniMaxRegion {
    /// `*.minimax.io`.
    Global,
    /// `*.minimaxi.com`.
    ChinaMainland,
}

impl MiniMaxRegion {
    const ALL: [Self; 2] = [Self::Global, Self::ChinaMainland];

    const fn alternate(self) -> Self {
        match self {
            Self::Global => Self::ChinaMainland,
            Self::ChinaMainland => Self::Global,
        }
    }

    const fn platform_origin(self) -> &'static str {
        match self {
            Self::Global => GLOBAL_PLATFORM,
            Self::ChinaMainland => CHINA_PLATFORM,
        }
    }

    const fn web_origin(self) -> &'static str {
        match self {
            Self::Global => GLOBAL_WEB,
            Self::ChinaMainland => CHINA_WEB,
        }
    }
}

struct RegionalRoutes {
    platform_origin: Url,
    web_origin: Url,
    api_origin: Url,
    coding_plan: Url,
    coding_plan_referer: Url,
    platform_remains: Url,
    web_remains: Url,
    has_web_remains_fallback: bool,
    token_plan_remains: Url,
    legacy_api_remains: Url,
    billing_history: Url,
    combo: Url,
}

/// Closed `MiniMax` route table. Production construction pins all six vendor origins.
pub struct MiniMaxRouteSet {
    global: RegionalRoutes,
    china: RegionalRoutes,
    base_class: EndpointClass,
    configured_origins: Vec<(String, EndpointClass)>,
}

impl MiniMaxRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        let global_platform = Url::parse(GLOBAL_PLATFORM).map_err(|_| api_error())?;
        let global_web = Url::parse(GLOBAL_WEB).map_err(|_| api_error())?;
        let global_api = Url::parse(GLOBAL_API).map_err(|_| api_error())?;
        let china_platform = Url::parse(CHINA_PLATFORM).map_err(|_| api_error())?;
        let china_web = Url::parse(CHINA_WEB).map_err(|_| api_error())?;
        let china_api = Url::parse(CHINA_API).map_err(|_| api_error())?;
        Self::from_origins(
            &global_platform,
            &global_web,
            &global_api,
            &china_platform,
            &china_web,
            &china_api,
            EndpointClass::PublicHttps,
        )
    }

    /// Resolves the injected MiniMax web endpoint settings without consulting
    /// the ambient process environment. API-key routes remain vendor-owned.
    ///
    /// # Errors
    ///
    /// Rejects any configured endpoint that is not credential-free HTTPS, has
    /// an unsafe query, or violates strict provider-owned-host mode.
    #[doc(hidden)]
    pub fn production_with_environment(
        region: MiniMaxRegion,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let mut routes = Self::production()?;
        routes.apply_environment(region, environment)?;
        Ok(routes)
    }

    /// Returns the resolved web URLs for deterministic settings-contract tests.
    #[must_use]
    #[doc(hidden)]
    pub fn resolved_web_routes(&self, region: MiniMaxRegion) -> MiniMaxResolvedWebRoutes {
        let routes = self.region(region);
        MiniMaxResolvedWebRoutes {
            coding_plan: routes.coding_plan.clone(),
            coding_plan_referer: routes.coding_plan_referer.clone(),
            remains: routes.platform_remains.clone(),
            billing_history: routes.billing_history.clone(),
            combo: routes.combo.clone(),
        }
    }

    fn apply_environment(
        &mut self,
        region: MiniMaxRegion,
        environment: &BTreeMap<String, String>,
    ) -> Result<(), ClassifiedError> {
        let strict = environment
            .get("MINIMAX_REQUIRE_PROVIDER_ENDPOINT_OVERRIDES")
            .and_then(|value| clean_setting(value))
            .is_some_and(|value| {
                ["1", "true", "yes", "on"]
                    .iter()
                    .any(|truthy| value.eq_ignore_ascii_case(truthy))
            });
        let host = configured_environment_url(environment, "MINIMAX_HOST", strict)?;
        let coding = configured_environment_url(environment, "MINIMAX_CODING_PLAN_URL", strict)?;
        let remains = configured_environment_url(environment, "MINIMAX_REMAINS_URL", strict)?;
        let billing =
            configured_environment_url(environment, "MINIMAX_BILLING_HISTORY_URL", strict)?;

        for configured in [&host, &coding, &remains, &billing].into_iter().flatten() {
            self.register_configured_origin(configured);
        }

        let routes = match region {
            MiniMaxRegion::Global => &mut self.global,
            MiniMaxRegion::ChinaMainland => &mut self.china,
        };
        if let Some(host) = host {
            let origin = host.origin;
            routes.coding_plan = route_url(&origin, CODING_PLAN_PATH, &[("cycle_type", "3")]);
            routes.coding_plan_referer = route_url(&origin, CODING_PLAN_REFERER_PATH, &[]);
            routes.platform_remains = route_url(&origin, CODING_PLAN_REMAINS_PATH, &[]);
            routes.web_remains = routes.platform_remains.clone();
            routes.has_web_remains_fallback = false;
            routes.billing_history = route_url(&origin, BILLING_HISTORY_PATH, &[]);
            routes.combo = route_url(
                &origin,
                COMBO_PATH,
                &[
                    ("biz_line", "2"),
                    ("cycle_type", "3"),
                    ("resource_package_type", "7"),
                ],
            );
        }
        if let Some(coding) = coding {
            routes.coding_plan = coding.url;
            routes.coding_plan_referer = routes.coding_plan.clone();
            routes.coding_plan_referer.set_query(None);
        }
        if let Some(remains) = remains {
            routes.platform_remains = remains.url;
            routes.web_remains = routes.platform_remains.clone();
            routes.has_web_remains_fallback = false;
        }
        if let Some(billing) = billing {
            routes.billing_history = billing.url;
        }
        Ok(())
    }

    fn register_configured_origin(&mut self, configured: &ConfiguredWebUrl) {
        let item = (
            configured.origin.origin().ascii_serialization(),
            configured.class,
        );
        if !self.configured_origins.contains(&item) {
            self.configured_origins.push(item);
        }
    }

    /// Creates a two-origin loopback table for deterministic HTTP tests.
    /// Each regional origin owns that region's platform, web, and API paths.
    ///
    /// # Errors
    ///
    /// Rejects non-origin, credential-bearing, or non-loopback URLs.
    #[doc(hidden)]
    pub fn loopback(global: &Url, china: &Url) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            global,
            global,
            global,
            china,
            china,
            china,
            EndpointClass::LoopbackDevelopment,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_origins(
        global_platform: &Url,
        global_web: &Url,
        global_api: &Url,
        china_platform: &Url,
        china_web: &Url,
        china_api: &Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        for origin in [
            global_platform,
            global_web,
            global_api,
            china_platform,
            china_web,
            china_api,
        ] {
            validate_bare_origin(origin, class)?;
        }
        if class == EndpointClass::PublicHttps
            && (!same_origin(global_platform, GLOBAL_PLATFORM)?
                || !same_origin(global_web, GLOBAL_WEB)?
                || !same_origin(global_api, GLOBAL_API)?
                || !same_origin(china_platform, CHINA_PLATFORM)?
                || !same_origin(china_web, CHINA_WEB)?
                || !same_origin(china_api, CHINA_API)?)
        {
            return Err(api_error());
        }
        Ok(Self {
            global: build_regional_routes(global_platform, global_web, global_api),
            china: build_regional_routes(china_platform, china_web, china_api),
            base_class: class,
            configured_origins: Vec::new(),
        })
    }

    const fn region(&self, region: MiniMaxRegion) -> &RegionalRoutes {
        match region {
            MiniMaxRegion::Global => &self.global,
            MiniMaxRegion::ChinaMainland => &self.china,
        }
    }

    fn policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        let mut origins = [
            self.global.platform_origin.origin().ascii_serialization(),
            self.global.web_origin.origin().ascii_serialization(),
            self.global.api_origin.origin().ascii_serialization(),
            self.china.platform_origin.origin().ascii_serialization(),
            self.china.web_origin.origin().ascii_serialization(),
            self.china.api_origin.origin().ascii_serialization(),
        ]
        .into_iter()
        .map(|origin| (origin, self.base_class))
        .collect::<Vec<_>>();
        origins.extend(self.configured_origins.iter().cloned());
        EndpointPolicy::new(origins).map_err(|_| api_error())
    }
}

/// Resolved, credential-free `MiniMax` web route view used by deterministic
/// environment settings tests.
pub struct MiniMaxResolvedWebRoutes {
    coding_plan: Url,
    coding_plan_referer: Url,
    remains: Url,
    billing_history: Url,
    combo: Url,
}

impl MiniMaxResolvedWebRoutes {
    /// Coding-plan page URL.
    #[must_use]
    pub const fn coding_plan(&self) -> &Url {
        &self.coding_plan
    }

    /// Coding-plan referer URL.
    #[must_use]
    pub const fn coding_plan_referer(&self) -> &Url {
        &self.coding_plan_referer
    }

    /// Primary remains URL.
    #[must_use]
    pub const fn remains(&self) -> &Url {
        &self.remains
    }

    /// Billing history base URL before bounded pagination fields are applied.
    #[must_use]
    pub const fn billing_history(&self) -> &Url {
        &self.billing_history
    }

    /// Subscription combo metadata URL.
    #[must_use]
    pub const fn combo(&self) -> &Url {
        &self.combo
    }
}

impl Debug for MiniMaxResolvedWebRoutes {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiniMaxResolvedWebRoutes")
            .field("routes", &"<redacted>")
            .finish()
    }
}

struct ConfiguredWebUrl {
    url: Url,
    origin: Url,
    class: EndpointClass,
}

impl Debug for MiniMaxRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiniMaxRouteSet")
            .field("routes", &"<redacted>")
            .field("base_class", &self.base_class)
            .field("configured_origin_count", &self.configured_origins.len())
            .finish_non_exhaustive()
    }
}

fn build_regional_routes(platform: &Url, web: &Url, api: &Url) -> RegionalRoutes {
    RegionalRoutes {
        platform_origin: platform.clone(),
        web_origin: web.clone(),
        api_origin: api.clone(),
        coding_plan: route_url(platform, CODING_PLAN_PATH, &[("cycle_type", "3")]),
        coding_plan_referer: route_url(platform, CODING_PLAN_REFERER_PATH, &[]),
        platform_remains: route_url(platform, CODING_PLAN_REMAINS_PATH, &[]),
        web_remains: route_url(web, CODING_PLAN_REMAINS_PATH, &[]),
        has_web_remains_fallback: true,
        token_plan_remains: route_url(api, TOKEN_PLAN_REMAINS_PATH, &[]),
        legacy_api_remains: route_url(api, CODING_PLAN_REMAINS_PATH, &[]),
        billing_history: route_url(platform, BILLING_HISTORY_PATH, &[]),
        combo: route_url(
            web,
            COMBO_PATH,
            &[
                ("biz_line", "2"),
                ("cycle_type", "3"),
                ("resource_package_type", "7"),
            ],
        ),
    }
}

fn route_url(origin: &Url, path: &str, query: &[(&str, &str)]) -> Url {
    let mut url = origin.clone();
    url.set_path(path);
    url.set_query(None);
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query.iter().copied());
    }
    url
}

fn replace_billing_query(url: &mut Url, page: usize) {
    let retained = url
        .query_pairs()
        .filter(|(name, _)| !matches!(name.as_ref(), "page" | "limit" | "aggregate"))
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut query = url.query_pairs_mut();
    query.clear().extend_pairs(retained).extend_pairs([
        ("page", page.to_string()),
        ("limit", BILLING_PAGE_LIMIT.to_string()),
        ("aggregate", "false".to_owned()),
    ]);
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
    EndpointPolicy::new([(url.origin().ascii_serialization(), class)])
        .and_then(|policy| policy.validate(url).map(|_| ()))
        .map_err(|_| api_error())
}

fn same_origin(actual: &Url, expected: &str) -> Result<bool, ClassifiedError> {
    let expected = Url::parse(expected).map_err(|_| api_error())?;
    Ok(actual.origin() == expected.origin())
}

fn configured_environment_url(
    environment: &BTreeMap<String, String>,
    key: &str,
    strict: bool,
) -> Result<Option<ConfiguredWebUrl>, ClassifiedError> {
    let Some(raw) = environment.get(key).and_then(|value| clean_setting(value)) else {
        return Ok(None);
    };
    if raw.len() > MAX_CONFIGURED_ENDPOINT_BYTES || raw.chars().any(char::is_control) {
        return Err(api_error());
    }
    let candidate = if has_explicit_url_scheme(raw) {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate).map_err(|_| api_error())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.fragment().is_some()
        || url
            .host_str()
            .is_some_and(|host| host.contains(['%', '\\']) || host.chars().any(char::is_whitespace))
    {
        return Err(api_error());
    }
    if strict && !is_minimax_owned_host(&url) {
        return Err(api_error());
    }
    let mut origin = url.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    let endpoint = ConfiguredEndpoint::parse(origin.as_str(), ConfiguredHttpPolicy::HttpsOnly)?;
    let policy = EndpointPolicy::new([(
        endpoint.url().origin().ascii_serialization(),
        endpoint.class(),
    )])
    .map_err(|_| api_error())?;
    policy.validate(&url).map_err(|_| api_error())?;
    Ok(Some(ConfiguredWebUrl {
        url,
        origin,
        class: endpoint.class(),
    }))
}

fn has_explicit_url_scheme(raw: &str) -> bool {
    raw.find(':').is_some_and(|colon| {
        let scheme = &raw[..colon];
        let authority_end = raw.find(['/', '?', '#']).unwrap_or(raw.len());
        if colon > authority_end {
            return false;
        }
        let suffix_end = raw[colon + 1..]
            .find(['/', '?', '#'])
            .map_or(raw.len(), |offset| colon + 1 + offset);
        let suffix = &raw[colon + 1..suffix_end];
        if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        !scheme.is_empty()
            && scheme.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic()
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                }
            })
    })
}

fn is_minimax_owned_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    ["minimax.io", "minimaxi.com"].iter().any(|suffix| {
        host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

struct WebRouteCookies {
    coding_plan: Option<Zeroizing<String>>,
    platform_remains: Option<Zeroizing<String>>,
    web_remains: Option<Zeroizing<String>>,
    billing: Option<Zeroizing<String>>,
    combo: Option<Zeroizing<String>>,
}

impl WebRouteCookies {
    fn manual(cookie: &str) -> Self {
        Self {
            coding_plan: Some(Zeroizing::new(cookie.to_owned())),
            platform_remains: Some(Zeroizing::new(cookie.to_owned())),
            web_remains: Some(Zeroizing::new(cookie.to_owned())),
            billing: Some(Zeroizing::new(cookie.to_owned())),
            combo: Some(Zeroizing::new(cookie.to_owned())),
        }
    }

    fn has_required_cookie(&self) -> bool {
        self.coding_plan.is_some() || self.platform_remains.is_some() || self.web_remains.is_some()
    }
}

struct WebSession {
    cookies: WebRouteCookies,
    tokens: Vec<Zeroizing<String>>,
    group_id: Option<Zeroizing<String>>,
    browser_fallbacks: bool,
}

impl Debug for WebSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSession")
            .field("cookies", &"<redacted>")
            .field("token_count", &self.tokens.len())
            .field("has_group_id", &self.group_id.is_some())
            .field("browser_fallbacks", &self.browser_fallbacks)
            .finish()
    }
}

enum Backend {
    ApiKey(Zeroizing<String>),
    Web(Vec<WebSession>),
}

/// Native `MiniMax` adapter bound to one account, source, and regional preference.
pub struct MiniMaxProvider {
    scope: AccountScope,
    source: ProviderSource,
    region: MiniMaxRegion,
    routes: MiniMaxRouteSet,
    backend: Backend,
    include_billing_history: bool,
    billing_local_offset: Option<UtcOffset>,
    transport: HttpTransport,
}

impl MiniMaxProvider {
    /// Creates the production Coding/Token Plan API-key adapter.
    ///
    /// # Errors
    ///
    /// Rejects missing/unsafe credentials, another provider's scope, or invalid fixed routes.
    pub fn new_api_key(
        scope: AccountScope,
        region: MiniMaxRegion,
        api_key: &str,
    ) -> Result<Self, ClassifiedError> {
        Self::from_api_key_routes(scope, region, api_key, MiniMaxRouteSet::production()?)
    }

    /// Creates an API-key adapter on an injected closed route table.
    ///
    /// # Errors
    ///
    /// Rejects missing/unsafe credentials, scope mismatches, or invalid routes.
    #[doc(hidden)]
    pub fn from_api_key_routes(
        scope: AccountScope,
        region: MiniMaxRegion,
        api_key: &str,
        routes: MiniMaxRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let token = normalize_coding_api_key(api_key)?;
        Self::build(
            scope,
            ProviderSource::ApiKey,
            region,
            routes,
            Backend::ApiKey(token),
            false,
        )
    }

    /// Resolves `MINIMAX_CODING_API_KEY` before `MINIMAX_API_KEY` without
    /// consulting the ambient process environment.
    ///
    /// # Errors
    ///
    /// Returns missing credential when neither injected value is usable.
    #[doc(hidden)]
    pub fn from_api_environment_routes(
        scope: AccountScope,
        region: MiniMaxRegion,
        environment: &BTreeMap<String, String>,
        routes: MiniMaxRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let token = ["MINIMAX_CODING_API_KEY", "MINIMAX_API_KEY"]
            .into_iter()
            .find_map(|name| environment.get(name).and_then(|value| clean_quoted(value)))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::from_api_key_routes(scope, region, &token, routes)
    }

    /// Creates the production web adapter from a Cookie header or inert cURL capture.
    ///
    /// # Errors
    ///
    /// Returns stable missing, capture, credential, scope, or route failures.
    pub fn new_manual(
        scope: AccountScope,
        region: MiniMaxRegion,
        raw: &str,
    ) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, region, raw, MiniMaxRouteSet::production()?)
    }

    /// Creates a production web adapter from an injected environment map.
    /// `MINIMAX_COOKIE` is considered before `MINIMAX_COOKIE_HEADER`; an
    /// invalid primary value does not mask a valid fallback. Endpoint settings
    /// are validated before the provider can construct a credentialed request.
    ///
    /// # Errors
    ///
    /// Returns stable missing, capture, scope, or configured-endpoint failures.
    #[doc(hidden)]
    pub fn from_manual_environment(
        scope: AccountScope,
        region: MiniMaxRegion,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let routes = MiniMaxRouteSet::production_with_environment(region, environment)?;
        let raw = ["MINIMAX_COOKIE", "MINIMAX_COOKIE_HEADER"]
            .into_iter()
            .filter_map(|key| environment.get(key))
            .find(|raw| parse_manual_session(raw).is_ok())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Self::from_manual_capture_routes(scope, region, raw, routes)
    }

    /// Creates a manual web adapter on an injected closed route table.
    /// Captured URLs remain restricted to exact production MiniMax hosts.
    ///
    /// # Errors
    ///
    /// Returns stable missing, parse, scope, or route failures.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        region: MiniMaxRegion,
        raw: &str,
        routes: MiniMaxRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let (cookie, token, group_id) = parse_manual_session(raw)?;
        let session = WebSession {
            cookies: WebRouteCookies::manual(cookie.as_str()),
            tokens: token.into_iter().collect(),
            group_id,
            browser_fallbacks: false,
        };
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            region,
            routes,
            Backend::Web(vec![session]),
            true,
        )
    }

    /// Creates the production browser adapter from explicitly enabled Linux
    /// profile discovery. Profiles stay isolated and retain discovery order.
    ///
    /// # Errors
    ///
    /// Returns stable missing/expired, local-data, scope, or route failures.
    pub fn new_browser(
        scope: AccountScope,
        region: MiniMaxRegion,
        discovery: &BrowserProfileDiscovery,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::new_browser_with_decryptor(
            scope,
            region,
            discovery,
            now,
            &DisabledChromiumCookieDecryptor,
        )
    }

    /// Creates the production browser adapter with a caller-owned Chromium
    /// cookie decryptor. The provider never opens a keyring on its own.
    ///
    /// # Errors
    ///
    /// Returns stable missing/expired, local-data, scope, or route failures.
    pub fn new_browser_with_decryptor(
        scope: AccountScope,
        region: MiniMaxRegion,
        discovery: &BrowserProfileDiscovery,
        now: OffsetDateTime,
        decryptor: &dyn ChromiumCookieDecryptor,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_discovery_routes(
            scope,
            region,
            discovery,
            now,
            decryptor,
            MiniMaxRouteSet::production()?,
        )
    }

    /// Creates a browser adapter with injected MiniMax endpoint settings and
    /// the disabled default Chromium decryptor.
    ///
    /// # Errors
    ///
    /// Returns stable endpoint, local-data, credential, scope, or route failures.
    #[doc(hidden)]
    pub fn new_browser_with_environment(
        scope: AccountScope,
        region: MiniMaxRegion,
        environment: &BTreeMap<String, String>,
        discovery: &BrowserProfileDiscovery,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::new_browser_with_environment_and_decryptor(
            scope,
            region,
            environment,
            discovery,
            now,
            &DisabledChromiumCookieDecryptor,
        )
    }

    /// Creates a browser adapter with injected endpoint settings and a
    /// caller-owned Chromium cookie decryptor.
    ///
    /// # Errors
    ///
    /// Returns stable endpoint, local-data, credential, scope, or route failures.
    #[doc(hidden)]
    pub fn new_browser_with_environment_and_decryptor(
        scope: AccountScope,
        region: MiniMaxRegion,
        environment: &BTreeMap<String, String>,
        discovery: &BrowserProfileDiscovery,
        now: OffsetDateTime,
        decryptor: &dyn ChromiumCookieDecryptor,
    ) -> Result<Self, ClassifiedError> {
        let routes = MiniMaxRouteSet::production_with_environment(region, environment)?;
        Self::from_browser_discovery_routes(scope, region, discovery, now, decryptor, routes)
    }

    /// Creates a browser adapter on injected routes while cookie and storage
    /// selection remain bound to exact production MiniMax origins.
    ///
    /// # Errors
    ///
    /// Returns stable missing/expired, local-data, scope, or route failures.
    #[doc(hidden)]
    pub fn from_browser_discovery_routes(
        scope: AccountScope,
        region: MiniMaxRegion,
        discovery: &BrowserProfileDiscovery,
        now: OffsetDateTime,
        decryptor: &dyn ChromiumCookieDecryptor,
        routes: MiniMaxRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let sessions = browser_sessions(discovery, region, now, decryptor)?;
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            region,
            routes,
            Backend::Web(sessions),
            true,
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        region: MiniMaxRegion,
        routes: MiniMaxRouteSet,
        backend: Backend,
        include_billing_history: bool,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::MiniMax
            || !matches!(
                source,
                ProviderSource::ApiKey
                    | ProviderSource::ManualCookie
                    | ProviderSource::BrowserSession
            )
            || !backend_matches_source(&backend, source)
        {
            return Err(api_error());
        }
        let policy = routes.policy()?;
        for region in MiniMaxRegion::ALL {
            let selected = routes.region(region);
            for endpoint in [
                &selected.coding_plan,
                &selected.platform_remains,
                &selected.web_remains,
                &selected.token_plan_remains,
                &selected.legacy_api_remains,
                &selected.billing_history,
                &selected.combo,
            ] {
                policy.validate(endpoint).map_err(|_| api_error())?;
            }
        }
        let config = TransportConfig::new(
            CONNECT_TIMEOUT,
            REQUEST_TIMEOUT,
            MAX_RESPONSE_BYTES,
            0,
            RetryPolicy::none(),
        )
        .map_err(|_| api_error())?;
        let transport = HttpTransport::new(policy, config).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            region,
            routes,
            backend,
            include_billing_history,
            billing_local_offset: None,
            transport,
        })
    }

    /// Source to which this adapter is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Configured primary region.
    #[must_use]
    pub const fn region(&self) -> MiniMaxRegion {
        self.region
    }

    /// Enables or disables optional billing history for web-session requests.
    #[must_use]
    pub const fn with_billing_history(mut self, enabled: bool) -> Self {
        self.include_billing_history = enabled;
        self
    }

    /// Pins the calendar offset used to bucket billing records. Production
    /// resolves the system-local offset at each instant when this is unset.
    #[must_use]
    #[doc(hidden)]
    pub const fn with_billing_local_offset(mut self, offset: UtcOffset) -> Self {
        self.billing_local_offset = Some(offset);
        self
    }

    /// Fetches one deterministic sample at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable scope, credential, network, API, or bounded-parse failures.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }
        let snapshot = match &self.backend {
            Backend::ApiKey(token) => self.fetch_api(context, fetched_at, token.as_str()).await?,
            Backend::Web(sessions) => self.fetch_web(context, fetched_at, sessions).await?,
        };
        snapshot.normalize(self.scope.clone(), fetched_at, self.source)
    }
}

impl ProviderAdapter for MiniMaxProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::MiniMax)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

/// Parses one bounded MiniMax remains response without performing network I/O.
///
/// # Errors
///
/// Rejects another provider's scope, unsupported sources, vendor error envelopes,
/// malformed or oversized JSON, and responses without usable quota data.
#[doc(hidden)]
pub fn parse_usage_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::MiniMax
        || !matches!(
            source,
            ProviderSource::ApiKey | ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(api_error());
    }
    parse_usage_payload(body, fetched_at)?.normalize(scope, fetched_at, source)
}

impl Debug for MiniMaxProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiniMaxProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("region", &self.region)
            .field("routes", &"<redacted>")
            .field("backend", &"<redacted>")
            .field("include_billing_history", &self.include_billing_history)
            .field(
                "has_fixed_billing_offset",
                &self.billing_local_offset.is_some(),
            )
            .field("transport", &"<redacted>")
            .finish()
    }
}

fn backend_matches_source(backend: &Backend, source: ProviderSource) -> bool {
    matches!(
        (backend, source),
        (Backend::ApiKey(_), ProviderSource::ApiKey)
    ) || matches!(
        (backend, source),
        (
            Backend::Web(_),
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    )
}

struct AttemptFailure {
    error: ClassifiedError,
    can_fallback: bool,
    credential_failure: bool,
}

impl AttemptFailure {
    fn new(error: ClassifiedError, can_fallback: bool, credential_failure: bool) -> Self {
        Self {
            error,
            can_fallback,
            credential_failure,
        }
    }

    fn authentication() -> Self {
        Self::new(
            ClassifiedError::new(ErrorKind::AuthenticationExpired),
            true,
            true,
        )
    }
}

impl MiniMaxProvider {
    async fn fetch_api(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        token: &str,
    ) -> Result<MiniMaxSnapshot, ClassifiedError> {
        let first = self
            .fetch_api_region(context, fetched_at, token, self.region)
            .await;
        match first {
            Ok(snapshot) => Ok(snapshot),
            Err(failure) if self.region == MiniMaxRegion::Global && failure.credential_failure => {
                self.fetch_api_region(context, fetched_at, token, self.region.alternate())
                    .await
                    .map_err(|_| ClassifiedError::new(ErrorKind::AuthenticationExpired))
            }
            Err(failure) => Err(failure.error),
        }
    }

    async fn fetch_api_region(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        token: &str,
        region: MiniMaxRegion,
    ) -> Result<MiniMaxSnapshot, AttemptFailure> {
        let routes = self.routes.region(region);
        let first = self
            .fetch_api_endpoint(context, fetched_at, token, &routes.token_plan_remains)
            .await;
        let first_failure = match first {
            Ok(snapshot) => return Ok(snapshot),
            Err(failure) if failure.can_fallback => failure,
            Err(failure) => return Err(failure),
        };
        match self
            .fetch_api_endpoint(context, fetched_at, token, &routes.legacy_api_remains)
            .await
        {
            Ok(snapshot) => Ok(snapshot),
            Err(_) if first_failure.credential_failure => Err(AttemptFailure::authentication()),
            Err(failure) => Err(failure),
        }
    }

    async fn fetch_api_endpoint(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        token: &str,
        url: &Url,
    ) -> Result<MiniMaxSnapshot, AttemptFailure> {
        let authentication = Authentication::bearer(token.to_owned())
            .map_err(|_| AttemptFailure::new(api_error(), false, false))?;
        let request = HttpRequest::get_json(url.clone())
            .empty_json_content_type()
            .public_header("mm-api-source", "omarchy-ai-bar")
            .map_err(|_| AttemptFailure::new(api_error(), false, false))?
            .authentication(authentication);
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(api_attempt_transport)?;
        parse_usage_payload(response.body(), fetched_at).map_err(|error| {
            let credential = error.kind() == ErrorKind::AuthenticationExpired;
            AttemptFailure::new(error, true, credential)
        })
    }

    async fn fetch_web(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        sessions: &[WebSession],
    ) -> Result<MiniMaxSnapshot, ClassifiedError> {
        let mut last_error = None;
        for session in sessions {
            let attempts = bearer_attempts(session);
            for bearer in &attempts {
                match self
                    .fetch_web_attempt(
                        context,
                        fetched_at,
                        session,
                        bearer.as_ref().map(|value| value.as_str()),
                    )
                    .await
                {
                    Ok(snapshot) => return Ok(snapshot),
                    Err(error) => {
                        let retryable = matches!(
                            error.kind(),
                            ErrorKind::AuthenticationExpired | ErrorKind::Parse
                        );
                        last_error = Some(error);
                        if !retryable || context.cancellation().is_cancelled() {
                            return Err(last_error.expect("error was just stored"));
                        }
                    }
                }
            }
            if !session.browser_fallbacks {
                break;
            }
        }
        Err(last_error.unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }

    async fn fetch_web_attempt(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        session: &WebSession,
        bearer: Option<&str>,
    ) -> Result<MiniMaxSnapshot, ClassifiedError> {
        let routes = self.routes.region(self.region);
        let html_result = if let Some(cookie) = &session.cookies.coding_plan {
            Some(
                self.fetch_coding_plan(context, fetched_at, routes, cookie.as_str(), bearer)
                    .await,
            )
        } else {
            None
        };

        let mut snapshot = match html_result {
            Some(Ok(html_snapshot)) if !html_snapshot.services.is_empty() => html_snapshot,
            Some(Ok(html_snapshot)) => {
                match self
                    .fetch_web_remains(context, fetched_at, routes, session, bearer)
                    .await
                {
                    Ok(mut remains) => {
                        if remains.plan_name.is_none() {
                            remains.plan_name = html_snapshot.plan_name;
                        }
                        remains
                    }
                    Err(error)
                        if error.kind() != ErrorKind::AuthenticationExpired
                            && !context.cancellation().is_cancelled() =>
                    {
                        html_snapshot
                    }
                    Err(error) => return Err(error),
                }
            }
            Some(Err(error)) if error.kind() != ErrorKind::Parse => return Err(error),
            Some(Err(_)) | None => {
                self.fetch_web_remains(context, fetched_at, routes, session, bearer)
                    .await?
            }
        };

        if let Some(group_id) = session.group_id.as_ref() {
            match self
                .fetch_subscription_metadata(context, routes, session, group_id.as_str())
                .await
            {
                Ok(metadata) => snapshot.merge_subscription(metadata),
                Err(error) if context.cancellation().is_cancelled() => return Err(error),
                Err(_) => {}
            }
        }

        if self.include_billing_history {
            match self
                .fetch_billing(context, fetched_at, routes, session, bearer)
                .await
            {
                Ok(summary) => snapshot.billing = Some(summary),
                Err(error) if context.cancellation().is_cancelled() => return Err(error),
                Err(error)
                    if bearer.is_some() && error.kind() == ErrorKind::AuthenticationExpired =>
                {
                    return Err(error);
                }
                Err(_) => {}
            }
        }
        Ok(snapshot)
    }

    async fn fetch_coding_plan(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        routes: &RegionalRoutes,
        cookie: &str,
        bearer: Option<&str>,
    ) -> Result<MiniMaxSnapshot, ClassifiedError> {
        let request = web_request(
            routes.coding_plan.clone(),
            cookie,
            bearer,
            WebRequestKind::Html,
            &origin_url(&routes.coding_plan),
            &routes.coding_plan_referer,
        )?
        .response_headers(&["content-type"])
        .map_err(|_| api_error())?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(classify_web_transport)?;
        let is_json = response
            .header("content-type")
            .is_some_and(|value| value.to_ascii_lowercase().contains("application/json"));
        if is_json || first_non_whitespace(response.body()) == Some(b'{') {
            return parse_usage_payload(response.body(), fetched_at);
        }
        parse_usage_html(response.body(), fetched_at)
    }

    async fn fetch_web_remains(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        routes: &RegionalRoutes,
        session: &WebSession,
        bearer: Option<&str>,
    ) -> Result<MiniMaxSnapshot, ClassifiedError> {
        let candidates = [
            (
                true,
                &routes.platform_remains,
                &session.cookies.platform_remains,
            ),
            (
                routes.has_web_remains_fallback,
                &routes.web_remains,
                &session.cookies.web_remains,
            ),
        ];
        let mut last_error = None;
        for (enabled, url, cookie) in candidates {
            if !enabled {
                continue;
            }
            let Some(cookie) = cookie else { continue };
            let mut request_url = url.clone();
            if let Some(group_id) = session.group_id.as_ref() {
                request_url
                    .query_pairs_mut()
                    .append_pair("GroupId", group_id.as_str());
            }
            let request = web_request(
                request_url,
                cookie.as_str(),
                bearer,
                WebRequestKind::Xhr,
                &origin_url(url),
                &routes.coding_plan_referer,
            )?;
            match self.transport.send(&request, context.cancellation()).await {
                Ok(response) => match parse_usage_payload(response.body(), fetched_at) {
                    Ok(snapshot) => return Ok(snapshot),
                    Err(error) if error.kind() == ErrorKind::AuthenticationExpired => {
                        return Err(error);
                    }
                    Err(error) => last_error = Some(error),
                },
                Err(error) => {
                    let retry = matches!(
                        error,
                        TransportError::Network
                            | TransportError::Timeout
                            | TransportError::ResponseTooLarge
                            | TransportError::MalformedResponse
                            | TransportError::Api { status: 404 | 405 }
                    );
                    let classified = classify_web_transport(error);
                    if !retry || context.cancellation().is_cancelled() {
                        return Err(classified);
                    }
                    last_error = Some(classified);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }

    async fn fetch_subscription_metadata(
        &self,
        context: &ProviderContext,
        routes: &RegionalRoutes,
        session: &WebSession,
        group_id: &str,
    ) -> Result<SubscriptionMetadata, ClassifiedError> {
        validate_group_id(group_id)?;
        let cookie = session
            .cookies
            .combo
            .as_ref()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let request = web_request(
            routes.combo.clone(),
            cookie.as_str(),
            None,
            WebRequestKind::Combo,
            &routes.platform_origin,
            &routes.platform_origin,
        )?
        .sensitive_header("x-group-id", group_id.to_owned())
        .map_err(|_| api_error())?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(classify_web_transport)?;
        parse_subscription_metadata(response.body())
    }

    async fn fetch_billing(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        routes: &RegionalRoutes,
        session: &WebSession,
        bearer: Option<&str>,
    ) -> Result<BillingSummary, ClassifiedError> {
        let cookie = session
            .cookies
            .billing
            .as_ref()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let mut records = Vec::new();
        let mut total_count = None;
        let mut coverage_established = false;
        for page in 1..=MAX_BILLING_PAGES {
            let mut url = routes.billing_history.clone();
            replace_billing_query(&mut url, page);
            let billing_origin = origin_url(&url);
            let referer = route_url(&billing_origin, "/account", &[]);
            let request = web_request(
                url,
                cookie.as_str(),
                bearer,
                WebRequestKind::Xhr,
                &billing_origin,
                &referer,
            )?;
            let response = self
                .transport
                .send(&request, context.cancellation())
                .await
                .map_err(classify_web_transport)?;
            let page = parse_billing_page(response.body(), self.billing_local_offset)?;
            total_count = page.total_count.or(total_count);
            if page.records.is_empty() {
                coverage_established = true;
                break;
            }
            let has_old = page
                .records
                .iter()
                .filter_map(BillingRecord::day)
                .any(|day| day < cutoff_day(fetched_at, self.billing_local_offset));
            records.extend(page.records);
            if records.len() > MAX_BILLING_RECORDS {
                return Err(parse_error());
            }
            if has_old || total_count.is_some_and(|total| records.len() >= total) {
                coverage_established = true;
                break;
            }
        }
        aggregate_billing(
            records,
            fetched_at,
            coverage_established,
            self.billing_local_offset,
        )
    }
}

fn api_attempt_transport(error: TransportError) -> AttemptFailure {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            AttemptFailure::authentication()
        }
        TransportError::Api { status: 404 | 405 } => AttemptFailure::new(api_error(), true, false),
        TransportError::Network
        | TransportError::Timeout
        | TransportError::ResponseTooLarge
        | TransportError::MalformedResponse => {
            let error = error.classified();
            AttemptFailure::new(error, true, false)
        }
        other => AttemptFailure::new(other.classified(), false, false),
    }
}

fn classify_web_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        other => other.classified(),
    }
}

#[derive(Clone, Copy)]
enum WebRequestKind {
    Html,
    Xhr,
    Combo,
}

impl WebRequestKind {
    const fn accept(self) -> RequestAccept {
        match self {
            Self::Html => RequestAccept::Html,
            Self::Xhr | Self::Combo => RequestAccept::JsonTextAny,
        }
    }

    const fn accept_language(self) -> &'static str {
        match self {
            Self::Html | Self::Xhr => ACCEPT_LANGUAGE,
            Self::Combo => "zh-CN,zh;q=0.9",
        }
    }

    const fn is_xhr(self) -> bool {
        matches!(self, Self::Xhr)
    }
}

fn web_request(
    url: Url,
    cookie: &str,
    bearer: Option<&str>,
    kind: WebRequestKind,
    origin: &Url,
    referer: &Url,
) -> Result<HttpRequest, ClassifiedError> {
    let authentication = match bearer {
        Some(bearer) => Authentication::bearer_and_cookie(bearer.to_owned(), cookie.to_owned()),
        None => Authentication::cookie(cookie.to_owned()),
    }
    .map_err(|_| api_error())?;
    let mut request = HttpRequest::get(url)
        .accept(kind.accept())
        .public_header("user-agent", USER_AGENT)
        .and_then(|request| request.public_header("accept-language", kind.accept_language()))
        .and_then(|request| request.public_header("origin", origin.origin().ascii_serialization()))
        .and_then(|request| request.public_header("referer", referer.as_str()))
        .map_err(|_| api_error())?
        .authentication(authentication);
    if kind.is_xhr() {
        request = request
            .public_header("x-requested-with", "XMLHttpRequest")
            .map_err(|_| api_error())?;
    }
    Ok(request)
}

fn bearer_attempts(session: &WebSession) -> Vec<Option<Zeroizing<String>>> {
    if !session.browser_fallbacks {
        return if let Some(token) = session.tokens.first() {
            vec![Some(token.clone())]
        } else {
            vec![None]
        };
    }
    let mut attempts = Vec::new();
    let mut seen = BTreeSet::new();
    for token in &session.tokens {
        if seen.insert(token.as_str().to_owned()) {
            attempts.push(Some(token.clone()));
        }
    }
    let cookie_token = [
        session.cookies.coding_plan.as_ref(),
        session.cookies.platform_remains.as_ref(),
        session.cookies.web_remains.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|cookie| cookie_value(cookie.as_str(), "HERTZ-SESSION"));
    if let Some(token) = cookie_token
        && seen.insert(token.clone())
    {
        attempts.push(Some(Zeroizing::new(token)));
    }
    attempts.push(None);
    attempts
}

type ManualSession = (
    Zeroizing<String>,
    Option<Zeroizing<String>>,
    Option<Zeroizing<String>>,
);

fn parse_manual_session(raw: &str) -> Result<ManualSession, ClassifiedError> {
    let policy = ManualCapturePolicy::new(
        [
            "platform.minimax.io",
            "openplatform.minimax.io",
            "minimax.io",
            "www.minimax.io",
            "platform.minimaxi.com",
            "openplatform.minimaxi.com",
            "minimaxi.com",
            "www.minimaxi.com",
        ],
        [CaptureHeader::Cookie, CaptureHeader::Authorization],
    )
    .and_then(|policy| policy.with_forwarded_headers(["x-group-id"]))
    .map_err(classify_capture_error)?
    .with_ignored_url_query();
    let capture = policy.parse(raw).map_err(classify_capture_error)?;
    let cookie = capture
        .header(CaptureHeader::Cookie)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let cookie = normalize_cookie(cookie)?;
    let token = capture
        .header(CaptureHeader::Authorization)
        .map(parse_bearer)
        .transpose()?;
    let forwarded_group = capture
        .forwarded_headers()
        .find(|(name, _)| *name == "x-group-id")
        .map(|(_, value)| value.to_owned());
    let group_id = forwarded_group
        .or_else(|| extract_group_id_text(raw))
        .or_else(|| {
            cookie_value(cookie.as_str(), "minimax_group_id_v2")
                .or_else(|| cookie_value(cookie.as_str(), "group_id"))
        })
        .map(|value| validate_group_id(&value).map(|()| Zeroizing::new(value)))
        .transpose()?;
    Ok((cookie, token, group_id))
}

fn normalize_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    CookieHeaderNormalizer::normalize(Some(raw))
        .map_err(|_| parse_error())?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let value = raw.split(';').map(str::trim).collect::<Vec<_>>().join("; ");
    if value.is_empty() || value.len() > 64 * 1024 || value.chars().any(char::is_control) {
        return Err(parse_error());
    }
    Ok(Zeroizing::new(value))
}

fn parse_bearer(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let raw = raw.trim();
    let token = raw
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))
        .map(|_| raw[7..].trim())
        .ok_or_else(parse_error)?;
    normalize_secret(token)
}

fn normalize_secret(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let value =
        clean_quoted(raw).ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if value.len() > MAX_SECRET_BYTES
        || value.chars().any(char::is_control)
        || value.contains(['\r', '\n'])
    {
        return Err(parse_error());
    }
    Authentication::bearer(value.clone()).map_err(|_| parse_error())?;
    Ok(Zeroizing::new(value))
}

fn normalize_coding_api_key(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let token = normalize_secret(raw)?;
    if token.starts_with("sk-api-") {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    Ok(token)
}

fn clean_quoted(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    let value = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn classify_capture_error(error: ManualCaptureError) -> ClassifiedError {
    ClassifiedError::new(match error {
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
    })
}

fn validate_group_id(group_id: &str) -> Result<(), ClassifiedError> {
    if !(1..=128).contains(&group_id.len())
        || !group_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(parse_error());
    }
    Ok(())
}

fn extract_group_id_text(raw: &str) -> Option<String> {
    if raw.len() > 64 * 1024 {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    for marker in [
        "x-group-id:",
        "minimax_group_id_v2=",
        "groupid=",
        "group_id=",
    ] {
        let Some(index) = lower.find(marker) else {
            continue;
        };
        let candidate = raw[index + marker.len()..]
            .trim_start()
            .bytes()
            .take_while(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
            .map(char::from)
            .collect::<String>();
        if validate_group_id(&candidate).is_ok() {
            return Some(candidate);
        }
    }
    None
}

fn cookie_value(cookie: &str, name: &str) -> Option<String> {
    cookie.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        candidate
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn browser_sessions(
    discovery: &BrowserProfileDiscovery,
    region: MiniMaxRegion,
    now: OffsetDateTime,
    decryptor: &dyn ChromiumCookieDecryptor,
) -> Result<Vec<WebSession>, ClassifiedError> {
    let allowlist = BrowserCookieDomainAllowlist::new([
        BrowserCookieDomainRule {
            domain: "minimax.io",
            policy: BrowserCookieDomainPolicy::DomainAndSubdomains,
        },
        BrowserCookieDomainRule {
            domain: "minimaxi.com",
            policy: BrowserCookieDomainPolicy::DomainAndSubdomains,
        },
    ])
    .map_err(|_| api_error())?;
    let report = discovery.discover();
    if report.profiles().len() > MAX_BROWSER_PROFILES {
        return Err(parse_error());
    }
    let mut sessions = Vec::new();
    for (index, profile) in report.profiles().iter().enumerate() {
        let source_number = u16::try_from(index + 1).map_err(|_| parse_error())?;
        let source = CookieSourceId::new(source_number);
        let Ok(import) = import_browser_cookies_merging_chromium_stores_with_decryptor(
            profile, source, &allowlist, decryptor,
        ) else {
            continue;
        };
        let order = CookieImportOrder::new([source]).map_err(|_| api_error())?;
        let jar = CookieJar::from_imports(&order, [import]).map_err(|_| parse_error())?;
        let cookies = browser_route_cookies(region, &jar, now)?;
        if !cookies.has_required_cookie() {
            continue;
        }
        let storage = read_profile_storage(profile).unwrap_or_default();
        let cookie_group = [
            cookies.coding_plan.as_ref(),
            cookies.platform_remains.as_ref(),
            cookies.web_remains.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find_map(|cookie| {
            cookie_value(cookie.as_str(), "minimax_group_id_v2")
                .or_else(|| cookie_value(cookie.as_str(), "group_id"))
        });
        let group_id = storage
            .group_id
            .or(cookie_group)
            .filter(|value| validate_group_id(value).is_ok())
            .map(Zeroizing::new);
        sessions.push(WebSession {
            cookies,
            tokens: storage.tokens.into_iter().map(Zeroizing::new).collect(),
            group_id,
            browser_fallbacks: true,
        });
        if sessions.len() > MAX_BROWSER_SESSIONS {
            return Err(parse_error());
        }
    }
    if sessions.is_empty() {
        return Err(ClassifiedError::new(if report.is_empty() {
            ErrorKind::MissingCredential
        } else {
            ErrorKind::AuthenticationExpired
        }));
    }
    Ok(sessions)
}

fn browser_route_cookies(
    region: MiniMaxRegion,
    jar: &CookieJar,
    now: OffsetDateTime,
) -> Result<WebRouteCookies, ClassifiedError> {
    let platform = region.platform_origin();
    let web = region.web_origin();
    Ok(WebRouteCookies {
        coding_plan: browser_cookie_for(jar, platform, CODING_PLAN_PATH, now)?,
        platform_remains: browser_cookie_for(jar, platform, CODING_PLAN_REMAINS_PATH, now)?,
        web_remains: browser_cookie_for(jar, web, CODING_PLAN_REMAINS_PATH, now)?,
        billing: browser_cookie_for(jar, platform, BILLING_HISTORY_PATH, now)?,
        combo: browser_cookie_for(jar, web, COMBO_PATH, now)?,
    })
}

fn browser_cookie_for(
    jar: &CookieJar,
    origin: &str,
    path: &str,
    now: OffsetDateTime,
) -> Result<Option<Zeroizing<String>>, ClassifiedError> {
    let mut url = Url::parse(origin).map_err(|_| api_error())?;
    url.set_path(path);
    let target =
        ValidatedCookieUrl::new(url, CookieUrlPolicy::HttpsOnly).map_err(|_| api_error())?;
    jar.header_for(&target, now)
        .map(|header| header.map(|value| Zeroizing::new(value.expose().to_owned())))
        .map_err(|_| parse_error())
}

#[derive(Default)]
struct StorageSnapshot {
    tokens: Vec<String>,
    group_id: Option<String>,
}

fn read_profile_storage(profile: &BrowserProfile) -> Result<StorageSnapshot, ClassifiedError> {
    if !is_chromium(profile.browser()) {
        return Ok(StorageSnapshot::default());
    }
    let mut snapshot = StorageSnapshot::default();
    if let Ok(reader) = ChromiumLevelDbReader::open(profile, Path::new(LOCAL_STORAGE_DIRECTORY)) {
        collect_local_storage(&reader, &mut snapshot)?;
    }
    if snapshot.tokens.is_empty()
        && let Ok(reader) =
            ChromiumLevelDbReader::open(profile, Path::new(SESSION_STORAGE_DIRECTORY))
    {
        collect_session_storage(&reader, &mut snapshot)?;
    }
    if snapshot.tokens.is_empty() {
        collect_indexed_db(profile, &mut snapshot)?;
    }
    deduplicate_storage(&mut snapshot)?;
    Ok(snapshot)
}

fn is_chromium(browser: BrowserKind) -> bool {
    matches!(
        browser,
        BrowserKind::Chromium
            | BrowserKind::GoogleChrome
            | BrowserKind::Brave
            | BrowserKind::BraveOrigin
            | BrowserKind::MicrosoftEdge
    )
}

fn collect_local_storage(
    reader: &ChromiumLevelDbReader,
    snapshot: &mut StorageSnapshot,
) -> Result<(), ClassifiedError> {
    let origins = [
        GLOBAL_PLATFORM,
        GLOBAL_WEB,
        "https://minimax.io",
        CHINA_PLATFORM,
        CHINA_WEB,
        "https://minimaxi.com",
    ];
    let mut saw_signal = false;
    for raw_origin in origins {
        let origin = ChromiumHttpsOrigin::parse(raw_origin).map_err(|_| api_error())?;
        let entries = reader
            .local_storage_entries(&origin)
            .map_err(|_| parse_error())?;
        saw_signal |= !entries.is_empty();
        for entry in entries {
            collect_storage_text(entry.expose_value(), snapshot)?;
        }
    }
    if snapshot.tokens.is_empty() {
        for entry in reader.text_entries().map_err(|_| parse_error())? {
            let key = entry.expose_key().to_ascii_lowercase();
            let value = entry.expose_value().to_ascii_lowercase();
            if key.contains("minimax.io")
                || key.contains("minimaxi.com")
                || value.contains("minimax.io")
                || value.contains("minimaxi.com")
            {
                saw_signal = true;
                collect_storage_text(entry.expose_value(), snapshot)?;
            }
        }
    }
    if snapshot.tokens.is_empty() && saw_signal {
        for candidate in reader
            .default_token_candidates()
            .map_err(|_| parse_error())?
        {
            let value = candidate.expose_secret();
            if looks_like_token(value) && is_minimax_jwt(value) {
                snapshot.tokens.push(value.to_owned());
            }
        }
    }
    Ok(())
}

fn collect_session_storage(
    reader: &ChromiumLevelDbReader,
    snapshot: &mut StorageSnapshot,
) -> Result<(), ClassifiedError> {
    let entries = reader.text_entries().map_err(|_| parse_error())?;
    let mut map_ids = BTreeSet::new();
    for entry in &entries {
        if entry.expose_key().starts_with("namespace-")
            && ["minimax.io", "minimaxi.com"]
                .iter()
                .any(|domain| entry.expose_key().contains(domain))
            && let Ok(id) = entry.expose_value().trim().parse::<u64>()
        {
            map_ids.insert(id);
        }
    }
    for entry in entries {
        let Some(rest) = entry.expose_key().strip_prefix("map-") else {
            continue;
        };
        let Some((id, _)) = rest.split_once('-') else {
            continue;
        };
        if id.parse::<u64>().is_ok_and(|id| map_ids.contains(&id)) {
            collect_storage_text(entry.expose_value(), snapshot)?;
        }
    }
    Ok(())
}

fn collect_indexed_db(
    profile: &BrowserProfile,
    snapshot: &mut StorageSnapshot,
) -> Result<(), ClassifiedError> {
    let root = profile.path().join("IndexedDB");
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(parse_error()),
    };
    let mut directories = Vec::<PathBuf>::new();
    for entry in entries {
        if directories.len() == MAX_INDEXED_DB_DIRECTORIES {
            return Err(parse_error());
        }
        let entry = entry.map_err(|_| parse_error())?;
        let name = entry.file_name().into_string().map_err(|_| parse_error())?;
        if !valid_indexed_db_name(&name) {
            continue;
        }
        let file_type = entry.file_type().map_err(|_| parse_error())?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(parse_error());
        }
        directories.push(PathBuf::from("IndexedDB").join(name));
    }
    directories.sort();
    for relative in directories {
        let Ok(reader) = ChromiumLevelDbReader::open(profile, &relative) else {
            continue;
        };
        for entry in reader.text_entries().map_err(|_| parse_error())? {
            collect_storage_text(entry.expose_value(), snapshot)?;
        }
        if snapshot.tokens.is_empty() {
            for candidate in reader
                .default_token_candidates()
                .map_err(|_| parse_error())?
            {
                if looks_like_token(candidate.expose_secret()) {
                    snapshot.tokens.push(candidate.expose_secret().to_owned());
                }
            }
        }
    }
    Ok(())
}

fn valid_indexed_db_name(name: &str) -> bool {
    name.len() <= 255
        && name.ends_with(".indexeddb.leveldb")
        && [
            "https_platform.minimax.io_",
            "https_www.minimax.io_",
            "https_minimax.io_",
            "https_platform.minimaxi.com_",
            "https_www.minimaxi.com_",
            "https_minimaxi.com_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn collect_storage_text(raw: &str, snapshot: &mut StorageSnapshot) -> Result<(), ClassifiedError> {
    if raw.len() > MAX_STORAGE_VALUE_BYTES || raw.contains('\0') {
        return Err(parse_error());
    }
    let extracted = extract_tokens(raw);
    snapshot.tokens.extend(extracted);
    if snapshot.group_id.is_none() {
        snapshot.group_id = extract_group_id_from_json_text(raw)
            .or_else(|| extract_group_id_text(raw))
            .or_else(|| {
                snapshot
                    .tokens
                    .iter()
                    .find_map(|token| group_id_from_jwt(token))
            });
    }
    Ok(())
}

fn deduplicate_storage(snapshot: &mut StorageSnapshot) -> Result<(), ClassifiedError> {
    let mut seen = BTreeSet::new();
    snapshot.tokens.retain(|token| seen.insert(token.clone()));
    if snapshot.tokens.len() > MAX_STORAGE_TOKENS {
        return Err(parse_error());
    }
    snapshot
        .tokens
        .retain(|token| normalize_secret(token).is_ok() && looks_like_storage_token(token));
    if snapshot.group_id.is_none() {
        snapshot.group_id = snapshot
            .tokens
            .iter()
            .find_map(|token| group_id_from_jwt(token));
    }
    Ok(())
}

fn extract_tokens(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        collect_json_tokens(&value, 0, &mut tokens);
    }
    for marker in [
        "access_token",
        "accessToken",
        "id_token",
        "idToken",
        "authToken",
        "authorization",
    ] {
        scan_after_marker(raw, marker, &mut tokens);
    }
    for candidate in raw.split(|character: char| {
        !(character.is_ascii_alphanumeric()
            || matches!(character, '.' | '_' | '-' | '+' | '=' | '/'))
    }) {
        if looks_like_jwt(candidate) {
            tokens.push(candidate.to_owned());
        }
    }
    let has_long = tokens.iter().any(|token| token.len() >= 60);
    if has_long {
        tokens.retain(|token| token.len() >= 60);
    }
    let mut seen = BTreeSet::new();
    tokens.retain(|token| seen.insert(token.clone()));
    tokens
}

fn collect_json_tokens(value: &Value, depth: usize, tokens: &mut Vec<String>) {
    if depth > 16 || tokens.len() > MAX_STORAGE_TOKENS {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if is_token_key(key)
                    && let Some(token) = child.as_str()
                    && looks_like_token(token)
                {
                    tokens.push(token.to_owned());
                }
                collect_json_tokens(child, depth + 1, tokens);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_json_tokens(child, depth + 1, tokens);
            }
        }
        Value::String(string) => {
            if looks_like_token(string) {
                tokens.push(string.clone());
            } else if string.len() <= MAX_STORAGE_VALUE_BYTES
                && let Ok(nested) = serde_json::from_str::<Value>(string)
            {
                collect_json_tokens(&nested, depth + 1, tokens);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn is_token_key(key: &str) -> bool {
    matches!(
        key,
        "access_token"
            | "accessToken"
            | "id_token"
            | "idToken"
            | "token"
            | "authToken"
            | "authorization"
            | "bearer"
    )
}

fn scan_after_marker(raw: &str, marker: &str, tokens: &mut Vec<String>) {
    let mut remainder = raw;
    while let Some(index) = remainder.find(marker) {
        let tail = &remainder[index + marker.len()..];
        let token = tail
            .trim_start_matches(|character: char| {
                character.is_ascii_whitespace()
                    || matches!(character, ':' | '=' | '"' | '\'' | '\\')
            })
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '_' | '-' | '+' | '=' | '/')
            })
            .collect::<String>();
        if looks_like_storage_token(&token) {
            tokens.push(token);
        }
        remainder = tail;
    }
}

fn looks_like_token(value: &str) -> bool {
    let value = value.trim();
    if value.len() > MAX_SECRET_BYTES {
        return false;
    }
    if looks_like_jwt(value) {
        return value.len() >= 60;
    }
    value.len() >= 60
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'=' | b'/')
        })
}

fn looks_like_storage_token(value: &str) -> bool {
    let value = value.trim();
    (20..=MAX_SECRET_BYTES).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'=' | b'/')
        })
}

fn looks_like_jwt(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() >= 3
        && parts.iter().take(3).all(|part| {
            part.len() >= 10
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

fn jwt_claims(token: &str) -> Option<Map<String, Value>> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    if bytes.len() > MAX_STORAGE_VALUE_BYTES {
        return None;
    }
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()
        .cloned()
}

fn is_minimax_jwt(token: &str) -> bool {
    let Some(claims) = jwt_claims(token) else {
        return false;
    };
    claims
        .get("iss")
        .and_then(Value::as_str)
        .is_some_and(|issuer| issuer.to_ascii_lowercase().contains("minimax"))
        || [
            "GroupID",
            "GroupName",
            "UserName",
            "SubjectID",
            "Mail",
            "TokenType",
        ]
        .iter()
        .any(|key| claims.contains_key(*key))
}

fn group_id_from_jwt(token: &str) -> Option<String> {
    let claims = jwt_claims(token)?;
    for key in [
        "group_id",
        "groupId",
        "groupID",
        "GroupID",
        "gid",
        "tenant_id",
        "tenantId",
        "org_id",
        "orgId",
    ] {
        if let Some(id) = scalar_group_id(claims.get(key)) {
            return Some(id);
        }
    }
    claims.iter().find_map(|(key, value)| {
        key.to_ascii_lowercase()
            .contains("group")
            .then(|| scalar_group_id(Some(value)))
            .flatten()
    })
}

fn extract_group_id_from_json_text(raw: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(raw).ok()?;
    find_group_id(&value, 0)
}

fn find_group_id(value: &Value, depth: usize) -> Option<String> {
    if depth > 16 {
        return None;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key.to_ascii_lowercase().contains("group")
                    && let Some(id) = scalar_group_id(Some(child))
                {
                    return Some(id);
                }
                if let Some(id) = find_group_id(child, depth + 1) {
                    return Some(id);
                }
            }
            None
        }
        Value::Array(array) => array
            .iter()
            .find_map(|child| find_group_id(child, depth + 1)),
        Value::String(string) => serde_json::from_str::<Value>(string)
            .ok()
            .and_then(|nested| find_group_id(&nested, depth + 1)),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

fn scalar_group_id(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let text = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => return None,
    };
    longest_digit_sequence(&text).or_else(|| validate_group_id(&text).is_ok().then_some(text))
}

fn longest_digit_sequence(raw: &str) -> Option<String> {
    raw.split(|character: char| !character.is_ascii_digit())
        .filter(|candidate| validate_group_id(candidate).is_ok())
        .max_by_key(|candidate| candidate.len())
        .map(str::to_owned)
}

struct MiniMaxSnapshot {
    plan_name: Option<String>,
    available_prompts: Option<i64>,
    window_minutes: Option<i64>,
    used_percent: Option<f64>,
    resets_at: Option<Timestamp>,
    services: Vec<ServiceUsage>,
    points_balance: Option<Decimal>,
    subscription_expires_at: Option<Timestamp>,
    subscription_renews_at: Option<Timestamp>,
    billing: Option<BillingSummary>,
}

impl MiniMaxSnapshot {
    fn merge_subscription(&mut self, metadata: SubscriptionMetadata) {
        if metadata.plan_name.is_some() {
            self.plan_name = metadata.plan_name;
        }
        if metadata.expires_at.is_some() {
            self.subscription_expires_at = metadata.expires_at;
        }
        if metadata.renews_at.is_some() {
            self.subscription_renews_at = metadata.renews_at;
        }
    }

    #[allow(clippy::too_many_lines)]
    fn normalize(
        self,
        scope: AccountScope,
        fetched_at: Timestamp,
        source: ProviderSource,
    ) -> Result<UsageSample, ClassifiedError> {
        let mut builder = UsageSampleBuilder::new(scope, fetched_at)
            .login_method(self.plan_name.filter(|value| !value.trim().is_empty()))?
            .subscription_expires_at(self.subscription_expires_at)
            .subscription_renews_at(self.subscription_renews_at);
        let ordered = ordered_services(&self.services);
        if ordered.is_empty() {
            let percent = self.used_percent.unwrap_or(0.0).clamp(0.0, 100.0);
            let duration = self
                .window_minutes
                .map(WindowDuration::from_provider_minutes)
                .transpose()
                .map_err(|_| parse_error())?;
            let description =
                fallback_window_description(self.available_prompts, self.window_minutes)
                    .map(BoundedText::new)
                    .transpose()
                    .map_err(|_| parse_error())?;
            let primary = RateWindow::new(
                WindowUsage::known(UsagePercent::new(percent).map_err(|_| parse_error())?),
                duration,
                self.resets_at,
                description,
                None,
                false,
            )
            .map_err(|_| parse_error())?;
            builder = builder.primary(primary);
        } else {
            let windows = ordered
                .iter()
                .map(|service| service.rate_window())
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(primary) = windows.first() {
                builder = builder.primary(primary.clone());
            }
            if let Some(secondary) = windows.get(1) {
                builder = builder.secondary(secondary.clone());
            }
            if let Some(tertiary) = windows.get(2) {
                builder = builder.tertiary(tertiary.clone());
            }
            let extras = ordered
                .iter()
                .zip(windows.iter())
                .enumerate()
                .skip(3)
                .map(|(index, (service, window))| {
                    Ok(NamedRateWindow::new(
                        BoundedText::new(format!("minimax-service-{}", index + 1))
                            .map_err(|_| api_error())?,
                        BoundedText::new(service.detail_label()).map_err(|_| parse_error())?,
                        window.clone(),
                    ))
                })
                .collect::<Result<Vec<_>, ClassifiedError>>()?;
            builder = builder.extra_windows(extras);
        }

        let mut details = Vec::new();
        if !ordered.is_empty() {
            details.push(quota_detail_section(&ordered)?);
        }
        if let Some(points) = self.points_balance
            && points >= Decimal::ZERO
        {
            let used = CostAmount::provider(ExactDecimal::new(points), "Points")
                .map_err(|_| parse_error())?;
            let cost = CostSummary::new(
                used,
                ExactDecimal::new(Decimal::ZERO),
                Some("MiniMax points balance".to_owned()),
                None,
                None,
                None,
                Some(ExactDecimal::new(points)),
                fetched_at,
                None,
                None,
                CostProvenance::VendorMetered,
            )
            .map_err(|_| parse_error())?;
            builder = builder.cost(cost);
        }
        if let Some(billing) = &self.billing {
            details.push(billing.detail_section()?);
            builder = builder.cost_usage(billing.cost_usage(fetched_at)?);
        }
        let strategy = match source {
            ProviderSource::ApiKey => "api",
            ProviderSource::ManualCookie => "manual",
            ProviderSource::BrowserSession => "browser",
            ProviderSource::ConfigurableEndpoint
            | ProviderSource::OAuth
            | ProviderSource::Cli
            | ProviderSource::LocalData
            | ProviderSource::CloudCredentials => return Err(api_error()),
        };
        builder
            .detail_sections(details)
            .provenance("minimax", strategy)?
            .build()
    }
}

#[derive(Clone)]
struct ServiceUsage {
    service_type: String,
    display_name: String,
    window_type: String,
    usage: i64,
    limit: i64,
    percent: f64,
    unlimited: bool,
    resets_at: Option<Timestamp>,
    reset_description: String,
}

impl ServiceUsage {
    fn is_primary_text(&self) -> bool {
        let normalized = self.service_type.trim().to_ascii_lowercase();
        normalized == "general" || self.display_name == "Text Generation"
    }

    fn is_weekly(&self) -> bool {
        self.window_type.trim().eq_ignore_ascii_case("weekly")
    }

    fn detail_label(&self) -> String {
        format!("{} · {}", self.display_name, self.window_type)
    }

    fn rate_window(&self) -> Result<RateWindow, ClassifiedError> {
        let duration = service_window_minutes(&self.window_type)
            .map(WindowDuration::from_provider_minutes)
            .transpose()
            .map_err(|_| parse_error())?;
        RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(self.percent.clamp(0.0, 100.0)).map_err(|_| parse_error())?,
            ),
            duration,
            self.resets_at,
            Some(BoundedText::new(self.reset_description.clone()).map_err(|_| parse_error())?),
            None,
            false,
        )
        .map_err(|_| parse_error())
    }
}

fn ordered_services(services: &[ServiceUsage]) -> Vec<&ServiceUsage> {
    let mut ordered = services.iter().enumerate().collect::<Vec<_>>();
    ordered.sort_by_key(|(index, service)| {
        (
            u8::from(!service.is_primary_text()),
            u8::from(service.is_weekly()),
            *index,
        )
    });
    ordered.into_iter().map(|(_, service)| service).collect()
}

fn quota_detail_section(services: &[&ServiceUsage]) -> Result<DetailSection, ClassifiedError> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for service in services {
        *counts.entry(service.display_name.as_str()).or_default() += 1;
    }
    let rows = services
        .iter()
        .map(|service| {
            let label = if counts
                .get(service.display_name.as_str())
                .copied()
                .unwrap_or(0)
                > 1
            {
                service.detail_label()
            } else {
                service.display_name.clone()
            };
            let value = if service.unlimited {
                "Unlimited".to_owned()
            } else {
                format!(
                    "{} / {}",
                    format_integer(service.usage),
                    format_integer(service.limit)
                )
            };
            DetailRow::new(
                label,
                value,
                Some(format!(
                    "{} · {}",
                    percent_label(service.percent),
                    service.reset_description
                )),
                DetailSensitivity::Public,
            )
            .map_err(|_| parse_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    DetailSection::new(Some("Quota services".to_owned()), rows, None).map_err(|_| parse_error())
}

fn percent_label(percent: f64) -> String {
    if percent.fract().abs() < f64::EPSILON {
        format!("{percent:.0}% used")
    } else {
        format!("{percent:.1}% used")
    }
}

fn fallback_window_description(
    available: Option<i64>,
    window_minutes: Option<i64>,
) -> Option<String> {
    let window = window_minutes.and_then(window_description);
    match (available.filter(|value| *value > 0), window) {
        (Some(prompts), Some(window)) => Some(format!("{prompts} prompts / {window}")),
        (Some(prompts), None) => Some(format!("{prompts} prompts")),
        (None, window) => window,
    }
}

fn window_description(minutes: i64) -> Option<String> {
    if minutes <= 0 {
        None
    } else if minutes % 1_440 == 0 {
        let days = minutes / 1_440;
        Some(format!("{days} day{}", if days == 1 { "" } else { "s" }))
    } else if minutes % 60 == 0 {
        let hours = minutes / 60;
        Some(format!("{hours} hour{}", if hours == 1 { "" } else { "s" }))
    } else {
        Some(format!(
            "{minutes} minute{}",
            if minutes == 1 { "" } else { "s" }
        ))
    }
}

fn service_window_minutes(window: &str) -> Option<i64> {
    let normalized = window.trim().to_ascii_lowercase();
    if normalized == "today" || normalized == "今日" {
        return Some(1_440);
    }
    if normalized == "weekly" {
        return Some(10_080);
    }
    let mut parts = normalized.split_ascii_whitespace();
    let value = parts.next()?.parse::<i64>().ok()?;
    let unit = parts.next()?;
    match unit {
        "hour" | "hours" | "h" | "hr" | "hrs" | "小时" => value.checked_mul(60),
        "minute" | "minutes" | "m" | "min" | "mins" => Some(value),
        "day" | "days" | "d" => value.checked_mul(1_440),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn parse_usage_payload(
    body: &[u8],
    fetched_at: Timestamp,
) -> Result<MiniMaxSnapshot, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    validate_base_response(&root)?;
    if let Some(snapshot) = parse_multi_service(&root, fetched_at)? {
        return Ok(snapshot);
    }
    let data = root
        .as_object()
        .and_then(|object| object.get("data"))
        .and_then(Value::as_object)
        .or_else(|| root.as_object())
        .ok_or_else(parse_error)?;
    if let Some(base) = data.get("base_resp") {
        validate_base_response(base)?;
    }
    let remains = data
        .get("model_remains")
        .or_else(|| data.get("modelRemains"))
        .and_then(Value::as_array)
        .ok_or_else(parse_error)?;
    if remains.is_empty() || remains.len() > MAX_SERVICES {
        return Err(parse_error());
    }

    let mut services = Vec::new();
    for item in remains {
        let Some(object) = item.as_object() else {
            return Err(parse_error());
        };
        let input = ModelRemains::parse(object);
        let Some(model_name) = input.model_name.as_deref() else {
            continue;
        };
        let service_type = map_model_service(model_name);
        if let Some(service) = make_service(&service_type, None, input.interval, fetched_at)? {
            services.push(service);
        }
        if is_text_model(model_name)
            && let Some(service) =
                make_service(&service_type, Some("Weekly"), input.weekly, fetched_at)?
        {
            services.push(service);
        }
        if services.len() > MAX_SERVICES {
            return Err(parse_error());
        }
    }

    let first = remains
        .first()
        .and_then(Value::as_object)
        .map(ModelRemains::parse)
        .ok_or_else(parse_error)?;
    let percent_quota = first.interval.remaining_percent.is_some();
    let total = if percent_quota && first.interval.total == Some(0) {
        None
    } else {
        first.interval.total
    };
    let remaining = if percent_quota && first.interval.remaining == Some(0) {
        None
    } else {
        first.interval.remaining
    };
    let used_percent = quota_percent(total, remaining, first.interval.remaining_percent);
    let start = epoch_timestamp(first.interval.start);
    let end = epoch_timestamp(first.interval.end);
    let window_minutes = start.zip(end).and_then(|(start, end)| {
        let minutes = end.unix_timestamp().checked_sub(start.unix_timestamp())? / 60;
        (minutes > 0).then_some(minutes)
    });
    let reset = reset_timestamp(end, first.interval.remains_time, fetched_at);
    let mut plan_name = first_non_empty_string(
        data,
        &[
            "current_subscribe_title",
            "currentSubscribeTitle",
            "plan_name",
            "planName",
            "combo_title",
            "comboTitle",
            "current_plan_title",
            "currentPlanTitle",
        ],
    );
    if plan_name.is_none() {
        plan_name = data
            .get("current_combo_card")
            .or_else(|| data.get("currentComboCard"))
            .and_then(Value::as_object)
            .and_then(|card| bounded_string(card.get("title")));
    }
    if plan_name.is_none() && inferred_plus_plan(remains) {
        plan_name = Some("Plus".to_owned());
    }
    let points_balance = [
        "points_balance",
        "pointsBalance",
        "point_balance",
        "credits_balance",
        "creditsBalance",
        "credit_balance",
        "balance",
    ]
    .into_iter()
    .find_map(|key| decimal_value(data.get(key)));

    Ok(MiniMaxSnapshot {
        plan_name,
        available_prompts: total,
        window_minutes,
        used_percent,
        resets_at: reset,
        services,
        points_balance,
        subscription_expires_at: None,
        subscription_renews_at: None,
        billing: None,
    })
}

#[derive(Clone, Copy, Default)]
struct QuotaInput {
    total: Option<i64>,
    remaining: Option<i64>,
    remaining_percent: Option<f64>,
    status: Option<i64>,
    start: Option<i64>,
    end: Option<i64>,
    remains_time: Option<i64>,
    boost_permille: Option<i64>,
}

struct ModelRemains {
    model_name: Option<String>,
    interval: QuotaInput,
    weekly: QuotaInput,
}

impl ModelRemains {
    fn parse(object: &Map<String, Value>) -> Self {
        Self {
            model_name: bounded_string(object.get("model_name")),
            interval: QuotaInput {
                total: integer_value(object.get("current_interval_total_count")),
                remaining: integer_value(object.get("current_interval_usage_count")),
                remaining_percent: finite_value(object.get("current_interval_remaining_percent")),
                status: integer_value(object.get("current_interval_status")),
                start: integer_value(object.get("start_time")),
                end: integer_value(object.get("end_time")),
                remains_time: integer_value(object.get("remains_time")),
                boost_permille: integer_value(object.get("interval_boost_permill"))
                    .or_else(|| integer_value(object.get("interval_boost_permille"))),
            },
            weekly: QuotaInput {
                total: integer_value(object.get("current_weekly_total_count")),
                remaining: integer_value(object.get("current_weekly_usage_count")),
                remaining_percent: finite_value(object.get("current_weekly_remaining_percent")),
                status: integer_value(object.get("current_weekly_status")),
                start: integer_value(object.get("weekly_start_time")),
                end: integer_value(object.get("weekly_end_time")),
                remains_time: integer_value(object.get("weekly_remains_time")),
                boost_permille: integer_value(object.get("weekly_boost_permill"))
                    .or_else(|| integer_value(object.get("weekly_boost_permille"))),
            },
        }
    }
}

fn make_service(
    service_type: &str,
    window_override: Option<&str>,
    input: QuotaInput,
    fetched_at: Timestamp,
) -> Result<Option<ServiceUsage>, ClassifiedError> {
    let is_weekly = window_override.is_some_and(|window| window.eq_ignore_ascii_case("weekly"));
    let unlimited = input.status == Some(3)
        && is_weekly
        && matches!(
            service_type.to_ascii_lowercase().as_str(),
            "text generation" | "general"
        )
        && input.remaining_percent.is_some_and(|value| value >= 100.0);
    let unavailable = !unlimited
        && input.status == Some(3)
        && input.total.unwrap_or(0) == 0
        && input.remaining.unwrap_or(0) == 0
        && input.remaining_percent.is_some_and(|value| value >= 100.0);
    if unavailable {
        return Ok(None);
    }
    let start = epoch_timestamp(input.start);
    let end = epoch_timestamp(input.end);
    let (mut window_type, mut time_range) = quota_window_info(start, end);
    if let Some(override_value) = window_override {
        override_value.clone_into(&mut window_type);
        if is_weekly && let Some(range) = format_date_time_range(start, end) {
            time_range = range;
        }
    }
    let reset = (!unlimited)
        .then(|| reset_timestamp(end, input.remains_time, fetched_at))
        .flatten();
    let (usage, limit, percent) = if unlimited {
        (0, 0, 0.0)
    } else if let Some(remaining_percent) = input.remaining_percent {
        if !remaining_percent.is_finite() {
            return Err(parse_error());
        }
        let percent = (100.0 - remaining_percent).clamp(0.0, 100.0);
        let limit = input
            .boost_permille
            .filter(|value| *value > 0)
            .map_or(100, |value| value.saturating_add(5) / 10)
            .max(1);
        let usage = (percent * limit.to_f64().ok_or_else(parse_error)? / 100.0)
            .round()
            .to_i64()
            .ok_or_else(parse_error)?;
        (usage, limit, percent)
    } else {
        let (Some(total), Some(remaining)) = (input.total, input.remaining) else {
            return Ok(None);
        };
        if total <= 0 {
            return Ok(None);
        }
        let usage = total.saturating_sub(remaining).max(0);
        let percent = ratio_percent(usage, total).ok_or_else(parse_error)?;
        (usage, total, percent)
    };
    let reset_description = if unlimited {
        "Unlimited".to_owned()
    } else {
        reset_description(&window_type, &time_range, reset, fetched_at)
    };
    for value in [service_type, &window_type, &time_range, &reset_description] {
        if value.is_empty()
            || value.len() > MAX_SERVICE_TEXT_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(parse_error());
        }
    }
    Ok(Some(ServiceUsage {
        service_type: service_type.to_owned(),
        display_name: service_display_name(service_type),
        window_type,
        usage,
        limit,
        percent,
        unlimited,
        resets_at: reset,
        reset_description,
    }))
}

fn quota_percent(
    total: Option<i64>,
    remaining: Option<i64>,
    remaining_percent: Option<f64>,
) -> Option<f64> {
    if let Some(remaining_percent) = remaining_percent.filter(|value| value.is_finite()) {
        return Some((100.0 - remaining_percent).clamp(0.0, 100.0));
    }
    let (total, remaining) = total.zip(remaining)?;
    ratio_percent(total.saturating_sub(remaining).max(0), total)
}

fn ratio_percent(numerator: i64, denominator: i64) -> Option<f64> {
    let numerator = numerator.to_f64()?;
    let denominator = denominator.to_f64()?;
    (denominator > 0.0).then(|| (numerator / denominator * 100.0).clamp(0.0, 100.0))
}

fn inferred_plus_plan(remains: &[Value]) -> bool {
    let has_text = remains.iter().any(|item| {
        item.as_object()
            .and_then(|object| bounded_string(object.get("model_name")))
            .is_some_and(|model| is_text_model(&model))
    });
    let has_unavailable_video = remains.iter().any(|item| {
        let Some(object) = item.as_object() else {
            return false;
        };
        bounded_string(object.get("model_name"))
            .is_some_and(|name| name.trim().eq_ignore_ascii_case("video"))
            && integer_value(object.get("current_interval_status")) == Some(3)
            && integer_value(object.get("current_interval_total_count")).unwrap_or(0) == 0
            && integer_value(object.get("current_interval_usage_count")).unwrap_or(0) == 0
            && finite_value(object.get("current_interval_remaining_percent"))
                .is_some_and(|value| value >= 100.0)
    });
    has_text && has_unavailable_video
}

fn map_model_service(model_name: &str) -> String {
    let lower = model_name.trim().to_ascii_lowercase();
    if matches!(lower.as_str(), "general" | "video") {
        return lower;
    }
    if is_text_model(model_name) {
        return "Text Generation".to_owned();
    }
    if lower.contains("speech") {
        return "Text to Speech".to_owned();
    }
    if lower.contains("hailuo") && lower.contains("fast") {
        return "Image to Video".to_owned();
    }
    if lower.contains("hailuo") {
        return "Text to Video".to_owned();
    }
    if lower.starts_with("image-") {
        return "Image Generation".to_owned();
    }
    if lower.contains("music") {
        return "Music Generation".to_owned();
    }
    model_name.trim().to_owned()
}

fn is_text_model(model_name: &str) -> bool {
    let lower = model_name.trim().to_ascii_lowercase();
    lower == "general" || lower.contains("minimax-m") || lower.starts_with("m2.")
}

fn service_display_name(service: &str) -> String {
    match service.trim().to_ascii_lowercase().as_str() {
        "general" => "General",
        "video" => "Video",
        "text-generation" | "text generation" => "Text Generation",
        "text-to-speech" | "text to speech" => "Text to Speech",
        "image" => "Image",
        "image generation" => "Image Generation",
        "text to video" => "Text to Video",
        "image to video" => "Image to Video",
        "music generation" => "Music Generation",
        "music generation · v2.6" => "Music Generation · v2.6",
        "music cover" => "Music Cover",
        "lyrics generation" => "Lyrics Generation",
        "image understanding" => "Image Understanding",
        _ => service,
    }
    .to_owned()
}

fn quota_window_info(start: Option<Timestamp>, end: Option<Timestamp>) -> (String, String) {
    let Some((start, end)) = start.zip(end) else {
        return ("Unknown".to_owned(), "N/A".to_owned());
    };
    let seconds = end.unix_timestamp().saturating_sub(start.unix_timestamp());
    let window = if (23 * 3_600..=25 * 3_600).contains(&seconds) {
        "Today".to_owned()
    } else if (4 * 3_600..=6 * 3_600).contains(&seconds) {
        "5 hours".to_owned()
    } else if (3_600..23 * 3_600).contains(&seconds) {
        format!("{} hours", seconds / 3_600)
    } else {
        "Custom".to_owned()
    };
    let offset = time::UtcOffset::from_hms(8, 0, 0).expect("fixed UTC+8 offset");
    let start = start.as_offset_date_time().to_offset(offset);
    let end = end.as_offset_date_time().to_offset(offset);
    let range = format!(
        "{:02}:{:02}-{:02}:{:02}(UTC+8)",
        start.hour(),
        start.minute(),
        end.hour(),
        end.minute()
    );
    (window, range)
}

fn format_date_time_range(start: Option<Timestamp>, end: Option<Timestamp>) -> Option<String> {
    let (start, end) = start.zip(end)?;
    let offset = time::UtcOffset::from_hms(8, 0, 0).ok()?;
    let start = start.as_offset_date_time().to_offset(offset);
    let end = end.as_offset_date_time().to_offset(offset);
    Some(format!(
        "{:02}/{:02} {:02}:{:02} - {:02}/{:02} {:02}:{:02}(UTC+8)",
        u8::from(start.month()),
        start.day(),
        start.hour(),
        start.minute(),
        u8::from(end.month()),
        end.day(),
        end.hour(),
        end.minute()
    ))
}

fn reset_timestamp(
    end: Option<Timestamp>,
    remains: Option<i64>,
    fetched_at: Timestamp,
) -> Option<Timestamp> {
    if end.is_some_and(|end| end > fetched_at) {
        return end;
    }
    let remains = remains.filter(|value| *value > 0)?;
    let seconds = if remains > 1_000_000 {
        remains / 1_000
    } else {
        remains
    };
    fetched_at
        .unix_timestamp()
        .checked_add(seconds)
        .and_then(|seconds| Timestamp::from_unix_timestamp(seconds).ok())
}

fn reset_description(
    window_type: &str,
    time_range: &str,
    reset: Option<Timestamp>,
    fetched_at: Timestamp,
) -> String {
    if let Some(reset) = reset.filter(|reset| *reset > fetched_at) {
        let seconds = reset
            .unix_timestamp()
            .saturating_sub(fetched_at.unix_timestamp());
        if seconds < 60 {
            return format!("Resets in {seconds} seconds");
        }
        if seconds < 3_600 {
            let minutes = seconds / 60;
            return format!(
                "Resets in {minutes} minute{}",
                if minutes == 1 { "" } else { "s" }
            );
        }
        if seconds < 86_400 {
            let hours = seconds / 3_600;
            return format!(
                "Resets in {hours} hour{}",
                if hours == 1 { "" } else { "s" }
            );
        }
        let days = seconds / 86_400;
        return format!("Resets in {days} day{}", if days == 1 { "" } else { "s" });
    }
    format!("{window_type}: {time_range}")
}

fn epoch_timestamp(value: Option<i64>) -> Option<Timestamp> {
    let raw = value?;
    let seconds = if raw > 1_000_000_000_000 {
        raw / 1_000
    } else if raw > 1_000_000_000 {
        raw
    } else {
        return None;
    };
    Timestamp::from_unix_timestamp(seconds).ok()
}

fn parse_multi_service(
    root: &Value,
    fetched_at: Timestamp,
) -> Result<Option<MiniMaxSnapshot>, ClassifiedError> {
    let Some(items) = root
        .as_object()
        .and_then(|object| object.get("data"))
        .and_then(Value::as_object)
        .and_then(|data| data.get("services"))
        .and_then(Value::as_array)
    else {
        return Ok(None);
    };
    if items.is_empty() {
        return Ok(None);
    }
    if items.len() > MAX_SERVICES {
        return Err(parse_error());
    }
    let mut services = Vec::new();
    let mut plan_name = None;
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(raw_type) = bounded_string(object.get("service_type")) else {
            continue;
        };
        if plan_name.is_none()
            && ["pro", "max"]
                .iter()
                .any(|marker| raw_type.to_ascii_lowercase().contains(marker))
        {
            plan_name = Some(raw_type.clone());
        }
        let Some(window_type) = bounded_string(object.get("window_type")) else {
            continue;
        };
        let Some(time_range) = bounded_string(object.get("time_range")) else {
            continue;
        };
        let (Some(usage), Some(limit)) = (
            integer_value(object.get("usage")),
            integer_value(object.get("limit")),
        ) else {
            continue;
        };
        if limit <= 0 {
            continue;
        }
        let percent = finite_value(object.get("percent"))
            .or_else(|| ratio_percent(usage, limit))
            .unwrap_or(0.0)
            .clamp(0.0, 100.0);
        let service_type = normalize_multi_service_type(&raw_type);
        let reset = parse_time_range_reset(&time_range, &window_type, fetched_at);
        let description = reset_description(&window_type, &time_range, reset, fetched_at);
        services.push(ServiceUsage {
            display_name: service_display_name(&service_type),
            service_type,
            window_type,
            usage,
            limit,
            percent,
            unlimited: false,
            resets_at: reset,
            reset_description: description,
        });
    }
    if services.is_empty() {
        return Ok(None);
    }
    Ok(Some(MiniMaxSnapshot {
        plan_name,
        available_prompts: None,
        window_minutes: None,
        used_percent: None,
        resets_at: None,
        services,
        points_balance: None,
        subscription_expires_at: None,
        subscription_renews_at: None,
        billing: None,
    }))
}

fn normalize_multi_service_type(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("text") && lower.contains("generation") {
        "text-generation".to_owned()
    } else if lower.contains("text") && lower.contains("speech") {
        "text-to-speech".to_owned()
    } else if lower.contains("image") {
        "image".to_owned()
    } else {
        lower.replace([' ', '_'], "-")
    }
}

fn parse_time_range_reset(
    time_range: &str,
    window_type: &str,
    fetched_at: Timestamp,
) -> Option<Timestamp> {
    if window_type.trim().eq_ignore_ascii_case("today") {
        let (_, end) = time_range.rsplit_once('-')?;
        let format =
            time::format_description::parse_borrowed::<3>("[year]/[month]/[day] [hour]:[minute]")
                .ok()?;
        let local = PrimitiveDateTime::parse(end.trim(), &format).ok()?;
        let offset = time::UtcOffset::from_hms(8, 0, 0).ok()?;
        return Timestamp::new(local.assume_offset(offset)).ok();
    }
    if window_type.to_ascii_lowercase().contains("hour") {
        let (_, end) = time_range.split_once('-')?;
        let end = end.split('(').next()?.trim();
        let (hour, minute) = end.split_once(':')?;
        let hour = hour.parse::<u8>().ok()?;
        let minute = minute.parse::<u8>().ok()?;
        let offset = time::UtcOffset::from_hms(8, 0, 0).ok()?;
        let now = fetched_at.as_offset_date_time().to_offset(offset);
        let time = Time::from_hms(hour, minute, 0).ok()?;
        let mut candidate = PrimitiveDateTime::new(now.date(), time).assume_offset(offset);
        if candidate.unix_timestamp() < fetched_at.unix_timestamp() {
            candidate = candidate.checked_add(time::Duration::days(1))?;
        }
        return Timestamp::new(candidate).ok();
    }
    None
}

fn parse_usage_html(
    body: &[u8],
    fetched_at: Timestamp,
) -> Result<MiniMaxSnapshot, ClassifiedError> {
    let html = std::str::from_utf8(body).map_err(|_| parse_error())?;
    if html.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    if let Some(next_data) = next_data_json(html)
        && let Ok(root) = parse_bounded_json(next_data.as_bytes())
        && let Some(payload) = find_remains_payload(&root, 0)
    {
        let bytes = serde_json::to_vec(payload).map_err(|_| parse_error())?;
        if let Ok(snapshot) = parse_usage_payload(&bytes, fetched_at) {
            return Ok(snapshot);
        }
    }
    let visible = visible_html_text(html);
    let lower = visible.to_ascii_lowercase();
    if lower.contains("sign in")
        || lower.contains("log in")
        || visible.contains("登录")
        || visible.contains("登入")
    {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let available = parse_available_usage(&visible);
    let used_percent = parse_used_percent(&visible);
    let plan_name = parse_raw_html_plan(html).or_else(|| parse_html_plan(&visible));
    if available.is_none() && used_percent.is_none() && plan_name.is_none() {
        return Err(parse_error());
    }
    let resets_at = parse_html_reset(&visible, fetched_at);
    Ok(MiniMaxSnapshot {
        plan_name,
        available_prompts: available.map(|value| value.0),
        window_minutes: available.map(|value| value.1),
        used_percent,
        resets_at,
        services: Vec::new(),
        points_balance: None,
        subscription_expires_at: None,
        subscription_renews_at: None,
        billing: None,
    })
}

fn next_data_json(html: &str) -> Option<&str> {
    let marker = "id=\"__NEXT_DATA__\"";
    let marker_index = html.find(marker)?;
    let open = html[marker_index + marker.len()..].find('>')? + marker_index + marker.len();
    let start = open + 1;
    let close = html[start..].find("</script>")? + start;
    let value = html[start..close].trim();
    (!value.is_empty()).then_some(value)
}

fn find_remains_payload(value: &Value, depth: usize) -> Option<&Value> {
    if depth > MAX_JSON_DEPTH {
        return None;
    }
    match value {
        Value::Object(object) => {
            if object.contains_key("model_remains") || object.contains_key("modelRemains") {
                return Some(value);
            }
            object
                .values()
                .find_map(|child| find_remains_payload(child, depth + 1))
        }
        Value::Array(array) => array
            .iter()
            .find_map(|child| find_remains_payload(child, depth + 1)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

fn visible_html_text(html: &str) -> String {
    let mut output = String::with_capacity(html.len().min(MAX_RESPONSE_BYTES));
    let bytes = html.as_bytes();
    let mut index = 0;
    let mut skip_tag = false;
    while index < bytes.len() {
        if bytes[index] == b'<' {
            let tail = &html[index..];
            if starts_ascii_case_insensitive(tail, "<script")
                && let Some(close) = find_ascii_case_insensitive(tail, "</script>")
            {
                index += close + "</script>".len();
                output.push(' ');
                continue;
            }
            if starts_ascii_case_insensitive(tail, "<style")
                && let Some(close) = find_ascii_case_insensitive(tail, "</style>")
            {
                index += close + "</style>".len();
                output.push(' ');
                continue;
            }
            if tail.starts_with("<!--")
                && let Some(close) = tail.find("-->")
            {
                index += close + 3;
                output.push(' ');
                continue;
            }
            skip_tag = true;
            index += 1;
            continue;
        }
        if skip_tag {
            if bytes[index] == b'>' {
                skip_tag = false;
                output.push(' ');
            }
            index += 1;
            continue;
        }
        let tail = &html[index..];
        let replacements = [
            ("&nbsp;", " "),
            ("&amp;", "&"),
            ("&lt;", "<"),
            ("&gt;", ">"),
        ];
        if let Some((entity, replacement)) = replacements
            .iter()
            .find(|(entity, _)| tail.starts_with(entity))
        {
            output.push_str(replacement);
            index += entity.len();
            continue;
        }
        let character = tail.chars().next().expect("non-empty tail");
        output.push(character);
        index += character.len_utf8();
    }
    output.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn starts_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn find_ascii_case_insensitive(value: &str, needle: &str) -> Option<usize> {
    value
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn parse_available_usage(text: &str) -> Option<(i64, i64)> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("available usage")?;
    let tail = &text[start + "available usage".len()..];
    let prompts_index = tail.to_ascii_lowercase().find("prompt")?;
    let count_text = tail[..prompts_index]
        .trim_matches(|character: char| {
            character.is_ascii_whitespace() || matches!(character, ':' | ',')
        })
        .replace(',', "");
    let count = count_text
        .split_whitespace()
        .last()?
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)?;
    let after_prompts = &tail[prompts_index..];
    let slash = after_prompts.find('/')?;
    let duration = after_prompts[slash + 1..]
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>();
    if duration.len() != 2 {
        return None;
    }
    let value = duration[0].parse::<f64>().ok()?;
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    let unit = duration[1].to_ascii_lowercase();
    let minutes = if unit.starts_with('d') {
        (value * 1_440.0).round()
    } else if unit.starts_with('h') {
        (value * 60.0).round()
    } else if unit.starts_with('m') {
        value.round()
    } else if unit.starts_with('s') {
        (value / 60.0).round().max(1.0)
    } else {
        return None;
    }
    .to_i64()?;
    (minutes > 0).then_some((count, minutes))
}

fn parse_used_percent(text: &str) -> Option<f64> {
    for token in text.split_ascii_whitespace().collect::<Vec<_>>().windows(2) {
        let first = token[0]
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '%');
        let second = token[1]
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '%');
        if token[0].contains('%') && second.eq_ignore_ascii_case("used") {
            let value = token[0]
                .trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
            if let Ok(value) = value.parse::<f64>()
                && value.is_finite()
                && (0.0..=100.0).contains(&value)
            {
                return Some(value);
            }
        }
        if first.eq_ignore_ascii_case("used") {
            let value = token[1]
                .trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
            if let Ok(value) = value.parse::<f64>()
                && value.is_finite()
                && (0.0..=100.0).contains(&value)
            {
                return Some(value);
            }
        }
    }
    let lower = text.to_ascii_lowercase();
    if let Some(index) = lower.find("used ") {
        let value = text[index + 5..]
            .chars()
            .take_while(|character| character.is_ascii_digit() || *character == '.')
            .collect::<String>();
        return value
            .parse::<f64>()
            .ok()
            .filter(|value| (0.0..=100.0).contains(value));
    }
    None
}

fn parse_html_plan(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let index = lower.find("coding plan")?;
    let tail = text[index + "coding plan".len()..].trim();
    let end = ["available usage", "current usage", "% used", "used "]
        .iter()
        .filter_map(|marker| tail.to_ascii_lowercase().find(marker))
        .min()
        .unwrap_or(tail.len());
    let candidate = tail[..end]
        .trim_matches(|character: char| {
            character.is_ascii_whitespace() || matches!(character, ':' | '-' | '·')
        })
        .split_whitespace()
        .take(6)
        .collect::<Vec<_>>()
        .join(" ");
    let candidate = candidate
        .strip_prefix("Coding Plan ")
        .unwrap_or(&candidate)
        .trim();
    if candidate.is_empty()
        || candidate.len() > MAX_PLAN_BYTES
        || candidate.chars().any(char::is_control)
    {
        None
    } else {
        Some(candidate.to_owned())
    }
}

fn parse_raw_html_plan(html: &str) -> Option<String> {
    ["planName", "plan", "packageName"]
        .into_iter()
        .find_map(|key| raw_json_string_for_key(html, key))
        .and_then(|value| clean_plan_name(&value))
}

fn raw_json_string_for_key(raw: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let mut remainder = raw;
    while let Some(index) = remainder.find(&marker) {
        let tail = remainder[index + marker.len()..].trim_start();
        let Some(tail) = tail.strip_prefix(':').map(str::trim_start) else {
            remainder = &remainder[index + marker.len()..];
            continue;
        };
        if !tail.starts_with('"') {
            remainder = tail;
            continue;
        }
        let mut escaped = false;
        for (offset, character) in tail[1..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == '"' {
                let encoded = &tail[..offset + 2];
                if encoded.len() > MAX_PLAN_BYTES.saturating_mul(6) {
                    return None;
                }
                return serde_json::from_str::<String>(encoded).ok();
            }
        }
        return None;
    }
    None
}

fn clean_plan_name(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_PLAN_BYTES && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn parse_html_reset(text: &str, fetched_at: Timestamp) -> Option<Timestamp> {
    let lower = text.to_ascii_lowercase();
    if let Some(index) = lower.find("resets in ") {
        let tail = &text[index + "resets in ".len()..];
        let mut parts = tail.split_ascii_whitespace();
        let value = parts.next()?.parse::<i64>().ok()?;
        let unit = parts.next()?.to_ascii_lowercase();
        let seconds = if unit.starts_with('d') {
            value.checked_mul(86_400)?
        } else if unit.starts_with('h') {
            value.checked_mul(3_600)?
        } else if unit.starts_with('m') {
            value.checked_mul(60)?
        } else {
            value
        };
        return fetched_at
            .unix_timestamp()
            .checked_add(seconds)
            .and_then(|seconds| Timestamp::from_unix_timestamp(seconds).ok());
    }
    for marker in ["resets at ", "reset at "] {
        let Some(index) = lower.find(marker) else {
            continue;
        };
        let tail = text[index + marker.len()..].trim_start();
        let hour_end = tail.find(':')?;
        let hour = tail[..hour_end].trim().parse::<u8>().ok()?;
        let after_colon = &tail[hour_end + 1..];
        let minute_text = after_colon
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        if minute_text.len() != 2 {
            return None;
        }
        let minute = minute_text.parse::<u8>().ok()?;
        let suffix = after_colon[minute_text.len()..].trim_start();
        let hint = suffix
            .strip_prefix('(')
            .and_then(|value| value.split_once(')'))
            .map(|(value, _)| value.trim());
        let offset = reset_timezone_offset(hint, fetched_at);
        let now = fetched_at.as_offset_date_time().to_offset(offset);
        let time = Time::from_hms(hour, minute, 0).ok()?;
        let mut candidate = PrimitiveDateTime::new(now.date(), time).assume_offset(offset);
        if candidate.unix_timestamp() < fetched_at.unix_timestamp() {
            candidate = candidate.checked_add(time::Duration::days(1))?;
        }
        return Timestamp::new(candidate).ok();
    }
    None
}

fn reset_timezone_offset(hint: Option<&str>, fetched_at: Timestamp) -> UtcOffset {
    let local =
        UtcOffset::local_offset_at(fetched_at.as_offset_date_time()).unwrap_or(UtcOffset::UTC);
    let Some(hint) = hint.map(str::trim).filter(|hint| !hint.is_empty()) else {
        return local;
    };
    let normalized = hint.to_ascii_uppercase().replace(' ', "");
    if matches!(normalized.as_str(), "UTC" | "GMT" | "Z") {
        return UtcOffset::UTC;
    }
    if matches!(normalized.as_str(), "ASIA/SHANGHAI" | "PRC") {
        return UtcOffset::from_hms(8, 0, 0).unwrap_or(local);
    }
    for prefix in ["UTC", "GMT"] {
        let Some(raw) = normalized.strip_prefix(prefix) else {
            continue;
        };
        let (sign, raw) = if let Some(raw) = raw.strip_prefix('+') {
            (1_i8, raw)
        } else if let Some(raw) = raw.strip_prefix('-') {
            (-1_i8, raw)
        } else {
            continue;
        };
        let (hours, minutes) = raw.split_once(':').unwrap_or((raw, "0"));
        if let (Ok(hours), Ok(minutes)) = (hours.parse::<i8>(), minutes.parse::<i8>())
            && let Ok(offset) = UtcOffset::from_hms(sign * hours, sign * minutes, 0)
        {
            return offset;
        }
    }
    local
}

fn first_non_whitespace(bytes: &[u8]) -> Option<u8> {
    bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
}

fn parse_bounded_json(body: &[u8]) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let value = serde_json::from_slice::<Value>(body).map_err(|_| parse_error())?;
    validate_json_tree(&value)?;
    Ok(value)
}

fn validate_json_tree(root: &Value) -> Result<(), ClassifiedError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    let mut string_bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(parse_error)?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(parse_error());
        }
        match value {
            Value::String(value) => {
                if value.len() > MAX_JSON_STRING_BYTES {
                    return Err(parse_error());
                }
                string_bytes = string_bytes
                    .checked_add(value.len())
                    .filter(|total| *total <= MAX_JSON_AGGREGATE_BYTES)
                    .ok_or_else(parse_error)?;
            }
            Value::Array(array) => {
                stack.extend(array.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(object) => {
                for (key, value) in object {
                    if key.len() > MAX_JSON_STRING_BYTES {
                        return Err(parse_error());
                    }
                    string_bytes = string_bytes
                        .checked_add(key.len())
                        .filter(|total| *total <= MAX_JSON_AGGREGATE_BYTES)
                        .ok_or_else(parse_error)?;
                    stack.push((value, depth + 1));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn validate_base_response(root: &Value) -> Result<(), ClassifiedError> {
    let object = root.as_object().ok_or_else(parse_error)?;
    let base = if object.contains_key("status_code") || object.contains_key("statusCode") {
        Some(object)
    } else {
        object
            .get("base_resp")
            .or_else(|| object.get("baseResp"))
            .and_then(Value::as_object)
            .or_else(|| {
                object
                    .get("data")
                    .and_then(Value::as_object)
                    .and_then(|data| data.get("base_resp").or_else(|| data.get("baseResp")))
                    .and_then(Value::as_object)
            })
    };
    let Some(base) = base else { return Ok(()) };
    let status =
        integer_value(base.get("status_code").or_else(|| base.get("statusCode"))).unwrap_or(0);
    if status == 0 {
        return Ok(());
    }
    let message = bounded_string(base.get("status_msg")).unwrap_or_default();
    let lower = message.to_ascii_lowercase();
    if status == 1004
        || lower.contains("cookie")
        || lower.contains("log in")
        || lower.contains("login")
        || lower == "invalid api key"
    {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    Err(api_error())
}

fn validate_billing_base_response(root: &Value) -> Result<(), ClassifiedError> {
    let object = root.as_object().ok_or_else(parse_error)?;
    let Some(base) = object
        .get("base_resp")
        .or_else(|| object.get("baseResp"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let status =
        integer_value(base.get("status_code").or_else(|| base.get("statusCode"))).unwrap_or(0);
    if status == 0 {
        Ok(())
    } else {
        Err(api_error())
    }
}

fn bounded_string(value: Option<&Value>) -> Option<String> {
    let value = value?.as_str()?.trim();
    (!value.is_empty() && value.len() <= MAX_PLAN_BYTES && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn first_non_empty_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| bounded_string(object.get(*key)))
}

fn integer_value(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(value) => value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
            .or_else(|| value.as_f64().and_then(|value| value.trunc().to_i64())),
        Value::String(value) if value.len() <= 64 => value.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn finite_value(value: Option<&Value>) -> Option<f64> {
    let value = match value? {
        Value::Number(value) => value.as_f64(),
        Value::String(value) if value.len() <= 64 => value.trim().parse::<f64>().ok(),
        _ => None,
    }?;
    value.is_finite().then_some(value)
}

fn decimal_value(value: Option<&Value>) -> Option<Decimal> {
    match value? {
        Value::Number(value) => Decimal::from_str(&value.to_string()).ok(),
        Value::String(value) if value.len() <= 128 => Decimal::from_str(value.trim()).ok(),
        _ => None,
    }
}

struct SubscriptionMetadata {
    plan_name: Option<String>,
    expires_at: Option<Timestamp>,
    renews_at: Option<Timestamp>,
}

fn parse_subscription_metadata(body: &[u8]) -> Result<SubscriptionMetadata, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    validate_base_response(&root)?;
    let mut current_strings = Vec::new();
    collect_current_subscription_strings(&root, 0, &mut current_strings)?;
    let mut all_strings = Vec::new();
    collect_strings(&root, 0, &mut all_strings)?;
    let plan_name = best_plan_name(&current_strings).or_else(|| best_plan_name(&all_strings));
    let expires_at = find_date_value(
        &root,
        &[
            "current_subscribe_end_time_ts",
            "current_subscribe_end_time",
        ],
        0,
    );
    let renews_at = find_date_value(&root, &["renewal_trigger_time_ts", "renewal_date"], 0);
    if plan_name.is_none() && expires_at.is_none() && renews_at.is_none() {
        return Err(parse_error());
    }
    Ok(SubscriptionMetadata {
        plan_name,
        expires_at,
        renews_at,
    })
}

fn collect_current_subscription_strings(
    value: &Value,
    depth: usize,
    output: &mut Vec<String>,
) -> Result<(), ClassifiedError> {
    if depth > MAX_JSON_DEPTH || output.len() > 512 {
        return Err(parse_error());
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let lower = key.to_ascii_lowercase();
                if lower == "current_subscribe"
                    || lower == "current_subscription"
                    || lower.contains("current_subscribe")
                    || lower.contains("current_subscription")
                    || lower.contains("current_plan")
                {
                    collect_strings(child, depth + 1, output)?;
                }
                collect_current_subscription_strings(child, depth + 1, output)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_current_subscription_strings(child, depth + 1, output)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn collect_strings(
    value: &Value,
    depth: usize,
    output: &mut Vec<String>,
) -> Result<(), ClassifiedError> {
    if depth > MAX_JSON_DEPTH || output.len() > 512 {
        return Err(parse_error());
    }
    match value {
        Value::String(value)
            if !value.trim().is_empty()
                && value.len() <= MAX_PLAN_BYTES
                && !value.chars().any(char::is_control) =>
        {
            output.push(value.trim().to_owned());
        }
        Value::Object(object) => {
            for child in object.values() {
                collect_strings(child, depth + 1, output)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_strings(child, depth + 1, output)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn best_plan_name(strings: &[String]) -> Option<String> {
    strings
        .iter()
        .filter_map(|value| token_plan_rank(value).map(|rank| (rank, value)))
        .min_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.len().cmp(&right.len()))
        })
        .map(|(_, value)| value.trim().to_owned())
        .or_else(|| {
            strings.iter().find_map(|value| {
                ["plus", "max", "ultra"]
                    .contains(&value.trim().to_ascii_lowercase().as_str())
                    .then(|| value.trim().to_owned())
            })
        })
}

fn token_plan_rank(value: &str) -> Option<u8> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("tokenplanplus") {
        Some(0)
    } else if lower.contains("tokenplanmax") {
        Some(1)
    } else if lower.contains("tokenplanultra") {
        Some(2)
    } else if lower.contains("token plan")
        && ["plus", "max", "ultra"]
            .iter()
            .any(|marker| lower.contains(marker))
    {
        Some(3)
    } else {
        None
    }
}

fn find_date_value(value: &Value, keys: &[&str], depth: usize) -> Option<Timestamp> {
    if depth > MAX_JSON_DEPTH {
        return None;
    }
    match value {
        Value::Object(object) => {
            for key in keys {
                if let Some(timestamp) = object.get(*key).and_then(parse_subscription_date) {
                    return Some(timestamp);
                }
            }
            object
                .values()
                .find_map(|child| find_date_value(child, keys, depth + 1))
        }
        Value::Array(array) => array
            .iter()
            .find_map(|child| find_date_value(child, keys, depth + 1)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

fn parse_subscription_date(value: &Value) -> Option<Timestamp> {
    if let Some(number) = finite_value(Some(value)) {
        if number <= 0.0 {
            return None;
        }
        let seconds = if number > 10_000_000_000.0 {
            number / 1_000.0
        } else {
            number
        };
        return Timestamp::from_unix_timestamp(seconds.trunc().to_i64()?).ok();
    }
    let raw = value.as_str()?.trim();
    let format = time::format_description::parse_borrowed::<3>("[month]/[day]/[year]").ok()?;
    let date = Date::parse(raw, &format).ok()?;
    let offset = time::UtcOffset::from_hms(8, 0, 0).ok()?;
    Timestamp::new(PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_offset(offset)).ok()
}

struct BillingPage {
    records: Vec<BillingRecord>,
    total_count: Option<usize>,
}

struct BillingRecord {
    day: Option<Date>,
    tokens: u64,
    cash: Option<Decimal>,
    method: Option<String>,
    model: Option<String>,
    successful: bool,
}

impl BillingRecord {
    const fn day(&self) -> Option<Date> {
        self.day
    }
}

#[derive(Default, Clone)]
struct BillingAccumulator {
    tokens: u64,
    cash: Decimal,
    has_cash: bool,
    models: BTreeMap<String, BillingBreakdown>,
}

#[derive(Default, Clone)]
struct BillingBreakdown {
    tokens: u64,
    cash: Decimal,
    has_cash: bool,
}

struct BillingDay {
    day: Date,
    tokens: u64,
    cash: Option<Decimal>,
    models: BTreeMap<String, BillingBreakdown>,
}

struct NamedBillingBreakdown {
    name: String,
    tokens: u64,
}

struct BillingSummary {
    today_tokens: u64,
    last_30_days_tokens: u64,
    today_cash: Option<Decimal>,
    last_30_days_cash: Option<Decimal>,
    daily: Vec<BillingDay>,
    top_methods: Vec<NamedBillingBreakdown>,
    top_models: Vec<NamedBillingBreakdown>,
    coverage_established: bool,
}

impl BillingSummary {
    fn detail_section(&self) -> Result<DetailSection, ClassifiedError> {
        let mut rows = vec![
            DetailRow::new(
                "Today tokens",
                format_integer(i64::try_from(self.today_tokens).map_err(|_| parse_error())?),
                None,
                DetailSensitivity::Public,
            )
            .map_err(|_| parse_error())?,
            DetailRow::new(
                "30d tokens",
                format_integer(i64::try_from(self.last_30_days_tokens).map_err(|_| parse_error())?),
                None,
                DetailSensitivity::Public,
            )
            .map_err(|_| parse_error())?,
            DetailRow::new(
                "Today cash",
                self.today_cash
                    .map_or_else(|| "—".to_owned(), |value| format!("{value:.2}")),
                None,
                DetailSensitivity::Public,
            )
            .map_err(|_| parse_error())?,
            DetailRow::new(
                "Models",
                self.top_models.len().to_string(),
                None,
                DetailSensitivity::Public,
            )
            .map_err(|_| parse_error())?,
        ];
        if let Some(model) = self.top_models.first() {
            rows.push(
                DetailRow::new(
                    "Top model",
                    model.name.clone(),
                    None,
                    DetailSensitivity::Public,
                )
                .map_err(|_| parse_error())?,
            );
        }
        if let Some(method) = self.top_methods.first() {
            rows.push(
                DetailRow::new(
                    "Top method",
                    method.name.clone(),
                    None,
                    DetailSensitivity::Public,
                )
                .map_err(|_| parse_error())?,
            );
        }
        if let Some(cash) = self.last_30_days_cash {
            rows.push(
                DetailRow::new(
                    "30d cash",
                    format!("{cash:.2}"),
                    None,
                    DetailSensitivity::Public,
                )
                .map_err(|_| parse_error())?,
            );
        }
        let points = self
            .daily
            .iter()
            .map(|day| {
                DetailChartPoint::new(
                    format_date(day.day),
                    FiniteNumber::new(day.tokens.to_f64().ok_or_else(parse_error)?)
                        .map_err(|_| parse_error())?,
                )
                .map_err(|_| parse_error())
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;
        let chart = if points.is_empty() {
            None
        } else {
            Some(
                DetailChart::new(
                    DetailChartKind::Bars,
                    Some("Daily tokens".to_owned()),
                    Some("tokens".to_owned()),
                    points,
                )
                .map_err(|_| parse_error())?,
            )
        };
        DetailSection::new(Some("Billing history".to_owned()), rows, chart)
            .map_err(|_| parse_error())
    }

    fn cost_usage(&self, fetched_at: Timestamp) -> Result<CostUsageSnapshot, ClassifiedError> {
        let daily = self
            .daily
            .iter()
            .map(|day| {
                let models = day
                    .models
                    .iter()
                    .map(|(name, aggregate)| {
                        CostUsageModelBreakdown::new(
                            name,
                            billing_metrics(
                                aggregate.tokens,
                                aggregate.has_cash.then_some(aggregate.cash),
                            )?,
                            None,
                            None,
                            None,
                            None,
                        )
                        .map_err(|_| parse_error())
                    })
                    .collect::<Result<Vec<_>, ClassifiedError>>()?;
                CostUsageDailyBucket::new(
                    format_date(day.day),
                    None,
                    billing_metrics(day.tokens, day.cash)?,
                    day.models.keys().cloned().collect(),
                    models,
                    Vec::new(),
                )
                .map_err(|_| parse_error())
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;
        let session = billing_metrics(self.today_tokens, self.today_cash)?;
        let history = billing_metrics(self.last_30_days_tokens, self.last_30_days_cash)?;
        CostUsageSnapshot::new(
            CostUnit::provider("Cash").map_err(|_| parse_error())?,
            session,
            history,
            self.last_30_days_cash.map(ExactDecimal::new),
            30,
            self.coverage_established,
            Some("Last 30 days (local)".to_owned()),
            None,
            daily,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            fetched_at,
            CostProvenance::VendorMetered,
        )
        .map_err(|_| parse_error())
    }
}

fn billing_metrics(
    tokens: u64,
    cash: Option<Decimal>,
) -> Result<CostUsageMetrics, ClassifiedError> {
    CostUsageMetrics::new(
        CostUsageTokenMix::default(),
        Some(tokens),
        None,
        cash.map(ExactDecimal::new),
        CostUsageCoverage::default(),
    )
    .map_err(|_| parse_error())
}

fn parse_billing_page(
    body: &[u8],
    fixed_local_offset: Option<UtcOffset>,
) -> Result<BillingPage, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    validate_billing_base_response(&root)?;
    let object = root.as_object().ok_or_else(parse_error)?;
    let total_count =
        integer_value(object.get("total_cnt")).and_then(|value| usize::try_from(value).ok());
    let records = object
        .get("charge_records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if records.len() > BILLING_PAGE_LIMIT {
        return Err(parse_error());
    }
    let records = records
        .iter()
        .map(|record| parse_billing_record(record, fixed_local_offset))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BillingPage {
        records,
        total_count,
    })
}

fn parse_billing_record(
    value: &Value,
    fixed_local_offset: Option<UtcOffset>,
) -> Result<BillingRecord, ClassifiedError> {
    let object = value.as_object().ok_or_else(parse_error)?;
    let direct_tokens = integer_value(object.get("consume_token"))
        .unwrap_or(0)
        .max(0);
    let tokens = if direct_tokens > 0 {
        direct_tokens
    } else {
        integer_value(object.get("consume_input_token"))
            .unwrap_or(0)
            .max(0)
            .checked_add(
                integer_value(object.get("consume_output_token"))
                    .unwrap_or(0)
                    .max(0),
            )
            .ok_or_else(parse_error)?
    };
    let cash = decimal_value(object.get("consume_cash_after_voucher"))
        .or_else(|| decimal_value(object.get("consume_cash")));
    if cash.is_some_and(|value| value < Decimal::ZERO) {
        return Err(parse_error());
    }
    let result = scalar_text(object.get("result")).or_else(|| scalar_text(object.get("status")));
    let successful = result
        .as_deref()
        .is_none_or(|value| value.trim().eq_ignore_ascii_case("SUCCESS"));
    let day = parse_record_day(object, fixed_local_offset);
    let method = bounded_string(object.get("method"));
    let model = bounded_string(object.get("model"));
    Ok(BillingRecord {
        day,
        tokens: u64::try_from(tokens).map_err(|_| parse_error())?,
        cash,
        method,
        model,
        successful,
    })
}

fn scalar_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) if value.len() <= 128 => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) | Value::String(_) => None,
    }
}

fn parse_record_day(
    object: &Map<String, Value>,
    fixed_local_offset: Option<UtcOffset>,
) -> Option<Date> {
    if let Some(created) = integer_value(object.get("created_at")) {
        let seconds = if created > 1_000_000_000_000 {
            created / 1_000
        } else {
            created
        };
        return OffsetDateTime::from_unix_timestamp(seconds)
            .ok()
            .map(|instant| local_calendar_day(instant, fixed_local_offset));
    }
    if let Some(ymd) = bounded_string(object.get("ymd")) {
        for pattern in [
            "[year]-[month]-[day]",
            "[year][month][day]",
            "[year]/[month]/[day]",
        ] {
            let format = time::format_description::parse_borrowed::<3>(pattern).ok()?;
            if let Ok(day) = Date::parse(&ymd, &format) {
                return Some(day);
            }
        }
    }
    let consume_time = bounded_string(object.get("consume_time"))?;
    for pattern in [
        "[year]-[month]-[day] [hour]:[minute]:[second]",
        "[year]/[month]/[day] [hour]:[minute]:[second]",
    ] {
        let format = time::format_description::parse_borrowed::<3>(pattern).ok()?;
        if let Ok(timestamp) = PrimitiveDateTime::parse(&consume_time, &format) {
            return Some(local_calendar_day(
                timestamp.assume_utc(),
                fixed_local_offset,
            ));
        }
    }
    Timestamp::parse(&consume_time)
        .ok()
        .map(|timestamp| local_calendar_day(timestamp.as_offset_date_time(), fixed_local_offset))
}

fn aggregate_billing(
    records: Vec<BillingRecord>,
    fetched_at: Timestamp,
    coverage_established: bool,
    fixed_local_offset: Option<UtcOffset>,
) -> Result<BillingSummary, ClassifiedError> {
    let today = local_calendar_day(fetched_at.as_offset_date_time(), fixed_local_offset);
    let cutoff = cutoff_day(fetched_at, fixed_local_offset);
    let mut daily = BTreeMap::<Date, BillingAccumulator>::new();
    let mut methods = BTreeMap::<String, BillingBreakdown>::new();
    let mut models = BTreeMap::<String, BillingBreakdown>::new();
    for record in records {
        if !record.successful {
            continue;
        }
        let Some(day) = record.day.filter(|day| *day >= cutoff && *day <= today) else {
            continue;
        };
        let bucket = daily.entry(day).or_default();
        add_billing_values(bucket, record.tokens, record.cash)?;
        if let Some(model) = &record.model {
            add_breakdown(&mut bucket.models, model, record.tokens, record.cash)?;
            add_breakdown(&mut models, model, record.tokens, record.cash)?;
        }
        if let Some(method) = &record.method {
            add_breakdown(&mut methods, method, record.tokens, record.cash)?;
        }
    }
    let today_bucket = daily.get(&today);
    let today_tokens = today_bucket.map_or(0, |bucket| bucket.tokens);
    let today_cash = today_bucket.and_then(|bucket| bucket.has_cash.then_some(bucket.cash));
    let last_30_days_tokens = daily.values().try_fold(0_u64, |total, bucket| {
        total.checked_add(bucket.tokens).ok_or_else(parse_error)
    })?;
    let mut last_cash = Decimal::ZERO;
    let mut has_cash = false;
    for bucket in daily.values() {
        if bucket.has_cash {
            last_cash = last_cash.checked_add(bucket.cash).ok_or_else(parse_error)?;
            has_cash = true;
        }
    }
    let daily = daily
        .into_iter()
        .map(|(day, bucket)| BillingDay {
            day,
            tokens: bucket.tokens,
            cash: bucket.has_cash.then_some(bucket.cash),
            models: bucket.models,
        })
        .collect();
    Ok(BillingSummary {
        today_tokens,
        last_30_days_tokens,
        today_cash,
        last_30_days_cash: has_cash.then_some(last_cash),
        daily,
        top_methods: top_breakdowns(methods),
        top_models: top_breakdowns(models),
        coverage_established,
    })
}

fn add_billing_values(
    bucket: &mut BillingAccumulator,
    tokens: u64,
    cash: Option<Decimal>,
) -> Result<(), ClassifiedError> {
    bucket.tokens = bucket.tokens.checked_add(tokens).ok_or_else(parse_error)?;
    if let Some(cash) = cash {
        bucket.cash = bucket.cash.checked_add(cash).ok_or_else(parse_error)?;
        bucket.has_cash = true;
    }
    Ok(())
}

fn add_breakdown(
    output: &mut BTreeMap<String, BillingBreakdown>,
    name: &str,
    tokens: u64,
    cash: Option<Decimal>,
) -> Result<(), ClassifiedError> {
    if name.is_empty() || name.len() > MAX_SERVICE_TEXT_BYTES || name.chars().any(char::is_control)
    {
        return Err(parse_error());
    }
    let bucket = output.entry(name.to_owned()).or_default();
    bucket.tokens = bucket.tokens.checked_add(tokens).ok_or_else(parse_error)?;
    if let Some(cash) = cash {
        bucket.cash = bucket.cash.checked_add(cash).ok_or_else(parse_error)?;
        bucket.has_cash = true;
    }
    Ok(())
}

fn top_breakdowns(values: BTreeMap<String, BillingBreakdown>) -> Vec<NamedBillingBreakdown> {
    let mut values = values
        .into_iter()
        .map(|(name, value)| NamedBillingBreakdown {
            name,
            tokens: value.tokens,
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right.tokens.cmp(&left.tokens).then_with(|| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
        })
    });
    values.truncate(3);
    values
}

fn cutoff_day(fetched_at: Timestamp, fixed_local_offset: Option<UtcOffset>) -> Date {
    local_calendar_day(fetched_at.as_offset_date_time(), fixed_local_offset)
        .checked_sub(time::Duration::days(29))
        .unwrap_or(Date::MIN)
}

fn local_calendar_day(instant: OffsetDateTime, fixed_local_offset: Option<UtcOffset>) -> Date {
    let offset = fixed_local_offset
        .unwrap_or_else(|| UtcOffset::local_offset_at(instant).unwrap_or(UtcOffset::UTC));
    instant.to_offset(offset).date()
}

fn format_date(day: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        day.year(),
        u8::from(day.month()),
        day.day()
    )
}

fn origin_url(url: &Url) -> Url {
    let mut origin = url.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
