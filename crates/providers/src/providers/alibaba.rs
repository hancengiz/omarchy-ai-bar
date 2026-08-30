//! Native Alibaba Coding Plan quota adapter.

use std::collections::BTreeMap;
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
use crate::cookie::{CookieHeaderNormalizer, CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
    TransportError,
};

const INTERNATIONAL_GATEWAY: &str = "https://modelstudio.console.alibabacloud.com";
const INTERNATIONAL_RPC: &str = "https://bailian-singapore-cs.alibabacloud.com";
const CHINA_GATEWAY: &str = "https://bailian.console.aliyun.com";
const CHINA_RPC: &str = "https://bailian-cs.console.aliyun.com";
const QUOTA_PATH: &str = "/data/api.json";
const USER_INFO_PATH: &str = "/tool/user/info.json";
const QUOTA_API: &str = "zeldaEasy.broadscope-bailian.codingPlan.queryCodingPlanInstanceInfoV2";
const API_PRODUCT: &str = "broadscope-bailian";
const CONSOLE_PRODUCT: &str = "sfm_bailian";
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
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_SEC_TOKEN_BYTES: usize = 8 * 1024;
const MAX_PLAN_NAME_BYTES: usize = 256;
const AUTH_TICKET_COOKIE: &str = "login_aliyunid_ticket";
const AUTH_ACCOUNT_COOKIES: [&str; 3] = ["login_aliyunid_pk", "login_current_pk", "login_aliyunid"];
const API_KEY_NAMES: [&str; 3] = [
    "ALIBABA_CODING_PLAN_API_KEY",
    "ALIBABA_QWEN_API_KEY",
    "DASHSCOPE_API_KEY",
];
const INTERNATIONAL_CAPTURE_HOSTS: [&str; 2] = [
    "modelstudio.console.alibabacloud.com",
    "bailian-singapore-cs.alibabacloud.com",
];
const CHINA_CAPTURE_HOSTS: [&str; 2] = [
    "bailian.console.aliyun.com",
    "bailian-cs.console.aliyun.com",
];

static TRACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Fixed Alibaba Coding Plan gateway selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlibabaRegion {
    /// International Model Studio, routed through `ap-southeast-1`.
    International,
    /// China mainland Bailian, routed through `cn-beijing`.
    ChinaMainland,
}

impl AlibabaRegion {
    const fn region_id(self) -> &'static str {
        match self {
            Self::International => "ap-southeast-1",
            Self::ChinaMainland => "cn-beijing",
        }
    }

    const fn commodity_code(self) -> &'static str {
        match self {
            Self::International => "sfm_codingplan_public_intl",
            Self::ChinaMainland => "sfm_codingplan_public_cn",
        }
    }

    const fn console_action(self) -> &'static str {
        match self {
            Self::International => "IntlBroadScopeAspnGateway",
            Self::ChinaMainland => "BroadScopeAspnGateway",
        }
    }

    const fn gateway_origin(self) -> &'static str {
        match self {
            Self::International => INTERNATIONAL_GATEWAY,
            Self::ChinaMainland => CHINA_GATEWAY,
        }
    }

    const fn dashboard_path(self) -> &'static str {
        match self {
            Self::International => "/ap-southeast-1/",
            Self::ChinaMainland => "/cn-beijing/",
        }
    }

    const fn dashboard_tab(self) -> &'static str {
        match self {
            Self::International => "coding-plan",
            Self::ChinaMainland => "model",
        }
    }

    const fn console_domain(self) -> &'static str {
        match self {
            Self::International => "modelstudio.console.alibabacloud.com",
            Self::ChinaMainland => "bailian.console.aliyun.com",
        }
    }

    const fn console_site(self) -> &'static str {
        match self {
            Self::International => "MODELSTUDIO_ALIBABACLOUD",
            Self::ChinaMainland => "BAILIAN_ALIYUN",
        }
    }

    fn dashboard_reference(self) -> String {
        format!(
            "{}{path}?tab={tab}#/efm/coding_plan",
            self.gateway_origin(),
            path = self.dashboard_path(),
            tab = self.dashboard_tab()
        )
    }

    fn console_referer(self) -> String {
        format!(
            "{}{path}?tab={tab}",
            self.gateway_origin(),
            path = self.dashboard_path(),
            tab = self.dashboard_tab()
        )
    }
}

struct RegionRoutes {
    api_quota: Url,
    dashboard: Url,
    user_info: Url,
    console_rpc: Url,
}

/// Complete fixed routing table for both Alibaba regions.
///
/// Production construction pins all four known Alibaba origins. The loopback
/// constructor exists only as an injected, typed HTTP-test seam.
pub struct AlibabaRouteSet {
    international: RegionRoutes,
    china: RegionRoutes,
    class: EndpointClass,
}

impl AlibabaRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origins(
            Url::parse(INTERNATIONAL_GATEWAY).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            Url::parse(INTERNATIONAL_RPC).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            Url::parse(CHINA_GATEWAY).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            Url::parse(CHINA_RPC).map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates an exact loopback route table for isolated HTTP tests.
    ///
    /// # Errors
    ///
    /// Rejects non-origin, credential-bearing, or non-loopback URLs.
    #[doc(hidden)]
    pub fn loopback(
        international_gateway: Url,
        international_rpc: Url,
        china_gateway: Url,
        china_rpc: Url,
    ) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            international_gateway,
            international_rpc,
            china_gateway,
            china_rpc,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        international_gateway: Url,
        international_rpc: Url,
        china_gateway: Url,
        china_rpc: Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        for origin in [
            &international_gateway,
            &international_rpc,
            &china_gateway,
            &china_rpc,
        ] {
            validate_bare_origin(origin, class)?;
        }
        if class == EndpointClass::PublicHttps
            && (!same_origin(&international_gateway, INTERNATIONAL_GATEWAY)?
                || !same_origin(&international_rpc, INTERNATIONAL_RPC)?
                || !same_origin(&china_gateway, CHINA_GATEWAY)?
                || !same_origin(&china_rpc, CHINA_RPC)?)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        if !matches!(
            class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            international: build_region_routes(
                AlibabaRegion::International,
                international_gateway,
                international_rpc,
            ),
            china: build_region_routes(AlibabaRegion::ChinaMainland, china_gateway, china_rpc),
            class,
        })
    }

    const fn region(&self, region: AlibabaRegion) -> &RegionRoutes {
        match region {
            AlibabaRegion::International => &self.international,
            AlibabaRegion::ChinaMainland => &self.china,
        }
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        let origins = [
            self.international.api_quota.origin().ascii_serialization(),
            self.international
                .console_rpc
                .origin()
                .ascii_serialization(),
            self.china.api_quota.origin().ascii_serialization(),
            self.china.console_rpc.origin().ascii_serialization(),
        ];
        EndpointPolicy::new(origins.map(|origin| (origin, self.class)))
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

impl Debug for AlibabaRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlibabaRouteSet")
            .field("international", &"<redacted>")
            .field("china", &"<redacted>")
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

fn build_region_routes(region: AlibabaRegion, gateway: Url, rpc: Url) -> RegionRoutes {
    let mut api_quota = gateway.clone();
    api_quota.set_path(QUOTA_PATH);
    api_quota.query_pairs_mut().clear().extend_pairs([
        ("action", QUOTA_API),
        ("product", API_PRODUCT),
        ("api", "queryCodingPlanInstanceInfoV2"),
        ("currentRegionId", region.region_id()),
    ]);

    let mut dashboard = gateway.clone();
    dashboard.set_path(region.dashboard_path());
    dashboard
        .query_pairs_mut()
        .clear()
        .append_pair("tab", region.dashboard_tab());

    let mut user_info = gateway;
    user_info.set_path(USER_INFO_PATH);

    let mut console_rpc = rpc;
    console_rpc.set_path(QUOTA_PATH);
    console_rpc.query_pairs_mut().clear().extend_pairs([
        ("action", region.console_action()),
        ("product", CONSOLE_PRODUCT),
        ("api", QUOTA_API),
        ("_v", "undefined"),
    ]);
    RegionRoutes {
        api_quota,
        dashboard,
        user_info,
        console_rpc,
    }
}

/// Bounded, zeroizing Alibaba API credential with a fully redacted debug view.
pub struct AlibabaApiCredential {
    value: Zeroizing<String>,
}

impl AlibabaApiCredential {
    /// Validates one selected Alibaba API key.
    ///
    /// # Errors
    ///
    /// Returns missing-credential for empty, oversized, or control-bearing input.
    pub fn new(raw: &str) -> Result<Self, ClassifiedError> {
        let value =
            clean_secret(raw).ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Ok(Self { value })
    }

    fn expose(&self) -> &str {
        self.value.as_str()
    }
}

impl Debug for AlibabaApiCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AlibabaApiCredential(<redacted>)")
    }
}

fn clean_secret(raw: &str) -> Option<Zeroizing<String>> {
    let mut value = raw.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value = value[1..value.len() - 1].trim();
    }
    if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.chars().any(char::is_control) {
        return None;
    }
    Some(Zeroizing::new(value.to_owned()))
}

/// Resolves Alibaba's three pinned API-key environment aliases in precedence order.
///
/// # Errors
///
/// Returns missing-credential when no bounded value is available.
pub fn resolve_api_key(
    environment: &BTreeMap<String, String>,
) -> Result<AlibabaApiCredential, ClassifiedError> {
    for name in API_KEY_NAMES {
        if let Some(value) = environment.get(name).and_then(|value| clean_secret(value)) {
            return Ok(AlibabaApiCredential { value });
        }
    }
    Err(ClassifiedError::new(ErrorKind::MissingCredential))
}

struct RoutedCookieHeaders {
    dashboard: Option<Zeroizing<String>>,
    user_info: Option<Zeroizing<String>>,
    console_rpc: Option<Zeroizing<String>>,
}

impl RoutedCookieHeaders {
    fn manual(value: &str) -> Self {
        Self {
            dashboard: Some(Zeroizing::new(value.to_owned())),
            user_info: Some(Zeroizing::new(value.to_owned())),
            console_rpc: Some(Zeroizing::new(value.to_owned())),
        }
    }

    fn from_jar(
        routes: &RegionRoutes,
        policy: CookieUrlPolicy,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Ok(Self {
            dashboard: cookie_for(jar, &routes.dashboard, policy, now)?,
            user_info: cookie_for(jar, &routes.user_info, policy, now)?,
            console_rpc: cookie_for(jar, &routes.console_rpc, policy, now)?,
        })
    }

    fn is_authenticated(&self) -> bool {
        let headers = [
            self.dashboard.as_deref(),
            self.user_info.as_deref(),
            self.console_rpc.as_deref(),
        ];
        let has_ticket = headers
            .iter()
            .flatten()
            .any(|header| extract_cookie_value(AUTH_TICKET_COOKIE, header).is_some());
        let has_account = headers.iter().flatten().any(|header| {
            AUTH_ACCOUNT_COOKIES
                .iter()
                .any(|name| extract_cookie_value(name, header).is_some())
        });
        has_ticket && has_account
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
    jar.header_for(&target, now)
        .map(|header| header.map(|value| Zeroizing::new(value.expose().to_owned())))
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

struct BrowserCookieRoutes {
    international: RoutedCookieHeaders,
    china: RoutedCookieHeaders,
}

impl BrowserCookieRoutes {
    const fn region(&self, region: AlibabaRegion) -> &RoutedCookieHeaders {
        match region {
            AlibabaRegion::International => &self.international,
            AlibabaRegion::ChinaMainland => &self.china,
        }
    }
}

enum Backend {
    ApiKey(AlibabaApiCredential),
    ManualCookie(Zeroizing<String>),
    BrowserSession(BrowserCookieRoutes),
}

/// Native Alibaba Coding Plan adapter bound to one account, source, and region.
pub struct AlibabaProvider {
    scope: AccountScope,
    region: AlibabaRegion,
    routes: AlibabaRouteSet,
    backend: Backend,
    transport: HttpTransport,
}

impl AlibabaProvider {
    /// Creates the production API-key adapter.
    ///
    /// # Errors
    ///
    /// Rejects missing credentials, another provider scope, or invalid fixed routing.
    pub fn new_api_key(
        scope: AccountScope,
        region: AlibabaRegion,
        api_key: &str,
    ) -> Result<Self, ClassifiedError> {
        Self::from_api_key_routes(scope, region, api_key, AlibabaRouteSet::production()?)
    }

    /// Creates an API-key adapter with an injected typed route table.
    ///
    /// # Errors
    ///
    /// Rejects missing credentials, another provider scope, or invalid routing.
    #[doc(hidden)]
    pub fn from_api_key_routes(
        scope: AccountScope,
        region: AlibabaRegion,
        api_key: &str,
        routes: AlibabaRouteSet,
    ) -> Result<Self, ClassifiedError> {
        Self::build(
            scope,
            region,
            routes,
            Backend::ApiKey(AlibabaApiCredential::new(api_key)?),
        )
    }

    /// Creates an injected-route adapter from the pinned environment-key precedence.
    ///
    /// # Errors
    ///
    /// Returns missing-credential when none of the three aliases is usable.
    #[doc(hidden)]
    pub fn from_api_environment_routes(
        scope: AccountScope,
        region: AlibabaRegion,
        environment: &BTreeMap<String, String>,
        routes: AlibabaRouteSet,
    ) -> Result<Self, ClassifiedError> {
        Self::build(
            scope,
            region,
            routes,
            Backend::ApiKey(resolve_api_key(environment)?),
        )
    }

    /// Creates the production manual-cookie adapter from a raw cookie/header/cURL capture.
    ///
    /// # Errors
    ///
    /// Returns stable missing, parse, or configuration failures.
    pub fn new_manual(
        scope: AccountScope,
        region: AlibabaRegion,
        raw: &str,
    ) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, region, raw, AlibabaRouteSet::production()?)
    }

    /// Creates a manual adapter with injected transport routes. Captured URLs
    /// remain restricted to the selected production regional allowlist.
    ///
    /// # Errors
    ///
    /// Returns stable missing, parse, or configuration failures.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        region: AlibabaRegion,
        raw: &str,
        routes: AlibabaRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let hosts: &[&str] = match region {
            AlibabaRegion::International => &[
                INTERNATIONAL_CAPTURE_HOSTS[0],
                INTERNATIONAL_CAPTURE_HOSTS[1],
                CHINA_CAPTURE_HOSTS[0],
                CHINA_CAPTURE_HOSTS[1],
            ],
            AlibabaRegion::ChinaMainland => &CHINA_CAPTURE_HOSTS,
        };
        let policy = ManualCapturePolicy::new(hosts.iter().copied(), [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let cookie = normalize_manual_cookie(cookie)?;
        Self::build(scope, region, routes, Backend::ManualCookie(cookie))
    }

    /// Creates the production browser-session adapter from an already imported jar.
    ///
    /// Cookie headers are derived independently for every exact dashboard,
    /// user-info, and RPC target at the injected instant.
    ///
    /// # Errors
    ///
    /// Returns stable missing/expired/configuration failures.
    pub fn new_browser(
        scope: AccountScope,
        region: AlibabaRegion,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jar_routes(scope, region, jar, now, AlibabaRouteSet::production()?)
    }

    /// Creates a browser-session adapter using an injected typed route table.
    ///
    /// # Errors
    ///
    /// Returns stable missing/expired/configuration failures.
    #[doc(hidden)]
    pub fn from_browser_jar_routes(
        scope: AccountScope,
        region: AlibabaRegion,
        jar: &CookieJar,
        now: OffsetDateTime,
        routes: AlibabaRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = routes.cookie_policy();
        let cookies = BrowserCookieRoutes {
            international: RoutedCookieHeaders::from_jar(
                routes.region(AlibabaRegion::International),
                policy,
                jar,
                now,
            )?,
            china: RoutedCookieHeaders::from_jar(
                routes.region(AlibabaRegion::ChinaMainland),
                policy,
                jar,
                now,
            )?,
        };
        let has_relevant = match region {
            AlibabaRegion::International => {
                cookies.international.is_authenticated() || cookies.china.is_authenticated()
            }
            AlibabaRegion::ChinaMainland => cookies.china.is_authenticated(),
        };
        if !has_relevant {
            return Err(ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        }
        Self::build(scope, region, routes, Backend::BrowserSession(cookies))
    }

    fn build(
        scope: AccountScope,
        region: AlibabaRegion,
        routes: AlibabaRouteSet,
        backend: Backend,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Alibaba {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let policy = routes.endpoint_policy()?;
        for selected in [AlibabaRegion::International, AlibabaRegion::ChinaMainland] {
            let route = routes.region(selected);
            for endpoint in [
                &route.api_quota,
                &route.dashboard,
                &route.user_info,
                &route.console_rpc,
            ] {
                policy
                    .validate(endpoint)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
            }
        }
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            region,
            routes,
            backend,
            transport,
        })
    }

    /// Source to which this provider is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        match self.backend {
            Backend::ApiKey(_) => ProviderSource::ApiKey,
            Backend::ManualCookie(_) => ProviderSource::ManualCookie,
            Backend::BrowserSession(_) => ProviderSource::BrowserSession,
        }
    }

    /// Configured primary region.
    #[must_use]
    pub const fn region(&self) -> AlibabaRegion {
        self.region
    }

    /// Fetches one sample at an injected wall-clock instant.
    ///
    /// International routing retries China mainland once only for the exact
    /// credential/host/missing-quota classes preserved from the baseline.
    ///
    /// # Errors
    ///
    /// Returns stable account, credential, network, API, or parse failures.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source() {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let first = self.fetch_region(context, fetched_at, self.region).await;
        match first {
            Ok(sample) => Ok(sample),
            Err(failure)
                if self.region == AlibabaRegion::International && failure.retry_alternate =>
            {
                self.fetch_region(context, fetched_at, AlibabaRegion::ChinaMainland)
                    .await
                    .map_err(|failure| failure.error)
            }
            Err(failure) => Err(failure.error),
        }
    }

    async fn fetch_region(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        region: AlibabaRegion,
    ) -> Result<UsageSample, RegionalFailure> {
        match &self.backend {
            Backend::ApiKey(credential) => {
                self.fetch_api_region(context, fetched_at, region, credential)
                    .await
            }
            Backend::ManualCookie(cookie) => {
                let headers = RoutedCookieHeaders::manual(cookie.as_str());
                self.fetch_web_region(context, fetched_at, region, &headers)
                    .await
            }
            Backend::BrowserSession(cookies) => {
                self.fetch_web_region(context, fetched_at, region, cookies.region(region))
                    .await
            }
        }
    }

    async fn fetch_api_region(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        region: AlibabaRegion,
        credential: &AlibabaApiCredential,
    ) -> Result<UsageSample, RegionalFailure> {
        let routes = self.routes.region(region);
        let body = serde_json::to_vec(&json!({
            "queryCodingPlanInstanceInfoRequest": {
                "commodityCode": region.commodity_code(),
            }
        }))
        .map_err(|_| RegionalFailure::new(ErrorKind::Api, false))?;
        let request = HttpRequest::post_json(routes.api_quota.clone(), body)
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .public_header("user-agent", BROWSER_USER_AGENT)
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .public_header("origin", region.gateway_origin())
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .public_header("referer", region.dashboard_reference())
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .sensitive_header("x-api-key", credential.expose().to_owned())
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .sensitive_header("x-dashscope-api-key", credential.expose().to_owned())
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .authentication(
                Authentication::bearer(credential.expose().to_owned())
                    .map_err(|error| RegionalFailure::from_transport(error, false))?,
            );
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(RegionalFailure::from_completed_transport)?;
        if response.status() != 200 {
            return Err(RegionalFailure::new(ErrorKind::Api, false));
        }
        parse_and_normalize(
            context.scope().clone(),
            fetched_at,
            response.body(),
            AuthMode::ApiKey,
            "api",
        )
    }

    async fn fetch_web_region(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        region: AlibabaRegion,
        cookies: &RoutedCookieHeaders,
    ) -> Result<UsageSample, RegionalFailure> {
        let rpc_cookie = cookies
            .console_rpc
            .as_ref()
            .ok_or_else(|| RegionalFailure::new(ErrorKind::AuthenticationExpired, true))?;
        let sec_token = self
            .resolve_sec_token(context, region, cookies, rpc_cookie)
            .await?;
        let anonymous_id = extract_cookie_value("cna", rpc_cookie.as_str());
        let body = console_request_body(region, sec_token.as_str(), anonymous_id, fetched_at)?;
        let routes = self.routes.region(region);
        let mut request = HttpRequest::post(routes.console_rpc.clone(), body)
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .accept(RequestAccept::Any)
            .content_type(RequestContentType::FormUrlEncoded)
            .public_header("x-requested-with", "XMLHttpRequest")
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .public_header("user-agent", BROWSER_USER_AGENT)
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .public_header("origin", region.gateway_origin())
            .map_err(|error| RegionalFailure::from_transport(error, false))?
            .public_header("referer", region.console_referer())
            .map_err(|error| RegionalFailure::from_transport(error, false))?;
        if let Some(csrf) = extract_cookie_value("login_aliyunid_csrf", rpc_cookie.as_str())
            .or_else(|| extract_cookie_value("csrf", rpc_cookie.as_str()))
        {
            request = request
                .sensitive_header("x-xsrf-token", csrf.to_owned())
                .map_err(|error| RegionalFailure::from_transport(error, false))?
                .sensitive_header("x-csrf-token", csrf.to_owned())
                .map_err(|error| RegionalFailure::from_transport(error, false))?;
        }
        request = request.authentication(
            Authentication::cookie(rpc_cookie.as_str().to_owned())
                .map_err(|error| RegionalFailure::from_transport(error, false))?,
        );
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(RegionalFailure::from_completed_transport)?;
        if response.status() != 200 {
            return Err(RegionalFailure::new(ErrorKind::Api, false));
        }
        parse_and_normalize(
            context.scope().clone(),
            fetched_at,
            response.body(),
            AuthMode::WebSession,
            "web",
        )
    }

    async fn resolve_sec_token(
        &self,
        context: &ProviderContext,
        region: AlibabaRegion,
        cookies: &RoutedCookieHeaders,
        rpc_cookie: &Zeroizing<String>,
    ) -> Result<Zeroizing<String>, RegionalFailure> {
        let routes = self.routes.region(region);
        if let Some(cookie) = &cookies.dashboard {
            let request = HttpRequest::get(routes.dashboard.clone())
                .accept(RequestAccept::Html)
                .public_header("user-agent", SAFARI_USER_AGENT)
                .map_err(|error| RegionalFailure::from_transport(error, false))?
                .authentication(
                    Authentication::cookie(cookie.as_str().to_owned())
                        .map_err(|error| RegionalFailure::from_transport(error, false))?,
                );
            match self.transport.send(&request, context.cancellation()).await {
                Ok(response) if response.status() == 200 => {
                    if let Some(token) = extract_sec_token_html(response.body()) {
                        return Ok(token);
                    }
                }
                Err(_) if context.cancellation().is_cancelled() => {
                    return Err(RegionalFailure::new(ErrorKind::Network, false));
                }
                Ok(_) | Err(_) => {}
            }
        }

        if let Some(cookie) = &cookies.user_info {
            let referer = format!("{}/", region.gateway_origin());
            let request = HttpRequest::get(routes.user_info.clone())
                .accept(RequestAccept::Json)
                .public_header("user-agent", SAFARI_USER_AGENT)
                .map_err(|error| RegionalFailure::from_transport(error, false))?
                .public_header("referer", referer)
                .map_err(|error| RegionalFailure::from_transport(error, false))?
                .authentication(
                    Authentication::cookie(cookie.as_str().to_owned())
                        .map_err(|error| RegionalFailure::from_transport(error, false))?,
                );
            match self.transport.send(&request, context.cancellation()).await {
                Ok(response) if response.status() == 200 => {
                    if let Ok(root) = parse_bounded_json(response.body())
                        && let Some(token) = find_first_string(&root, &["secToken", "sec_token"])
                            .and_then(valid_sec_token)
                    {
                        return Ok(Zeroizing::new(token.to_owned()));
                    }
                }
                Err(_) if context.cancellation().is_cancelled() => {
                    return Err(RegionalFailure::new(ErrorKind::Network, false));
                }
                Ok(_) | Err(_) => {}
            }
        }

        extract_cookie_value("sec_token", rpc_cookie.as_str())
            .and_then(valid_sec_token)
            .map(|value| Zeroizing::new(value.to_owned()))
            .ok_or_else(|| RegionalFailure::new(ErrorKind::AuthenticationExpired, true))
    }
}

impl ProviderAdapter for AlibabaProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Alibaba)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for AlibabaProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlibabaProvider")
            .field("scope", &"<redacted>")
            .field("region", &self.region)
            .field("routes", &"<redacted>")
            .field("backend", &"<redacted>")
            .field("transport", &"<redacted>")
            .field("source", &self.source())
            .finish()
    }
}

struct RegionalFailure {
    error: ClassifiedError,
    retry_alternate: bool,
}

impl RegionalFailure {
    fn new(kind: ErrorKind, retry_alternate: bool) -> Self {
        Self {
            error: ClassifiedError::new(kind),
            retry_alternate,
        }
    }

    fn from_transport(error: impl Into<Self>, retry_alternate: bool) -> Self {
        let mut failure = error.into();
        failure.retry_alternate = retry_alternate;
        failure
    }

    fn from_completed_transport(error: TransportError) -> Self {
        match error.http_status() {
            Some(401 | 403) => Self::new(ErrorKind::AuthenticationExpired, true),
            Some(404) => Self::new(ErrorKind::Api, true),
            _ => Self::from_transport(error, false),
        }
    }
}

impl From<TransportError> for RegionalFailure {
    fn from(error: TransportError) -> Self {
        Self {
            error: error.classified(),
            retry_alternate: false,
        }
    }
}

fn normalize_manual_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    CookieHeaderNormalizer::normalize(Some(raw))
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let normalized = raw.split(';').map(str::trim).collect::<Vec<_>>().join("; ");
    Ok(Zeroizing::new(normalized))
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

fn extract_cookie_value<'a>(name: &str, header: &'a str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (candidate, value) = pair.trim().split_once('=')?;
        (candidate.trim() == name)
            .then(|| value.trim())
            .filter(|value| !value.is_empty())
    })
}

fn valid_sec_token(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= MAX_SEC_TOKEN_BYTES
        && !value.chars().any(char::is_control))
    .then_some(value)
}

fn extract_sec_token_html(body: &[u8]) -> Option<Zeroizing<String>> {
    let html = std::str::from_utf8(body).ok()?;
    for key in ["SEC_TOKEN", "secToken", "sec_token"] {
        let mut remaining = html;
        while let Some(index) = remaining.find(key) {
            let after_key = &remaining[index + key.len()..];
            let after_key = after_key.trim_start_matches(['"', '\'', ' ', '\t']);
            let Some(after_colon) = after_key.strip_prefix(':') else {
                remaining = after_key;
                continue;
            };
            let value = after_colon.trim_start();
            let Some(quote) = value
                .chars()
                .next()
                .filter(|value| matches!(value, '"' | '\''))
            else {
                remaining = after_key;
                continue;
            };
            let value = &value[quote.len_utf8()..];
            let end = value.find(quote)?;
            let token = &value[..end];
            if let Some(token) = valid_sec_token(token) {
                return Some(Zeroizing::new(token.to_owned()));
            }
            remaining = after_key;
        }
    }
    None
}

fn console_request_body(
    region: AlibabaRegion,
    sec_token: &str,
    anonymous_id: Option<&str>,
    fetched_at: Timestamp,
) -> Result<Vec<u8>, RegionalFailure> {
    let mut cornerstone = json!({
        "feTraceId": trace_id(fetched_at),
        "feURL": region.dashboard_reference(),
        "protocol": "V2",
        "console": "ONE_CONSOLE",
        "productCode": "p_efm",
        "domain": region.console_domain(),
        "consoleSite": region.console_site(),
        "userNickName": "",
        "userPrincipalName": "",
        "xsp_lang": "en-US",
    });
    if let Some(anonymous_id) = anonymous_id {
        cornerstone
            .as_object_mut()
            .ok_or_else(|| RegionalFailure::new(ErrorKind::Api, false))?
            .insert(
                "X-Anonymous-Id".to_owned(),
                Value::String(anonymous_id.to_owned()),
            );
    }
    let params = json!({
        "Api": QUOTA_API,
        "V": "1.0",
        "Data": {
            "queryCodingPlanInstanceInfoRequest": {
                "commodityCode": region.commodity_code(),
                "onlyLatestOne": true,
            },
            "cornerstoneParam": cornerstone,
        },
    });
    let params =
        serde_json::to_string(&params).map_err(|_| RegionalFailure::new(ErrorKind::Api, false))?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("params", &params)
        .append_pair("region", region.region_id())
        .append_pair("sec_token", sec_token);
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    ApiKey,
    WebSession,
}

struct ParsedUsage {
    plan_name: Option<String>,
    five_hour_used: Option<i64>,
    five_hour_total: Option<i64>,
    five_hour_reset: Option<Timestamp>,
    weekly_used: Option<i64>,
    weekly_total: Option<i64>,
    weekly_reset: Option<Timestamp>,
    monthly_used: Option<i64>,
    monthly_total: Option<i64>,
    monthly_reset: Option<Timestamp>,
}

impl ParsedUsage {
    const fn plan_only(plan_name: Option<String>) -> Self {
        Self {
            plan_name,
            five_hour_used: None,
            five_hour_total: None,
            five_hour_reset: None,
            weekly_used: None,
            weekly_total: None,
            weekly_reset: None,
            monthly_used: None,
            monthly_total: None,
            monthly_reset: None,
        }
    }
}

/// Parses and normalizes one bounded Alibaba Coding Plan response.
///
/// `source` must be one of the adapter's three supported credential sources;
/// it selects the baseline console-login classification and provenance only.
///
/// # Errors
///
/// Returns stable scope, login, API, or parse errors without payload text.
pub fn parse_usage_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Alibaba {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let (auth_mode, source_label) = match source {
        ProviderSource::ApiKey => (AuthMode::ApiKey, "api"),
        ProviderSource::ManualCookie | ProviderSource::BrowserSession => {
            (AuthMode::WebSession, "web")
        }
        ProviderSource::ConfigurableEndpoint
        | ProviderSource::Cli
        | ProviderSource::OAuth
        | ProviderSource::LocalData
        | ProviderSource::CloudCredentials => {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
    };
    parse_and_normalize(scope, fetched_at, body, auth_mode, source_label)
        .map_err(|failure| failure.error)
}

fn parse_and_normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    auth_mode: AuthMode,
    source_label: &'static str,
) -> Result<UsageSample, RegionalFailure> {
    let parsed = parse_payload(body, fetched_at, auth_mode)?;
    normalize_usage(scope, fetched_at, parsed, source_label).map_err(|error| RegionalFailure {
        error,
        retry_alternate: false,
    })
}

fn parse_payload(
    body: &[u8],
    fetched_at: Timestamp,
    auth_mode: AuthMode,
) -> Result<ParsedUsage, RegionalFailure> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(RegionalFailure::new(ErrorKind::Parse, false));
    }
    let text =
        std::str::from_utf8(body).map_err(|_| RegionalFailure::new(ErrorKind::Parse, false))?;
    if text.trim_start().starts_with('<') && text.to_ascii_lowercase().contains("login") {
        return Err(login_failure(auth_mode));
    }
    let root = parse_bounded_json(body).map_err(|error| RegionalFailure {
        error,
        retry_alternate: false,
    })?;
    let root_map = root
        .as_object()
        .ok_or_else(|| RegionalFailure::new(ErrorKind::Parse, false))?;
    validate_payload_status(&root, auth_mode)?;

    let (selected_instance, instance_count) = find_active_instance(&root, fetched_at);
    let scope_to_selected = instance_count > 1
        && selected_instance.is_some_and(|instance| active_signal_score(instance, fetched_at) > 0);
    let selected_value = selected_instance.cloned().map(Value::Object);
    let quota = if scope_to_selected {
        selected_value.as_ref().and_then(find_quota_info)
    } else {
        selected_value
            .as_ref()
            .and_then(find_quota_info)
            .or_else(|| find_quota_info(&root))
    };
    let Some(quota) = quota else {
        if let Some(fallback) = active_plan_fallback(&root, root_map, selected_instance, fetched_at)
        {
            return Ok(fallback);
        }
        return Err(RegionalFailure::new(ErrorKind::Parse, true));
    };

    let plan_name = selected_instance
        .and_then(find_plan_name_in_map)
        .or_else(|| find_plan_name(&root));
    let parsed = ParsedUsage {
        plan_name,
        five_hour_used: any_i64(quota, &["per5HourUsedQuota", "perFiveHourUsedQuota"]),
        five_hour_total: any_i64(quota, &["per5HourTotalQuota", "perFiveHourTotalQuota"]),
        five_hour_reset: any_timestamp(
            quota,
            &[
                "per5HourQuotaNextRefreshTime",
                "perFiveHourQuotaNextRefreshTime",
            ],
        ),
        weekly_used: any_i64(quota, &["perWeekUsedQuota"]),
        weekly_total: any_i64(quota, &["perWeekTotalQuota"]),
        weekly_reset: any_timestamp(quota, &["perWeekQuotaNextRefreshTime"]),
        monthly_used: any_i64(quota, &["perBillMonthUsedQuota", "perMonthUsedQuota"]),
        monthly_total: any_i64(quota, &["perBillMonthTotalQuota", "perMonthTotalQuota"]),
        monthly_reset: any_timestamp(
            quota,
            &[
                "perBillMonthQuotaNextRefreshTime",
                "perMonthQuotaNextRefreshTime",
            ],
        ),
    };
    if parsed.five_hour_total.is_none()
        && parsed.weekly_total.is_none()
        && parsed.monthly_total.is_none()
    {
        if let Some(fallback) = active_plan_fallback(&root, root_map, selected_instance, fetched_at)
        {
            return Ok(fallback);
        }
        return Err(RegionalFailure::new(ErrorKind::Parse, true));
    }
    Ok(parsed)
}

fn validate_payload_status(root: &Value, auth_mode: AuthMode) -> Result<(), RegionalFailure> {
    if let Some(status) = find_first_i64(root, &["statusCode", "status_code", "code"])
        && !matches!(status, 0 | 200)
    {
        let message = find_first_string(root, &["statusMessage", "status_msg", "message", "msg"])
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(status, 401 | 403)
            || message.contains("api key")
            || message.contains("unauthorized")
        {
            return Err(RegionalFailure::new(ErrorKind::AuthenticationExpired, true));
        }
        return Err(RegionalFailure::new(ErrorKind::Api, false));
    }

    if let Some(code) = find_first_string(root, &["code", "status", "statusCode"])
        && contains_login_signal(code)
    {
        return Err(login_failure(auth_mode));
    }
    if let Some(message) = find_first_string(root, &["message", "msg", "statusMessage"]) {
        let normalized = message.to_ascii_lowercase();
        if normalized.contains("log in") || normalized.contains("login") {
            return Err(login_failure(auth_mode));
        }
        if auth_mode == AuthMode::ApiKey
            && (normalized.contains("console session")
                || normalized.contains("api key mode may be unavailable"))
        {
            return Err(RegionalFailure::new(ErrorKind::PermissionDenied, false));
        }
    }
    Ok(())
}

fn login_failure(auth_mode: AuthMode) -> RegionalFailure {
    match auth_mode {
        AuthMode::ApiKey => RegionalFailure::new(ErrorKind::PermissionDenied, false),
        AuthMode::WebSession => RegionalFailure::new(ErrorKind::AuthenticationExpired, true),
    }
}

fn contains_login_signal(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("needlogin") || normalized.contains("login")
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    parsed: ParsedUsage,
    source_label: &'static str,
) -> Result<UsageSample, ClassifiedError> {
    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if let Some(window) = quota_window(
        parsed.five_hour_used,
        parsed.five_hour_total,
        normalize_five_hour_reset(parsed.five_hour_reset, fetched_at)?,
        5 * 60,
    )? {
        builder = builder.primary(window);
    }
    if let Some(window) = quota_window(
        parsed.weekly_used,
        parsed.weekly_total,
        parsed.weekly_reset,
        7 * 24 * 60,
    )? {
        builder = builder.secondary(window);
    }
    if let Some(window) = quota_window(
        parsed.monthly_used,
        parsed.monthly_total,
        parsed.monthly_reset,
        30 * 24 * 60,
    )? {
        builder = builder.tertiary(window);
    }
    let plan_name = parsed.plan_name.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    });
    builder
        .login_method(plan_name)?
        .provenance("alibaba", source_label)?
        .build()
}

fn quota_window(
    used: Option<i64>,
    total: Option<i64>,
    resets_at: Option<Timestamp>,
    duration_minutes: i64,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let (Some(used), Some(total)) = (used, total) else {
        return Ok(None);
    };
    if total <= 0 {
        return Ok(None);
    }
    let normalized_used = used.clamp(0, total);
    let percent = (Decimal::from(normalized_used) * Decimal::from(100_u8) / Decimal::from(total))
        .to_f64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let percent = UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let description = BoundedText::new(format!("{used} / {total} used"))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let duration = WindowDuration::from_provider_minutes(duration_minutes)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        resets_at,
        Some(description),
        None,
        false,
    )
    .map(Some)
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn normalize_five_hour_reset(
    raw: Option<Timestamp>,
    fetched_at: Timestamp,
) -> Result<Option<Timestamp>, ClassifiedError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let minimum = time::Duration::seconds(60);
    if raw.as_offset_date_time() - fetched_at.as_offset_date_time() >= minimum {
        return Ok(Some(raw));
    }
    let window = time::Duration::hours(5);
    if let Some(shifted) = raw.as_offset_date_time().checked_add(window)
        && shifted - fetched_at.as_offset_date_time() >= minimum
    {
        return Timestamp::new(shifted)
            .map(Some)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse));
    }
    let fallback = fetched_at
        .as_offset_date_time()
        .checked_add(window)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::new(fallback)
        .map(Some)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn active_plan_fallback(
    root: &Value,
    root_map: &Map<String, Value>,
    selected: Option<&Map<String, Value>>,
    fetched_at: Timestamp,
) -> Option<ParsedUsage> {
    let source = selected.unwrap_or(root_map);
    let active = if contains_plan_instances(root) {
        active_signal_score(source, fetched_at) > 0
    } else {
        active_signal_score(source, fetched_at) > 0 || active_signal_score(root_map, fetched_at) > 0
    };
    if !active {
        return None;
    }
    let plan_name = find_plan_name_in_map(source).or_else(|| find_plan_name(root))?;
    Some(ParsedUsage::plan_only(Some(plan_name)))
}

fn find_active_instance(
    root: &Value,
    fetched_at: Timestamp,
) -> (Option<&Map<String, Value>>, usize) {
    let Some(infos) = find_first_array(
        root,
        &["codingPlanInstanceInfos", "coding_plan_instance_infos"],
    ) else {
        return (None, 0);
    };
    let mut first = None;
    let mut best = None;
    let mut best_score = i8::MIN;
    let mut count = 0_usize;
    for value in infos {
        let Some(info) = value.as_object() else {
            continue;
        };
        count += 1;
        first.get_or_insert(info);
        let score = active_signal_score(info, fetched_at);
        if score > best_score {
            best = Some(info);
            best_score = score;
        }
    }
    if best_score > 0 {
        (best, count)
    } else {
        (first, count)
    }
}

fn active_signal_score(source: &Map<String, Value>, fetched_at: Timestamp) -> i8 {
    if let Some(status) = any_string(source, &["status", "instanceStatus"]) {
        let status = status.to_ascii_uppercase();
        if matches!(status.as_str(), "VALID" | "ACTIVE") {
            return 3;
        }
        if matches!(
            status.as_str(),
            "EXPIRED" | "INVALID" | "INACTIVE" | "DISABLED" | "TERMINATED" | "STOPPED"
        ) {
            return -1;
        }
    }
    if let Some(active) = any_bool(source, &["isActive", "active"]) {
        return if active { 3 } else { -1 };
    }
    if any_timestamp(
        source,
        &["endTime", "periodEndTime", "expireTime", "expirationTime"],
    )
    .is_some_and(|expiry| expiry > fetched_at)
    {
        return 1;
    }
    0
}

fn contains_plan_instances(root: &Value) -> bool {
    find_first_array(
        root,
        &["codingPlanInstanceInfos", "coding_plan_instance_infos"],
    )
    .is_some_and(|values| values.iter().any(Value::is_object))
}

fn find_plan_name(root: &Value) -> Option<String> {
    if let Some(infos) = find_first_array(
        root,
        &["codingPlanInstanceInfos", "coding_plan_instance_infos"],
    ) {
        for info in infos.iter().filter_map(Value::as_object) {
            if let Some(value) = any_string(
                info,
                &[
                    "planName",
                    "plan_name",
                    "instanceName",
                    "instance_name",
                    "packageName",
                    "package_name",
                ],
            ) {
                return Some(value.to_owned());
            }
        }
    }
    find_first_string(
        root,
        &["planName", "plan_name", "packageName", "package_name"],
    )
    .map(str::to_owned)
}

fn find_plan_name_in_map(source: &Map<String, Value>) -> Option<String> {
    any_string(
        source,
        &[
            "planName",
            "plan_name",
            "instanceName",
            "instance_name",
            "packageName",
            "package_name",
        ],
    )
    .map(str::to_owned)
    .or_else(|| find_plan_name(&Value::Object(source.clone())))
}

fn find_quota_info(root: &Value) -> Option<&Map<String, Value>> {
    find_first_object_value(root, &["codingPlanQuotaInfo", "coding_plan_quota_info"]).or_else(
        || {
            find_object_containing_any(
                root,
                &[
                    "per5HourUsedQuota",
                    "per5HourTotalQuota",
                    "perWeekUsedQuota",
                    "perWeekTotalQuota",
                    "perBillMonthUsedQuota",
                    "perBillMonthTotalQuota",
                ],
            )
        },
    )
}

fn any_i64(source: &Map<String, Value>, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| source.get(*key).and_then(scalar_i64))
}

fn any_string<'a>(source: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| source.get(*key).and_then(scalar_string))
}

fn any_bool(source: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| source.get(*key).and_then(scalar_bool))
}

fn any_timestamp(source: &Map<String, Value>, keys: &[&str]) -> Option<Timestamp> {
    keys.iter()
        .find_map(|key| source.get(*key).and_then(scalar_timestamp))
}

fn find_first_i64(root: &Value, keys: &[&str]) -> Option<i64> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(values) = value
            && let Some(found) = any_i64(values, keys)
        {
            return Some(found);
        }
        push_children(&mut stack, value);
    }
    None
}

fn find_first_string<'a>(root: &'a Value, keys: &[&str]) -> Option<&'a str> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(values) = value
            && let Some(found) = any_string(values, keys)
        {
            return Some(found);
        }
        push_children(&mut stack, value);
    }
    None
}

fn find_first_array<'a>(root: &'a Value, keys: &[&str]) -> Option<&'a Vec<Value>> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        if let Value::Object(values) = value {
            for key in keys {
                if let Some(Value::Array(found)) = values.get(*key) {
                    return Some(found);
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
        if let Value::Object(values) = value {
            for key in keys {
                if let Some(Value::Object(found)) = values.get(*key) {
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
        if let Value::Object(values) = value
            && keys.iter().any(|key| values.contains_key(*key))
        {
            return Some(values);
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

fn scalar_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(value) => Some(i64::from(*value)),
        Value::Number(value) => value.to_string().parse::<Decimal>().ok()?.trunc().to_i64(),
        Value::String(value) => value.trim().parse().ok(),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn scalar_string(value: &Value) -> Option<&str> {
    let Value::String(value) = value else {
        return None;
    };
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_PLAN_NAME_BYTES.max(MAX_SEC_TOKEN_BYTES))
        .then_some(value)
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
            "true" | "1" | "yes" | "active" | "valid" => Some(true),
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

fn scalar_decimal(value: &Value) -> Option<Decimal> {
    match value {
        Value::Number(value) => value.to_string().parse().ok(),
        Value::String(value) => value.trim().parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
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
