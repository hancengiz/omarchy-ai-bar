//! Notion AI rolling and billing-period allowance usage.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use url::Url;
use zeroize::Zeroizing;

use crate::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    ChromiumCookieDecryptor, import_browser_cookie_stores_with_decryptor,
};
use crate::browser_profile::BrowserProfileDiscovery;
use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{
    CookieImport, CookieImportOrder, CookieJar, CookieSourceId, CookieUrlPolicy, ValidatedCookieUrl,
};
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

const PRODUCTION_ORIGIN: &str = "https://app.notion.com";
const GET_SPACES_PATH: &str = "/api/v3/getSpaces";
const RATE_LIMIT_PATH: &str = "/api/v3/getCreditRateLimitStatus";
const SESSION_COOKIE_NAME: &str = "token_v2";
const DEFAULT_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_KEY_BYTES: usize = 512;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_WORKSPACE_ID_BYTES: usize = 512;
const MONTHLY_SENTINEL_MINUTES: i64 = 30 * 24 * 60;
const MAX_BROWSER_PROFILES: usize = 128;

const COOKIE_DOMAINS: [&str; 5] = [
    "app.notion.com",
    "www.notion.com",
    "notion.com",
    "www.notion.so",
    "notion.so",
];

const FORWARDED_HEADERS: [&str; 10] = [
    "accept",
    "accept-language",
    "notion-audit-log-platform",
    "notion-client-version",
    "referer",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "user-agent",
    "x-notion-active-user-header",
];

const DEFAULT_HEADERS: [(&str, &str); 6] = [
    ("accept-language", "en-US,en;q=0.9"),
    ("user-agent", DEFAULT_USER_AGENT),
    ("referer", "https://app.notion.com/"),
    ("sec-fetch-dest", "empty"),
    ("sec-fetch-mode", "cors"),
    ("sec-fetch-site", "same-origin"),
];

/// Fixed Notion route table. Production credentials can only reach the pinned
/// Notion origin; the loopback constructor exists solely for deterministic tests.
#[derive(Clone)]
pub struct NotionRouteSet {
    spaces: Url,
    rate_limit: Url,
    class: EndpointClass,
}

impl NotionRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origin(
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| api_error())?,
            EndpointClass::PublicHttps,
        )
    }

    /// Builds exact loopback routes while retaining production capture and
    /// browser-cookie authority.
    ///
    /// # Errors
    ///
    /// Returns an API error unless `origin` is a bare loopback origin.
    #[doc(hidden)]
    pub fn loopback(origin: Url) -> Result<Self, ClassifiedError> {
        Self::from_origin(origin, EndpointClass::LoopbackDevelopment)
    }

    fn from_origin(mut origin: Url, class: EndpointClass) -> Result<Self, ClassifiedError> {
        if origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || !matches!(
                class,
                EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
            )
        {
            return Err(api_error());
        }
        if class == EndpointClass::PublicHttps {
            let expected = Url::parse(PRODUCTION_ORIGIN).map_err(|_| api_error())?;
            if origin.origin() != expected.origin() {
                return Err(api_error());
            }
        }
        origin.set_query(None);
        origin.set_fragment(None);
        let mut spaces = origin.clone();
        spaces.set_path(GET_SPACES_PATH);
        let mut rate_limit = origin;
        rate_limit.set_path(RATE_LIMIT_PATH);
        let routes = Self {
            spaces,
            rate_limit,
            class,
        };
        routes.validate()?;
        Ok(routes)
    }

    fn validate(&self) -> Result<(), ClassifiedError> {
        for (url, path) in [
            (&self.spaces, GET_SPACES_PATH),
            (&self.rate_limit, RATE_LIMIT_PATH),
        ] {
            if url.path() != path
                || url.query().is_some()
                || url.fragment().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(api_error());
            }
        }
        if self.spaces.origin() != self.rate_limit.origin() {
            return Err(api_error());
        }
        let policy = self.endpoint_policy()?;
        policy.validate(&self.spaces).map_err(|_| api_error())?;
        policy.validate(&self.rate_limit).map_err(|_| api_error())?;
        Ok(())
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        EndpointPolicy::new([(self.spaces.origin().ascii_serialization(), self.class)])
            .map_err(|_| api_error())
    }

    fn manual_cookie_target(&self) -> Result<ValidatedCookieUrl, ClassifiedError> {
        let policy = if self.class == EndpointClass::LoopbackDevelopment {
            CookieUrlPolicy::LoopbackHttp
        } else {
            CookieUrlPolicy::HttpsOnly
        };
        ValidatedCookieUrl::new(self.spaces.clone(), policy).map_err(|_| api_error())
    }
}

impl Debug for NotionRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotionRouteSet")
            .field("spaces", &"<redacted>")
            .field("rate_limit", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

/// One Notion workspace visible to the authenticated account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotionWorkspace {
    id: String,
    name: Option<String>,
    plan_type: Option<String>,
    subscription_tier: Option<String>,
}

impl NotionWorkspace {
    /// API workspace identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Optional workspace display name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Optional Notion plan type.
    #[must_use]
    pub fn plan_type(&self) -> Option<&str> {
        self.plan_type.as_deref()
    }

    /// Optional subscription tier.
    #[must_use]
    pub fn subscription_tier(&self) -> Option<&str> {
        self.subscription_tier.as_deref()
    }

    fn may_have_allowance(&self) -> bool {
        self.subscription_tier.as_deref().is_some_and(|tier| {
            tier.eq_ignore_ascii_case("business") || tier.eq_ignore_ascii_case("enterprise")
        })
    }

    fn display_tier(&self) -> Option<String> {
        let tier = self.subscription_tier.as_deref()?.trim();
        if tier.is_empty() {
            return None;
        }
        let mut characters = tier.chars();
        let first = characters.next()?.to_uppercase().collect::<String>();
        Some(first + characters.as_str())
    }
}

/// Parsed account and workspace inventory from `getSpaces`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotionAccount {
    user_id: Option<String>,
    email: Option<String>,
    name: Option<String>,
    workspaces: Vec<NotionWorkspace>,
}

impl NotionAccount {
    /// Provider-owned account identifier.
    #[must_use]
    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Account email.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Account display name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Deterministically ordered workspaces.
    #[must_use]
    pub fn workspaces(&self) -> &[NotionWorkspace] {
        &self.workspaces
    }

    fn resolve_workspace(&self, preferred: Option<&str>) -> Option<&NotionWorkspace> {
        if let Some(preferred) = preferred.and_then(normalize_space_id)
            && let Some(workspace) = self
                .workspaces
                .iter()
                .find(|workspace| normalize_space_id(&workspace.id).as_deref() == Some(&preferred))
        {
            return Some(workspace);
        }
        self.workspaces
            .iter()
            .find(|workspace| workspace.may_have_allowance())
            .or_else(|| self.workspaces.first())
    }
}

/// Notion adapter permanently bound to one source, account, and optional
/// preferred workspace.
pub struct NotionProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: NotionRouteSet,
    cookie: Zeroizing<String>,
    accept: RequestAccept,
    forwarded_headers: BTreeMap<String, Zeroizing<String>>,
    preferred_space_id: Option<Zeroizing<String>>,
    transport: HttpTransport,
}

impl NotionProvider {
    /// Creates a production adapter from a bare `token_v2`, Cookie header, or
    /// copied cURL command.
    ///
    /// # Errors
    ///
    /// Returns a stable credential, capture, scope, or endpoint error.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::new_manual_for_workspace(scope, raw, None)
    }

    /// Creates a production manual adapter with an optional preferred workspace.
    ///
    /// # Errors
    ///
    /// Returns a stable credential, capture, workspace, scope, or endpoint error.
    pub fn new_manual_for_workspace(
        scope: AccountScope,
        raw: &str,
        preferred_space_id: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(
            scope,
            raw,
            preferred_space_id,
            NotionRouteSet::production()?,
        )
    }

    /// Creates a manual adapter at exact injected routes.
    ///
    /// Capture authority remains restricted to Notion's production domains.
    ///
    /// # Errors
    ///
    /// Returns a stable credential, capture, workspace, scope, or route error.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        preferred_space_id: Option<&str>,
        routes: NotionRouteSet,
    ) -> Result<Self, ClassifiedError> {
        if let Some(token) = bare_manual_token(raw) {
            let named = Zeroizing::new(format!("{SESSION_COOKIE_NAME}={token}"));
            let cookie = normalize_manual_cookie(named.as_str(), &routes.manual_cookie_target()?)?;
            return Self::build(
                scope,
                ProviderSource::ManualCookie,
                routes,
                cookie,
                RequestAccept::Any,
                BTreeMap::new(),
                preferred_space_id,
            );
        }
        let policy = ManualCapturePolicy::new(COOKIE_DOMAINS, [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query()
            .with_forwarded_headers(FORWARDED_HEADERS)
            .map_err(classify_capture_error)?;
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let raw_cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let normalized_input = if is_bare_token(raw_cookie) {
            Zeroizing::new(format!("{SESSION_COOKIE_NAME}={raw_cookie}"))
        } else {
            Zeroizing::new(raw_cookie.to_owned())
        };
        let cookie =
            normalize_manual_cookie(normalized_input.as_str(), &routes.manual_cookie_target()?)?;
        let mut accept = RequestAccept::Any;
        let mut forwarded_headers = BTreeMap::new();
        for (name, value) in capture.forwarded_headers() {
            if name == "accept" {
                accept = captured_accept(value)?;
            } else {
                forwarded_headers.insert(name.to_owned(), Zeroizing::new(value.to_owned()));
            }
        }
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            routes,
            cookie,
            accept,
            forwarded_headers,
            preferred_space_id,
        )
    }

    /// Creates a production adapter from one already imported Linux browser jar.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential, scope, or endpoint error.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::new_browser_for_workspace(scope, jar, now, None)
    }

    /// Creates a browser adapter with an optional preferred workspace.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential, workspace, scope, or endpoint error.
    pub fn new_browser_for_workspace(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        preferred_space_id: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jar_routes(
            scope,
            jar,
            now,
            preferred_space_id,
            NotionRouteSet::production()?,
        )
    }

    /// Creates the production adapter from ordered Linux browser profiles.
    ///
    /// Every browser store remains an isolated candidate. Within a selected
    /// store the fixed Notion domain priority removes duplicate cookie names,
    /// and `token_v2` is required before an adapter can be returned. No
    /// profiles or Chromium stores are combined.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired, bounded local-data, decryption,
    /// workspace, scope, or endpoint error without exposing browser data.
    pub fn new_browser_from_discovery(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
        preferred_space_id: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Notion {
            return Err(api_error());
        }
        let report = discovery.discover();
        if report.profiles().len() > MAX_BROWSER_PROFILES {
            return Err(parse_error());
        }
        let allowlist = BrowserCookieDomainAllowlist::new(COOKIE_DOMAINS.map(|domain| {
            BrowserCookieDomainRule {
                domain,
                policy: BrowserCookieDomainPolicy::Exact,
            }
        }))
        .map_err(|_| api_error())?;
        let routes = NotionRouteSet::production()?;
        let mut saw_cookie_data = false;
        for (index, profile) in report.profiles().iter().enumerate() {
            let store_sources = browser_store_sources(index)?;
            let Ok(imports) = import_browser_cookie_stores_with_decryptor(
                profile,
                store_sources,
                &allowlist,
                decryptor,
            ) else {
                continue;
            };
            let order = CookieImportOrder::new(store_sources).map_err(|_| api_error())?;
            for import in imports {
                let jar = CookieJar::from_imports(&order, [import]).map_err(|_| parse_error())?;
                saw_cookie_data |= !jar.is_empty();
                match Self::from_browser_jar_routes(
                    scope.clone(),
                    &jar,
                    now,
                    preferred_space_id,
                    routes.clone(),
                ) {
                    Ok(provider) => return Ok(provider),
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::MissingCredential | ErrorKind::AuthenticationExpired
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        drop(scope);
        Err(ClassifiedError::new(if saw_cookie_data {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::MissingCredential
        }))
    }

    /// Creates a browser adapter at exact injected transport routes.
    ///
    /// Cookie selection remains bound to the five fixed HTTPS Notion domains.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential, workspace, scope, or route error.
    #[doc(hidden)]
    pub fn from_browser_jar_routes(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        preferred_space_id: Option<&str>,
        routes: NotionRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let cookie = browser_cookie_header(jar, now)?;
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            routes,
            cookie,
            RequestAccept::Any,
            BTreeMap::new(),
            preferred_space_id,
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: NotionRouteSet,
        cookie: Zeroizing<String>,
        accept: RequestAccept,
        forwarded_headers: BTreeMap<String, Zeroizing<String>>,
        preferred_space_id: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Notion
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
        {
            return Err(api_error());
        }
        routes.validate()?;
        Authentication::cookie(cookie.as_str().to_owned()).map_err(|error| error.classified())?;
        let preferred_space_id = preferred_space_id
            .map(validate_preferred_space_id)
            .transpose()?
            .map(Zeroizing::new);
        let transport = HttpTransport::new(routes.endpoint_policy()?, transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            routes,
            cookie,
            accept,
            forwarded_headers,
            preferred_space_id,
            transport,
        })
    }

    /// Fetches at an injected timestamp for deterministic normalization tests.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, transport, authentication, API, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }
        let spaces_request = self.request(self.routes.spaces.clone(), b"{}".to_vec())?;
        let spaces = self.send_exact_200(&spaces_request, context).await?;
        let account = parse_spaces_response(spaces.body())?;
        let workspace = account
            .resolve_workspace(
                self.preferred_space_id
                    .as_ref()
                    .map(|preferred| preferred.as_str()),
            )
            .ok_or_else(api_error)?;
        let body =
            serde_json::to_vec(&json!({"spaceId": workspace.id()})).map_err(|_| api_error())?;
        let usage_request = self.request(self.routes.rate_limit.clone(), body)?;
        let usage = self.send_exact_200(&usage_request, context).await?;
        let status = parse_rate_limit_response(usage.body())?;
        if status.is_not_applicable() {
            return Err(api_error());
        }
        normalize_usage(
            context.scope().clone(),
            fetched_at,
            &status,
            &account,
            workspace,
            self.source,
        )
    }

    async fn send_exact_200(
        &self,
        request: &HttpRequest,
        context: &ProviderContext,
    ) -> Result<HttpResponse, ClassifiedError> {
        let response = self
            .transport
            .send(request, context.cancellation())
            .await
            .map_err(|error| classify_transport_error(&error))?;
        if response.status() != 200 {
            return Err(api_error());
        }
        Ok(response)
    }

    fn request(&self, url: Url, body: Vec<u8>) -> Result<HttpRequest, ClassifiedError> {
        let mut request = HttpRequest::post(url, body)
            .map_err(|error| error.classified())?
            .accept(self.accept)
            .content_type(RequestContentType::Json);
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
        request
            .public_header("origin", PRODUCTION_ORIGIN)
            .map_err(|error| error.classified())
            .and_then(|request| {
                Authentication::cookie(self.cookie.as_str().to_owned())
                    .map(|authentication| request.authentication(authentication))
                    .map_err(|error| error.classified())
            })
    }

    /// Credential source bound to this adapter.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }
}

fn browser_store_sources(index: usize) -> Result<[CookieSourceId; 2], ClassifiedError> {
    let first = index
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(parse_error)?;
    Ok([CookieSourceId::new(first), CookieSourceId::new(first + 1)])
}

impl ProviderAdapter for NotionProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Notion)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for NotionProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotionProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &self.routes)
            .field("cookie", &"<redacted>")
            .field("accept", &self.accept)
            .field("forwarded_header_count", &self.forwarded_headers.len())
            .field(
                "preferred_space_id",
                &self.preferred_space_id.as_ref().map(|_| "<redacted>"),
            )
            .field("transport", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RollingWindow {
    window: Option<String>,
    used: Option<f64>,
    limit: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BillingWindow {
    used: Option<f64>,
    limit: Option<f64>,
    period_end_ms: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RateLimitStatus {
    status: Option<String>,
    window: Option<RollingWindow>,
    resets_in_seconds: Option<f64>,
    billing_period_window: Option<BillingWindow>,
}

impl RateLimitStatus {
    fn is_not_applicable(&self) -> bool {
        self.status
            .as_deref()
            .is_some_and(|status| status.eq_ignore_ascii_case("not_applicable"))
    }
}

/// Parses one bounded `getSpaces` response.
///
/// # Errors
///
/// Returns a stable parse error for malformed, ambiguous, or excessive JSON.
pub fn parse_spaces_response(body: &[u8]) -> Result<NotionAccount, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let root = root.as_object().ok_or_else(parse_error)?;
    let user_id = resolve_user_id(root).ok_or_else(parse_error)?;
    let container = root
        .get(&user_id)
        .and_then(Value::as_object)
        .ok_or_else(parse_error)?;

    let user_record = container
        .get("notion_user")
        .and_then(Value::as_object)
        .and_then(|users| {
            users
                .get(&user_id)
                .and_then(unwrap_record)
                .or_else(|| users.values().find_map(unwrap_record))
        });
    let email = user_record.and_then(|record| optional_string(record, "email"));
    let name = user_record.and_then(|record| optional_string(record, "name"));

    let mut workspaces = Vec::new();
    if let Some(spaces) = container.get("space").and_then(Value::as_object) {
        let mut keys = spaces.keys().collect::<Vec<_>>();
        keys.sort();
        for key in keys {
            let Some(record) = spaces.get(key).and_then(unwrap_record) else {
                continue;
            };
            let id = optional_string(record, "id").unwrap_or_else(|| key.clone());
            if id.is_empty() || id.len() > MAX_WORKSPACE_ID_BYTES {
                return Err(parse_error());
            }
            workspaces.push(NotionWorkspace {
                id,
                name: optional_string(record, "name"),
                plan_type: optional_string(record, "plan_type"),
                subscription_tier: optional_string(record, "subscription_tier"),
            });
        }
    }

    Ok(NotionAccount {
        user_id: Some(user_id),
        email,
        name,
        workspaces,
    })
}

fn parse_rate_limit_response(body: &[u8]) -> Result<RateLimitStatus, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let status: RateLimitStatus = serde_json::from_value(root).map_err(|_| parse_error())?;
    if !status.is_not_applicable()
        && status.window.is_none()
        && status.billing_period_window.is_none()
    {
        return Err(parse_error());
    }
    Ok(status)
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    status: &RateLimitStatus,
    account: &NotionAccount,
    workspace: &NotionWorkspace,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    let primary = status
        .window
        .as_ref()
        .and_then(|window| percent(window.used, window.limit).map(|value| (window, value)))
        .map(|(window, value)| {
            let duration = rolling_minutes(window.window.as_deref())
                .map(WindowDuration::from_provider_minutes)
                .transpose()
                .map_err(|_| parse_error())?;
            RateWindow::new(
                WindowUsage::known(value?),
                duration,
                timestamp_after_seconds(fetched_at, status.resets_in_seconds)?,
                None,
                None,
                false,
            )
            .map_err(|_| parse_error())
        })
        .transpose()?;

    let secondary = status
        .billing_period_window
        .as_ref()
        .and_then(|window| percent(window.used, window.limit).map(|value| (window, value)))
        .map(|(window, value)| {
            RateWindow::new(
                WindowUsage::known(value?),
                Some(
                    WindowDuration::from_provider_minutes(MONTHLY_SENTINEL_MINUTES)
                        .map_err(|_| parse_error())?,
                ),
                timestamp_from_milliseconds(window.period_end_ms)?,
                None,
                None,
                false,
            )
            .map_err(|_| parse_error())
        })
        .transpose()?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .provider_account_id(account.user_id.clone())?
        .email(account.email.clone())?
        .organization(workspace.name.clone())?
        .login_method(workspace.display_tier())?;
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder
        .provenance("notion", source_strategy(source))?
        .build()
}

fn percent(used: Option<f64>, limit: Option<f64>) -> Option<Result<UsagePercent, ClassifiedError>> {
    let (used, limit) = (used?, limit?);
    if !used.is_finite() || !limit.is_finite() || limit <= 0.0 {
        return None;
    }
    let value = (used / limit * 100.0).max(0.0);
    Some(UsagePercent::new(value).map_err(|_| parse_error()))
}

fn rolling_minutes(raw: Option<&str>) -> Option<i64> {
    let raw = raw?.trim().to_ascii_lowercase();
    let (unit_index, unit) = raw.char_indices().next_back()?;
    let value = raw[..unit_index]
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)?;
    let minutes = match unit {
        'm' => value,
        'h' => value.checked_mul(60)?,
        'd' => value.checked_mul(24 * 60)?,
        'w' => value.checked_mul(7 * 24 * 60)?,
        _ => return None,
    };
    (minutes != MONTHLY_SENTINEL_MINUTES).then_some(minutes)
}

fn timestamp_after_seconds(
    fetched_at: Timestamp,
    seconds: Option<f64>,
) -> Result<Option<Timestamp>, ClassifiedError> {
    let Some(seconds) = seconds.filter(|seconds| seconds.is_finite() && *seconds >= 0.0) else {
        return Ok(None);
    };
    let nanos = Decimal::from_f64(seconds)
        .and_then(|seconds| seconds.checked_mul(Decimal::from(1_000_000_000_u64)))
        .and_then(|nanos| nanos.round().to_i128())
        .ok_or_else(parse_error)?;
    let value = fetched_at
        .as_offset_date_time()
        .checked_add(time::Duration::nanoseconds_i128(nanos))
        .ok_or_else(parse_error)?;
    Timestamp::new(value).map(Some).map_err(|_| parse_error())
}

fn timestamp_from_milliseconds(raw: Option<f64>) -> Result<Option<Timestamp>, ClassifiedError> {
    let Some(raw) = raw.filter(|value| value.is_finite() && *value > 0.0) else {
        return Ok(None);
    };
    let nanos = Decimal::from_f64(raw)
        .and_then(|millis| millis.checked_mul(Decimal::from(1_000_000_u64)))
        .and_then(|nanos| nanos.round().to_i128())
        .ok_or_else(parse_error)?;
    let value = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| parse_error())?;
    Timestamp::new(value).map(Some).map_err(|_| parse_error())
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

fn resolve_user_id(root: &Map<String, Value>) -> Option<String> {
    let identified = root
        .iter()
        .filter_map(|(key, container)| {
            let users = container.as_object()?.get("notion_user")?.as_object()?;
            let record = users.get(key).and_then(unwrap_record)?;
            (record.get("id").and_then(Value::as_str) == Some(key.as_str())).then(|| key.clone())
        })
        .collect::<Vec<_>>();
    if identified.len() == 1 {
        identified.into_iter().next()
    } else if identified.is_empty() && root.len() == 1 {
        root.keys().next().cloned()
    } else {
        None
    }
}

fn unwrap_record(value: &Value) -> Option<&Map<String, Value>> {
    let outer = value.as_object()?;
    let Some(value) = outer.get("value").and_then(Value::as_object) else {
        return Some(outer);
    };
    value
        .get("value")
        .and_then(Value::as_object)
        .or(Some(value))
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn normalize_space_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let compact = trimmed.replace('-', "").to_ascii_lowercase();
    if compact.len() == 32 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(format!(
            "{}-{}-{}-{}-{}",
            &compact[0..8],
            &compact[8..12],
            &compact[12..16],
            &compact[16..20],
            &compact[20..32]
        ));
    }
    Some(trimmed.to_ascii_lowercase())
}

fn validate_preferred_space_id(raw: &str) -> Result<String, ClassifiedError> {
    if raw.len() > MAX_WORKSPACE_ID_BYTES || raw.chars().any(char::is_control) {
        return Err(api_error());
    }
    normalize_space_id(raw).ok_or_else(api_error)
}

fn browser_cookie_header(
    jar: &CookieJar,
    now: OffsetDateTime,
) -> Result<Zeroizing<String>, ClassifiedError> {
    let mut cookies = BTreeMap::<String, Zeroizing<String>>::new();
    for domain in COOKIE_DOMAINS {
        let target =
            ValidatedCookieUrl::parse(&format!("https://{domain}/"), CookieUrlPolicy::HttpsOnly)
                .map_err(|_| api_error())?;
        let Some(header) = jar.header_for(&target, now).map_err(|_| api_error())? else {
            continue;
        };
        for pair in header.expose().split(';') {
            let (name, value) = pair.trim().split_once('=').ok_or_else(parse_error)?;
            if name.is_empty() {
                return Err(parse_error());
            }
            cookies
                .entry(name.to_owned())
                .or_insert_with(|| Zeroizing::new(value.to_owned()));
        }
    }
    if !cookies.contains_key(SESSION_COOKIE_NAME) {
        return Err(ClassifiedError::new(if jar.is_empty() {
            ErrorKind::MissingCredential
        } else {
            ErrorKind::AuthenticationExpired
        }));
    }
    let mut header = Zeroizing::new(String::new());
    for (index, (name, value)) in cookies.iter().enumerate() {
        if index != 0 {
            header.push_str("; ");
        }
        header.push_str(name);
        header.push('=');
        header.push_str(value);
    }
    Ok(header)
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

fn is_bare_token(raw: &str) -> bool {
    !raw.is_empty()
        && !raw.contains('=')
        && !raw.contains(';')
        && !raw.chars().any(char::is_whitespace)
}

fn bare_manual_token(raw: &str) -> Option<&str> {
    if raw.chars().any(char::is_control) {
        return None;
    }
    let raw = raw.trim();
    let candidate = raw
        .get(.."cookie:".len())
        .filter(|prefix| prefix.eq_ignore_ascii_case("cookie:"))
        .map_or(raw, |_| raw["cookie:".len()..].trim());
    let candidate = if candidate.len() >= 2
        && ((candidate.starts_with('\'') && candidate.ends_with('\''))
            || (candidate.starts_with('"') && candidate.ends_with('"')))
    {
        &candidate[1..candidate.len() - 1]
    } else {
        candidate
    };
    (is_bare_token(candidate) && !candidate.eq_ignore_ascii_case("curl")).then_some(candidate)
}

fn captured_accept(value: &str) -> Result<RequestAccept, ClassifiedError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("*/*") {
        Ok(RequestAccept::Any)
    } else if value.eq_ignore_ascii_case("application/json") {
        Ok(RequestAccept::Json)
    } else if value.eq_ignore_ascii_case("application/json, text/plain, */*") {
        Ok(RequestAccept::JsonTextAny)
    } else if value.eq_ignore_ascii_case("text/html,application/xhtml+xml") {
        Ok(RequestAccept::Html)
    } else {
        Err(api_error())
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

fn classify_transport_error(error: &TransportError) -> ClassifiedError {
    if matches!(error, TransportError::AuthenticationExpired) {
        return ClassifiedError::new(ErrorKind::AuthenticationExpired);
    }
    if error.http_status().is_some()
        || matches!(
            error,
            TransportError::Endpoint(_) | TransportError::TooManyRedirects
        )
    {
        return api_error();
    }
    error.classified()
}

fn source_strategy(source: ProviderSource) -> &'static str {
    match source {
        ProviderSource::ManualCookie => "manual_cookie",
        ProviderSource::BrowserSession => "browser_session",
        _ => "invalid",
    }
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        10,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}

fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}
