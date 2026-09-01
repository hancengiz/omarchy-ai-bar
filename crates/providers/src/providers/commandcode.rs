//! Command Code rolling limits, monthly credits, and subscription enrichment.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, DetailSensitivity, ErrorKind, ExactDecimal, ExtensionFact,
    ExtensionValue, ProviderExtension, ProviderExtensionKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use url::Url;
use zeroize::Zeroizing;

use crate::browser_cookie::{
    BrowserCookieDomainAllowlist, BrowserCookieDomainPolicy, BrowserCookieDomainRule,
    ChromiumCookieDecryptor, import_browser_cookies_merging_chromium_stores_with_decryptor,
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
    Authentication, HttpRequest, HttpResponse, HttpTransport, RequestAccept, TransportConfig,
    TransportError,
};

const WEB_ORIGIN: &str = "https://commandcode.ai";
const API_ORIGIN: &str = "https://api.commandcode.ai";
const CREDITS_PATH: &str = "/internal/billing/credits";
const SUBSCRIPTIONS_PATH: &str = "/internal/billing/subscriptions";
const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_JSON_KEY_BYTES: usize = 512;
const MAX_AMOUNT: i64 = 1_000_000_000_000_000;
const MONTH_SECONDS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_SUBSCRIPTION_GRACE: Duration = Duration::from_secs(2);
const BARE_COOKIE_NAME: &str = "__Secure-better-auth.session_token";
const MAX_BROWSER_PROFILES: usize = 128;

#[derive(Clone)]
pub struct CommandCodeRouteSet {
    web: Url,
    credits: Url,
    subscriptions: Url,
    class: EndpointClass,
}

impl CommandCodeRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origins(
            Url::parse(WEB_ORIGIN).map_err(|_| api_error())?,
            Url::parse(API_ORIGIN).map_err(|_| api_error())?,
            Url::parse(API_ORIGIN).map_err(|_| api_error())?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates isolated loopback routes for deterministic HTTP tests.
    /// Paths and queries on the supplied URLs are replaced with fixed routes.
    ///
    /// # Errors
    ///
    /// Returns an API error unless all three URLs have loopback origins.
    #[doc(hidden)]
    pub fn loopback(
        web_origin: Url,
        credits_origin: Url,
        subscriptions_origin: Url,
    ) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            web_origin,
            credits_origin,
            subscriptions_origin,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        web_origin: Url,
        credits_origin: Url,
        subscriptions_origin: Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let routes = Self {
            web: fixed_url(web_origin, "/")?,
            credits: fixed_url(credits_origin, CREDITS_PATH)?,
            subscriptions: fixed_url(subscriptions_origin, SUBSCRIPTIONS_PATH)?,
            class,
        };
        routes.validate()?;
        Ok(routes)
    }

    fn validate(&self) -> Result<(), ClassifiedError> {
        if !matches!(
            self.class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) || self.web.path() != "/"
            || self.credits.path() != CREDITS_PATH
            || self.subscriptions.path() != SUBSCRIPTIONS_PATH
            || [&self.web, &self.credits, &self.subscriptions]
                .into_iter()
                .any(|url| {
                    !url.username().is_empty()
                        || url.password().is_some()
                        || url.query().is_some()
                        || url.fragment().is_some()
                })
        {
            return Err(api_error());
        }
        if self.class == EndpointClass::PublicHttps
            && (!same_origin(&self.web, WEB_ORIGIN)?
                || !same_origin(&self.credits, API_ORIGIN)?
                || !same_origin(&self.subscriptions, API_ORIGIN)?)
        {
            return Err(api_error());
        }
        let policy = self.endpoint_policy()?;
        policy
            .validate(&self.credits)
            .and_then(|_| policy.validate(&self.subscriptions))
            .map_err(|_| api_error())?;
        self.cookie_target().map(|_| ())
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        EndpointPolicy::new([
            (self.credits.origin().ascii_serialization(), self.class),
            (
                self.subscriptions.origin().ascii_serialization(),
                self.class,
            ),
        ])
        .map_err(|_| api_error())
    }

    fn cookie_target(&self) -> Result<ValidatedCookieUrl, ClassifiedError> {
        let policy = if self.class == EndpointClass::LoopbackDevelopment {
            CookieUrlPolicy::LoopbackHttp
        } else {
            CookieUrlPolicy::HttpsOnly
        };
        ValidatedCookieUrl::new(self.web.clone(), policy).map_err(|_| api_error())
    }
}

impl Debug for CommandCodeRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandCodeRouteSet")
            .field("web", &"<redacted>")
            .field("credits", &"<redacted>")
            .field("subscriptions", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

/// Command Code adapter permanently bound to one account and credential source.
pub struct CommandCodeProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: CommandCodeRouteSet,
    cookie: Zeroizing<String>,
    transport: HttpTransport,
}

impl CommandCodeProvider {
    /// Creates a production adapter from a bare token, Cookie header, or cURL capture.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, capture, scope, or endpoint error.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, CommandCodeRouteSet::production()?)
    }

    /// Creates a manual adapter using an injected route table.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, capture, scope, or endpoint error.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: CommandCodeRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        let target = routes.cookie_target()?;
        let normalized_input = if is_bare_token(raw) {
            Zeroizing::new(format!("{BARE_COOKIE_NAME}={raw}"))
        } else {
            let policy = ManualCapturePolicy::new(
                ["commandcode.ai", "www.commandcode.ai", "api.commandcode.ai"],
                [CaptureHeader::Cookie],
            )
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
            let capture = policy.parse(raw).map_err(classify_capture_error)?;
            Zeroizing::new(
                capture
                    .header(CaptureHeader::Cookie)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?
                    .to_owned(),
            )
        };
        let cookie = normalize_manual_cookie(normalized_input.as_str(), &target)?;
        Self::build(scope, ProviderSource::ManualCookie, routes, cookie)
    }

    /// Creates a production adapter from one already imported browser cookie jar.
    ///
    /// # Errors
    ///
    /// Returns missing-credential for an empty jar and authentication-expired
    /// when no active cookie matches the Command Code web origin.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jar_routes(scope, jar, now, CommandCodeRouteSet::production()?)
    }

    /// Creates the production adapter from ordered Linux browser profiles.
    ///
    /// `CodexBar` treats each browser profile as an independent session while
    /// merging that profile's Chromium Network and primary stores. The shared
    /// importer implements the same expiry precedence: a later persistent
    /// expiry wins, with Network winning equal expiries and session-cookie
    /// ties. Cookies are never combined across profiles.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired, bounded local-data, decryption,
    /// scope, or endpoint error without exposing browser data.
    pub fn new_browser_from_discovery(
        scope: AccountScope,
        discovery: &BrowserProfileDiscovery,
        decryptor: &dyn ChromiumCookieDecryptor,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::CommandCode {
            return Err(api_error());
        }
        let report = discovery.discover();
        if report.profiles().len() > MAX_BROWSER_PROFILES {
            return Err(parse_error());
        }
        let allowlist = BrowserCookieDomainAllowlist::new([
            BrowserCookieDomainRule {
                domain: "commandcode.ai",
                policy: BrowserCookieDomainPolicy::Exact,
            },
            BrowserCookieDomainRule {
                domain: "www.commandcode.ai",
                policy: BrowserCookieDomainPolicy::Exact,
            },
        ])
        .map_err(|_| api_error())?;
        let routes = CommandCodeRouteSet::production()?;
        let target = routes.cookie_target()?;
        let mut saw_cookie_data = false;
        for (index, profile) in report.profiles().iter().enumerate() {
            let source = browser_source(index)?;
            let Ok(import) = import_browser_cookies_merging_chromium_stores_with_decryptor(
                profile, source, &allowlist, decryptor,
            ) else {
                continue;
            };
            let order = CookieImportOrder::new([source]).map_err(|_| api_error())?;
            let jar = CookieJar::from_imports(&order, [import]).map_err(|_| parse_error())?;
            saw_cookie_data |= !jar.is_empty();
            let Some(header) = jar.header_for(&target, now).map_err(|_| api_error())? else {
                continue;
            };
            return Self::build(
                scope,
                ProviderSource::BrowserSession,
                routes,
                Zeroizing::new(header.expose().to_owned()),
            );
        }
        drop(scope);
        Err(ClassifiedError::new(if saw_cookie_data {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::MissingCredential
        }))
    }

    /// Creates a browser adapter using an injected route table.
    ///
    /// # Errors
    ///
    /// Returns stable cookie, source, scope, or endpoint errors.
    #[doc(hidden)]
    pub fn from_browser_jar_routes(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        routes: CommandCodeRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let target = routes.cookie_target()?;
        let selected = jar.header_for(&target, now).map_err(|_| api_error())?;
        let Some(selected) = selected else {
            return Err(ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            }));
        };
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            routes,
            Zeroizing::new(selected.expose().to_owned()),
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: CommandCodeRouteSet,
        cookie: Zeroizing<String>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::CommandCode
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
        {
            return Err(api_error());
        }
        routes.validate()?;
        Authentication::cookie(cookie.as_str().to_owned()).map_err(|error| error.classified())?;
        let transport = HttpTransport::new(routes.endpoint_policy()?, transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            routes,
            cookie,
            transport,
        })
    }

    /// Fetches required credits and concurrently enriches them with bounded
    /// optional subscription metadata.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, API, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.fetch_at_with_subscription_grace(context, fetched_at, DEFAULT_SUBSCRIPTION_GRACE)
            .await
    }

    /// Fetches with an injected post-credits grace period for deterministic tests.
    ///
    /// # Errors
    ///
    /// Returns the same stable errors as [`Self::fetch_at`].
    #[doc(hidden)]
    pub async fn fetch_at_with_subscription_grace(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
        grace: Duration,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }

        let credits_request = self.request(self.routes.credits.clone())?;
        let subscription_request = self.request(self.routes.subscriptions.clone())?;
        let credits_future = self
            .transport
            .send(&credits_request, context.cancellation());
        let subscription_future = self
            .transport
            .send(&subscription_request, context.cancellation());
        tokio::pin!(credits_future);
        tokio::pin!(subscription_future);

        let mut subscription_result: Option<Result<HttpResponse, TransportError>> = None;
        let credits_result = loop {
            tokio::select! {
                biased;
                () = context.cancellation().cancelled() => {
                    return Err(ClassifiedError::new(ErrorKind::Network));
                }
                result = &mut credits_future => break result,
                result = &mut subscription_future, if subscription_result.is_none() => {
                    subscription_result = Some(result);
                }
            }
        };
        let credits = credits_result.map_err(classify_required_transport)?;

        if context.cancellation().is_cancelled() {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }

        if subscription_result.is_none() {
            let deadline = tokio::time::sleep(grace);
            tokio::pin!(deadline);
            subscription_result = tokio::select! {
                biased;
                () = context.cancellation().cancelled() => {
                    return Err(ClassifiedError::new(ErrorKind::Network));
                }
                result = &mut subscription_future => Some(result),
                () = &mut deadline => None,
            };
        }
        if context.cancellation().is_cancelled() {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }

        let (subscription_body, subscription_unavailable) = match subscription_result.as_ref() {
            Some(Ok(response)) => (Some(response.body()), false),
            Some(Err(_)) | None => (None, true),
        };
        parse_commandcode_responses(
            context.scope().clone(),
            fetched_at,
            credits.body(),
            subscription_body,
            subscription_unavailable,
            self.source,
        )
    }

    fn request(&self, url: Url) -> Result<HttpRequest, ClassifiedError> {
        let authentication = Authentication::cookie(self.cookie.as_str().to_owned())
            .map_err(|error| error.classified())?;
        HttpRequest::get(url)
            .accept(RequestAccept::JsonTextAny)
            .public_header("accept-language", "en-US,en;q=0.9")
            .and_then(|request| request.public_header("user-agent", USER_AGENT))
            .and_then(|request| request.public_header("origin", WEB_ORIGIN))
            .and_then(|request| request.public_header("referer", "https://commandcode.ai/"))
            .map(|request| request.authentication(authentication))
            .map_err(|error| error.classified())
    }

    /// Credential source bound to this adapter.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }
}

fn browser_source(index: usize) -> Result<CookieSourceId, ClassifiedError> {
    index
        .checked_add(1)
        .and_then(|value| u16::try_from(value).ok())
        .map(CookieSourceId::new)
        .ok_or_else(parse_error)
}

impl ProviderAdapter for CommandCodeProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::CommandCode)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for CommandCodeProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandCodeProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("cookie", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy)]
struct Plan {
    id: &'static str,
    name: &'static str,
    monthly_total: Decimal,
}

const PLANS: [Plan; 6] = [
    Plan {
        id: "individual-go",
        name: "Go",
        monthly_total: Decimal::TEN,
    },
    Plan {
        id: "individual-goat",
        name: "GOAT",
        monthly_total: Decimal::from_parts(70, 0, 0, false, 0),
    },
    Plan {
        id: "individual-pro",
        name: "Pro",
        monthly_total: Decimal::from_parts(30, 0, 0, false, 0),
    },
    Plan {
        id: "individual-pro-v1",
        name: "Pro",
        monthly_total: Decimal::from_parts(80, 0, 0, false, 0),
    },
    Plan {
        id: "individual-max",
        name: "Max",
        monthly_total: Decimal::from_parts(150, 0, 0, false, 0),
    },
    Plan {
        id: "individual-ultra",
        name: "Ultra",
        monthly_total: Decimal::from_parts(300, 0, 0, false, 0),
    },
];

struct Credits {
    monthly_remaining: Decimal,
    purchased: Decimal,
    premium: Decimal,
    opensource: Decimal,
    five_hour: Option<ParsedWindow>,
    weekly: Option<ParsedWindow>,
}

struct ParsedWindow {
    cap: Decimal,
    used: Decimal,
    resets_at: Option<Timestamp>,
    seconds: u64,
}

struct Subscription {
    plan_id: String,
    status: String,
    period_end: Option<Timestamp>,
}

/// Parses required credits and optional subscription enrichment into the common model.
/// Invalid optional enrichment is marked unavailable without discarding valid credits.
///
/// # Errors
///
/// Returns stable source/scope, bounded parse, or unknown-active-plan failures.
pub fn parse_commandcode_responses(
    scope: AccountScope,
    fetched_at: Timestamp,
    credits_body: &[u8],
    subscription_body: Option<&[u8]>,
    subscription_unavailable: bool,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope_source(&scope, source)?;
    let credits = parse_credits(credits_body)?;
    let (subscription, subscription_unavailable) = match subscription_body {
        Some(body) => match parse_subscription(body) {
            Ok(subscription) => (subscription, subscription_unavailable),
            Err(_) => (None, true),
        },
        // The pinned provider recognizes the free tier only from an explicit
        // successful `data: null` envelope. An absent response is unavailable,
        // regardless of a caller-provided marker.
        None => (None, true),
    };
    normalize_usage(
        scope,
        fetched_at,
        &credits,
        subscription.as_ref(),
        subscription_unavailable,
        source,
    )
}

fn parse_credits(body: &[u8]) -> Result<Credits, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let root = root.as_object().ok_or_else(parse_error)?;
    let credits = root
        .get("credits")
        .and_then(Value::as_object)
        .ok_or_else(parse_error)?;
    let monthly_remaining = required_decimal(credits, "monthlyCredits")?;
    let purchased = optional_decimal(credits.get("purchasedCredits")).unwrap_or(Decimal::ZERO);
    let premium = optional_decimal(credits.get("premiumMonthlyCredits")).unwrap_or(Decimal::ZERO);
    let opensource =
        optional_decimal(credits.get("opensourceMonthlyCredits")).unwrap_or(Decimal::ZERO);
    let limits = root
        .get("windowLimits")
        .and_then(Value::as_object)
        .or_else(|| credits.get("windowLimits").and_then(Value::as_object));
    Ok(Credits {
        monthly_remaining,
        purchased,
        premium,
        opensource,
        five_hour: parse_window(limits.and_then(|limits| limits.get("fiveHour")), 5 * 60),
        weekly: parse_window(limits.and_then(|limits| limits.get("weekly")), 7 * 24 * 60),
    })
}

fn parse_window(value: Option<&Value>, minutes: u64) -> Option<ParsedWindow> {
    let value = value?.as_object()?;
    let cap = optional_decimal(value.get("cap"))?;
    if cap <= Decimal::ZERO {
        return None;
    }
    let used = optional_decimal(value.get("used")).unwrap_or(Decimal::ZERO);
    let seconds = minutes.checked_mul(60)?;
    Some(ParsedWindow {
        cap,
        used,
        resets_at: value.get("resetAt").and_then(optional_timestamp),
        seconds,
    })
}

fn parse_subscription(body: &[u8]) -> Result<Option<Subscription>, ClassifiedError> {
    let root = parse_bounded_json(body)?;
    let root = root.as_object().ok_or_else(parse_error)?;
    if root.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(parse_error());
    }
    let data = root.get("data").ok_or_else(parse_error)?;
    if data.is_null() {
        return Ok(None);
    }
    let data = data.as_object().ok_or_else(parse_error)?;
    let plan_id = data
        .get("planId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(parse_error)?
        .to_owned();
    let status = data
        .get("status")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= 256)
        .unwrap_or("unknown")
        .to_owned();
    Ok(Some(Subscription {
        plan_id,
        status,
        period_end: data.get("currentPeriodEnd").and_then(optional_timestamp),
    }))
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    credits: &Credits,
    subscription: Option<&Subscription>,
    subscription_unavailable: bool,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    let plan = subscription.and_then(|subscription| plan_for(&subscription.plan_id));
    if subscription.is_some_and(|subscription| subscription.status.to_lowercase() == "active")
        && plan.is_none()
    {
        return Err(parse_error());
    }

    let primary = credits
        .five_hour
        .as_ref()
        .map(normalize_window)
        .transpose()?;
    let secondary = credits.weekly.as_ref().map(normalize_window).transpose()?;
    let tertiary = monthly_window(
        credits,
        plan,
        subscription.and_then(|value| value.period_end),
    )?;
    let login_method = login_method(credits, plan)?;
    let extension = commandcode_extension(
        credits,
        subscription_unavailable,
        plan.is_some(),
        credits.monthly_remaining <= Decimal::ZERO,
    )?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(login_method)?
        .subscription_renews_at(subscription.and_then(|value| value.period_end))
        .extensions(vec![extension])
        .provenance(
            "commandcode",
            if source == ProviderSource::ManualCookie {
                "manual_cookie"
            } else {
                "browser_session"
            },
        )?;
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    if let Some(tertiary) = tertiary {
        builder = builder.tertiary(tertiary);
    }
    builder.build()
}

fn normalize_window(window: &ParsedWindow) -> Result<RateWindow, ClassifiedError> {
    let percent = decimal_percent(window.used, window.cap)?;
    let duration = WindowDuration::from_seconds(window.seconds).map_err(|_| parse_error())?;
    RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        window.resets_at,
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn monthly_window(
    credits: &Credits,
    plan: Option<Plan>,
    period_end: Option<Timestamp>,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let percent = if let Some(plan) = plan {
        let used = (plan.monthly_total - credits.monthly_remaining)
            .clamp(Decimal::ZERO, plan.monthly_total);
        decimal_percent(used, plan.monthly_total)?
    } else if credits.monthly_remaining > Decimal::ZERO || credits.purchased > Decimal::ZERO {
        UsagePercent::new(0.0).map_err(|_| parse_error())?
    } else {
        return Ok(None);
    };
    let duration = WindowDuration::from_seconds(MONTH_SECONDS).map_err(|_| parse_error())?;
    RateWindow::new(
        WindowUsage::known(percent),
        Some(duration),
        period_end,
        None,
        None,
        false,
    )
    .map(Some)
    .map_err(|_| parse_error())
}

fn login_method(credits: &Credits, plan: Option<Plan>) -> Result<Option<String>, ClassifiedError> {
    let mut parts = Vec::new();
    if let Some(plan) = plan {
        parts.push(plan.name.to_owned());
        let used = (plan.monthly_total - credits.monthly_remaining)
            .clamp(Decimal::ZERO, plan.monthly_total);
        parts.push(format!(
            "{} of {}",
            format_usd(used)?,
            format_usd(plan.monthly_total)?
        ));
    } else if credits.monthly_remaining > Decimal::ZERO {
        parts.push(format!(
            "{} remaining",
            format_usd(credits.monthly_remaining)?
        ));
    }
    if credits.purchased > Decimal::ZERO {
        parts.push(format!("+ {} credits", format_usd(credits.purchased)?));
    }
    Ok((!parts.is_empty()).then(|| parts.join(" · ")))
}

fn commandcode_extension(
    credits: &Credits,
    subscription_unavailable: bool,
    has_plan: bool,
    monthly_depleted: bool,
) -> Result<ProviderExtension, ClassifiedError> {
    let mut facts = [
        (
            "subscription_enrichment_unavailable",
            "Subscription enrichment unavailable",
            subscription_unavailable,
        ),
        ("has_subscription_plan", "Has subscription plan", has_plan),
        (
            "monthly_grant_depleted",
            "Monthly grant depleted",
            monthly_depleted,
        ),
    ]
    .into_iter()
    .map(|(key, label, value)| {
        ExtensionFact::new(
            key,
            label,
            ExtensionValue::Boolean { value },
            DetailSensitivity::Public,
        )
        .map_err(|_| parse_error())
    })
    .collect::<Result<Vec<_>, _>>()?;
    for (key, label, value) in [
        (
            "monthly_credits_remaining",
            "Monthly credits remaining",
            credits.monthly_remaining,
        ),
        ("purchased_credits", "Purchased credits", credits.purchased),
        (
            "premium_monthly_credits",
            "Premium monthly credits",
            credits.premium,
        ),
        (
            "opensource_monthly_credits",
            "Open-source monthly credits",
            credits.opensource,
        ),
    ] {
        facts.push(
            ExtensionFact::new(
                key,
                label,
                ExtensionValue::Decimal {
                    value: ExactDecimal::new(value),
                },
                DetailSensitivity::Personal,
            )
            .map_err(|_| parse_error())?,
        );
    }
    ProviderExtension::new(ProviderExtensionKind::CommandCodeMarkers, facts, Vec::new())
        .map_err(|_| parse_error())
}

fn plan_for(plan_id: &str) -> Option<Plan> {
    PLANS
        .iter()
        .copied()
        .find(|plan| plan.id.eq_ignore_ascii_case(plan_id))
}

fn decimal_percent(used: Decimal, limit: Decimal) -> Result<UsagePercent, ClassifiedError> {
    let hundred = Decimal::from(100_u8);
    let percent = if limit > Decimal::ZERO {
        (used * hundred / limit)
            .clamp(Decimal::ZERO, hundred)
            .to_f64()
            .ok_or_else(parse_error)?
    } else {
        0.0
    };
    UsagePercent::new(percent).map_err(|_| parse_error())
}

fn format_usd(value: Decimal) -> Result<String, ClassifiedError> {
    let scale = if value < Decimal::from(100_u8) { 2 } else { 0 };
    let rounded = value.round_dp(scale);
    let plain = if scale == 2 {
        format!("{rounded:.2}")
    } else {
        format!("{rounded:.0}")
    };
    let (integer, fraction) = plain
        .split_once('.')
        .map_or((plain.as_str(), None), |(integer, fraction)| {
            (integer, Some(fraction))
        });
    let (sign, digits) = integer
        .strip_prefix('-')
        .map_or(("", integer), |digits| ("-", digits));
    if digits.len() > 48 {
        return Err(parse_error());
    }
    let mut grouped = String::with_capacity(plain.len() + plain.len() / 3 + 1);
    grouped.push('$');
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
    Ok(grouped)
}

fn required_decimal(object: &Map<String, Value>, key: &str) -> Result<Decimal, ClassifiedError> {
    optional_decimal(object.get(key)).ok_or_else(parse_error)
}

fn optional_decimal(value: Option<&Value>) -> Option<Decimal> {
    let text = match value? {
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.trim().to_owned(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => return None,
    };
    if text.is_empty() || text.len() > 128 {
        return None;
    }
    let value = text.parse::<Decimal>().ok()?;
    (value.abs() <= Decimal::from(MAX_AMOUNT)).then_some(value)
}

fn optional_timestamp(value: &Value) -> Option<Timestamp> {
    if let Some(mut numeric) = optional_decimal(Some(value)) {
        if numeric <= Decimal::ZERO {
            return None;
        }
        if numeric > Decimal::from(10_000_000_000_i64) {
            numeric /= Decimal::from(1_000_u16);
        }
        let nanoseconds = (numeric * Decimal::from(1_000_000_000_u64))
            .trunc()
            .to_i128()?;
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(nanoseconds).ok()?;
        return Timestamp::new(timestamp).ok();
    }
    let Value::String(value) = value else {
        return None;
    };
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    Timestamp::parse(value).ok()
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

fn fixed_url(mut origin: Url, path: &str) -> Result<Url, ClassifiedError> {
    if origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.fragment().is_some()
    {
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

fn is_bare_token(value: &str) -> bool {
    !value.contains('=') && !value.contains(';') && !value.contains(char::is_whitespace)
}

fn validate_scope_source(
    scope: &AccountScope,
    source: ProviderSource,
) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::CommandCode
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

fn classify_required_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        TransportError::RequestTimeout
        | TransportError::RateLimited { .. }
        | TransportError::ProviderUnavailable { .. } => ClassifiedError::new(ErrorKind::Api),
        TransportError::TooManyRedirects => ClassifiedError::new(ErrorKind::Network),
        other => other.classified(),
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
