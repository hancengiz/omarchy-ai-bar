//! Native Mistral billing-usage, monthly-plan, and credit-balance adapter.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostProvenance, CostUnit, CostUsageCoverage,
    CostUsageDailyBucket, CostUsageMetrics, CostUsageModelBreakdown, CostUsageSnapshot,
    CostUsageTokenMix, CurrencyCode, ErrorKind, ExactDecimal, Money, NamedRateWindow, ProviderId,
    RateWindow, Timestamp, UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::Value;
use time::{Date, Duration as TimeDuration, Month, OffsetDateTime, PrimitiveDateTime, Time};
use tokio::time::Instant;
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
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig, TransportError,
};

const ADMIN_ORIGIN: &str = "https://admin.mistral.ai";
const CONSOLE_ORIGIN: &str = "https://console.mistral.ai";
const USAGE_PATH: &str = "/api/billing/v2/usage";
const CREDITS_PATH: &str = "/api/billing/credits";
const VIBE_PATH: &str = "/api-ui/trpc/billing.vibeUsage";
const VIBE_QUERY: &str = "batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%2C%22meta%22%3A%7B%22values%22%3A%5B%22undefined%22%5D%2C%22v%22%3A1%7D%7D%7D";
const USAGE_REFERER: &str = "https://admin.mistral.ai/organization/usage";
const BILLING_REFERER: &str = "https://admin.mistral.ai/organization/billing";
const SESSION_COOKIE_PREFIX: &str = "ory_session_";
const CSRF_COOKIE_NAME: &str = "csrftoken";
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
const OPTIONAL_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_USAGE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_OPTIONAL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 65_536;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_COOKIE_HEADER_BYTES: usize = 16 * 1024;
const MAX_COOKIE_VALUE_BYTES: usize = 8 * 1024;
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_MODELS: usize = 128;
const MAX_MODEL_NAME_BYTES: usize = 160;
const MAX_ENTRIES: usize = 32_768;
const MAX_PRICES: usize = 1_024;
const MAX_DAILY_BUCKETS: usize = 365;
const HISTORY_DAYS: u16 = 30;

struct Routes {
    usage: Url,
    credits: Url,
    vibe: Url,
}

/// Fixed Mistral admin and console routing.
///
/// Production construction pins both baseline HTTPS origins. The loopback
/// constructor is an explicit seam for deterministic local tests only.
pub struct MistralRouteSet {
    routes: Routes,
    class: EndpointClass,
}

impl MistralRouteSet {
    fn production() -> Result<Self, ClassifiedError> {
        Self::from_origins(
            Url::parse(ADMIN_ORIGIN).map_err(|_| api_error())?,
            Url::parse(CONSOLE_ORIGIN).map_err(|_| api_error())?,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates exact admin and console loopback origins for HTTP tests.
    ///
    /// # Errors
    ///
    /// Rejects non-origin, credential-bearing, or non-loopback URLs.
    #[doc(hidden)]
    pub fn loopback(admin_origin: Url, console_origin: Url) -> Result<Self, ClassifiedError> {
        Self::from_origins(
            admin_origin,
            console_origin,
            EndpointClass::LoopbackDevelopment,
        )
    }

    fn from_origins(
        admin_origin: Url,
        console_origin: Url,
        class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        validate_bare_origin(&admin_origin, class)?;
        validate_bare_origin(&console_origin, class)?;
        if class == EndpointClass::PublicHttps
            && (!same_origin(&admin_origin, ADMIN_ORIGIN)?
                || !same_origin(&console_origin, CONSOLE_ORIGIN)?)
        {
            return Err(api_error());
        }
        if !matches!(
            class,
            EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
        ) {
            return Err(api_error());
        }
        let usage = with_path(admin_origin.clone(), USAGE_PATH);
        let credits = with_path(admin_origin, CREDITS_PATH);
        let mut vibe = with_path(console_origin, VIBE_PATH);
        vibe.set_query(Some(VIBE_QUERY));
        Ok(Self {
            routes: Routes {
                usage,
                credits,
                vibe,
            },
            class,
        })
    }

    fn endpoint_policy(&self) -> Result<EndpointPolicy, ClassifiedError> {
        EndpointPolicy::new([
            (self.routes.usage.origin().ascii_serialization(), self.class),
            (self.routes.vibe.origin().ascii_serialization(), self.class),
        ])
        .map_err(|_| api_error())
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

impl Debug for MistralRouteSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MistralRouteSet")
            .field("routes", &"<redacted>")
            .field("class", &self.class)
            .finish()
    }
}

struct SessionCredential {
    admin_cookie: Zeroizing<String>,
    csrf_token: Option<Zeroizing<String>>,
    console_cookie: Option<Zeroizing<String>>,
}

impl Debug for SessionCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredential")
            .field("admin_cookie", &"<redacted>")
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "console_cookie",
                &self.console_cookie.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Mistral adapter bound to one account and one explicit web-session source.
pub struct MistralProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: MistralRouteSet,
    sessions: Vec<SessionCredential>,
    required_transport: HttpTransport,
    optional_transport: HttpTransport,
}

impl MistralProvider {
    /// Creates the production manual-cookie adapter from a Cookie header or
    /// inert cURL capture.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or configuration failure.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        Self::from_manual_capture_routes(scope, raw, MistralRouteSet::production()?)
    }

    /// Creates a manual adapter with injected fixed transport routes.
    ///
    /// A captured cURL URL, if present, must still target an exact production
    /// Mistral host. Only the rebuilt request uses the injected route.
    ///
    /// # Errors
    ///
    /// Returns stable redacted capture or configuration failures.
    #[doc(hidden)]
    pub fn from_manual_capture_routes(
        scope: AccountScope,
        raw: &str,
        routes: MistralRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(
            [
                "mistral.ai",
                "admin.mistral.ai",
                "auth.mistral.ai",
                "console.mistral.ai",
            ],
            [CaptureHeader::Cookie],
        )
        .map_err(classify_capture_error)?
        .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let session = manual_session(&routes, cookie)?;
        Self::build(scope, ProviderSource::ManualCookie, routes, vec![session])
    }

    /// Creates the production browser-session adapter from one injected jar.
    ///
    /// # Errors
    ///
    /// Returns a stable missing, expired, or configuration failure.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::new_browser_sessions(scope, &[jar], now)
    }

    /// Creates the production browser adapter from ordered, isolated profile
    /// jars. Profiles remain isolated and are attempted in the supplied order.
    ///
    /// # Errors
    ///
    /// Returns a stable missing, expired, or configuration failure.
    pub fn new_browser_sessions(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        Self::from_browser_jars_routes(scope, jars, now, MistralRouteSet::production()?)
    }

    /// Creates a browser adapter with injected fixed routes.
    ///
    /// # Errors
    ///
    /// Returns a stable failure when no ordered jar supplies an active,
    /// admin-targeted `ory_session_*` cookie.
    #[doc(hidden)]
    pub fn from_browser_jars_routes(
        scope: AccountScope,
        jars: &[&CookieJar],
        now: OffsetDateTime,
        routes: MistralRouteSet,
    ) -> Result<Self, ClassifiedError> {
        let sessions = browser_sessions(&routes, jars, now)?;
        Self::build(scope, ProviderSource::BrowserSession, routes, sessions)
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        routes: MistralRouteSet,
        sessions: Vec<SessionCredential>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Mistral
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
            || sessions.is_empty()
        {
            return Err(api_error());
        }
        let policy = routes.endpoint_policy()?;
        for endpoint in [
            &routes.routes.usage,
            &routes.routes.credits,
            &routes.routes.vibe,
        ] {
            policy.validate(endpoint).map_err(|_| api_error())?;
        }
        let required_transport = HttpTransport::new(policy.clone(), required_transport_config()?)
            .map_err(|error| error.classified())?;
        let optional_transport = HttpTransport::new(policy, optional_transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            routes,
            sessions,
            required_transport,
            optional_transport,
        })
    }

    /// Source to which this adapter is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Fetches current-month billing usage and best-effort Vibe/credit
    /// enrichments at an injected UTC instant.
    ///
    /// Browser sessions advance only after an HTTP 401 or 403 from the
    /// required usage endpoint. Optional endpoint failures never discard a
    /// valid required response, while cooperative cancellation always wins.
    ///
    /// # Errors
    ///
    /// Returns stable scope, credential, network, status, or bounded-parse
    /// failures without provider body or cookie text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(api_error());
        }
        let mut selected = None;
        let mut billing_body = None;
        for session in &self.sessions {
            let deadline = Instant::now() + TOTAL_TIMEOUT;
            match self
                .send_usage(context, session, fetched_at, deadline)
                .await
            {
                Ok(body) => {
                    selected = Some((session, deadline));
                    billing_body = Some(body);
                    break;
                }
                Err(TransportError::AuthenticationExpired | TransportError::PermissionDenied) => {}
                Err(error) => return Err(classify_required_transport(&error)),
            }
        }
        let (session, deadline) =
            selected.ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))?;
        let billing_body = billing_body.ok_or_else(api_error)?;
        let billing = parse_billing(&billing_body)?;

        let vibe = if let Some(cookie) = session.console_cookie.as_deref() {
            self.fetch_optional_vibe(
                context,
                cookie,
                session.csrf_token.as_ref().map(|value| value.as_str()),
                deadline,
            )
            .await?
        } else {
            None
        };
        let credits = self
            .fetch_optional_credits(context, session, deadline)
            .await?;
        normalize_usage(
            self.scope.clone(),
            fetched_at,
            self.source,
            &billing,
            vibe,
            credits,
        )
    }

    async fn send_usage(
        &self,
        context: &ProviderContext,
        session: &SessionCredential,
        fetched_at: Timestamp,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError> {
        let mut url = self.routes.routes.usage.clone();
        let now = fetched_at.as_offset_date_time();
        url.query_pairs_mut().clear().extend_pairs([
            ("month", u8::from(now.month()).to_string()),
            ("year", now.year().to_string()),
        ]);
        let mut request = HttpRequest::get(url)
            .accept(RequestAccept::Any)
            .public_header("referer", USAGE_REFERER)?
            .public_header("origin", ADMIN_ORIGIN)?;
        if let Some(csrf) = session.csrf_token.as_deref() {
            request = request.sensitive_header("x-csrftoken", csrf.to_owned())?;
        }
        request = request.authentication(Authentication::cookie(
            session.admin_cookie.as_str().to_owned(),
        )?);
        let response = tokio::time::timeout_at(
            deadline,
            self.required_transport
                .send(&request, context.cancellation()),
        )
        .await
        .map_err(|_| TransportError::Timeout)??;
        if response.status() != 200 {
            return Err(TransportError::Api {
                status: response.status(),
            });
        }
        Ok(response.body().to_vec())
    }

    async fn fetch_optional_vibe(
        &self,
        context: &ProviderContext,
        cookie: &str,
        csrf: Option<&str>,
        deadline: Instant,
    ) -> Result<Option<VibeUsage>, ClassifiedError> {
        let Some(csrf) = csrf else {
            return Ok(None);
        };
        let Some(remaining) = optional_remaining(deadline) else {
            return Ok(None);
        };
        let request = HttpRequest::get(self.routes.routes.vibe.clone())
            .accept(RequestAccept::Any)
            .sensitive_header("x-csrftoken", csrf.to_owned())
            .map_err(|error| error.classified())?
            .authentication(
                Authentication::cookie(cookie.to_owned()).map_err(|error| error.classified())?,
            );
        let result = tokio::time::timeout(
            remaining,
            self.optional_transport
                .send(&request, context.cancellation()),
        )
        .await;
        match result {
            Ok(Ok(response)) if response.status() == 200 => Ok(parse_vibe(response.body()).ok()),
            Ok(Err(TransportError::Cancelled)) => Err(network_error()),
            Err(_) if context.cancellation().is_cancelled() => Err(network_error()),
            Ok(Ok(_) | Err(_)) | Err(_) => Ok(None),
        }
    }

    async fn fetch_optional_credits(
        &self,
        context: &ProviderContext,
        session: &SessionCredential,
        deadline: Instant,
    ) -> Result<Option<Credits>, ClassifiedError> {
        let Some(remaining) = optional_remaining(deadline) else {
            return Ok(None);
        };
        let mut request = HttpRequest::get(self.routes.routes.credits.clone())
            .accept(RequestAccept::Any)
            .public_header("referer", BILLING_REFERER)
            .and_then(|request| request.public_header("origin", ADMIN_ORIGIN))
            .map_err(|error| error.classified())?;
        if let Some(csrf) = session.csrf_token.as_deref() {
            request = request
                .sensitive_header("x-csrftoken", csrf.to_owned())
                .map_err(|error| error.classified())?;
        }
        request = request.authentication(
            Authentication::cookie(session.admin_cookie.as_str().to_owned())
                .map_err(|error| error.classified())?,
        );
        let result = tokio::time::timeout(
            remaining,
            self.optional_transport
                .send(&request, context.cancellation()),
        )
        .await;
        match result {
            Ok(Ok(response)) if response.status() == 200 => Ok(parse_credits(response.body()).ok()),
            Ok(Err(TransportError::Cancelled)) => Err(network_error()),
            Err(_) if context.cancellation().is_cancelled() => Err(network_error()),
            Ok(Ok(_) | Err(_)) | Err(_) => Ok(None),
        }
    }
}

impl ProviderAdapter for MistralProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Mistral)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for MistralProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MistralProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("session_count", &self.sessions.len())
            .field("required_transport", &"<redacted>")
            .field("optional_transport", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
struct BillingResponse {
    completion: Option<ModelCategory>,
    ocr: Option<ModelCategory>,
    connectors: Option<ModelCategory>,
    #[serde(rename = "libraries_api")]
    libraries_api: Option<LibrariesCategory>,
    #[serde(rename = "fine_tuning")]
    fine_tuning: Option<FineTuningCategory>,
    audio: Option<ModelCategory>,
    #[serde(rename = "start_date")]
    start_date: Option<String>,
    #[serde(rename = "end_date")]
    end_date: Option<String>,
    currency: Option<String>,
    #[serde(rename = "currency_symbol")]
    currency_symbol: Option<String>,
    prices: Option<Vec<PriceDefinition>>,
}

#[derive(Deserialize)]
struct ModelCategory {
    models: Option<BTreeMap<String, ModelUsage>>,
}

#[derive(Deserialize)]
struct LibrariesCategory {
    pages: Option<ModelCategory>,
    tokens: Option<ModelCategory>,
}

#[derive(Deserialize)]
struct FineTuningCategory {
    training: Option<BTreeMap<String, ModelUsage>>,
    storage: Option<BTreeMap<String, ModelUsage>>,
}

#[derive(Deserialize)]
struct ModelUsage {
    input: Option<Vec<UsageEntry>>,
    output: Option<Vec<UsageEntry>>,
    cached: Option<Vec<UsageEntry>>,
}

#[derive(Deserialize)]
struct UsageEntry {
    #[serde(rename = "billing_metric")]
    billing_metric: Option<String>,
    #[serde(rename = "billing_display_name")]
    billing_display_name: Option<String>,
    #[serde(rename = "billing_group")]
    billing_group: Option<String>,
    timestamp: Option<String>,
    value: Option<i64>,
    #[serde(rename = "value_paid")]
    value_paid: Option<i64>,
}

#[derive(Deserialize)]
struct PriceDefinition {
    #[serde(rename = "billing_metric")]
    billing_metric: Option<String>,
    #[serde(rename = "billing_group")]
    billing_group: Option<String>,
    #[serde(rename = "price")]
    raw_value: Option<String>,
}

#[derive(Default, Clone)]
struct TokenAccumulator {
    input: i128,
    output: i128,
    cached: i128,
    overflowed: bool,
}

impl TokenAccumulator {
    fn add(&mut self, kind: TokenKind, value: i64) {
        let destination = match kind {
            TokenKind::Input => &mut self.input,
            TokenKind::Output => &mut self.output,
            TokenKind::Cached => &mut self.cached,
        };
        if let Some(total) = destination.checked_add(i128::from(value)) {
            *destination = total;
        } else {
            self.overflowed = true;
        }
    }

    fn merge(&mut self, other: &Self) {
        self.overflowed |= other.overflowed;
        for (destination, value) in [
            (&mut self.input, other.input),
            (&mut self.output, other.output),
            (&mut self.cached, other.cached),
        ] {
            if let Some(total) = destination.checked_add(value) {
                *destination = total;
            } else {
                self.overflowed = true;
            }
        }
    }

    fn is_nonnegative(&self) -> bool {
        !self.overflowed && self.input >= 0 && self.output >= 0 && self.cached >= 0
    }

    fn total_u64(&self) -> Option<u64> {
        let total = self
            .input
            .checked_add(self.output)?
            .checked_add(self.cached)?;
        (!self.overflowed && total >= 0)
            .then(|| u64::try_from(total).ok())
            .flatten()
    }

    fn token_mix(&self, complete: bool) -> CostUsageTokenMix {
        if !complete {
            return CostUsageTokenMix::default();
        }
        CostUsageTokenMix::new(
            u64::try_from(self.input).ok(),
            u64::try_from(self.output).ok(),
            u64::try_from(self.cached).ok(),
            None,
            None,
        )
    }
}

#[derive(Clone, Copy)]
enum TokenKind {
    Input,
    Output,
    Cached,
}

#[derive(Default)]
struct ModelAccumulator {
    cost: Decimal,
    tokens: TokenAccumulator,
}

#[derive(Default)]
struct DailyAccumulator {
    cost: Decimal,
    tokens: TokenAccumulator,
    models: BTreeMap<String, ModelAccumulator>,
}

struct BillingAggregate {
    total_cost: Decimal,
    total_tokens: TokenAccumulator,
    daily: BTreeMap<String, DailyAccumulator>,
    start_date: Option<Timestamp>,
    end_date: Option<Timestamp>,
    currency: CurrencyCode,
    currency_symbol: String,
}

struct VibeUsage {
    percent: f64,
    reset_at: Option<Timestamp>,
}

struct Credits {
    available: Decimal,
    currency: CurrencyCode,
}

#[derive(Deserialize)]
struct VibeEnvelope {
    result: VibeResult,
}

#[derive(Deserialize)]
struct VibeResult {
    data: VibeData,
}

#[derive(Deserialize)]
struct VibeData {
    json: VibeJson,
}

#[derive(Deserialize)]
struct VibeJson {
    #[serde(rename = "usage_percentage")]
    usage_percentage: f64,
    #[serde(rename = "reset_at")]
    reset_at: Option<String>,
}

/// Parses one required Mistral billing response without optional enrichments.
///
/// This deterministic seam is used by fixture tests and applies the same
/// account/source and bounded-normalization rules as the network adapter.
///
/// # Errors
///
/// Returns stable scope or parse failures without response text.
pub fn parse_billing_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Mistral
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(api_error());
    }
    let billing = parse_billing(body)?;
    normalize_usage(scope, fetched_at, source, &billing, None, None)
}

fn parse_billing(body: &[u8]) -> Result<BillingAggregate, ClassifiedError> {
    let root = parse_bounded_json(body, MAX_USAGE_RESPONSE_BYTES)?;
    let billing: BillingResponse = serde_json::from_value(root).map_err(|_| parse_error())?;
    validate_billing_limits(&billing)?;

    let prices = build_price_index(billing.prices.as_deref().unwrap_or_default());
    let mut total_cost = Decimal::ZERO;
    let mut total_tokens = TokenAccumulator::default();
    let mut daily = BTreeMap::<String, DailyAccumulator>::new();

    if let Some(models) = billing
        .completion
        .as_ref()
        .and_then(|value| value.models.as_ref())
    {
        aggregate_models(
            models,
            &prices,
            true,
            &mut total_cost,
            &mut total_tokens,
            &mut daily,
        );
    }
    for category in [&billing.ocr, &billing.connectors, &billing.audio] {
        if let Some(models) = category.as_ref().and_then(|value| value.models.as_ref()) {
            aggregate_models(
                models,
                &prices,
                false,
                &mut total_cost,
                &mut total_tokens,
                &mut daily,
            );
        }
    }
    if let Some(libraries) = &billing.libraries_api {
        if let Some(models) = libraries
            .pages
            .as_ref()
            .and_then(|value| value.models.as_ref())
        {
            aggregate_models(
                models,
                &prices,
                false,
                &mut total_cost,
                &mut total_tokens,
                &mut daily,
            );
        }
        if let Some(models) = libraries
            .tokens
            .as_ref()
            .and_then(|value| value.models.as_ref())
        {
            aggregate_models(
                models,
                &prices,
                true,
                &mut total_cost,
                &mut total_tokens,
                &mut daily,
            );
        }
    }
    if let Some(fine_tuning) = &billing.fine_tuning {
        for models in [&fine_tuning.training, &fine_tuning.storage]
            .into_iter()
            .flatten()
        {
            aggregate_models(
                models,
                &prices,
                false,
                &mut total_cost,
                &mut total_tokens,
                &mut daily,
            );
        }
    }
    if daily.len() > MAX_DAILY_BUCKETS {
        return Err(parse_error());
    }

    let (currency, currency_symbol) = billing_currency(&billing)?;

    Ok(BillingAggregate {
        total_cost,
        total_tokens,
        daily,
        start_date: billing.start_date.as_deref().and_then(parse_timestamp),
        end_date: billing.end_date.as_deref().and_then(parse_timestamp),
        currency,
        currency_symbol,
    })
}

fn billing_currency(billing: &BillingResponse) -> Result<(CurrencyCode, String), ClassifiedError> {
    let raw_currency = billing.currency.as_deref().unwrap_or_default().trim();
    let currency = if raw_currency.is_empty() {
        CurrencyCode::new("XXX")
    } else {
        CurrencyCode::new(raw_currency)
    }
    .map_err(|_| parse_error())?;
    let symbol = billing
        .currency_symbol
        .as_deref()
        .unwrap_or_default()
        .trim();
    let currency_symbol = if symbol.is_empty() {
        match currency.as_str() {
            "EUR" => "€".to_owned(),
            "XXX" => "¤".to_owned(),
            value => value.to_owned(),
        }
    } else {
        if symbol.len() > MAX_MODEL_NAME_BYTES || symbol.chars().any(char::is_control) {
            return Err(parse_error());
        }
        symbol.to_owned()
    };
    Ok((currency, currency_symbol))
}

fn build_price_index(prices: &[PriceDefinition]) -> BTreeMap<String, Decimal> {
    let mut index = BTreeMap::new();
    for price in prices {
        let (Some(metric), Some(group), Some(raw)) = (
            price.billing_metric.as_deref(),
            price.billing_group.as_deref(),
            price.raw_value.as_deref(),
        ) else {
            continue;
        };
        let Some(value) = parse_decimal(raw) else {
            continue;
        };
        index.insert(format!("{metric}::{group}"), value);
    }
    index
}

fn aggregate_models(
    models: &BTreeMap<String, ModelUsage>,
    prices: &BTreeMap<String, Decimal>,
    counts_tokens: bool,
    total_cost: &mut Decimal,
    total_tokens: &mut TokenAccumulator,
    daily: &mut BTreeMap<String, DailyAccumulator>,
) {
    for (raw_model_name, model) in models {
        let mut model_cost = Decimal::ZERO;
        let mut model_tokens = TokenAccumulator::default();
        for (kind, entries) in model_entries(model) {
            for entry in entries {
                let units = entry.value_paid.or(entry.value).unwrap_or(0);
                let cost = entry_cost(entry, units, prices);
                accumulate_cost(&mut model_cost, cost);
                if counts_tokens {
                    model_tokens.add(kind, units);
                }
            }
        }
        accumulate_cost(total_cost, model_cost);
        if counts_tokens {
            total_tokens.merge(&model_tokens);
        }
        add_daily_entries(raw_model_name, model, prices, counts_tokens, daily);
    }
}

fn model_entries(model: &ModelUsage) -> [(TokenKind, &[UsageEntry]); 3] {
    [
        (TokenKind::Input, model.input.as_deref().unwrap_or_default()),
        (
            TokenKind::Output,
            model.output.as_deref().unwrap_or_default(),
        ),
        (
            TokenKind::Cached,
            model.cached.as_deref().unwrap_or_default(),
        ),
    ]
}

fn add_daily_entries(
    raw_model_name: &str,
    model: &ModelUsage,
    prices: &BTreeMap<String, Decimal>,
    counts_tokens: bool,
    daily: &mut BTreeMap<String, DailyAccumulator>,
) {
    for (kind, entries) in model_entries(model) {
        for entry in entries {
            let Some(day) = entry.timestamp.as_deref().and_then(day_key) else {
                continue;
            };
            let units = entry.value_paid.or(entry.value).unwrap_or(0);
            let cost = entry_cost(entry, units, prices);
            let name = display_model_name(raw_model_name, entry);
            let bucket = daily.entry(day.to_owned()).or_default();
            accumulate_cost(&mut bucket.cost, cost);
            let model = bucket.models.entry(name).or_default();
            accumulate_cost(&mut model.cost, cost);
            if counts_tokens {
                bucket.tokens.add(kind, units);
                model.tokens.add(kind, units);
            }
        }
    }
}

fn entry_cost(entry: &UsageEntry, units: i64, prices: &BTreeMap<String, Decimal>) -> Decimal {
    let (Some(metric), Some(group)) = (
        entry.billing_metric.as_deref(),
        entry.billing_group.as_deref(),
    ) else {
        return Decimal::ZERO;
    };
    let key = format!("{metric}::{group}");
    prices
        .get(&key)
        .and_then(|price| Decimal::from(units).checked_mul(*price))
        .unwrap_or(Decimal::ZERO)
}

fn accumulate_cost(total: &mut Decimal, value: Decimal) {
    if let Some(updated) = total.checked_add(value) {
        *total = updated;
    }
}

fn display_model_name(raw: &str, entry: &UsageEntry) -> String {
    entry
        .billing_display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| raw.split_once("::").map_or(raw, |(prefix, _)| prefix))
        .to_owned()
}

fn day_key(value: &str) -> Option<&str> {
    let value = value.trim();
    value.get(..10)
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    source: ProviderSource,
    billing: &BillingAggregate,
    vibe: Option<VibeUsage>,
    credits: Option<Credits>,
) -> Result<UsageSample, ClassifiedError> {
    let spend = if billing.total_cost > Decimal::ZERO {
        format!("{:.4}", billing.total_cost.round_dp(4))
    } else {
        "0.0000".to_owned()
    };
    let login = format!("API spend: {}{} this month", billing.currency_symbol, spend);
    let cost_usage = project_cost_usage(billing, fetched_at)?;

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(Some(login))?
        .cost_usage(cost_usage)
        .provenance("mistral", "web")?;
    if let Some(vibe) = vibe {
        let window = RateWindow::new(
            WindowUsage::known(UsagePercent::new(vibe.percent).map_err(|_| parse_error())?),
            None,
            vibe.reset_at,
            None,
            None,
            false,
        )
        .map_err(|_| parse_error())?;
        let named = NamedRateWindow::new(
            BoundedText::new("mistral-monthly-plan").map_err(|_| api_error())?,
            BoundedText::new("Monthly Plan").map_err(|_| api_error())?,
            window,
        );
        builder = builder.extra_windows(vec![named]);
    }
    if let Some(credits) = credits {
        builder = builder.balance(Money::new(
            ExactDecimal::new(credits.available),
            credits.currency,
        ));
    }
    if !matches!(
        source,
        ProviderSource::ManualCookie | ProviderSource::BrowserSession
    ) {
        return Err(api_error());
    }
    builder.build()
}

struct DailyWindow<'a> {
    selected: Vec<(Date, &'a str, &'a DailyAccumulator)>,
    invalid: Vec<(&'a str, &'a DailyAccumulator)>,
    covered_days: u16,
    coverage_established: bool,
    month_to_date: bool,
    observation_end: Date,
}

fn project_cost_usage(
    billing: &BillingAggregate,
    fetched_at: Timestamp,
) -> Result<CostUsageSnapshot, ClassifiedError> {
    let window = daily_window(billing, fetched_at)?;
    let cost_complete = cost_data_complete(billing, &window);
    let tokens_complete = token_data_complete(billing, &window);
    let coverage = CostUsageCoverage::new(0, 0, 0, 0).map_err(|_| parse_error())?;
    let daily = project_daily_buckets(&window, cost_complete, tokens_complete, coverage)?;

    let history_amount = if cost_complete {
        checked_cost_sum(window.selected.iter().map(|(_, _, bucket)| bucket.cost))
            .map(ExactDecimal::new)
    } else {
        None
    };
    let history_tokens = if tokens_complete {
        checked_token_sum(window.selected.iter().map(|(_, _, bucket)| &bucket.tokens))
    } else {
        None
    };
    let history_mix = if tokens_complete {
        sum_token_mix(window.selected.iter().map(|(_, _, bucket)| &bucket.tokens))?
    } else {
        CostUsageTokenMix::default()
    };
    let history =
        CostUsageMetrics::new(history_mix, history_tokens, None, history_amount, coverage)
            .map_err(|_| parse_error())?;

    let latest = window.selected.iter().max_by_key(|(date, _, _)| *date);
    let session = if let Some((_, _, bucket)) = latest {
        CostUsageMetrics::new(
            bucket.tokens.token_mix(tokens_complete),
            tokens_complete.then(|| bucket.tokens.total_u64()).flatten(),
            None,
            cost_complete.then_some(ExactDecimal::new(bucket.cost)),
            coverage,
        )
        .map_err(|_| parse_error())?
    } else {
        CostUsageMetrics::new(
            CostUsageTokenMix::default(),
            tokens_complete.then_some(0),
            None,
            cost_complete.then_some(ExactDecimal::new(Decimal::ZERO)),
            coverage,
        )
        .map_err(|_| parse_error())?
    };

    CostUsageSnapshot::new(
        CostUnit::currency(billing.currency.clone()),
        session,
        history,
        history_amount,
        window.covered_days,
        window.coverage_established,
        window.month_to_date.then(|| "This month".to_owned()),
        None,
        daily,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        day_timestamp(window.observation_end)?,
        CostProvenance::VendorMetered,
    )
    .map_err(|_| parse_error())
}

fn project_daily_buckets(
    window: &DailyWindow<'_>,
    cost_complete: bool,
    tokens_complete: bool,
    coverage: CostUsageCoverage,
) -> Result<Vec<CostUsageDailyBucket>, ClassifiedError> {
    let mut daily = Vec::with_capacity(window.selected.len());
    for (_date, day, bucket) in &window.selected {
        let metrics = CostUsageMetrics::new(
            bucket.tokens.token_mix(tokens_complete),
            tokens_complete.then(|| bucket.tokens.total_u64()).flatten(),
            None,
            cost_complete.then_some(ExactDecimal::new(bucket.cost)),
            coverage,
        )
        .map_err(|_| parse_error())?;
        let models = bucket
            .models
            .iter()
            .map(|(name, model)| {
                let metrics = CostUsageMetrics::new(
                    model.tokens.token_mix(tokens_complete),
                    tokens_complete.then(|| model.tokens.total_u64()).flatten(),
                    None,
                    cost_complete.then_some(ExactDecimal::new(model.cost)),
                    coverage,
                )
                .map_err(|_| parse_error())?;
                CostUsageModelBreakdown::new(name, metrics, None, None, None, None)
                    .map_err(|_| parse_error())
            })
            .collect::<Result<Vec<_>, _>>()?;
        daily.push(
            CostUsageDailyBucket::new(
                day,
                None,
                metrics,
                bucket.models.keys().cloned().collect(),
                models,
                Vec::new(),
            )
            .map_err(|_| parse_error())?,
        );
    }
    Ok(daily)
}

fn daily_window(
    billing: &BillingAggregate,
    fetched_at: Timestamp,
) -> Result<DailyWindow<'_>, ClassifiedError> {
    let fetched_day = fetched_at.as_offset_date_time().date();
    let end_day = billing
        .end_date
        .map(|value| value.as_offset_date_time().date());
    let selection_end = end_day.map_or(fetched_day, |value| value.min(fetched_day));
    let window_start = selection_end
        .checked_sub(TimeDuration::days(i64::from(HISTORY_DAYS - 1)))
        .ok_or_else(parse_error)?;
    let mut selected = Vec::new();
    let mut invalid = Vec::new();
    let mut selected_dates = Vec::new();
    for (day, bucket) in &billing.daily {
        let Some(date) = parse_day(day) else {
            invalid.push((day.as_str(), bucket));
            continue;
        };
        if date >= window_start && date <= selection_end {
            selected.push((date, day.as_str(), bucket));
            selected_dates.push(date);
        }
    }

    let metadata_coverage = billing
        .start_date
        .zip(billing.end_date)
        .and_then(|(start, end)| {
            let start = start.as_offset_date_time().date().max(window_start);
            let end = end
                .as_offset_date_time()
                .date()
                .min(fetched_day)
                .min(selection_end);
            inclusive_days(start, end).map(|days| (days, end))
        });
    let selected_coverage = selected_dates
        .iter()
        .min()
        .copied()
        .zip(selected_dates.iter().max().copied())
        .and_then(|(start, end)| inclusive_days(start, end).map(|days| (days, end)));
    let (covered_days, observation_end, coverage_established) = metadata_coverage
        .map(|(days, end)| (days, end, true))
        .or_else(|| selected_coverage.map(|(days, end)| (days, end, true)))
        .unwrap_or((1, selection_end, false));

    let month_to_date = billing
        .start_date
        .zip(billing.end_date)
        .is_some_and(|(start, end)| {
            let start = start.as_offset_date_time().date();
            let end = end.as_offset_date_time().date();
            let observation = end.min(fetched_day);
            start.day() == 1
                && start.year() == fetched_day.year()
                && start.month() == fetched_day.month()
                && end >= fetched_day
                && window_start <= start
                && selection_end >= observation
        });
    Ok(DailyWindow {
        selected,
        invalid,
        covered_days,
        coverage_established,
        month_to_date,
        observation_end,
    })
}

fn cost_data_complete(billing: &BillingAggregate, window: &DailyWindow<'_>) -> bool {
    if billing.total_cost < Decimal::ZERO
        || billing.daily.values().any(|bucket| {
            bucket.cost < Decimal::ZERO
                || bucket
                    .models
                    .values()
                    .any(|model| model.cost < Decimal::ZERO)
        })
        || window.invalid.iter().any(|(_, bucket)| {
            bucket.cost != Decimal::ZERO
                || bucket
                    .models
                    .values()
                    .any(|model| model.cost != Decimal::ZERO)
        })
        || !window.coverage_established
    {
        return false;
    }
    checked_cost_sum(billing.daily.values().map(|bucket| bucket.cost)) == Some(billing.total_cost)
}

fn token_data_complete(billing: &BillingAggregate, window: &DailyWindow<'_>) -> bool {
    if !billing.total_tokens.is_nonnegative()
        || billing.daily.values().any(|bucket| {
            !bucket.tokens.is_nonnegative()
                || bucket
                    .models
                    .values()
                    .any(|model| !model.tokens.is_nonnegative())
        })
        || window.invalid.iter().any(|(_, bucket)| {
            bucket.tokens.total_u64().is_some_and(|value| value != 0)
                || bucket
                    .models
                    .values()
                    .any(|model| model.tokens.total_u64().is_some_and(|value| value != 0))
        })
        || !window.coverage_established
    {
        return false;
    }
    checked_token_sum(billing.daily.values().map(|bucket| &bucket.tokens))
        == billing.total_tokens.total_u64()
}

fn checked_cost_sum(values: impl IntoIterator<Item = Decimal>) -> Option<Decimal> {
    values
        .into_iter()
        .try_fold(Decimal::ZERO, Decimal::checked_add)
}

fn checked_token_sum<'a>(values: impl IntoIterator<Item = &'a TokenAccumulator>) -> Option<u64> {
    values
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value.total_u64()?))
}

fn sum_token_mix<'a>(
    values: impl IntoIterator<Item = &'a TokenAccumulator>,
) -> Result<CostUsageTokenMix, ClassifiedError> {
    let mut total = TokenAccumulator::default();
    for value in values {
        total.merge(value);
    }
    if !total.is_nonnegative() {
        return Err(parse_error());
    }
    Ok(total.token_mix(true))
}

fn inclusive_days(start: Date, end: Date) -> Option<u16> {
    if start > end {
        return None;
    }
    let days = (end - start).whole_days().checked_add(1)?;
    u16::try_from(days).ok().filter(|days| *days <= 365)
}

fn parse_day(value: &str) -> Option<Date> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || ![0, 1, 2, 3, 5, 6, 8, 9]
            .into_iter()
            .all(|index| bytes[index].is_ascii_digit())
    {
        return None;
    }
    let year = value.get(..4)?.parse().ok()?;
    let month = value.get(5..7)?.parse::<u8>().ok()?;
    let day = value.get(8..)?.parse().ok()?;
    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()
}

fn day_timestamp(day: Date) -> Result<Timestamp, ClassifiedError> {
    Timestamp::new(PrimitiveDateTime::new(day, Time::MIDNIGHT).assume_utc())
        .map_err(|_| parse_error())
}

fn parse_vibe(body: &[u8]) -> Result<VibeUsage, ClassifiedError> {
    let root = parse_bounded_json(body, MAX_OPTIONAL_RESPONSE_BYTES)?;
    let responses: Vec<VibeEnvelope> = serde_json::from_value(root).map_err(|_| parse_error())?;
    let first = responses.first().ok_or_else(parse_error)?;
    let percent = first.result.data.json.usage_percentage;
    if !percent.is_finite() || !(0.0..=100.0).contains(&percent) {
        return Err(parse_error());
    }
    Ok(VibeUsage {
        percent,
        reset_at: first
            .result
            .data
            .json
            .reset_at
            .as_deref()
            .and_then(parse_timestamp),
    })
}

fn parse_credits(body: &[u8]) -> Result<Credits, ClassifiedError> {
    let root = parse_bounded_json(body, MAX_OPTIONAL_RESPONSE_BYTES)?;
    let object = root.as_object().ok_or_else(parse_error)?;
    let wallet = required_json_decimal(object.get("wallet_amount"))?;
    let notes = optional_json_decimal(object.get("credit_notes_amount"))?;
    let ongoing = optional_json_decimal(object.get("ongoing_usage_balance"))?;
    let available = wallet
        .checked_add(notes)
        .and_then(|value| value.checked_sub(ongoing))
        .ok_or_else(parse_error)?
        .max(Decimal::ZERO);
    let currency = object
        .get("currency")
        .and_then(Value::as_str)
        .ok_or_else(parse_error)?;
    let currency = CurrencyCode::new(currency.trim()).map_err(|_| parse_error())?;
    Ok(Credits {
        available,
        currency,
    })
}

fn required_json_decimal(value: Option<&Value>) -> Result<Decimal, ClassifiedError> {
    let value = value.and_then(Value::as_number).ok_or_else(parse_error)?;
    parse_decimal(&value.to_string()).ok_or_else(parse_error)
}

fn optional_json_decimal(value: Option<&Value>) -> Result<Decimal, ClassifiedError> {
    match value {
        None | Some(Value::Null) => Ok(Decimal::ZERO),
        Some(value) => required_json_decimal(Some(value)),
    }
}

fn parse_decimal(value: &str) -> Option<Decimal> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    value
        .parse::<Decimal>()
        .or_else(|_| Decimal::from_scientific(value))
        .ok()
}

fn parse_timestamp(value: &str) -> Option<Timestamp> {
    Timestamp::parse(value).ok()
}

fn validate_billing_limits(billing: &BillingResponse) -> Result<(), ClassifiedError> {
    if billing
        .prices
        .as_ref()
        .is_some_and(|prices| prices.len() > MAX_PRICES)
    {
        return Err(parse_error());
    }
    let mut model_count = 0_usize;
    let mut entry_count = 0_usize;
    let mut model_maps = Vec::new();
    for category in [
        &billing.completion,
        &billing.ocr,
        &billing.connectors,
        &billing.audio,
    ]
    .into_iter()
    .flatten()
    {
        if let Some(models) = &category.models {
            model_maps.push(models);
        }
    }
    if let Some(libraries) = &billing.libraries_api {
        for category in [&libraries.pages, &libraries.tokens].into_iter().flatten() {
            if let Some(models) = &category.models {
                model_maps.push(models);
            }
        }
    }
    if let Some(fine_tuning) = &billing.fine_tuning {
        model_maps.extend(
            [&fine_tuning.training, &fine_tuning.storage]
                .into_iter()
                .flatten(),
        );
    }

    for models in model_maps {
        model_count = model_count
            .checked_add(models.len())
            .ok_or_else(parse_error)?;
        if model_count > MAX_MODELS {
            return Err(parse_error());
        }
        for (name, model) in models {
            validate_model_name(name)?;
            for (_, entries) in model_entries(model) {
                entry_count = entry_count
                    .checked_add(entries.len())
                    .ok_or_else(parse_error)?;
                if entry_count > MAX_ENTRIES {
                    return Err(parse_error());
                }
                for entry in entries {
                    for value in [
                        entry.billing_metric.as_deref(),
                        entry.billing_group.as_deref(),
                        entry.billing_display_name.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        validate_provider_text(value)?;
                    }
                    if let Some(timestamp) = entry.timestamp.as_deref() {
                        validate_provider_text(timestamp)?;
                    }
                }
            }
        }
    }
    if let Some(prices) = &billing.prices {
        for price in prices {
            for value in [
                price.billing_metric.as_deref(),
                price.billing_group.as_deref(),
                price.raw_value.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_provider_text(value)?;
            }
        }
    }
    Ok(())
}

fn validate_model_name(value: &str) -> Result<(), ClassifiedError> {
    if value.is_empty() {
        return Err(parse_error());
    }
    validate_provider_text(value)
}

fn validate_provider_text(value: &str) -> Result<(), ClassifiedError> {
    if value.len() > MAX_MODEL_NAME_BYTES || value.chars().any(char::is_control) {
        return Err(parse_error());
    }
    Ok(())
}

fn parse_bounded_json(body: &[u8], max_bytes: usize) -> Result<Value, ClassifiedError> {
    if body.is_empty() || body.len() > max_bytes {
        return Err(parse_error());
    }
    let root = serde_json::from_slice::<Value>(body).map_err(|_| parse_error())?;
    let mut stack = vec![(&root, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(parse_error)?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(parse_error());
        }
        match value {
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                return Err(parse_error());
            }
            Value::Array(values) => {
                stack.extend(values.iter().rev().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.keys().any(|key| key.len() > MAX_JSON_STRING_BYTES) {
                    return Err(parse_error());
                }
                stack.extend(values.values().rev().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(root)
}

fn manual_session(
    routes: &MistralRouteSet,
    raw: &str,
) -> Result<SessionCredential, ClassifiedError> {
    let target = cookie_target(routes.routes.usage.clone(), routes.cookie_policy())?;
    let import = CookieImport::from_host_only_capture(CookieSourceId::MANUAL, raw, &target, None)
        .map_err(|_| parse_error())?;
    let order = CookieImportOrder::new([CookieSourceId::MANUAL]).map_err(|_| api_error())?;
    let jar = CookieJar::from_imports(&order, [import]).map_err(|_| parse_error())?;
    let header = jar
        .header_for(&target, OffsetDateTime::UNIX_EPOCH)
        .map_err(|_| parse_error())?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let _validated_header = header;
    let normalized = normalize_manual_cookie(raw)?;
    session_from_headers(&normalized, Some(&normalized), true)
}

fn normalize_manual_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let mut normalized = Zeroizing::new(String::with_capacity(raw.len()));
    for (index, part) in raw.split(';').enumerate() {
        let (name, value) = part.trim().split_once('=').ok_or_else(parse_error)?;
        if index != 0 {
            normalized.push_str("; ");
        }
        normalized.push_str(name.trim());
        normalized.push('=');
        normalized.push_str(value.trim());
    }
    if normalized.is_empty() || normalized.len() > MAX_COOKIE_HEADER_BYTES {
        return Err(parse_error());
    }
    Ok(normalized)
}

fn browser_sessions(
    routes: &MistralRouteSet,
    jars: &[&CookieJar],
    now: OffsetDateTime,
) -> Result<Vec<SessionCredential>, ClassifiedError> {
    if jars.len() > MAX_BROWSER_SESSIONS {
        return Err(api_error());
    }
    let any_records = jars.iter().any(|jar| !jar.is_empty());
    let admin_target = cookie_target(routes.routes.usage.clone(), routes.cookie_policy())?;
    let console_target = cookie_target(routes.routes.vibe.clone(), routes.cookie_policy())?;
    let mut sessions = Vec::new();
    for jar in jars {
        let admin = jar
            .header_for(&admin_target, now)
            .map_err(|_| api_error())?;
        let Some(admin) = admin else {
            continue;
        };
        if !has_session_cookie(admin.expose()) {
            continue;
        }
        let console = jar
            .header_for(&console_target, now)
            .map_err(|_| api_error())?;
        sessions.push(session_from_headers(
            admin.expose(),
            console.as_ref().map(crate::cookie::CookieHeader::expose),
            false,
        )?);
    }
    if sessions.is_empty() {
        return Err(ClassifiedError::new(if any_records {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::MissingCredential
        }));
    }
    Ok(sessions)
}

fn session_from_headers(
    admin: &str,
    console: Option<&str>,
    manual: bool,
) -> Result<SessionCredential, ClassifiedError> {
    if admin.len() > MAX_COOKIE_HEADER_BYTES || admin.chars().any(char::is_control) {
        return Err(parse_error());
    }
    if !has_session_cookie(admin) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let csrf = cookie_pairs(admin)
        .find(|(name, value)| *name == CSRF_COOKIE_NAME && valid_cookie_value(value))
        .map(|(_, value)| value.to_owned())
        .or_else(|| {
            console.and_then(|header| {
                cookie_pairs(header)
                    .find(|(name, value)| *name == CSRF_COOKIE_NAME && valid_cookie_value(value))
                    .map(|(_, value)| value.to_owned())
            })
        });
    let source = if manual { Some(admin) } else { console };
    let console_cookie = csrf.as_deref().and_then(|csrf| {
        build_console_cookie(csrf, source.unwrap_or_default()).map(Zeroizing::new)
    });
    Ok(SessionCredential {
        admin_cookie: Zeroizing::new(admin.to_owned()),
        csrf_token: csrf.map(Zeroizing::new),
        console_cookie,
    })
}

fn build_console_cookie(csrf: &str, source: &str) -> Option<String> {
    if !valid_cookie_value(csrf) {
        return None;
    }
    let mut pairs = vec![format!("{CSRF_COOKIE_NAME}={csrf}")];
    pairs.extend(
        cookie_pairs(source)
            .filter(|(name, value)| {
                name.starts_with(SESSION_COOKIE_PREFIX) && valid_cookie_value(value)
            })
            .map(|(name, value)| format!("{name}={value}")),
    );
    let result = pairs.join("; ");
    (result.len() <= MAX_COOKIE_HEADER_BYTES).then_some(result)
}

fn has_session_cookie(header: &str) -> bool {
    header.len() <= MAX_COOKIE_HEADER_BYTES
        && !header.chars().any(char::is_control)
        && cookie_pairs(header).any(|(name, value)| {
            name.starts_with(SESSION_COOKIE_PREFIX) && valid_cookie_value(value)
        })
}

fn cookie_pairs(header: &str) -> impl Iterator<Item = (&str, &str)> {
    header.split(';').filter_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        Some((name.trim(), value.trim()))
    })
}

fn valid_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COOKIE_VALUE_BYTES
        && !value.contains([';', ',', '\r', '\n'])
        && !value.chars().any(char::is_control)
}

fn cookie_target(url: Url, policy: CookieUrlPolicy) -> Result<ValidatedCookieUrl, ClassifiedError> {
    ValidatedCookieUrl::new(url, policy).map_err(|_| api_error())
}

fn required_transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(10),
        TOTAL_TIMEOUT,
        MAX_USAGE_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|_| api_error())
}

fn optional_transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(4),
        OPTIONAL_TIMEOUT,
        MAX_OPTIONAL_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|_| api_error())
}

fn optional_remaining(deadline: Instant) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    (!remaining.is_zero()).then(|| remaining.min(OPTIONAL_TIMEOUT))
}

fn classify_required_transport(error: &TransportError) -> ClassifiedError {
    match error.http_status() {
        Some(401 | 403) => ClassifiedError::new(ErrorKind::AuthenticationExpired),
        Some(_) => api_error(),
        None => error.classified(),
    }
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
    let expected = Url::parse(expected).map_err(|_| api_error())?;
    Ok(actual.origin() == expected.origin())
}

fn with_path(mut origin: Url, path: &str) -> Url {
    origin.set_path(path);
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

fn network_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Network)
}
