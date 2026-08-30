//! Xiaomi `MiMo` balance, token-plan quota, and opt-in local accounting.

use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt::{self, Debug, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CurrencyCode, DetailRow, DetailSection,
    DetailSensitivity, ErrorKind, ExactDecimal, Money, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use reqwest::header::{ACCEPT, ACCEPT_LANGUAGE, COOKIE, HeaderValue, ORIGIN, REFERER, USER_AGENT};
use reqwest::{Client, StatusCode};
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, PrimitiveDateTime};
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, format_integer, system_timestamp};
use crate::registry::descriptor_for;

const PRODUCTION_ORIGIN: &str = "https://platform.xiaomimimo.com";
const BALANCE_PATH: &str = "/api/v1/balance";
const TOKEN_DETAIL_PATH: &str = "/api/v1/tokenPlan/detail";
const TOKEN_USAGE_PATH: &str = "/api/v1/tokenPlan/usage";
const ACCEPT_VALUE: &str = "application/json, text/plain, */*";
const ACCEPT_LANGUAGE_VALUE: &str = "en-US,en;q=0.9";
const TIME_ZONE_VALUE: &str = "UTC+01:00";
const REFERER_VALUE: &str = "https://platform.xiaomimimo.com/#/console/balance";
const USER_AGENT_VALUE: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOCAL_CACHE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_LOCAL_CACHE_BYTES_USIZE: usize = 2 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_DETAIL_TEXT_BYTES: usize = 120;
const MAX_IDENTITY_BYTES: usize = 256;
const MONTHLY_WINDOW_MINUTES: i64 = 30 * 24 * 60;
const LOCAL_STALE_SECONDS: i64 = 12 * 60 * 60;
const SERVICE_TOKEN_COOKIE: &str = "api-platform_serviceToken";
const USER_ID_COOKIE: &str = "userId";
const KNOWN_COOKIES: [&str; 4] = [
    "api-platform_ph",
    SERVICE_TOKEN_COOKIE,
    "api-platform_slh",
    USER_ID_COOKIE,
];

/// `MiMo` web adapter permanently bound to one manual or browser-session source.
pub struct MiMoProvider {
    scope: AccountScope,
    source: ProviderSource,
    routes: MiMoRoutes,
    cookie: Zeroizing<String>,
    transport: MiMoTransport,
}

impl MiMoProvider {
    /// Creates the production manual-cookie adapter.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or API error for invalid input.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_manual_capture_at(scope, raw, &origin, EndpointClass::PublicHttps)
    }

    /// Creates a manual adapter at an explicit exact-origin transport seam.
    ///
    /// A captured URL remains restricted to the production host. The injected
    /// origin replaces only the network authority for loopback tests.
    ///
    /// # Errors
    ///
    /// Returns a stable capture, credential, scope, or endpoint error.
    #[doc(hidden)]
    pub fn from_manual_capture_at(
        scope: AccountScope,
        raw: &str,
        origin: &Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(["platform.xiaomimimo.com"], [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let raw_cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let cookie = normalize_cookie(raw_cookie, DuplicatePreference::Last)?;
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            origin,
            endpoint_class,
            cookie,
        )
    }

    /// Creates the production browser adapter from an already imported jar.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential or API error.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let target = Self::browser_target(&origin, CookieUrlPolicy::HttpsOnly)?;
        Self::from_browser_jar_at(scope, jar, &target, now, EndpointClass::PublicHttps)
    }

    /// Creates a browser adapter from one validated target and cookie jar.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential or API error.
    #[doc(hidden)]
    pub fn from_browser_jar_at(
        scope: AccountScope,
        jar: &CookieJar,
        target: &ValidatedCookieUrl,
        now: OffsetDateTime,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let origin = origin_url(target.url())?;
        let routes = MiMoRoutes::new(&origin)?;
        if target.url() != &routes.balance {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_origin(&origin, endpoint_class)?;
        let selected = jar
            .header_for(target, now)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let Some(selected) = selected else {
            let kind = if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            };
            return Err(ClassifiedError::new(kind));
        };
        let cookie = normalize_cookie(selected.expose(), DuplicatePreference::First)
            .map_err(|_| ClassifiedError::new(ErrorKind::AuthenticationExpired))?;
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            &origin,
            endpoint_class,
            cookie,
        )
    }

    /// Builds the exact balance cookie-selection target.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for malformed URL policy input.
    #[doc(hidden)]
    pub fn browser_target(
        origin: &Url,
        policy: CookieUrlPolicy,
    ) -> Result<ValidatedCookieUrl, ClassifiedError> {
        let routes = MiMoRoutes::new(origin)?;
        ValidatedCookieUrl::new(routes.balance, policy)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        origin: &Url,
        endpoint_class: EndpointClass,
        cookie: Zeroizing<String>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Mimo
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_origin(origin, endpoint_class)?;
        let routes = MiMoRoutes::new(origin)?;
        let policy = EndpointPolicy::new([(
            routes.balance.origin().ascii_serialization(),
            endpoint_class,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        for endpoint in [&routes.balance, &routes.token_detail, &routes.token_usage] {
            policy
                .validate(endpoint)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        }
        secret_header(cookie.as_str())?;
        let transport = MiMoTransport::new(policy)?;
        Ok(Self {
            scope,
            source,
            routes,
            cookie,
            transport,
        })
    }

    /// Fetches balance plus two concurrent best-effort plan endpoints.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let required = self.transport.send(
            &self.routes.balance,
            self.cookie.as_str(),
            context.cancellation(),
        );
        let detail = async {
            Ok::<Option<Vec<u8>>, ClassifiedError>(
                self.transport
                    .send(
                        &self.routes.token_detail,
                        self.cookie.as_str(),
                        context.cancellation(),
                    )
                    .await
                    .ok(),
            )
        };
        let usage = async {
            Ok::<Option<Vec<u8>>, ClassifiedError>(
                self.transport
                    .send(
                        &self.routes.token_usage,
                        self.cookie.as_str(),
                        context.cancellation(),
                    )
                    .await
                    .ok(),
            )
        };
        let (balance, detail, usage) = tokio::try_join!(required, detail, usage)?;
        parse_combined_snapshot(
            context.scope().clone(),
            fetched_at,
            &balance,
            detail.as_deref(),
            usage.as_deref(),
        )
    }

    /// Fetches only the authoritative balance endpoint for conformance tests.
    ///
    /// # Errors
    ///
    /// Returns the same stable failures as [`Self::fetch_at`].
    #[doc(hidden)]
    pub async fn fetch_balance_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let balance = self
            .transport
            .send(
                &self.routes.balance,
                self.cookie.as_str(),
                context.cancellation(),
            )
            .await?;
        parse_combined_snapshot(context.scope().clone(), fetched_at, &balance, None, None)
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(())
    }
}

impl ProviderAdapter for MiMoProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Mimo)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for MiMoProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiMoProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("routes", &"<redacted>")
            .field("cookie", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

struct MiMoRoutes {
    balance: Url,
    token_detail: Url,
    token_usage: Url,
}

impl MiMoRoutes {
    fn new(origin: &Url) -> Result<Self, ClassifiedError> {
        if !origin.username().is_empty()
            || origin.password().is_some()
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            balance: fixed_path(origin, BALANCE_PATH),
            token_detail: fixed_path(origin, TOKEN_DETAIL_PATH),
            token_usage: fixed_path(origin, TOKEN_USAGE_PATH),
        })
    }
}

struct MiMoTransport {
    client: Client,
    policy: EndpointPolicy,
}

impl MiMoTransport {
    fn new(policy: EndpointPolicy) -> Result<Self, ClassifiedError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self { client, policy })
    }

    async fn send(
        &self,
        url: &Url,
        cookie: &str,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<Vec<u8>, ClassifiedError> {
        let endpoint = self
            .policy
            .validate(url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let cookie = secret_header(cookie)?;
        let request = self
            .client
            .get(endpoint.url().clone())
            .header(ACCEPT, ACCEPT_VALUE)
            .header(COOKIE, cookie)
            .header(ACCEPT_LANGUAGE, ACCEPT_LANGUAGE_VALUE)
            .header("x-timeZone", TIME_ZONE_VALUE)
            .header(ORIGIN, PRODUCTION_ORIGIN)
            .header(REFERER, REFERER_VALUE)
            .header(USER_AGENT, USER_AGENT_VALUE);
        let future = async {
            let response = request
                .send()
                .await
                .map_err(|_| ClassifiedError::new(ErrorKind::Network))?;
            read_response(response).await
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ClassifiedError::new(ErrorKind::Network)),
            result = tokio::time::timeout(REQUEST_TIMEOUT, future) => {
                result.unwrap_or_else(|_| Err(ClassifiedError::new(ErrorKind::Network)))
            }
        }
    }
}

impl Debug for MiMoTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("MiMoTransport(<redacted>)")
    }
}

async fn read_response(response: reqwest::Response) -> Result<Vec<u8>, ClassifiedError> {
    let status = response.status();
    if status != StatusCode::OK {
        let kind = if status.is_redirection()
            || matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
        {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::Network
        };
        return Err(ClassifiedError::new(kind));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let next = body
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length <= MAX_RESPONSE_BYTES)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        body.reserve(next.saturating_sub(body.len()));
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Parses required balance plus best-effort token-plan payloads.
///
/// # Errors
///
/// Malformed required data fails closed. Malformed or unsuccessful optional
/// plan payloads are treated as absent exactly like the pinned provider.
pub fn parse_combined_snapshot(
    scope: AccountScope,
    fetched_at: Timestamp,
    balance: &[u8],
    token_detail: Option<&[u8]>,
    token_usage: Option<&[u8]>,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Mimo {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    if balance.len() > MAX_RESPONSE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let balance = parse_balance(balance)?;
    let detail = token_detail
        .filter(|body| body.len() <= MAX_RESPONSE_BYTES)
        .and_then(|body| parse_token_detail(body).ok())
        .unwrap_or_default();
    let usage = token_usage
        .filter(|body| body.len() <= MAX_RESPONSE_BYTES)
        .and_then(|body| parse_token_usage(body).ok())
        .unwrap_or_default();
    normalize_web(scope, fetched_at, &balance, &detail, &usage)
}

#[derive(Deserialize)]
struct BalanceResponse {
    code: i64,
    #[serde(rename = "message")]
    _message: Option<String>,
    data: Option<BalancePayload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BalancePayload {
    balance: String,
    currency: String,
    cash_balance: Option<String>,
    gift_balance: Option<String>,
}

struct ParsedBalance {
    balance: Decimal,
    currency: CurrencyCode,
    cash_balance: Option<Decimal>,
    gift_balance: Option<Decimal>,
}

fn parse_balance(body: &[u8]) -> Result<ParsedBalance, ClassifiedError> {
    let response: BalanceResponse =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if response.code == 401 || response.code == 403 {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if response.code != 0 {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let data = response
        .data
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let balance = parse_provider_decimal(&data.balance)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let currency = CurrencyCode::new(data.currency.trim())
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(ParsedBalance {
        balance,
        currency,
        cash_balance: data
            .cash_balance
            .as_deref()
            .and_then(parse_provider_decimal),
        gift_balance: data
            .gift_balance
            .as_deref()
            .and_then(parse_provider_decimal),
    })
}

#[derive(Default)]
struct ParsedDetail {
    plan_code: Option<String>,
    period_end: Option<Timestamp>,
}

#[derive(Deserialize)]
struct TokenDetailResponse {
    code: i64,
    data: Option<TokenDetailPayload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenDetailPayload {
    plan_code: Option<String>,
    current_period_end: Option<String>,
    #[serde(rename = "expired")]
    _expired: bool,
}

fn parse_token_detail(body: &[u8]) -> Result<ParsedDetail, ClassifiedError> {
    let response: TokenDetailResponse =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let Some(payload) = response.data.filter(|_| response.code == 0) else {
        return Ok(ParsedDetail::default());
    };
    let period_end = payload
        .current_period_end
        .as_deref()
        .and_then(parse_plan_timestamp);
    Ok(ParsedDetail {
        plan_code: payload.plan_code,
        period_end,
    })
}

#[derive(Default)]
struct ParsedUsage {
    used: i64,
    limit: i64,
    percent: f64,
}

#[derive(Deserialize)]
struct TokenUsageResponse {
    code: i64,
    data: Option<TokenUsagePayload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenUsagePayload {
    month_usage: Option<MonthUsage>,
}

#[derive(Deserialize)]
struct MonthUsage {
    #[serde(rename = "percent")]
    _percent: f64,
    items: Vec<UsageItem>,
}

#[derive(Deserialize)]
struct UsageItem {
    #[serde(rename = "name")]
    _name: String,
    used: i64,
    limit: i64,
    percent: f64,
}

fn parse_token_usage(body: &[u8]) -> Result<ParsedUsage, ClassifiedError> {
    let response: TokenUsageResponse =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let Some(item) = response
        .data
        .filter(|_| response.code == 0)
        .and_then(|data| data.month_usage)
        .and_then(|usage| usage.items.into_iter().next())
    else {
        return Ok(ParsedUsage::default());
    };
    if !item.percent.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(ParsedUsage {
        used: item.used,
        limit: item.limit,
        percent: item.percent,
    })
}

fn normalize_web(
    scope: AccountScope,
    fetched_at: Timestamp,
    balance: &ParsedBalance,
    detail: &ParsedDetail,
    usage: &ParsedUsage,
) -> Result<UsageSample, ClassifiedError> {
    let row = DetailRow::new(
        "Balance",
        balance_detail(balance),
        None,
        DetailSensitivity::Personal,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let section = DetailSection::new(Some("Credits".to_owned()), vec![row], None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .balance(Money::new(
            ExactDecimal::new(balance.balance),
            balance.currency.clone(),
        ))
        .detail_sections(vec![section]);
    if usage.limit > 0 {
        let raw_percent = usage.percent * 100.0;
        let used_percent = UsagePercent::new(raw_percent.clamp(0.0, 100.0))
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let description = BoundedText::new(format!(
            "{} / {} Credits",
            format_integer(usage.used),
            format_integer(usage.limit)
        ))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let duration = detail
            .period_end
            .map(|_| WindowDuration::from_provider_minutes(MONTHLY_WINDOW_MINUTES))
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let window = RateWindow::new(
            WindowUsage::known(used_percent),
            duration,
            detail.period_end,
            Some(description),
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        builder = builder.primary(window);
    }
    builder
        .login_method(detail.plan_code.as_deref().and_then(capitalized_plan))?
        .provenance("mimo", "web")?
        .build()
}

fn balance_detail(balance: &ParsedBalance) -> String {
    let total = format_currency(balance.balance, &balance.currency);
    match (balance.cash_balance, balance.gift_balance) {
        (Some(cash), Some(gift)) => {
            let combined = format!(
                "{total} (Paid: {} / Granted: {})",
                format_currency(cash, &balance.currency),
                format_currency(gift, &balance.currency)
            );
            if combined.len() <= MAX_DETAIL_TEXT_BYTES {
                combined
            } else {
                total
            }
        }
        _ => total,
    }
}

fn parse_provider_decimal(value: &str) -> Option<Decimal> {
    Decimal::from_scientific(value)
        .or_else(|_| Decimal::from_str(value))
        .ok()
}

fn format_currency(value: Decimal, currency: &CurrencyCode) -> String {
    let negative = value.is_sign_negative();
    let absolute = value.abs();
    let fixed = format!("{absolute:.2}");
    let (whole, fraction) = fixed.split_once('.').unwrap_or((fixed.as_str(), "00"));
    let mut grouped = String::with_capacity(whole.len() + whole.len() / 3 + 3);
    for (index, byte) in whole.bytes().enumerate() {
        if index > 0 && (whole.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    let sign = if negative { "-" } else { "" };
    match currency.as_str() {
        "USD" => format!("{sign}${grouped}.{fraction}"),
        "EUR" => format!("{sign}€{grouped}.{fraction}"),
        "GBP" => format!("{sign}£{grouped}.{fraction}"),
        "CNY" => format!("{sign}CN¥{grouped}.{fraction}"),
        code => format!("{sign}{code} {grouped}.{fraction}"),
    }
}

fn capitalized_plan(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return None;
    }
    let mut capitalize = true;
    let mut output = String::with_capacity(raw.len());
    for character in raw.chars() {
        if character.is_alphanumeric() {
            if capitalize {
                output.extend(character.to_uppercase());
                capitalize = false;
            } else {
                output.extend(character.to_lowercase());
            }
        } else {
            output.push(character);
            capitalize = true;
        }
    }
    (output.len() <= MAX_IDENTITY_BYTES).then_some(output)
}

fn parse_plan_timestamp(value: &str) -> Option<Timestamp> {
    let format = time::format_description::parse_borrowed::<3>(
        "[year]-[month]-[day] [hour]:[minute]:[second]",
    )
    .ok()?;
    PrimitiveDateTime::parse(value, &format)
        .ok()
        .and_then(|value| Timestamp::new(value.assume_utc()).ok())
}

/// Opt-in local `MiMo` accounting adapter bound to one explicit cache path.
pub struct MiMoLocalProvider {
    scope: AccountScope,
    cache_path: PathBuf,
}

impl MiMoLocalProvider {
    /// Resolves `MIMO_LOCAL_USAGE_PATH`, then the app's XDG data path.
    ///
    /// Only the injected environment is read.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential or API error for unsafe inputs.
    pub fn resolve(
        scope: AccountScope,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let home = environment
            .get("HOME")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let path = if let Some(override_path) = environment
            .get("MIMO_LOCAL_USAGE_PATH")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            expand_home(override_path, home)?
        } else if let Some(data_home) = environment
            .get("XDG_DATA_HOME")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            PathBuf::from(data_home).join("omarchy-ai-bar/mimo-local-usage.json")
        } else {
            PathBuf::from(home.ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?)
                .join(".local/share/omarchy-ai-bar/mimo-local-usage.json")
        };
        Self::new(scope, path)
    }

    /// Binds an absolute cache path without opening it.
    ///
    /// # Errors
    ///
    /// Rejects relative, parent-traversing, control-bearing, or oversized paths.
    pub fn new(scope: AccountScope, cache_path: impl AsRef<Path>) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Mimo {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_cache_path(cache_path.as_ref())?;
        Ok(Self {
            scope,
            cache_path: cache_path.as_ref().to_owned(),
        })
    }

    /// Reads and parses the bounded cache at an injected refresh instant.
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, missing-file, permission, or parse errors.
    pub fn fetch_at(
        &self,
        context: &ProviderContext,
        now: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::LocalData {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        if context.cancellation().is_cancelled() {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }
        let (body, modified_at) = read_local_cache(&self.cache_path)?;
        if context.cancellation().is_cancelled() {
            return Err(ClassifiedError::new(ErrorKind::Network));
        }
        parse_local_usage(context.scope().clone(), now, &body, modified_at)
    }
}

impl ProviderAdapter for MiMoLocalProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Mimo)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let now = system_timestamp()?;
            self.fetch_at(context, now)
        })
    }
}

impl Debug for MiMoLocalProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MiMoLocalProvider")
            .field("scope", &"<redacted>")
            .field("cache_path", &"<redacted>")
            .finish()
    }
}

/// Parses the local tracker cache without fabricating a platform quota.
///
/// # Errors
///
/// Returns a stable parse error for malformed JSON, missing required window
/// objects, excessive input, another provider scope, or invalid output bounds.
pub fn parse_local_usage(
    scope: AccountScope,
    now: Timestamp,
    body: &[u8],
    modified_at: Option<Timestamp>,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Mimo {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    if body.len() > MAX_LOCAL_CACHE_BYTES_USIZE {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let root = root
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let windows = root
        .get("windows")
        .and_then(Value::as_object)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let today = required_window(windows, "today")?;
    let week = required_window(windows, "week")?;
    let all_time = required_window(windows, "all_time")?;
    let sessions = local_int(root.get("sessions_scanned"));
    let today_total = local_total(today);
    let week_total = local_total(week);
    let all_total = local_total(all_time);
    let updated_at = root
        .get("updated_at")
        .and_then(Value::as_str)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .and_then(|value| Timestamp::new(value).ok())
        .or(modified_at)
        .unwrap_or(now);

    let mut parts = vec!["Local".to_owned()];
    if today_total > 0 {
        parts.push(format!("{} today", format_local_tokens(today_total)));
    }
    if week_total > 0 {
        parts.push(format!("{} week", format_local_tokens(week_total)));
    }
    if all_total > 0 {
        parts.push(format!("{} total", format_local_tokens(all_total)));
    }
    parts.push(format!("{sessions} sessions"));
    if let Some(stale) = stale_suffix(updated_at, now) {
        parts.push(stale);
    }
    UsageSampleBuilder::new(scope, updated_at)
        .login_method(Some(parts.join(" · ")))?
        .provenance("mimo", "local")?
        .build()
}

fn required_window<'a>(
    windows: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, ClassifiedError> {
    windows
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn local_total(window: &Map<String, Value>) -> i64 {
    ["input", "output", "cache_read", "cache_create"]
        .into_iter()
        .fold(0_i64, |total, key| {
            total.saturating_add(local_int(window.get(key)))
        })
}

fn local_int(value: Option<&Value>) -> i64 {
    let Some(value) = value else {
        return 0;
    };
    if let Some(value) = value.as_i64() {
        return value.max(0);
    }
    if let Some(value) = value.as_u64().and_then(|value| i64::try_from(value).ok()) {
        return value;
    }
    if let Some(value) = value.as_f64()
        && value.is_finite()
        && value >= 0.0
    {
        return Decimal::from_f64(value)
            .and_then(|value| value.trunc().to_i64())
            .unwrap_or(0);
    }
    value
        .as_str()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0)
}

fn format_local_tokens(value: i64) -> String {
    if value >= 1_000_000 {
        let scaled = value.to_f64().unwrap_or(0.0) / 1_000_000.0;
        format!("{scaled:.1}M")
    } else if value >= 1_000 {
        let scaled = value.to_f64().unwrap_or(0.0) / 1_000.0;
        format!("{scaled:.1}k")
    } else {
        value.to_string()
    }
}

fn stale_suffix(updated_at: Timestamp, now: Timestamp) -> Option<String> {
    let age = now.as_offset_date_time() - updated_at.as_offset_date_time();
    let seconds = age.whole_seconds();
    if seconds <= LOCAL_STALE_SECONDS {
        return None;
    }
    let day = 24 * 60 * 60;
    if seconds >= day {
        Some(format!("stale {}d", seconds / day))
    } else {
        Some(format!("stale {}h", (seconds / (60 * 60)).max(1)))
    }
}

/// Whether the source planner may move from `MiMo` web to local data.
#[must_use]
pub const fn web_failure_allows_local_fallback(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::MissingCredential | ErrorKind::AuthenticationExpired
    )
}

#[derive(Clone, Copy)]
enum DuplicatePreference {
    First,
    Last,
}

fn normalize_cookie(
    raw: &str,
    preference: DuplicatePreference,
) -> Result<Zeroizing<String>, ClassifiedError> {
    let mut values = BTreeMap::<&str, &str>::new();
    for part in raw.split(';') {
        let part = part.trim();
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let name = name.trim();
        let value = value.trim();
        if value.is_empty() || !KNOWN_COOKIES.contains(&name) {
            continue;
        }
        match (values.entry(name), preference) {
            (Entry::Vacant(entry), _) => {
                entry.insert(value);
            }
            (Entry::Occupied(_), DuplicatePreference::First) => {}
            (Entry::Occupied(mut entry), DuplicatePreference::Last) => {
                entry.insert(value);
            }
        }
    }
    if !values.contains_key(SERVICE_TOKEN_COOKIE) || !values.contains_key(USER_ID_COOKIE) {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let mut output = Zeroizing::new(String::new());
    for (index, (name, value)) in values.into_iter().enumerate() {
        if index > 0 {
            output.push_str("; ");
        }
        output.push_str(name);
        output.push('=');
        output.push_str(value);
    }
    secret_header(output.as_str())?;
    Ok(output)
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

fn fixed_path(origin: &Url, path: &str) -> Url {
    let mut endpoint = origin.clone();
    endpoint.set_path(path);
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint
}

fn origin_url(url: &Url) -> Result<Url, ClassifiedError> {
    let mut origin = Url::parse(&url.origin().ascii_serialization())
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    origin.set_path("/");
    Ok(origin)
}

fn validate_origin(origin: &Url, class: EndpointClass) -> Result<(), ClassifiedError> {
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.host_str().is_none()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    match class {
        EndpointClass::PublicHttps
            if origin.scheme() == "https"
                && origin
                    .host_str()
                    .is_some_and(|host| host.eq_ignore_ascii_case("platform.xiaomimimo.com"))
                && origin.port_or_known_default() == Some(443) => {}
        EndpointClass::LoopbackDevelopment => {}
        EndpointClass::PublicHttps | EndpointClass::PrivateHttps | EndpointClass::PrivateHttp => {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
    }
    EndpointPolicy::new([(origin.origin().ascii_serialization(), class)])
        .and_then(|policy| policy.validate(origin).map(|_| policy))
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    Ok(())
}

fn secret_header(value: &str) -> Result<HeaderValue, ClassifiedError> {
    let mut value = HeaderValue::from_str(value)
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    value.set_sensitive(true);
    Ok(value)
}

fn expand_home(raw: &str, home: Option<&str>) -> Result<PathBuf, ClassifiedError> {
    if raw == "~" {
        return home
            .map(PathBuf::from)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential));
    }
    if let Some(suffix) = raw.strip_prefix("~/") {
        return home
            .map(|home| PathBuf::from(home).join(suffix))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential));
    }
    if raw.starts_with('~') {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(PathBuf::from(raw))
}

fn validate_cache_path(path: &Path) -> Result<(), ClassifiedError> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().is_empty()
        || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
        || path.as_os_str().as_bytes().iter().any(u8::is_ascii_control)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn read_local_cache(
    path: &Path,
) -> Result<(Zeroizing<Vec<u8>>, Option<Timestamp>), ClassifiedError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        Err(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    validate_local_file(&file)?;
    let metadata = file
        .metadata()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let modified_at = metadata.modified().ok().and_then(system_time_timestamp);
    let mut body = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(MAX_LOCAL_CACHE_BYTES_USIZE),
    ));
    file.read_to_end(&mut body)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if body.len() > MAX_LOCAL_CACHE_BYTES_USIZE {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok((body, modified_at))
}

fn validate_local_file(file: &File) -> Result<(), ClassifiedError> {
    let metadata = file
        .metadata()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_LOCAL_CACHE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(())
}

fn system_time_timestamp(value: SystemTime) -> Option<Timestamp> {
    let nanos = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::from(duration.as_secs())
            .checked_mul(1_000_000_000)?
            .checked_add(i128::from(duration.subsec_nanos()))?,
        Err(error) => i128::from(error.duration().as_secs())
            .checked_mul(1_000_000_000)?
            .checked_add(i128::from(error.duration().subsec_nanos()))?
            .checked_neg()?,
    };
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|value| Timestamp::new(value).ok())
}
