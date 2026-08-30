//! Perplexity recurring, promotional, and purchased credit usage.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::{Map, Value};
use time::{Month, OffsetDateTime};
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig, TransportError,
};

const PRODUCTION_ORIGIN: &str = "https://www.perplexity.ai";
const CREDITS_PATH: &str = "/rest/billing/credits";
const CREDITS_QUERY: &str = "version=2.18&source=default";
const ACCOUNT_USAGE_URL: &str = "https://www.perplexity.ai/account/usage";
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 40;
const MAX_JSON_STRING_BYTES: usize = 512 * 1024;
const MAX_COOKIE_HEADER_BYTES: usize = 64 * 1024;
const MAX_COOKIE_PAIRS: usize = 512;
const MAX_COOKIE_CHUNKS: usize = 64;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_GRANTS: usize = 8_192;
const MAX_CREDIT_MAGNITUDE: i64 = 1_000_000_000_000_000;
const SESSION_COOKIE_NAMES: [&str; 4] = [
    "__Secure-authjs.session-token",
    "authjs.session-token",
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
];

struct SessionCookie {
    name: String,
    token: Zeroizing<String>,
}

impl SessionCookie {
    fn new(name: &str, token: &str) -> Result<Self, ClassifiedError> {
        if !SESSION_COOKIE_NAMES
            .iter()
            .any(|expected| name.eq_ignore_ascii_case(expected))
            || !valid_token(token)
        {
            return Err(parse_error());
        }
        let header = format!("{name}={token}");
        Authentication::cookie(header).map_err(|_| parse_error())?;
        Ok(Self {
            name: name.to_owned(),
            token: Zeroizing::new(token.to_owned()),
        })
    }

    fn header(&self) -> Result<String, ClassifiedError> {
        let header = format!("{}={}", self.name, self.token.as_str());
        Authentication::cookie(header.clone()).map_err(|_| parse_error())?;
        Ok(header)
    }
}

impl Debug for SessionCookie {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionCookie(<redacted>)")
    }
}

/// Perplexity adapter permanently bound to one account and credential source.
pub struct PerplexityProvider {
    scope: AccountScope,
    source: ProviderSource,
    endpoint: Url,
    candidates: Vec<SessionCookie>,
    transport: HttpTransport,
}

impl PerplexityProvider {
    /// Creates a production manual-session adapter from a bare token, cookie
    /// header, or copied cURL command.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or configuration error.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_manual_capture_at(scope, raw, &origin, EndpointClass::PublicHttps)
    }

    /// Creates a manual adapter at an injected exact-origin test seam.
    ///
    /// A URL in a copied cURL command must still target Perplexity. The
    /// injected origin only replaces the transport authority after capture
    /// authorization.
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
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }
        let candidates =
            if !raw.contains('=') && !raw.contains(';') && !raw.contains(char::is_whitespace) {
                SESSION_COOKIE_NAMES
                    .iter()
                    .map(|name| SessionCookie::new(name, raw))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                let policy = ManualCapturePolicy::new(
                    ["www.perplexity.ai", "perplexity.ai"],
                    [CaptureHeader::Cookie],
                )
                .map_err(classify_capture_error)?
                .with_ignored_url_query();
                let capture = policy.parse(raw).map_err(classify_capture_error)?;
                let header = capture
                    .header(CaptureHeader::Cookie)
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
                vec![extract_session_cookie(header)?.ok_or_else(parse_error)?]
            };
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            origin,
            endpoint_class,
            candidates,
        )
    }

    /// Creates a production browser-session adapter from a pre-imported jar.
    ///
    /// # Errors
    ///
    /// Returns missing-credential for an empty jar and authentication-expired
    /// when no active target-scoped Perplexity session cookie remains.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
    ) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_browser_jar_at(scope, jar, now, &origin, EndpointClass::PublicHttps)
    }

    /// Creates a browser adapter at an injected exact-origin test seam.
    ///
    /// # Errors
    ///
    /// Returns stable cookie, authentication, scope, or endpoint failures.
    #[doc(hidden)]
    pub fn from_browser_jar_at(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        origin: &Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let endpoint = credits_url(origin.clone());
        validate_origin(origin, endpoint_class)?;
        let cookie_policy = match endpoint_class {
            EndpointClass::LoopbackDevelopment => CookieUrlPolicy::LoopbackHttp,
            EndpointClass::PublicHttps
            | EndpointClass::PrivateHttps
            | EndpointClass::PrivateHttp => CookieUrlPolicy::HttpsOnly,
        };
        let target = ValidatedCookieUrl::new(endpoint, cookie_policy)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let header = jar
            .header_for(&target, now)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let candidate = match header.as_ref() {
            Some(header) => extract_session_cookie(header.expose())?,
            None => None,
        }
        .ok_or_else(|| {
            ClassifiedError::new(if jar.is_empty() {
                ErrorKind::MissingCredential
            } else {
                ErrorKind::AuthenticationExpired
            })
        })?;
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            origin,
            endpoint_class,
            vec![candidate],
        )
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        origin: &Url,
        endpoint_class: EndpointClass,
        candidates: Vec<SessionCookie>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Perplexity
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
            || candidates.is_empty()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_origin(origin, endpoint_class)?;
        if endpoint_class == EndpointClass::PublicHttps
            && origin.origin()
                != Url::parse(PRODUCTION_ORIGIN)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
                    .origin()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let endpoint = credits_url(origin.clone());
        let policy = EndpointPolicy::new([(origin.as_str(), endpoint_class)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        policy
            .validate(&endpoint)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            source,
            endpoint,
            candidates,
            transport,
        })
    }

    /// Source to which this provider is permanently bound.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Fetches credits at an injected wall-clock instant.
    ///
    /// Bare-token manual sessions try the four baseline cookie names in
    /// priority order, advancing only after a 401/403 authentication failure.
    ///
    /// # Errors
    ///
    /// Returns stable scope, authentication, network, status, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let mut saw_invalid_session = false;
        for candidate in &self.candidates {
            let request = HttpRequest::get(self.endpoint.clone())
                .accept(RequestAccept::Json)
                .public_header("origin", PRODUCTION_ORIGIN)
                .map_err(|error| error.classified())?
                .public_header("referer", ACCOUNT_USAGE_URL)
                .map_err(|error| error.classified())?
                .public_header("user-agent", USER_AGENT)
                .map_err(|error| error.classified())?
                .authentication(
                    Authentication::cookie(candidate.header()?)
                        .map_err(|error| error.classified())?,
                );
            match self.transport.send(&request, context.cancellation()).await {
                Ok(response) => {
                    if response.status() != 200 {
                        return Err(ClassifiedError::new(ErrorKind::Api));
                    }
                    return parse_credits_response(
                        self.scope.clone(),
                        fetched_at,
                        response.body(),
                        self.source,
                    );
                }
                Err(TransportError::AuthenticationExpired | TransportError::PermissionDenied) => {
                    saw_invalid_session = true;
                }
                Err(error) => return Err(classify_transport(error)),
            }
        }
        Err(ClassifiedError::new(if saw_invalid_session {
            ErrorKind::AuthenticationExpired
        } else {
            ErrorKind::MissingCredential
        }))
    }
}

impl ProviderAdapter for PerplexityProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Perplexity)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for PerplexityProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PerplexityProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("endpoint", &"<redacted>")
            .field("candidates", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

fn validate_origin(origin: &Url, class: EndpointClass) -> Result<(), ClassifiedError> {
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    EndpointPolicy::new([(origin.as_str(), class)])
        .map(|_| ())
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn credits_url(mut origin: Url) -> Url {
    origin.set_path(CREDITS_PATH);
    origin.set_query(Some(CREDITS_QUERY));
    origin.set_fragment(None);
    origin
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(10),
        Duration::from_secs(15),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))
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

fn classify_transport(error: TransportError) -> ClassifiedError {
    match error {
        TransportError::AuthenticationExpired | TransportError::PermissionDenied => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        other => other.classified(),
    }
}

fn extract_session_cookie(header: &str) -> Result<Option<SessionCookie>, ClassifiedError> {
    if header.is_empty() || header.len() > MAX_COOKIE_HEADER_BYTES {
        return Err(parse_error());
    }
    let mut pairs = Vec::new();
    for raw in header.split(';') {
        if pairs.len() == MAX_COOKIE_PAIRS {
            return Err(parse_error());
        }
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((name, value)) = raw.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        pairs.push((name, value));
    }
    for expected in SESSION_COOKIE_NAMES {
        if let Some((name, value)) = pairs
            .iter()
            .copied()
            .find(|(name, _)| name.eq_ignore_ascii_case(expected))
        {
            return SessionCookie::new(name, value).map(Some);
        }

        let expected_prefix = format!("{}.", expected.to_ascii_lowercase());
        let mut chunks = BTreeMap::new();
        for (name, value) in &pairs {
            let lowered = name.to_ascii_lowercase();
            let Some(suffix) = lowered.strip_prefix(&expected_prefix) else {
                continue;
            };
            let Ok(index) = suffix.parse::<usize>() else {
                continue;
            };
            if index >= MAX_COOKIE_CHUNKS {
                return Err(parse_error());
            }
            chunks.insert(index, (*name, *value));
        }
        if chunks.is_empty() {
            continue;
        }
        let Some((first_name, _)) = chunks.get(&0).copied() else {
            continue;
        };
        let max_index = *chunks.keys().next_back().ok_or_else(parse_error)?;
        if chunks.len() != max_index + 1 {
            continue;
        }
        let mut token = Zeroizing::new(String::new());
        for index in 0..=max_index {
            let (_, value) = chunks.get(&index).copied().ok_or_else(parse_error)?;
            let next_len = token
                .len()
                .checked_add(value.len())
                .ok_or_else(parse_error)?;
            if next_len > MAX_TOKEN_BYTES {
                return Err(parse_error());
            }
            token.push_str(value);
        }
        let base_name = first_name
            .rsplit_once('.')
            .map_or(first_name, |(base, _)| base);
        return SessionCookie::new(base_name, token.as_str()).map(Some);
    }
    Ok(None)
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && !token.chars().any(char::is_control)
        && !token.contains([';', '\r', '\n'])
}

struct ParsedCredits {
    recurring_total: Decimal,
    recurring_used: Decimal,
    promo_total: Decimal,
    promo_used: Decimal,
    purchased_total: Decimal,
    purchased_used: Decimal,
    renewal: Timestamp,
    promo_expiration: Option<Timestamp>,
}

/// Parses a bounded Perplexity credits response into the normalized snapshot.
///
/// # Errors
///
/// Returns stable scope, source, or bounded parse failures without retaining
/// response text.
pub fn parse_credits_response(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    if scope.provider() != ProviderId::Perplexity
        || !matches!(
            source,
            ProviderSource::ManualCookie | ProviderSource::BrowserSession
        )
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let root = parse_bounded_json(body)?;
    let object = root.as_object().ok_or_else(parse_error)?;
    let parsed = parse_credits(object, fetched_at)?;
    normalize_credits(scope, fetched_at, &parsed, source)
}

fn parse_credits(
    object: &Map<String, Value>,
    fetched_at: Timestamp,
) -> Result<ParsedCredits, ClassifiedError> {
    let _balance = required_decimal(object, "balance_cents")?;
    let renewal = timestamp_from_decimal(required_decimal(object, "renewal_date_ts")?)?;
    let purchased_field = required_decimal(object, "current_period_purchased_cents")?;
    let total_usage = required_decimal(object, "total_usage_cents")?;
    let grants = object
        .get("credit_grants")
        .and_then(Value::as_array)
        .ok_or_else(parse_error)?;
    if grants.len() > MAX_GRANTS {
        return Err(parse_error());
    }
    let now = Decimal::from(fetched_at.unix_timestamp());
    let mut recurring_sum = Decimal::ZERO;
    let mut promo_sum = Decimal::ZERO;
    let mut purchased_sum = Decimal::ZERO;
    let mut promo_expiration = None;
    for grant in grants {
        let grant = grant.as_object().ok_or_else(parse_error)?;
        let kind = grant
            .get("type")
            .and_then(Value::as_str)
            .filter(|kind| kind.len() <= 64)
            .ok_or_else(parse_error)?;
        let amount = required_decimal(grant, "amount_cents")?;
        let expiration = match grant.get("expires_at_ts") {
            None | Some(Value::Null) => None,
            Some(value) => Some(decimal_value(value)?),
        };
        match kind {
            "recurring" => recurring_sum = checked_add(recurring_sum, amount)?,
            "promotional" if expiration.is_none_or(|value| value > now) => {
                promo_sum = checked_add(promo_sum, amount)?;
                if let Some(expiration) = expiration {
                    let expiration = timestamp_from_decimal(expiration)?;
                    promo_expiration = Some(
                        promo_expiration
                            .map_or(expiration, |current: Timestamp| current.min(expiration)),
                    );
                }
            }
            "purchased" => purchased_sum = checked_add(purchased_sum, amount)?,
            _ => {}
        }
    }
    let recurring_total = recurring_sum.max(Decimal::ZERO);
    let promo_total = promo_sum.max(Decimal::ZERO);
    let purchased_total = purchased_sum
        .max(Decimal::ZERO)
        .max(purchased_field.max(Decimal::ZERO));
    let mut remaining = total_usage;
    let recurring_used = remaining.min(recurring_total);
    remaining = checked_add(remaining, -recurring_used)?;
    let purchased_used = remaining.min(purchased_total);
    remaining = checked_add(remaining, -purchased_used)?;
    let promo_used = remaining.min(promo_total);
    Ok(ParsedCredits {
        recurring_total,
        recurring_used,
        promo_total,
        promo_used,
        purchased_total,
        purchased_used,
        renewal,
        promo_expiration,
    })
}

fn normalize_credits(
    scope: AccountScope,
    fetched_at: Timestamp,
    parsed: &ParsedCredits,
    source: ProviderSource,
) -> Result<UsageSample, ClassifiedError> {
    let has_fallback = parsed.promo_total > Decimal::ZERO || parsed.purchased_total > Decimal::ZERO;
    let primary = if parsed.recurring_total > Decimal::ZERO {
        Some(window(
            percent(parsed.recurring_used, parsed.recurring_total, false)?,
            Some(parsed.renewal),
            format!(
                "{}/{} credits",
                whole(parsed.recurring_used)?,
                whole(parsed.recurring_total)?
            ),
        )?)
    } else if has_fallback {
        None
    } else {
        Some(window(
            UsagePercent::new(100.0).map_err(|_| parse_error())?,
            Some(parsed.renewal),
            "0/0 credits".to_owned(),
        )?)
    };
    let mut promo_description = format!(
        "{}/{} bonus",
        whole(parsed.promo_used)?,
        whole(parsed.promo_total)?
    );
    if let Some(expiration) = parsed.promo_expiration {
        promo_description.push_str(" · exp. ");
        promo_description.push_str(&month_day(expiration));
    }
    let secondary = window(
        percent(parsed.promo_used, parsed.promo_total, true)?,
        None,
        promo_description,
    )?;
    let tertiary = window(
        percent(parsed.purchased_used, parsed.purchased_total, true)?,
        None,
        format!(
            "{}/{} credits",
            whole(parsed.purchased_used)?,
            whole(parsed.purchased_total)?
        ),
    )?;
    let plan = if parsed.recurring_total <= Decimal::ZERO {
        None
    } else if parsed.recurring_total < Decimal::from(5_000_u16) {
        Some("Pro".to_owned())
    } else {
        Some("Max".to_owned())
    };
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .secondary(secondary)
        .tertiary(tertiary)
        .login_method(plan)?
        .provenance(
            "perplexity",
            if source == ProviderSource::ManualCookie {
                "manual_cookie"
            } else {
                "browser_session"
            },
        )?;
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    builder.build()
}

fn window(
    percent: UsagePercent,
    resets_at: Option<Timestamp>,
    description: String,
) -> Result<RateWindow, ClassifiedError> {
    let description = BoundedText::new(description).map_err(|_| parse_error())?;
    RateWindow::new(
        WindowUsage::known(percent),
        None,
        resets_at,
        Some(description),
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn percent(
    used: Decimal,
    total: Decimal,
    exhausted_when_empty: bool,
) -> Result<UsagePercent, ClassifiedError> {
    let value = if total > Decimal::ZERO {
        (used * Decimal::from(100_u8) / total)
            .clamp(Decimal::ZERO, Decimal::from(100_u8))
            .to_f64()
            .ok_or_else(parse_error)?
    } else if exhausted_when_empty {
        100.0
    } else {
        0.0
    };
    UsagePercent::new(value).map_err(|_| parse_error())
}

fn whole(value: Decimal) -> Result<String, ClassifiedError> {
    value
        .round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
        .to_i128()
        .map(|value| value.to_string())
        .ok_or_else(parse_error)
}

fn month_day(timestamp: Timestamp) -> String {
    let date = timestamp.as_offset_date_time().date();
    let month = match date.month() {
        Month::January => "Jan",
        Month::February => "Feb",
        Month::March => "Mar",
        Month::April => "Apr",
        Month::May => "May",
        Month::June => "Jun",
        Month::July => "Jul",
        Month::August => "Aug",
        Month::September => "Sep",
        Month::October => "Oct",
        Month::November => "Nov",
        Month::December => "Dec",
    };
    format!("{month} {}", date.day())
}

fn required_decimal(object: &Map<String, Value>, key: &str) -> Result<Decimal, ClassifiedError> {
    object
        .get(key)
        .ok_or_else(parse_error)
        .and_then(decimal_value)
}

fn decimal_value(value: &Value) -> Result<Decimal, ClassifiedError> {
    let Value::Number(value) = value else {
        return Err(parse_error());
    };
    let value = value
        .to_string()
        .parse::<Decimal>()
        .map_err(|_| parse_error())?;
    if value.abs() > Decimal::from(MAX_CREDIT_MAGNITUDE) {
        return Err(parse_error());
    }
    Ok(value)
}

fn timestamp_from_decimal(value: Decimal) -> Result<Timestamp, ClassifiedError> {
    let nanos = (value * Decimal::from(1_000_000_000_u64))
        .trunc()
        .to_i128()
        .ok_or_else(parse_error)?;
    let value = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| parse_error())?;
    Timestamp::new(value).map_err(|_| parse_error())
}

fn checked_add(lhs: Decimal, rhs: Decimal) -> Result<Decimal, ClassifiedError> {
    lhs.checked_add(rhs).ok_or_else(parse_error)
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
                if values.keys().any(|key| key.len() > MAX_JSON_STRING_BYTES) {
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

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
