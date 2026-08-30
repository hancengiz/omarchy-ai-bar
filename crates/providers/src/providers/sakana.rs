//! Sakana AI subscription quotas and optional pay-as-you-go balance.

use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, DetailRow, DetailSection, DetailSensitivity, ErrorKind,
    ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp, timestamp_from_unix};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig, TransportError,
};

const PRODUCTION_ORIGIN: &str = "https://console.sakana.ai";
const BILLING_PATH: &str = "/billing";
const PAY_AS_YOU_GO_QUERY: &str = "tab=payAsYouGo";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ELEMENT_TEXT_BYTES: usize = 4 * 1024;
const MAX_HTML_ELEMENTS: usize = 4_096;
const MAX_PLAN_BYTES: usize = 256;
const OPTIONAL_ENRICHMENT_BUDGET: Duration = Duration::from_millis(200);

/// Native Sakana adapter permanently bound to one manual-cookie account.
pub struct SakanaProvider {
    scope: AccountScope,
    endpoint: Url,
    pay_as_you_go_endpoint: Url,
    cookie: Zeroizing<String>,
    transport: HttpTransport,
}

impl SakanaProvider {
    /// Creates the production adapter from a raw cookie header or copied cURL.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential, parse, or API error when the
    /// capture, scope, or fixed endpoint is invalid.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_manual_capture_at(scope, raw, origin, EndpointClass::PublicHttps)
    }

    /// Creates a deterministic adapter at an explicit exact-origin seam.
    ///
    /// A URL embedded in `raw` is still required to target the production
    /// `console.sakana.ai` host. `origin` only replaces the network authority
    /// for isolated loopback tests.
    ///
    /// # Errors
    ///
    /// Returns a stable error for an invalid capture, account scope, or
    /// endpoint authority.
    #[doc(hidden)]
    pub fn from_manual_capture_at(
        scope: AccountScope,
        raw: &str,
        origin: Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        let policy = ManualCapturePolicy::new(["console.sakana.ai"], [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;

        let endpoint = billing_url(origin)?;
        validate_endpoint_class(&endpoint, endpoint_class)?;
        let pay_as_you_go_endpoint = pay_as_you_go_url(&endpoint)?;
        let policy =
            EndpointPolicy::new([(endpoint.origin().ascii_serialization(), endpoint_class)])
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        policy
            .validate(&endpoint)
            .and_then(|_| policy.validate(&pay_as_you_go_endpoint))
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Authentication::cookie(cookie.to_owned()).map_err(|error| error.classified())?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;

        Ok(Self {
            scope,
            endpoint,
            pay_as_you_go_endpoint,
            cookie: Zeroizing::new(cookie.to_owned()),
            transport,
        })
    }

    /// Fetches required quota data and bounded optional PAYG enrichment.
    ///
    /// The optional request starts with the required request but owns only a
    /// 200 ms budget from that shared start. Its failure never erases valid
    /// quota data.
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
        let required_request = self.request(self.endpoint.clone())?;
        let optional_request = self.request(self.pay_as_you_go_endpoint.clone())?;
        let required = self
            .transport
            .send(&required_request, context.cancellation());
        let optional = tokio::time::timeout(
            OPTIONAL_ENRICHMENT_BUDGET,
            self.transport
                .send(&optional_request, context.cancellation()),
        );
        let (required, optional) = tokio::join!(required, optional);
        let response = required.map_err(classify_required_transport)?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let pay_as_you_go = optional
            .ok()
            .and_then(Result::ok)
            .filter(|response| response.status() == 200)
            .and_then(|response| parse_pay_as_you_go_html(response.body()).ok().flatten());
        parse_billing_html(
            context.scope().clone(),
            fetched_at,
            response.body(),
            pay_as_you_go,
        )
    }

    /// Fetches only the required billing page.
    ///
    /// This seam keeps deterministic request and failure tests independent of
    /// optional enrichment. Production [`ProviderAdapter::fetch`] uses
    /// [`Self::fetch_at`].
    ///
    /// # Errors
    ///
    /// Returns stable source/scope, authentication, network, or parse errors.
    #[doc(hidden)]
    pub async fn fetch_required_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        self.validate_context(context)?;
        let request = self.request(self.endpoint.clone())?;
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(classify_required_transport)?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        parse_billing_html(context.scope().clone(), fetched_at, response.body(), None)
    }

    fn validate_context(&self, context: &ProviderContext) -> Result<(), ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::ManualCookie {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(())
    }

    fn request(&self, endpoint: Url) -> Result<HttpRequest, ClassifiedError> {
        let authentication = Authentication::cookie(self.cookie.as_str().to_owned())
            .map_err(|error| error.classified())?;
        HttpRequest::get(endpoint)
            .accept(RequestAccept::Html)
            .public_header("accept-language", "en-US,en;q=0.9")
            .map_err(|error| error.classified())
            .map(|request| request.authentication(authentication))
    }
}

impl ProviderAdapter for SakanaProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Sakana)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for SakanaProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SakanaProvider")
            .field("scope", &"<redacted>")
            .field("source", &ProviderSource::ManualCookie)
            .field("endpoint", &"<redacted>")
            .field("cookie", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

/// Parsed optional Sakana pay-as-you-go fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SakanaPayAsYouGo {
    credit_balance: Decimal,
    period_usage_total: Option<Decimal>,
    period_label: Option<String>,
}

impl SakanaPayAsYouGo {
    /// Credit balance reported by the console.
    #[must_use]
    pub const fn credit_balance(&self) -> Decimal {
        self.credit_balance
    }

    /// Usage total for the console-selected period.
    #[must_use]
    pub const fn period_usage_total(&self) -> Option<Decimal> {
        self.period_usage_total
    }

    /// Console-selected period label.
    #[must_use]
    pub fn period_label(&self) -> Option<&str> {
        self.period_label.as_deref()
    }
}

/// Parses one bounded PAYG page. Missing PAYG markup returns `Ok(None)`.
///
/// # Errors
///
/// Returns a stable parse error for invalid UTF-8, oversized markup, or
/// excessive element/text complexity.
pub fn parse_pay_as_you_go_html(body: &[u8]) -> Result<Option<SakanaPayAsYouGo>, ClassifiedError> {
    let html = bounded_html(body)?;
    let lower = html.to_ascii_lowercase();
    let Some(balance_heading) =
        find_exact_element(html, &lower, "h2", "Credit balance", 0, html.len())?
    else {
        return Ok(None);
    };
    let balance_end = balance_heading
        .close_end
        .saturating_add(900)
        .min(html.len());
    let mut balance = None;
    let mut cursor = balance_heading.close_end;
    let mut inspected = 0;
    while let Some(element) = next_element(&lower, "p", cursor, balance_end) {
        inspected += 1;
        if inspected > MAX_HTML_ELEMENTS {
            return Err(parse_error());
        }
        let opening = &lower[element.open_start..element.inner_start];
        if opening.contains("tabular-nums") {
            balance = parse_amount(&visible_text(
                &html[element.inner_start..element.inner_end],
            )?);
            break;
        }
        cursor = element.close_end;
    }
    let Some(credit_balance) = balance else {
        return Ok(None);
    };

    let usage_heading = find_exact_element(
        html,
        &lower,
        "h2",
        "Usage",
        balance_heading.close_end,
        html.len(),
    )?;
    let mut period_usage_total = None;
    if let Some(usage_heading) = usage_heading {
        let usage_end = usage_heading
            .close_end
            .saturating_add(1_200)
            .min(html.len());
        let mut cursor = usage_heading.close_end;
        let mut inspected = 0;
        while let Some(element) = next_element(&lower, "span", cursor, usage_end) {
            inspected += 1;
            if inspected > MAX_HTML_ELEMENTS {
                return Err(parse_error());
            }
            let text = visible_text(&html[element.inner_start..element.inner_end])?;
            if let Some((label, amount)) = text.split_once(':')
                && label.trim().eq_ignore_ascii_case("total")
            {
                period_usage_total = parse_amount(amount);
                break;
            }
            cursor = element.close_end;
        }
    }

    let period_label =
        find_attribute_element(html, &lower, "button", "aria-label", "Usage date range")?
            .map(|element| visible_text(&html[element.inner_start..element.inner_end]))
            .transpose()?
            .filter(|value| !value.is_empty());

    Ok(Some(SakanaPayAsYouGo {
        credit_balance,
        period_usage_total,
        period_label,
    }))
}

/// Parses the required Sakana billing page into the common domain model.
///
/// # Errors
///
/// Returns a stable parse error for invalid/oversized HTML, malformed quota
/// percentages or dates, absent quota windows, or bounded domain failures.
pub fn parse_billing_html(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
    pay_as_you_go: Option<SakanaPayAsYouGo>,
) -> Result<UsageSample, ClassifiedError> {
    validate_scope(&scope)?;
    let html = bounded_html(body)?;
    let lower = html.to_ascii_lowercase();
    let five_hour = parse_window(html, &lower, "5-hour", 5 * 60 * 60)?;
    let weekly = parse_window(html, &lower, "Weekly", 7 * 24 * 60 * 60)?;
    if five_hour.is_none() && weekly.is_none() {
        return Err(parse_error());
    }

    let (plan_name, price_label) = parse_plan(html, &lower)?;
    let login_method = [plan_name, price_label]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method((!login_method.is_empty()).then_some(login_method))?;
    if let Some(window) = five_hour {
        builder = builder.primary(window);
    }
    if let Some(window) = weekly {
        builder = builder.secondary(window);
    }
    if let Some(pay_as_you_go) = pay_as_you_go {
        builder = builder.detail_sections(vec![pay_as_you_go_section(&pay_as_you_go)?]);
    }
    builder.provenance("sakana", "manual_cookie")?.build()
}

fn parse_window(
    html: &str,
    lower: &str,
    label: &str,
    duration_seconds: u64,
) -> Result<Option<RateWindow>, ClassifiedError> {
    let Some(label_element) = find_exact_element(html, lower, "p", label, 0, html.len())? else {
        return Ok(None);
    };
    let mut boundary = html.len();
    for next_label in ["5-hour", "Weekly"] {
        if next_label.eq_ignore_ascii_case(label) {
            continue;
        }
        if let Some(element) = find_exact_element(
            html,
            lower,
            "p",
            next_label,
            label_element.close_end,
            html.len(),
        )? {
            boundary = boundary.min(element.open_start);
        }
    }

    let mut percent = None;
    let mut resets_at = None;
    let mut cursor = label_element.close_end;
    let mut inspected = 0;
    while let Some(element) = next_element(lower, "p", cursor, boundary) {
        inspected += 1;
        if inspected > MAX_HTML_ELEMENTS {
            return Err(parse_error());
        }
        let text = visible_text(&html[element.inner_start..element.inner_end])?;
        if let Some(raw) = strip_suffix_ascii_case(&text, "% used") {
            let parsed = raw
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
                .ok_or_else(parse_error)?;
            percent = Some(parsed);
        } else if let Some(raw) = strip_prefix_ascii_case(&text, "Resets on ") {
            resets_at = parse_reset_date(raw)?;
        }
        cursor = element.close_end;
    }
    let percent = percent.ok_or_else(parse_error)?;
    let duration = WindowDuration::from_seconds(duration_seconds).map_err(|_| parse_error())?;
    let used_percent = UsagePercent::new(percent).map_err(|_| parse_error())?;
    RateWindow::new(
        WindowUsage::known(used_percent),
        Some(duration),
        resets_at,
        None,
        None,
        false,
    )
    .map(Some)
    .map_err(|_| parse_error())
}

fn parse_plan(
    html: &str,
    lower: &str,
) -> Result<(Option<String>, Option<String>), ClassifiedError> {
    let mut cursor = 0;
    let mut inspected = 0;
    while let Some(element) = next_element(lower, "div", cursor, html.len()) {
        inspected += 1;
        if inspected > MAX_HTML_ELEMENTS {
            return Err(parse_error());
        }
        let opening = &lower[element.open_start..element.inner_start];
        if has_attribute(opening, "data-slot", "card-title") {
            let search_end = element.inner_start.saturating_add(2_048).min(html.len());
            let mut span_cursor = element.inner_start;
            let mut values = Vec::new();
            while let Some(span) = next_element(lower, "span", span_cursor, search_end) {
                let value = visible_text(&html[span.inner_start..span.inner_end])?;
                if !value.is_empty() {
                    if value.len() > MAX_PLAN_BYTES {
                        return Err(parse_error());
                    }
                    values.push(value);
                }
                if values.len() == 2 {
                    break;
                }
                span_cursor = span.close_end;
            }
            if !values.is_empty() {
                let price = (values.len() == 2).then(|| values.remove(1));
                return Ok((values.pop(), price));
            }
        }
        cursor = element.close_end;
    }
    Ok((None, None))
}

fn pay_as_you_go_section(
    pay_as_you_go: &SakanaPayAsYouGo,
) -> Result<DetailSection, ClassifiedError> {
    let mut rows = vec![
        DetailRow::new(
            "Balance",
            format_usd(pay_as_you_go.credit_balance),
            None,
            DetailSensitivity::Personal,
        )
        .map_err(|_| parse_error())?,
    ];
    if let Some(usage) = pay_as_you_go.period_usage_total {
        rows.push(
            DetailRow::new(
                "Usage",
                format_usd(usage),
                pay_as_you_go.period_label.clone(),
                DetailSensitivity::Personal,
            )
            .map_err(|_| parse_error())?,
        );
    }
    DetailSection::new(Some("Extra usage".to_owned()), rows, None).map_err(|_| parse_error())
}

fn format_usd(value: Decimal) -> String {
    format!("${value:.2}")
}

fn parse_reset_date(value: &str) -> Result<Option<Timestamp>, ClassifiedError> {
    let words = value.split_ascii_whitespace().collect::<Vec<_>>();
    if words.len() != 6 || words[3] != "at" {
        return Ok(None);
    }
    let month = match words[0] {
        "January" => Month::January,
        "February" => Month::February,
        "March" => Month::March,
        "April" => Month::April,
        "May" => Month::May,
        "June" => Month::June,
        "July" => Month::July,
        "August" => Month::August,
        "September" => Month::September,
        "October" => Month::October,
        "November" => Month::November,
        "December" => Month::December,
        _ => return Ok(None),
    };
    let day = words[1].trim_end_matches(',').parse::<u8>().ok();
    let year = words[2].trim_end_matches(',').parse::<i32>().ok();
    let (hour, minute) = words[4]
        .split_once(':')
        .and_then(|(hour, minute)| Some((hour.parse::<u8>().ok()?, minute.parse::<u8>().ok()?)))
        .unwrap_or((0, 0));
    let marker = words[5];
    let (Some(day), Some(year)) = (day, year) else {
        return Ok(None);
    };
    if hour == 0 || hour > 12 || minute > 59 {
        return Ok(None);
    }
    let hour = match marker {
        "AM" if hour == 12 => 0,
        "AM" => hour,
        "PM" if hour == 12 => 12,
        "PM" => hour + 12,
        _ => return Ok(None),
    };
    let date = Date::from_calendar_date(year, month, day).ok();
    let time = Time::from_hms(hour, minute, 0).ok();
    let (Some(date), Some(time)) = (date, time) else {
        return Ok(None);
    };
    let seconds = PrimitiveDateTime::new(date, time)
        .assume_offset(UtcOffset::UTC)
        .unix_timestamp();
    timestamp_from_unix(seconds).map(Some)
}

#[derive(Clone, Copy)]
struct Element {
    open_start: usize,
    inner_start: usize,
    inner_end: usize,
    close_end: usize,
}

fn next_element(lower: &str, tag: &str, from: usize, end: usize) -> Option<Element> {
    let opening = format!("<{tag}");
    let closing = format!("</{tag}>");
    let mut cursor = from;
    while cursor < end {
        let relative = lower.get(cursor..end)?.find(&opening)?;
        let open_start = cursor + relative;
        let name_end = open_start + opening.len();
        let next = lower.as_bytes().get(name_end).copied()?;
        if next != b'>' && !next.is_ascii_whitespace() {
            cursor = name_end;
            continue;
        }
        let inner_start = lower.get(name_end..end)?.find('>')? + name_end + 1;
        let inner_end = lower.get(inner_start..end)?.find(&closing)? + inner_start;
        return Some(Element {
            open_start,
            inner_start,
            inner_end,
            close_end: inner_end + closing.len(),
        });
    }
    None
}

fn find_exact_element(
    html: &str,
    lower: &str,
    tag: &str,
    expected: &str,
    from: usize,
    end: usize,
) -> Result<Option<Element>, ClassifiedError> {
    let mut cursor = from;
    let mut inspected = 0;
    while let Some(element) = next_element(lower, tag, cursor, end) {
        inspected += 1;
        if inspected > MAX_HTML_ELEMENTS {
            return Err(parse_error());
        }
        if visible_text(&html[element.inner_start..element.inner_end])?
            .eq_ignore_ascii_case(expected)
        {
            return Ok(Some(element));
        }
        cursor = element.close_end;
    }
    Ok(None)
}

fn find_attribute_element(
    html: &str,
    lower: &str,
    tag: &str,
    name: &str,
    value: &str,
) -> Result<Option<Element>, ClassifiedError> {
    let mut cursor = 0;
    let mut inspected = 0;
    while let Some(element) = next_element(lower, tag, cursor, html.len()) {
        inspected += 1;
        if inspected > MAX_HTML_ELEMENTS {
            return Err(parse_error());
        }
        if has_attribute(
            &lower[element.open_start..element.inner_start],
            &name.to_ascii_lowercase(),
            &value.to_ascii_lowercase(),
        ) {
            return Ok(Some(element));
        }
        cursor = element.close_end;
    }
    Ok(None)
}

fn has_attribute(opening: &str, name: &str, value: &str) -> bool {
    let double = format!(r#"{name}="{value}""#);
    let single = format!("{name}='{value}'");
    opening.contains(&double) || opening.contains(&single)
}

fn visible_text(fragment: &str) -> Result<String, ClassifiedError> {
    if fragment.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    let mut result = String::new();
    let mut in_tag = false;
    let mut pending_space = false;
    for character in fragment.chars() {
        match character {
            '<' => {
                in_tag = true;
                pending_space = !result.is_empty();
            }
            '>' if in_tag => in_tag = false,
            _ if in_tag => {}
            _ if character.is_whitespace() => pending_space = !result.is_empty(),
            _ => {
                if pending_space && !result.ends_with(' ') {
                    result.push(' ');
                }
                pending_space = false;
                result.push(character);
                if result.len() > MAX_ELEMENT_TEXT_BYTES {
                    return Err(parse_error());
                }
            }
        }
    }
    let result = result
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    Ok(result.trim().to_owned())
}

fn parse_amount(raw: &str) -> Option<Decimal> {
    let cleaned = raw.trim().trim_start_matches('$').replace(',', "");
    let amount = Decimal::from_str(cleaned.trim()).ok()?;
    (amount >= Decimal::ZERO).then_some(amount)
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .and_then(|_| value.get(prefix.len()..))
}

fn strip_suffix_ascii_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let start = value.len().checked_sub(suffix.len())?;
    value
        .get(start..)
        .filter(|candidate| candidate.eq_ignore_ascii_case(suffix))
        .and_then(|_| value.get(..start))
}

fn bounded_html(body: &[u8]) -> Result<&str, ClassifiedError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(parse_error());
    }
    std::str::from_utf8(body).map_err(|_| parse_error())
}

fn billing_url(mut origin: Url) -> Result<Url, ClassifiedError> {
    if origin.cannot_be_a_base()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    origin.set_path(BILLING_PATH);
    validate_billing_url(&origin)?;
    Ok(origin)
}

fn pay_as_you_go_url(endpoint: &Url) -> Result<Url, ClassifiedError> {
    validate_billing_url(endpoint)?;
    let mut endpoint = endpoint.clone();
    endpoint.set_query(Some(PAY_AS_YOU_GO_QUERY));
    Ok(endpoint)
}

fn validate_billing_url(endpoint: &Url) -> Result<(), ClassifiedError> {
    if endpoint.cannot_be_a_base()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.path() != BILLING_PATH
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_endpoint_class(
    endpoint: &Url,
    endpoint_class: EndpointClass,
) -> Result<(), ClassifiedError> {
    match endpoint_class {
        EndpointClass::PublicHttps
            if endpoint.scheme() == "https"
                && endpoint
                    .host_str()
                    .is_some_and(|host| host.eq_ignore_ascii_case("console.sakana.ai"))
                && endpoint.port_or_known_default() == Some(443) =>
        {
            Ok(())
        }
        EndpointClass::LoopbackDevelopment => Ok(()),
        EndpointClass::PublicHttps | EndpointClass::PrivateHttps | EndpointClass::PrivateHttp => {
            Err(ClassifiedError::new(ErrorKind::Api))
        }
    }
}

fn validate_scope(scope: &AccountScope) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Sakana {
        return Err(ClassifiedError::new(ErrorKind::Api));
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
        TransportError::AuthenticationExpired
        | TransportError::PermissionDenied
        | TransportError::Endpoint(_)
        | TransportError::TooManyRedirects => {
            ClassifiedError::new(ErrorKind::AuthenticationExpired)
        }
        other => other.classified(),
    }
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

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
