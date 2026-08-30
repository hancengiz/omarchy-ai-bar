//! `OpenCode` browser-session usage adapter.

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use oab_domain::{
    AccountScope, ClassifiedError, CostAmount, CostProvenance, CostSummary, CurrencyCode,
    ErrorKind, ExactDecimal, Money, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample,
    WindowDuration, WindowUsage,
};
use reqwest::header::{ACCEPT, CONTENT_TYPE, COOKIE, HeaderValue, ORIGIN, REFERER, USER_AGENT};
use reqwest::{Client, Method, StatusCode};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::cookie::{CookieHeaderNormalizer, CookieJar, CookieUrlPolicy, ValidatedCookieUrl};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;

const PRODUCTION_ORIGIN: &str = "https://opencode.ai";
const SERVER_PATH: &str = "/_server";
const WORKSPACES_SERVER_ID: &str =
    "def39973159c7f0483d8793a822b8dbb10d067e12c65455fcb4608459ba0234f";
const SUBSCRIPTION_SERVER_ID: &str =
    "7abeebee372f304e050aaaf92be863f4a86490e382f8c79db68fd94040d691b4";
const BILLING_SERVER_ID: &str = "c83b78a614689c38ebee981f9b39a8b377716db85c1fd7dbab604adc02d3313d";
const USER_AGENT_VALUE: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
);
const ACCEPT_VALUE: &str = "text/javascript, application/json;q=0.9, */*;q=0.8";
const AUTH_COOKIE_NAMES: [&str; 2] = ["auth", "__Host-auth"];
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024;
const MAX_JSON_NODES: usize = 32_768;
const MAX_JSON_DEPTH: usize = 32;
const MAX_PAYLOAD_DEPTH: usize = 64;
const MAX_PAYLOAD_TOKENS: usize = 65_536;
const MAX_FIELD_BYTES: usize = 8 * 1024;
const MAX_WORKSPACES: usize = 64;
const MAX_WORKSPACE_BYTES: usize = 128;
const MAX_WINDOW_CANDIDATES: usize = 256;
const USD_SCALE: i64 = 100_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

static INSTANCE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// `OpenCode` adapter permanently bound to one credential source and account scope.
pub struct OpenCodeProvider {
    scope: AccountScope,
    source: ProviderSource,
    server_url: Url,
    cookie: Zeroizing<String>,
    workspace_override: Option<String>,
    transport: OpenCodeTransport,
}

impl OpenCodeProvider {
    /// Creates the production adapter from a manually supplied Cookie header or cURL capture.
    ///
    /// # Errors
    ///
    /// Returns a stable error for a malformed capture, missing `OpenCode` authentication cookie,
    /// invalid account scope, or invalid fixed endpoint configuration.
    pub fn new_manual(
        scope: AccountScope,
        raw: &str,
        workspace_override: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Self::from_manual_capture_at(
            scope,
            raw,
            workspace_override,
            origin,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates a manual adapter against an explicit exact-origin test seam.
    ///
    /// Captured cURL URLs remain restricted to exact `opencode.ai`; only the supplied origin is
    /// replaced for isolated loopback tests. Captured headers other than `Cookie` are rejected.
    ///
    /// # Errors
    ///
    /// Returns a stable redacted capture, credential, or endpoint error.
    pub fn from_manual_capture_at(
        scope: AccountScope,
        raw: &str,
        workspace_override: Option<&str>,
        origin: Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        let policy = ManualCapturePolicy::new(["opencode.ai"], [CaptureHeader::Cookie])
            .map_err(classify_capture_error)?
            .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture_error)?;
        let raw_cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let server_url = server_url(origin)?;
        let _target = ValidatedCookieUrl::new(
            server_url.clone(),
            cookie_policy(endpoint_class, &server_url)?,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let cookie = filtered_cookie(raw_cookie)?;
        Self::build(
            scope,
            ProviderSource::ManualCookie,
            server_url,
            endpoint_class,
            cookie,
            workspace_override,
        )
    }

    /// Creates the production adapter from one already imported browser cookie jar.
    ///
    /// No browser discovery, filesystem access, ambient cookie store, or cache is consulted.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential or endpoint error.
    pub fn new_browser(
        scope: AccountScope,
        jar: &CookieJar,
        now: OffsetDateTime,
        workspace_override: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        let origin =
            Url::parse(PRODUCTION_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let target = Self::browser_target(origin, CookieUrlPolicy::HttpsOnly)?;
        Self::from_browser_jar_at(
            scope,
            jar,
            &target,
            now,
            workspace_override,
            EndpointClass::PublicHttps,
        )
    }

    /// Creates a browser adapter from one validated exact target and injected time.
    ///
    /// # Errors
    ///
    /// Returns a stable missing/expired credential, target, or scope error.
    pub fn from_browser_jar_at(
        scope: AccountScope,
        jar: &CookieJar,
        target: &ValidatedCookieUrl,
        now: OffsetDateTime,
        workspace_override: Option<&str>,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        validate_server_url(target.url())?;
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
        let cookie = filtered_cookie(selected.expose()).map_err(|error| {
            if error.kind() == ErrorKind::MissingCredential {
                ClassifiedError::new(ErrorKind::AuthenticationExpired)
            } else {
                error
            }
        })?;
        Self::build(
            scope,
            ProviderSource::BrowserSession,
            target.url().clone(),
            endpoint_class,
            cookie,
            workspace_override,
        )
    }

    /// Builds the exact cookie target for an injected origin.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the origin or cookie policy is invalid.
    pub fn browser_target(
        origin: Url,
        policy: CookieUrlPolicy,
    ) -> Result<ValidatedCookieUrl, ClassifiedError> {
        ValidatedCookieUrl::new(server_url(origin)?, policy)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))
    }

    fn build(
        scope: AccountScope,
        source: ProviderSource,
        server_url: Url,
        endpoint_class: EndpointClass,
        cookie: Zeroizing<String>,
        workspace_override: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::OpenCode
            || !matches!(
                source,
                ProviderSource::ManualCookie | ProviderSource::BrowserSession
            )
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        validate_server_url(&server_url)?;
        validate_endpoint_class(&server_url, endpoint_class)?;
        let origin = server_url.origin().ascii_serialization();
        let policy = EndpointPolicy::new([(origin, endpoint_class)])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        policy
            .validate(&server_url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport = OpenCodeTransport::new(policy)?;
        let workspace_override = workspace_override.and_then(normalize_workspace_id);
        Ok(Self {
            scope,
            source,
            server_url,
            cookie,
            workspace_override,
            transport,
        })
    }

    /// Fetches one deterministic sample at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable redacted credential, rate-limit, challenge, network, API, or parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != self.source {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let workspace = match &self.workspace_override {
            Some(workspace) => workspace.clone(),
            None => self.discover_workspace(context).await?,
        };
        match self
            .fetch_subscription(context, &workspace, fetched_at)
            .await
        {
            Ok(sample) => Ok(sample),
            Err(subscription_error)
                if matches!(subscription_error.kind(), ErrorKind::Api | ErrorKind::Parse) =>
            {
                match self.fetch_billing(context, &workspace, fetched_at).await {
                    Ok(Some(sample)) => Ok(sample),
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::AuthenticationExpired | ErrorKind::MissingCredential
                        ) =>
                    {
                        Err(error)
                    }
                    Ok(None) | Err(_) => Err(subscription_error),
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn discover_workspace(
        &self,
        context: &ProviderContext,
    ) -> Result<String, ClassifiedError> {
        let referer = PRODUCTION_ORIGIN;
        let response = self
            .server_call(
                context,
                ServerCall::get(WORKSPACES_SERVER_ID, None, referer),
            )
            .await?;
        let mut ids = parse_workspace_ids(&response)?;
        if ids.is_empty() {
            let response = self
                .server_call(
                    context,
                    ServerCall::post(WORKSPACES_SERVER_ID, "[]", referer),
                )
                .await?;
            ids = parse_workspace_ids(&response)?;
        }
        ids.into_iter()
            .next()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
    }

    async fn fetch_subscription(
        &self,
        context: &ProviderContext,
        workspace: &str,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let args = workspace_args(workspace)?;
        let referer = format!("{PRODUCTION_ORIGIN}/workspace/{workspace}/billing");
        let response = self
            .server_call(
                context,
                ServerCall::get(SUBSCRIPTION_SERVER_ID, Some(args.as_str()), &referer),
            )
            .await?;
        if is_explicit_null(&response)? {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        if let Ok(sample) = parse_subscription(self.scope.clone(), fetched_at, &response) {
            return Ok(sample);
        }
        let response = self
            .server_call(
                context,
                ServerCall::post(SUBSCRIPTION_SERVER_ID, args.as_str(), &referer),
            )
            .await?;
        if is_explicit_null(&response)? {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        parse_subscription(self.scope.clone(), fetched_at, &response)
    }

    async fn fetch_billing(
        &self,
        context: &ProviderContext,
        workspace: &str,
        fetched_at: Timestamp,
    ) -> Result<Option<UsageSample>, ClassifiedError> {
        let args = workspace_args(workspace)?;
        let referer = format!("{PRODUCTION_ORIGIN}/workspace/{workspace}");
        let response = self
            .server_call(
                context,
                ServerCall::get(BILLING_SERVER_ID, Some(args.as_str()), &referer),
            )
            .await?;
        parse_billing(self.scope.clone(), fetched_at, &response)
    }

    async fn server_call(
        &self,
        context: &ProviderContext,
        call: ServerCall<'_>,
    ) -> Result<Vec<u8>, ClassifiedError> {
        let url = call.url(&self.server_url)?;
        let response = self
            .transport
            .send(
                call.method,
                url,
                self.cookie.as_str(),
                call.server_id,
                call.referer,
                call.body,
                context.cancellation(),
            )
            .await?;
        classify_response(response)
    }
}

impl ProviderAdapter for OpenCodeProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::OpenCode)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

impl Debug for OpenCodeProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCodeProvider")
            .field("scope", &"<redacted>")
            .field("source", &self.source)
            .field("server_url", &"<redacted>")
            .field("cookie", &"<redacted>")
            .field(
                "workspace_override",
                &self.workspace_override.as_ref().map(|_| "<redacted>"),
            )
            .field("transport", &"<redacted>")
            .finish()
    }
}

struct ServerCall<'a> {
    method: Method,
    server_id: &'static str,
    args: Option<&'a str>,
    body: Option<&'a str>,
    referer: &'a str,
}

impl<'a> ServerCall<'a> {
    const fn get(server_id: &'static str, args: Option<&'a str>, referer: &'a str) -> Self {
        Self {
            method: Method::GET,
            server_id,
            args,
            body: None,
            referer,
        }
    }

    const fn post(server_id: &'static str, body: &'a str, referer: &'a str) -> Self {
        Self {
            method: Method::POST,
            server_id,
            args: None,
            body: Some(body),
            referer,
        }
    }

    fn url(&self, server_url: &Url) -> Result<Url, ClassifiedError> {
        let mut url = server_url.clone();
        if self.method == Method::GET {
            url.query_pairs_mut().append_pair("id", self.server_id);
            if let Some(args) = self.args {
                url.query_pairs_mut().append_pair("args", args);
            }
        }
        validate_request_url(&url, self.method == Method::GET)?;
        Ok(url)
    }
}

struct OpenCodeTransport {
    client: Client,
    policy: EndpointPolicy,
}

impl OpenCodeTransport {
    fn new(policy: EndpointPolicy) -> Result<Self, ClassifiedError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self { client, policy })
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        method: Method,
        url: Url,
        cookie: &str,
        server_id: &str,
        referer: &str,
        body: Option<&str>,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<OpenCodeResponse, ClassifiedError> {
        let endpoint = self
            .policy
            .validate(&url)
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let instance = next_instance_header();
        let mut request = self
            .client
            .request(method, endpoint.url().clone())
            .header(COOKIE, sensitive_header(cookie)?)
            .header("x-server-id", server_id)
            .header("x-server-instance", instance)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(ORIGIN, PRODUCTION_ORIGIN)
            .header(REFERER, referer)
            .header(ACCEPT, ACCEPT_VALUE);
        if let Some(body) = body {
            if body.len() > MAX_REQUEST_BODY_BYTES {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(body.to_owned());
        }
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

struct OpenCodeResponse {
    status: StatusCode,
    challenge: bool,
    body: Vec<u8>,
}

async fn read_response(response: reqwest::Response) -> Result<OpenCodeResponse, ClassifiedError> {
    let status = response.status();
    let challenge = response
        .headers()
        .get("x-vercel-mitigated")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("challenge"));
    if status.is_redirection()
        || status.is_informational()
        || status == StatusCode::UNAUTHORIZED
        || challenge
        || status == StatusCode::FORBIDDEN
        || status == StatusCode::TOO_MANY_REQUESTS
    {
        return Ok(OpenCodeResponse {
            status,
            challenge,
            body: Vec::new(),
        });
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
    Ok(OpenCodeResponse {
        status,
        challenge,
        body,
    })
}

fn classify_response(response: OpenCodeResponse) -> Result<Vec<u8>, ClassifiedError> {
    if response.status.is_redirection() || response.status.is_informational() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    match response.status {
        StatusCode::UNAUTHORIZED => Err(ClassifiedError::new(ErrorKind::AuthenticationExpired)),
        _ if response.challenge => Err(ClassifiedError::new(ErrorKind::PermissionDenied)),
        StatusCode::FORBIDDEN => Err(ClassifiedError::new(ErrorKind::AuthenticationExpired)),
        StatusCode::TOO_MANY_REQUESTS => Err(ClassifiedError::new(ErrorKind::RateLimited)),
        status => {
            if looks_signed_out(&response.body)? {
                return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
            }
            if status == StatusCode::OK {
                Ok(response.body)
            } else {
                Err(ClassifiedError::new(ErrorKind::Api))
            }
        }
    }
}

/// Parses one bounded subscription response into the rolling and weekly lanes.
///
/// # Errors
///
/// Returns a stable parse error for malformed UTF-8, payload bounds, missing windows, invalid
/// timestamps, or values that violate the domain model.
pub fn parse_subscription(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
) -> Result<UsageSample, ClassifiedError> {
    let text = validated_text(body)?;
    let parsed = if let Ok(root) = serde_json::from_str::<Value>(text) {
        validate_json_shape(&root)?;
        parse_json_subscription(&root, fetched_at)?
    } else {
        parse_payload_subscription(text, fetched_at)?
    };
    subscription_sample(scope, fetched_at, parsed)
}

/// Parses a bounded billing response. `Ok(None)` means the payload is not a PAYG customer or still
/// carries a subscription, so callers must preserve the original subscription error.
///
/// # Errors
///
/// Returns a stable parse error for malformed UTF-8, payload bounds, or invalid money values.
pub fn parse_billing(
    scope: AccountScope,
    fetched_at: Timestamp,
    body: &[u8],
) -> Result<Option<UsageSample>, ClassifiedError> {
    let text = validated_text(body)?;
    let billing = if let Ok(root) = serde_json::from_str::<Value>(text) {
        validate_json_shape(&root)?;
        parse_json_billing(&root)?
    } else {
        parse_payload_billing(text)?
    };
    billing
        .filter(|billing| !billing.has_subscription)
        .map(|billing| billing_sample(scope, fetched_at, billing))
        .transpose()
}

#[derive(Clone, Copy)]
struct ParsedWindow {
    percent: f64,
    reset_seconds: i64,
}

#[derive(Clone, Copy)]
struct ParsedSubscription {
    rolling: ParsedWindow,
    weekly: ParsedWindow,
    renews_at: Option<Timestamp>,
}

#[derive(Clone, Copy)]
struct BillingInfo {
    monthly_usage: Decimal,
    monthly_limit: Option<Decimal>,
    balance: Option<Decimal>,
    has_subscription: bool,
}

fn subscription_sample(
    scope: AccountScope,
    fetched_at: Timestamp,
    parsed: ParsedSubscription,
) -> Result<UsageSample, ClassifiedError> {
    let rolling = rate_window(parsed.rolling, fetched_at, 5 * 60)?;
    let weekly = rate_window(parsed.weekly, fetched_at, 7 * 24 * 60)?;
    UsageSampleBuilder::new(scope, fetched_at)
        .primary(rolling)
        .secondary(weekly)
        .subscription_renews_at(parsed.renews_at)
        .provenance("opencode", "web")?
        .build()
}

fn rate_window(
    parsed: ParsedWindow,
    fetched_at: Timestamp,
    minutes: i64,
) -> Result<RateWindow, ClassifiedError> {
    let reset = fetched_at
        .as_offset_date_time()
        .checked_add(time::Duration::seconds(parsed.reset_seconds))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let reset = Timestamp::new(reset).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(parsed.percent)
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(
            WindowDuration::from_provider_minutes(minutes)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
        ),
        Some(reset),
        None,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn billing_sample(
    scope: AccountScope,
    fetched_at: Timestamp,
    billing: BillingInfo,
) -> Result<UsageSample, ClassifiedError> {
    let usd = CurrencyCode::new("USD").map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let limit = billing.monthly_limit.unwrap_or(Decimal::ZERO);
    let mut builder = UsageSampleBuilder::new(scope, fetched_at);
    if limit > Decimal::ZERO {
        let percent = billing
            .monthly_usage
            .checked_mul(Decimal::from(100_u8))
            .and_then(|value| value.checked_div(limit))
            .and_then(|value| value.to_f64())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .clamp(0.0, 100.0);
        let primary = RateWindow::new(
            WindowUsage::known(
                UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
            ),
            Some(
                WindowDuration::from_provider_minutes(30 * 24 * 60)
                    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            ),
            None,
            None,
            None,
            false,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        builder = builder.primary(primary);
    }
    if let Some(balance) = billing.balance {
        builder = builder.balance(Money::new(ExactDecimal::new(balance), usd.clone()));
    }
    let cost = CostSummary::new(
        CostAmount::money(ExactDecimal::new(billing.monthly_usage), usd),
        ExactDecimal::new(limit),
        Some("Monthly".to_owned()),
        None,
        None,
        None,
        billing.balance.map(ExactDecimal::new),
        fetched_at,
        None,
        None,
        CostProvenance::VendorMetered,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    builder.cost(cost).provenance("opencode", "web")?.build()
}

fn parse_json_subscription(
    root: &Value,
    fetched_at: Timestamp,
) -> Result<ParsedSubscription, ClassifiedError> {
    if let Some(parsed) = find_named_windows(root, fetched_at, None, 0)? {
        return Ok(parsed);
    }
    let mut candidates = Vec::new();
    collect_candidates(root, fetched_at, &mut Vec::new(), &mut candidates, 0)?;
    select_candidates(root, &candidates, fetched_at)
}

fn find_named_windows(
    value: &Value,
    fetched_at: Timestamp,
    inherited_renewal: Option<Timestamp>,
    depth: usize,
) -> Result<Option<ParsedSubscription>, ClassifiedError> {
    if depth > 4 {
        return Ok(None);
    }
    let Value::Object(object) = value else {
        return Ok(None);
    };
    let renewal = object_renewal(object).or(inherited_renewal);
    if let Some(Value::Object(usage)) = object.get("usage")
        && let Some(found) = find_named_windows(
            &Value::Object(usage.clone()),
            fetched_at,
            renewal,
            depth + 1,
        )?
    {
        return Ok(Some(found));
    }
    let rolling = named_object(object, &ROLLING_KEYS);
    let weekly = named_object(object, &WEEKLY_KEYS);
    if let (Some(rolling), Some(weekly)) = (rolling, weekly) {
        return Ok(Some(ParsedSubscription {
            rolling: parse_json_window(rolling, fetched_at)?,
            weekly: parse_json_window(weekly, fetched_at)?,
            renews_at: renewal,
        }));
    }
    for child in object.values() {
        if let Some(found) = find_named_windows(child, fetched_at, renewal, depth + 1)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

const ROLLING_KEYS: [&str; 5] = [
    "rollingUsage",
    "rolling",
    "rolling_usage",
    "rollingWindow",
    "rolling_window",
];
const WEEKLY_KEYS: [&str; 5] = [
    "weeklyUsage",
    "weekly",
    "weekly_usage",
    "weeklyWindow",
    "weekly_window",
];

fn named_object<'a>(
    object: &'a Map<String, Value>,
    names: &[&str],
) -> Option<&'a Map<String, Value>> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_object))
}

struct WindowCandidate {
    window: ParsedWindow,
    path: String,
    ordinal: usize,
}

fn collect_candidates(
    value: &Value,
    fetched_at: Timestamp,
    path: &mut Vec<String>,
    output: &mut Vec<WindowCandidate>,
    depth: usize,
) -> Result<(), ClassifiedError> {
    if depth > MAX_JSON_DEPTH || output.len() > MAX_WINDOW_CANDIDATES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    match value {
        Value::Object(object) => {
            if let Ok(window) = parse_json_window(object, fetched_at) {
                output.push(WindowCandidate {
                    window,
                    path: path.join(".").to_ascii_lowercase(),
                    ordinal: output.len(),
                });
                if output.len() > MAX_WINDOW_CANDIDATES {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
            }
            for (key, child) in object {
                path.push(key.clone());
                collect_candidates(child, fetched_at, path, output, depth + 1)?;
                path.pop();
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                path.push(format!("[{index}]"));
                collect_candidates(child, fetched_at, path, output, depth + 1)?;
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn select_candidates(
    root: &Value,
    candidates: &[WindowCandidate],
    _fetched_at: Timestamp,
) -> Result<ParsedSubscription, ClassifiedError> {
    let rolling = pick_candidate(candidates, true, None)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let weekly = pick_candidate(candidates, false, Some(rolling.ordinal))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let renewal = root.as_object().and_then(object_renewal);
    Ok(ParsedSubscription {
        rolling: rolling.window,
        weekly: weekly.window,
        renews_at: renewal,
    })
}

fn pick_candidate(
    candidates: &[WindowCandidate],
    rolling: bool,
    excluded: Option<usize>,
) -> Option<&WindowCandidate> {
    let preferred = |candidate: &&WindowCandidate| {
        let path = candidate.path.as_str();
        if rolling {
            path.contains("rolling")
                || path.contains("hour")
                || path.contains("5h")
                || path.contains("5-hour")
        } else {
            path.contains("weekly") || path.contains("week")
        }
    };
    let choose = |left: &&WindowCandidate, right: &&WindowCandidate| {
        let reset_ordering = left.window.reset_seconds.cmp(&right.window.reset_seconds);
        let reset_ordering = if rolling {
            reset_ordering
        } else {
            reset_ordering.reverse()
        };
        reset_ordering
            .then_with(|| right.window.percent.total_cmp(&left.window.percent))
            .then_with(|| left.ordinal.cmp(&right.ordinal))
    };
    let eligible = candidates
        .iter()
        .filter(|candidate| Some(candidate.ordinal) != excluded);
    eligible
        .clone()
        .filter(preferred)
        .min_by(choose)
        .or_else(|| eligible.min_by(choose))
}

fn parse_json_window(
    object: &Map<String, Value>,
    fetched_at: Timestamp,
) -> Result<ParsedWindow, ClassifiedError> {
    let direct = first_decimal(object, &PERCENT_KEYS)?;
    let percent = if let Some(mut percent) = direct {
        if (Decimal::ZERO..=Decimal::ONE).contains(&percent) {
            percent = percent
                .checked_mul(Decimal::from(100_u8))
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        }
        percent
    } else {
        let used = first_decimal(object, &USED_KEYS)?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let limit = first_decimal(object, &LIMIT_KEYS)?
            .filter(|limit| *limit > Decimal::ZERO)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        used.checked_mul(Decimal::from(100_u8))
            .and_then(|value| value.checked_div(limit))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
    };
    let percent = percent
        .to_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .clamp(0.0, 100.0);
    let reset_seconds = first_i64(object, &RESET_IN_KEYS)?
        .or_else(|| {
            first_value(object, &RESET_AT_KEYS)
                .and_then(|value| parse_json_timestamp(value).ok().flatten())
                .map(|reset| {
                    reset
                        .unix_timestamp()
                        .saturating_sub(fetched_at.unix_timestamp())
                })
        })
        .unwrap_or(0)
        .max(0);
    Ok(ParsedWindow {
        percent,
        reset_seconds,
    })
}

const PERCENT_KEYS: [&str; 10] = [
    "usagePercent",
    "usedPercent",
    "percentUsed",
    "percent",
    "usage_percent",
    "used_percent",
    "utilization",
    "utilizationPercent",
    "utilization_percent",
    "usage",
];
const USED_KEYS: [&str; 5] = ["used", "usage", "consumed", "count", "usedTokens"];
const LIMIT_KEYS: [&str; 6] = ["limit", "total", "quota", "max", "cap", "tokenLimit"];
const RESET_IN_KEYS: [&str; 9] = [
    "resetInSec",
    "resetInSeconds",
    "resetSeconds",
    "reset_sec",
    "reset_in_sec",
    "resetsInSec",
    "resetsInSeconds",
    "resetIn",
    "resetSec",
];
const RESET_AT_KEYS: [&str; 10] = [
    "resetAt",
    "resetsAt",
    "reset_at",
    "resets_at",
    "nextReset",
    "next_reset",
    "renewAt",
    "renew_at",
    "nextResetAt",
    "next_reset_at",
];
const RENEW_KEYS: [&str; 2] = ["renewAt", "renew_at"];

fn first_value<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn first_decimal(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Result<Option<Decimal>, ClassifiedError> {
    for key in keys {
        if let Some(value) = object.get(*key).filter(|value| !value.is_null()) {
            return json_decimal(value).map(Some);
        }
    }
    Ok(None)
}

fn first_i64(object: &Map<String, Value>, keys: &[&str]) -> Result<Option<i64>, ClassifiedError> {
    for key in keys {
        if let Some(value) = object.get(*key).filter(|value| !value.is_null()) {
            return json_i64(value).map(Some);
        }
    }
    Ok(None)
}

fn object_renewal(object: &Map<String, Value>) -> Option<Timestamp> {
    first_value(object, &RENEW_KEYS).and_then(|value| parse_json_timestamp(value).ok().flatten())
}

fn parse_json_timestamp(value: &Value) -> Result<Option<Timestamp>, ClassifiedError> {
    match value {
        Value::String(value) => parse_timestamp_text(value),
        Value::Number(_) => timestamp_from_decimal(json_decimal(value)?),
        Value::Null => Ok(None),
        Value::Bool(_) | Value::Array(_) | Value::Object(_) => {
            Err(ClassifiedError::new(ErrorKind::Parse))
        }
    }
}

fn parse_payload_subscription(
    text: &str,
    fetched_at: Timestamp,
) -> Result<ParsedSubscription, ClassifiedError> {
    let rolling = find_object_for_any_field(text, &ROLLING_KEYS)?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let weekly = find_object_for_any_field(text, &WEEKLY_KEYS)?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let rolling = parse_payload_window(rolling, fetched_at)?;
    let weekly = parse_payload_window(weekly, fetched_at)?;
    let renews_at = find_scalar_for_any_field(text, &RENEW_KEYS)
        .ok()
        .flatten()
        .and_then(|value| parse_payload_timestamp(value).ok().flatten());
    Ok(ParsedSubscription {
        rolling,
        weekly,
        renews_at,
    })
}

fn parse_payload_window(
    object: &str,
    fetched_at: Timestamp,
) -> Result<ParsedWindow, ClassifiedError> {
    let direct = find_decimal_for_any_field(object, &PERCENT_KEYS)?;
    let percent = if let Some(mut percent) = direct {
        if (Decimal::ZERO..=Decimal::ONE).contains(&percent) {
            percent = percent
                .checked_mul(Decimal::from(100_u8))
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        }
        percent
    } else {
        let used = find_decimal_for_any_field(object, &USED_KEYS)?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let limit = find_decimal_for_any_field(object, &LIMIT_KEYS)?
            .filter(|limit| *limit > Decimal::ZERO)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        used.checked_mul(Decimal::from(100_u8))
            .and_then(|value| value.checked_div(limit))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
    };
    let percent = percent
        .to_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .clamp(0.0, 100.0);
    let reset_seconds = if let Some(value) = find_i64_for_any_field(object, &RESET_IN_KEYS)? {
        value.max(0)
    } else if let Some(value) = find_scalar_for_any_field(object, &RESET_AT_KEYS)? {
        parse_payload_timestamp(value)?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .unix_timestamp()
            .saturating_sub(fetched_at.unix_timestamp())
            .max(0)
    } else {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    };
    Ok(ParsedWindow {
        percent,
        reset_seconds,
    })
}

fn parse_json_billing(root: &Value) -> Result<Option<BillingInfo>, ClassifiedError> {
    let Some(customer) = find_customer_object(root, 0)? else {
        return Ok(None);
    };
    let Some(monthly_usage) = customer.get("monthlyUsage") else {
        return Ok(None);
    };
    let monthly_usage = scaled_usd(json_decimal(monthly_usage)?)?;
    let monthly_limit = customer
        .get("monthlyLimit")
        .filter(|value| !value.is_null())
        .and_then(|value| json_decimal(value).ok());
    let balance = customer
        .get("balance")
        .filter(|value| !value.is_null())
        .and_then(|value| json_decimal(value).ok())
        .and_then(|value| scaled_usd(value).ok());
    let has_subscription = customer
        .get("subscription")
        .is_some_and(|value| !value.is_null());
    Ok(Some(BillingInfo {
        monthly_usage,
        monthly_limit,
        balance,
        has_subscription,
    }))
}

fn find_customer_object(
    value: &Value,
    depth: usize,
) -> Result<Option<&Map<String, Value>>, ClassifiedError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    match value {
        Value::Object(object) => {
            if object
                .get("customerID")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty() && value.len() <= MAX_FIELD_BYTES)
            {
                return Ok(Some(object));
            }
            for child in object.values() {
                if let Some(found) = find_customer_object(child, depth + 1)? {
                    return Ok(Some(found));
                }
            }
            Ok(None)
        }
        Value::Array(values) => {
            for child in values {
                if let Some(found) = find_customer_object(child, depth + 1)? {
                    return Ok(Some(found));
                }
            }
            Ok(None)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(None),
    }
}

fn parse_payload_billing(text: &str) -> Result<Option<BillingInfo>, ClassifiedError> {
    let customer = find_scalar_for_any_field(text, &["customerID"])?;
    if customer.is_none_or(|value| parse_string_scalar(value).is_none_or(str::is_empty)) {
        return Ok(None);
    }
    let Some(raw_usage) = find_decimal_for_any_field(text, &["monthlyUsage"])? else {
        return Ok(None);
    };
    let monthly_usage = scaled_usd(raw_usage)?;
    let monthly_limit = find_decimal_for_any_field(text, &["monthlyLimit"])
        .ok()
        .flatten();
    let balance = find_decimal_for_any_field(text, &["balance"])
        .ok()
        .flatten()
        .and_then(|value| scaled_usd(value).ok());
    let subscription = find_scalar_for_any_field(text, &["subscription"])?;
    let has_subscription = subscription.is_some_and(|value| {
        !value.trim_start().starts_with("null") && !value.trim_start().starts_with("undefined")
    });
    Ok(Some(BillingInfo {
        monthly_usage,
        monthly_limit,
        balance,
        has_subscription,
    }))
}

fn scaled_usd(raw: Decimal) -> Result<Decimal, ClassifiedError> {
    raw.checked_div(Decimal::from(USD_SCALE))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn json_decimal(value: &Value) -> Result<Decimal, ClassifiedError> {
    let raw = match value {
        Value::Number(number) => number.to_string(),
        Value::String(value) if value.len() <= MAX_FIELD_BYTES => value.trim().to_owned(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) | Value::String(_) => {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
    };
    raw.parse::<Decimal>()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn json_i64(value: &Value) -> Result<i64, ClassifiedError> {
    let decimal = json_decimal(value)?;
    if decimal.fract() != Decimal::ZERO {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    decimal
        .to_i64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn timestamp_from_decimal(value: Decimal) -> Result<Option<Timestamp>, ClassifiedError> {
    if value <= Decimal::from(1_000_000_000_u64) {
        return Ok(None);
    }
    let threshold = Decimal::from(1_000_000_000_000_i64);
    let seconds = if value > threshold {
        value
            .checked_div(Decimal::from(1000_u16))
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
    } else {
        value
    };
    let seconds = seconds
        .trunc()
        .to_i64()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::from_unix_timestamp(seconds)
        .map(Some)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn parse_timestamp_text(value: &str) -> Result<Option<Timestamp>, ClassifiedError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Timestamp::new(timestamp)
            .map(Some)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse));
    }
    let decimal = value
        .parse::<Decimal>()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    timestamp_from_decimal(decimal)
}

fn parse_payload_timestamp(value: &str) -> Result<Option<Timestamp>, ClassifiedError> {
    let value = value.trim_start();
    if value.starts_with("null") || value.starts_with("undefined") {
        return Ok(None);
    }
    if let Some(string) = parse_string_scalar(value) {
        return parse_timestamp_text(string);
    }
    let token = scalar_token(value);
    parse_timestamp_text(token)
}

fn validate_json_shape(root: &Value) -> Result<(), ClassifiedError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .filter(|nodes| *nodes <= MAX_JSON_NODES)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        if depth > MAX_JSON_DEPTH {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().rev().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > MAX_JSON_NODES
                    || values
                        .keys()
                        .any(|key| key.len() > MAX_FIELD_BYTES || key.contains(['\r', '\n']))
                {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                stack.extend(values.values().rev().map(|value| (value, depth + 1)));
            }
            Value::String(value) if value.len() > MAX_FIELD_BYTES => {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn validated_text(body: &[u8]) -> Result<&str, ClassifiedError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let text = std::str::from_utf8(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    validate_payload_shape(text)?;
    Ok(text)
}

fn validate_payload_shape(text: &str) -> Result<(), ClassifiedError> {
    let bytes = text.as_bytes();
    let mut stack = Vec::new();
    let mut tokens = 0_usize;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' => {
                let end = quoted_end(bytes, index)?;
                if end.saturating_sub(index) > MAX_FIELD_BYTES {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                index = end;
                tokens = bounded_increment(tokens, MAX_PAYLOAD_TOKENS)?;
            }
            open @ (b'{' | b'[' | b'(') => {
                stack.push(open);
                if stack.len() > MAX_PAYLOAD_DEPTH {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                tokens = bounded_increment(tokens, MAX_PAYLOAD_TOKENS)?;
            }
            close @ (b'}' | b']' | b')') => {
                let Some(open) = stack.pop() else {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                };
                if !matches!((open, close), (b'{', b'}') | (b'[', b']') | (b'(', b')')) {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                tokens = bounded_increment(tokens, MAX_PAYLOAD_TOKENS)?;
            }
            b',' | b':' | b'=' | b';' => {
                tokens = bounded_increment(tokens, MAX_PAYLOAD_TOKENS)?;
            }
            byte if byte.is_ascii_control() && !byte.is_ascii_whitespace() => {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            _ => {}
        }
        index += 1;
    }
    if stack.is_empty() {
        Ok(())
    } else {
        Err(ClassifiedError::new(ErrorKind::Parse))
    }
}

fn bounded_increment(value: usize, maximum: usize) -> Result<usize, ClassifiedError> {
    value
        .checked_add(1)
        .filter(|value| *value <= maximum)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn quoted_end(bytes: &[u8], start: usize) -> Result<usize, ClassifiedError> {
    let quote = bytes[start];
    let mut escaped = false;
    for (offset, byte) in bytes[start + 1..].iter().copied().enumerate() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == quote {
            return Ok(start + offset + 1);
        }
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn find_object_for_any_field<'a>(
    text: &'a str,
    fields: &[&str],
) -> Result<Option<&'a str>, ClassifiedError> {
    for field in fields {
        if let Some(start) = find_field_value(text, field, 0)? {
            let start = skip_assignment(text, start)?;
            let bytes = text.as_bytes();
            if bytes.get(start) != Some(&b'{') {
                continue;
            }
            let end = matching_delimiter(bytes, start, b'{', b'}')?;
            return Ok(Some(&text[start..=end]));
        }
    }
    Ok(None)
}

fn find_scalar_for_any_field<'a>(
    text: &'a str,
    fields: &[&str],
) -> Result<Option<&'a str>, ClassifiedError> {
    for field in fields {
        if let Some(start) = find_field_value(text, field, 0)? {
            let start = skip_assignment(text, start)?;
            return Ok(Some(&text[start..]));
        }
    }
    Ok(None)
}

fn find_decimal_for_any_field(
    text: &str,
    fields: &[&str],
) -> Result<Option<Decimal>, ClassifiedError> {
    for field in fields {
        if let Some(start) = find_field_value(text, field, 0)? {
            let value = &text[skip_assignment(text, start)?..];
            let trimmed = value.trim_start();
            if trimmed.starts_with("null") || trimmed.starts_with("undefined") {
                continue;
            }
            return parse_decimal_scalar(value).map(Some);
        }
    }
    Ok(None)
}

fn find_i64_for_any_field(text: &str, fields: &[&str]) -> Result<Option<i64>, ClassifiedError> {
    let Some(decimal) = find_decimal_for_any_field(text, fields)? else {
        return Ok(None);
    };
    if decimal.fract() != Decimal::ZERO {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    decimal
        .to_i64()
        .map(Some)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn find_field_value(
    text: &str,
    field: &str,
    mut index: usize,
) -> Result<Option<usize>, ClassifiedError> {
    let bytes = text.as_bytes();
    while index < bytes.len() {
        if matches!(bytes[index], b'"' | b'\'') {
            index = quoted_end(bytes, index)? + 1;
            continue;
        }
        if bytes[index..].starts_with(field.as_bytes())
            && identifier_before(bytes, index)
            && identifier_after(bytes, index + field.len())
        {
            let mut value = skip_space(bytes, index + field.len());
            if bytes.get(value) == Some(&b':') {
                value = skip_space(bytes, value + 1);
                return Ok(Some(value));
            }
        }
        index += 1;
    }
    Ok(None)
}

fn identifier_before(bytes: &[u8], index: usize) -> bool {
    bytes
        .get(index.wrapping_sub(1))
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn identifier_after(bytes: &[u8], index: usize) -> bool {
    bytes
        .get(index)
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn skip_space(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn skip_assignment(text: &str, start: usize) -> Result<usize, ClassifiedError> {
    let bytes = text.as_bytes();
    let mut index = skip_space(bytes, start);
    if bytes.get(index..index.saturating_add(3)) != Some(b"$R[") {
        return Ok(index);
    }
    index += 3;
    let digits_start = index;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    if index == digits_start || bytes.get(index) != Some(&b']') {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    index = skip_space(bytes, index + 1);
    if bytes.get(index) != Some(&b'=') {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(skip_space(bytes, index + 1))
}

fn matching_delimiter(
    bytes: &[u8],
    start: usize,
    open: u8,
    close: u8,
) -> Result<usize, ClassifiedError> {
    let mut depth = 0_usize;
    let mut index = start;
    while index < bytes.len() {
        if matches!(bytes[index], b'"' | b'\'') {
            index = quoted_end(bytes, index)? + 1;
            continue;
        }
        if bytes[index] == open {
            depth = bounded_increment(depth, MAX_PAYLOAD_DEPTH)?;
        } else if bytes[index] == close {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            if depth == 0 {
                return Ok(index);
            }
        }
        index += 1;
    }
    Err(ClassifiedError::new(ErrorKind::Parse))
}

fn scalar_token(value: &str) -> &str {
    let end = value
        .find(|character: char| character.is_ascii_whitespace() || ",})]".contains(character))
        .unwrap_or(value.len());
    &value[..end]
}

fn parse_decimal_scalar(value: &str) -> Result<Decimal, ClassifiedError> {
    let token = scalar_token(value.trim_start());
    if token.is_empty() || token.len() > MAX_FIELD_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    token
        .parse::<Decimal>()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn parse_string_scalar(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let quote = *value.as_bytes().first()?;
    if !matches!(quote, b'"' | b'\'') {
        return None;
    }
    let end = quoted_end(value.as_bytes(), 0).ok()?;
    (end > 0 && end - 1 <= MAX_FIELD_BYTES).then(|| &value[1..end])
}

fn parse_workspace_ids(body: &[u8]) -> Result<Vec<String>, ClassifiedError> {
    let text = validated_text(body)?;
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    let mut search = 0_usize;
    while let Some(start) = find_field_value(text, "id", search)? {
        let value_start = skip_assignment(text, start)?;
        let value = &text[value_start..];
        if let Some(candidate) = parse_string_scalar(value)
            .map(str::trim)
            .filter(|candidate| valid_workspace_id(candidate))
            && seen.insert(candidate.to_owned())
        {
            output.push(candidate.to_owned());
            if output.len() > MAX_WORKSPACES {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
        }
        search = if matches!(text.as_bytes().get(value_start), Some(b'"' | b'\'')) {
            value_start
                .checked_add(quoted_end(value.as_bytes(), 0)?)
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        } else {
            start.saturating_add(1)
        };
    }
    if output.is_empty()
        && let Ok(root) = serde_json::from_str::<Value>(text)
    {
        validate_json_shape(&root)?;
        collect_json_workspace_ids(&root, &mut output, &mut seen, 0)?;
    }
    Ok(output)
}

fn collect_json_workspace_ids(
    value: &Value,
    output: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), ClassifiedError> {
    if depth > MAX_JSON_DEPTH || output.len() > MAX_WORKSPACES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    match value {
        Value::String(value) => {
            let workspace = value.trim();
            if valid_workspace_id(workspace) && seen.insert(workspace.to_owned()) {
                output.push(workspace.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_json_workspace_ids(value, output, seen, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_json_workspace_ids(value, output, seen, depth + 1)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    if output.len() > MAX_WORKSPACES {
        Err(ClassifiedError::new(ErrorKind::Parse))
    } else {
        Ok(())
    }
}

fn normalize_workspace_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if valid_workspace_id(trimmed) {
        return Some(trimmed.to_owned());
    }
    if let Ok(url) = Url::parse(trimmed) {
        let segments = url.path_segments()?.collect::<Vec<_>>();
        if let Some(index) = segments.iter().position(|segment| *segment == "workspace")
            && let Some(candidate) = segments.get(index + 1)
            && valid_workspace_id(candidate)
        {
            return Some((*candidate).to_owned());
        }
    }
    for (index, _) in trimmed.match_indices("wrk_") {
        let candidate = trimmed[index..]
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .next()?;
        if valid_workspace_id(candidate) {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn valid_workspace_id(value: &str) -> bool {
    value.len() > 4
        && value.len() <= MAX_WORKSPACE_BYTES
        && value.starts_with("wrk_")
        && value[4..].bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn workspace_args(workspace: &str) -> Result<String, ClassifiedError> {
    if !valid_workspace_id(workspace) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    serde_json::to_string(&[workspace]).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn is_explicit_null(body: &[u8]) -> Result<bool, ClassifiedError> {
    let text = validated_text(body)?.trim();
    if text.eq_ignore_ascii_case("null") {
        return Ok(true);
    }
    if serde_json::from_str::<Value>(text).is_ok_and(|value| value.is_null()) {
        return Ok(true);
    }
    let compact = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    Ok(compact.ends_with(b"]=[],null)"))
}

fn looks_signed_out(body: &[u8]) -> Result<bool, ClassifiedError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let text = std::str::from_utf8(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let lower = text.to_ascii_lowercase();
    Ok([
        "login",
        "sign in",
        "auth/authorize",
        "not associated with an account",
        "actor of type \"public\"",
    ]
    .iter()
    .any(|marker| lower.contains(marker)))
}

fn filtered_cookie(raw: &str) -> Result<Zeroizing<String>, ClassifiedError> {
    let normalized = CookieHeaderNormalizer::filtered(Some(raw), &AUTH_COOKIE_NAMES)
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let mut output = Zeroizing::new(String::new());
    let mut retained = 0_usize;
    for segment in raw.split(';') {
        let Some((name, value)) = segment.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !AUTH_COOKIE_NAMES.contains(&name) {
            continue;
        }
        if !output.is_empty() {
            output.push_str("; ");
        }
        output.push_str(name);
        output.push('=');
        output.push_str(value.trim());
        retained = retained
            .checked_add(1)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    }
    if retained != normalized.len() || output.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    Ok(output)
}

fn server_url(mut origin: Url) -> Result<Url, ClassifiedError> {
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.host_str().is_none()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    origin.set_path(SERVER_PATH);
    validate_server_url(&origin)?;
    Ok(origin)
}

fn validate_server_url(url: &Url) -> Result<(), ClassifiedError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.path() != SERVER_PATH
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_request_url(url: &Url, get: bool) -> Result<(), ClassifiedError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.path() != SERVER_PATH
        || url.fragment().is_some()
        || (!get && url.query().is_some())
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_endpoint_class(
    url: &Url,
    endpoint_class: EndpointClass,
) -> Result<(), ClassifiedError> {
    match endpoint_class {
        EndpointClass::PublicHttps
            if url.scheme() == "https"
                && url
                    .host_str()
                    .is_some_and(|host| host.eq_ignore_ascii_case("opencode.ai"))
                && url.port_or_known_default() == Some(443) =>
        {
            Ok(())
        }
        EndpointClass::LoopbackDevelopment => Ok(()),
        EndpointClass::PublicHttps | EndpointClass::PrivateHttps | EndpointClass::PrivateHttp => {
            Err(ClassifiedError::new(ErrorKind::Api))
        }
    }
}

fn cookie_policy(
    endpoint_class: EndpointClass,
    url: &Url,
) -> Result<CookieUrlPolicy, ClassifiedError> {
    match endpoint_class {
        EndpointClass::LoopbackDevelopment if url.scheme() == "http" => {
            Ok(CookieUrlPolicy::LoopbackHttp)
        }
        EndpointClass::PublicHttps | EndpointClass::LoopbackDevelopment
            if url.scheme() == "https" =>
        {
            Ok(CookieUrlPolicy::HttpsOnly)
        }
        EndpointClass::PublicHttps
        | EndpointClass::PrivateHttps
        | EndpointClass::PrivateHttp
        | EndpointClass::LoopbackDevelopment => Err(ClassifiedError::new(ErrorKind::Api)),
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

fn next_instance_header() -> String {
    let sequence = INSTANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed) & 0x0000_ffff_ffff_ffff;
    format!("server-fn:00000000-0000-4000-8000-{sequence:012x}")
}

fn sensitive_header(value: &str) -> Result<HeaderValue, ClassifiedError> {
    let mut value = HeaderValue::from_str(value)
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        find_field_value, normalize_workspace_id, parse_string_scalar, parse_workspace_ids,
        skip_assignment, validate_payload_shape,
    };

    #[test]
    fn payload_workspace_scanner_accepts_baseline_object() {
        let payload = br#";0;($R=>$R[0]={id:"wrk_DISCOVER123"})($R)"#;
        assert!(validate_payload_shape(std::str::from_utf8(payload).expect("UTF-8")).is_ok());
        let text = std::str::from_utf8(payload).expect("UTF-8");
        let start = find_field_value(text, "id", 0)
            .expect("field scan")
            .expect("id field");
        let start = skip_assignment(text, start).expect("assignment");
        let candidate = parse_string_scalar(&text[start..]).expect("string");
        assert_eq!(candidate, "wrk_DISCOVER123");
        assert_eq!(
            normalize_workspace_id(candidate).as_deref(),
            Some(candidate)
        );
        assert_eq!(
            parse_workspace_ids(payload).expect("workspace payload"),
            ["wrk_DISCOVER123"]
        );
    }

    #[test]
    fn payload_workspace_scanner_ignores_embedded_id_decoys() {
        let payload = br#";0;($R=>$R[0]=[
          {id:"old wrk_DECOY"},
          {id:"wrk_REAL123"}
        ])($R)"#;
        assert_eq!(
            parse_workspace_ids(payload).expect("workspace payload"),
            ["wrk_REAL123"]
        );
    }
}
