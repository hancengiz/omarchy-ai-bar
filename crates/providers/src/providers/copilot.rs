//! GitHub Copilot OAuth usage and quota normalization.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, DetailRow, DetailSection, DetailSensitivity,
    ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use serde::Deserialize;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy, classify_https_endpoint};
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
};

const DEFAULT_HOST: &str = "github.com";
const TOKEN_KEY: &str = "COPILOT_API_TOKEN";
const DEVICE_CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";
const DEVICE_SCOPE: &str = "read:user";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_QUOTA_SNAPSHOTS: usize = 512;
const MAX_HOST_BYTES: usize = 512;
const MAX_DEVICE_CODE_BYTES: usize = 16 * 1024;
const MAX_USER_CODE_BYTES: usize = 256;
const MAX_VERIFICATION_URL_BYTES: usize = 8 * 1024;
const MAX_DEVICE_FLOW_LIFETIME: Duration = Duration::from_hours(24);
const MAX_DEVICE_POLL_INTERVAL: Duration = Duration::from_mins(5);
const SLOW_DOWN_DELAY: Duration = Duration::from_secs(5);

/// Monotonic time boundary used by the device authorization state machine.
///
/// The public trait keeps polling tests deterministic without relaxing the
/// production constructor's exact-origin HTTPS policy.
pub trait DeviceFlowClock: Send + Sync {
    /// Returns a duration from an arbitrary, stable monotonic origin.
    fn monotonic_now(&self) -> Duration;

    /// Sleeps for the requested bounded polling delay.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Runs one token request only while its challenge lifetime remains.
    fn run_before_timeout<'a, F, T>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Option<T>> + Send + 'a>>
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a;
}

/// Tokio-backed production clock for Copilot device authorization.
#[derive(Debug)]
pub struct TokioDeviceFlowClock {
    origin: Instant,
}

impl Default for TokioDeviceFlowClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl DeviceFlowClock for TokioDeviceFlowClock {
    fn monotonic_now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn run_before_timeout<'a, F, T>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Option<T>> + Send + 'a>>
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        Box::pin(async move { tokio::time::timeout(duration, future).await.ok() })
    }
}

/// Validated device-code challenge displayed while GitHub authorization is pending.
pub struct CopilotDeviceCode {
    device_code: Zeroizing<String>,
    token_endpoint: Url,
    issuer: Arc<()>,
    user_code: BoundedText<MAX_USER_CODE_BYTES>,
    verification_uri: Url,
    verification_uri_complete: Option<Url>,
    issued_at: Duration,
    expires_in: Duration,
    interval: Duration,
}

impl CopilotDeviceCode {
    /// Short code the user enters on GitHub's verification page.
    #[must_use]
    pub fn user_code(&self) -> &str {
        self.user_code.as_str()
    }

    /// Preferred verification URL, falling back to the base URI when GitHub
    /// does not return a pre-populated URL.
    #[must_use]
    pub fn verification_url_to_open(&self) -> &Url {
        self.verification_uri_complete
            .as_ref()
            .unwrap_or(&self.verification_uri)
    }

    /// Server-issued authorization lifetime.
    #[must_use]
    pub const fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// Server-issued delay required before each token poll.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }
}

impl Debug for CopilotDeviceCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CopilotDeviceCode")
            .field("device_code", &"<redacted>")
            .field("token_endpoint", &"<redacted>")
            .field("issuer", &"<redacted>")
            .field("user_code", &"<redacted>")
            .field("verification_uri", &"<redacted>")
            .field("verification_uri_complete", &"<redacted>")
            .field("issued_at", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// Exact-origin GitHub device authorization client.
pub struct CopilotDeviceFlow<C = TokioDeviceFlowClock> {
    transport: HttpTransport,
    device_code_url: Url,
    access_token_url: Url,
    issuer: Arc<()>,
    clock: C,
}

impl CopilotDeviceFlow<TokioDeviceFlowClock> {
    /// Creates a production device flow for GitHub or GitHub Enterprise.
    ///
    /// The configured origin must use HTTPS and cannot be loopback. Credentials
    /// are never attached to redirects or origins outside the exact policy.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for an invalid or insecure enterprise host.
    pub fn new(enterprise_host: Option<&str>) -> Result<Self, ClassifiedError> {
        let base_url = device_base_url(enterprise_host)?;
        let endpoint_class =
            classify_https_endpoint(&base_url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if endpoint_class == EndpointClass::LoopbackDevelopment {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let endpoints =
            EndpointPolicy::new([(base_url.origin().ascii_serialization(), endpoint_class)])
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport = HttpTransport::new(endpoints, device_transport_config()?)
            .map_err(|error| error.classified())?;
        Self::build(&base_url, transport, TokioDeviceFlowClock::default())
    }
}

impl<C: DeviceFlowClock> CopilotDeviceFlow<C> {
    /// Builds a flow around an explicitly supplied transport and clock.
    ///
    /// This seam exists for isolated loopback tests. The transport still owns
    /// and enforces its endpoint policy before every request.
    ///
    /// # Errors
    ///
    /// Returns a stable API error unless `base_url` is a credential-free bare
    /// origin URL.
    #[doc(hidden)]
    pub fn with_test_transport(
        base_url: &Url,
        transport: HttpTransport,
        clock: C,
    ) -> Result<Self, ClassifiedError> {
        Self::build(base_url, transport, clock)
    }

    fn build(base_url: &Url, transport: HttpTransport, clock: C) -> Result<Self, ClassifiedError> {
        if base_url.host_str().is_none()
            || !matches!(base_url.scheme(), "http" | "https")
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.path() != "/"
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let device_code_url = base_url
            .join("login/device/code")
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let access_token_url = base_url
            .join("login/oauth/access_token")
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        Ok(Self {
            transport,
            device_code_url,
            access_token_url,
            issuer: Arc::new(()),
            clock,
        })
    }

    /// Exact endpoint used to request the user-facing authorization challenge.
    #[must_use]
    pub const fn device_code_url(&self) -> &Url {
        &self.device_code_url
    }

    /// Exact endpoint used to poll for the resulting access token.
    #[must_use]
    pub const fn access_token_url(&self) -> &Url {
        &self.access_token_url
    }

    /// Requests and validates one bounded device authorization challenge.
    ///
    /// # Errors
    ///
    /// Returns stable transport or parse errors without exposing response text
    /// or the server-issued device code.
    pub async fn request_device_code(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<CopilotDeviceCode, ClassifiedError> {
        let body = form_body(&[("client_id", DEVICE_CLIENT_ID), ("scope", DEVICE_SCOPE)]);
        let issued_at = self.clock.monotonic_now();
        let request = HttpRequest::post(self.device_code_url.clone(), body)
            .map_err(|error| error.classified())?
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::FormUrlEncoded);
        let response = self
            .transport
            .send(&request, cancellation)
            .await
            .map_err(|error| error.classified())?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let wire: DeviceCodeWire = response.json()?;
        CopilotDeviceCode::from_wire(
            wire,
            self.access_token_url.clone(),
            Arc::clone(&self.issuer),
            issued_at,
        )
    }

    /// Polls GitHub until the challenge succeeds, expires, is cancelled, or is
    /// denied, returning a bounded redacted credential on success.
    ///
    /// GitHub's required interval is slept before every request. A `slow_down`
    /// response inserts the provider-mandated additional five-second delay.
    ///
    /// # Errors
    ///
    /// Returns authentication-expired for challenge expiry, permission-denied
    /// for an explicit user denial, network for cancellation, and stable
    /// transport/parse errors for other failures.
    pub async fn poll_for_token(
        &self,
        challenge: &CopilotDeviceCode,
        cancellation: &CancellationToken,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        if challenge.token_endpoint != self.access_token_url
            || !Arc::ptr_eq(&challenge.issuer, &self.issuer)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let body = form_body(&[
            ("client_id", DEVICE_CLIENT_ID),
            ("device_code", challenge.device_code.as_str()),
            ("grant_type", DEVICE_GRANT_TYPE),
        ]);
        let request = HttpRequest::post(self.access_token_url.clone(), body)
            .map_err(|error| error.classified())?
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::FormUrlEncoded)
            .accepted_statuses(&[400])
            .map_err(|error| error.classified())?;
        let started_at = challenge.issued_at;

        loop {
            self.sleep_with_deadline(
                challenge.interval,
                started_at,
                challenge.expires_in,
                cancellation,
            )
            .await?;
            let remaining = self.remaining(started_at, challenge.expires_in)?;
            let response = self
                .clock
                .run_before_timeout(remaining, self.transport.send(&request, cancellation))
                .await
                .ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))?
                .map_err(|error| error.classified())?;
            self.remaining(started_at, challenge.expires_in)?;

            let wire: AccessTokenWire = response.json()?;
            if let Some(error) = wire.error.as_deref() {
                match error {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        self.sleep_with_deadline(
                            SLOW_DOWN_DELAY,
                            started_at,
                            challenge.expires_in,
                            cancellation,
                        )
                        .await?;
                        continue;
                    }
                    "access_denied" => {
                        return Err(ClassifiedError::new(ErrorKind::PermissionDenied));
                    }
                    "expired_token" => {
                        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
                    }
                    _ => return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired)),
                }
            }
            if response.status() != 200 {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            let token = wire
                .access_token
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            let _token_type = wire
                .token_type
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            let _scope = wire
                .scope
                .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
            return ApiKeyCredential::new(token.as_str())
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse));
        }
    }

    async fn sleep_with_deadline(
        &self,
        requested: Duration,
        started_at: Duration,
        expires_in: Duration,
        cancellation: &CancellationToken,
    ) -> Result<(), ClassifiedError> {
        let remaining = self.remaining(started_at, expires_in)?;
        let delay = requested.min(remaining);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(ClassifiedError::new(ErrorKind::Network)),
            () = self.clock.sleep(delay) => {}
        }
        if requested >= remaining {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        self.remaining(started_at, expires_in).map(|_| ())
    }

    fn remaining(
        &self,
        started_at: Duration,
        expires_in: Duration,
    ) -> Result<Duration, ClassifiedError> {
        let elapsed = self
            .clock
            .monotonic_now()
            .checked_sub(started_at)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))?;
        expires_in
            .checked_sub(elapsed)
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))
    }
}

#[derive(Deserialize)]
struct DeviceCodeWire {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

impl CopilotDeviceCode {
    fn from_wire(
        wire: DeviceCodeWire,
        token_endpoint: Url,
        issuer: Arc<()>,
        issued_at: Duration,
    ) -> Result<Self, ClassifiedError> {
        if wire.device_code.is_empty()
            || wire.device_code.len() > MAX_DEVICE_CODE_BYTES
            || wire.device_code.chars().any(char::is_control)
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let user_code = BoundedText::new(&wire.user_code)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let expires_in = bounded_duration(wire.expires_in, MAX_DEVICE_FLOW_LIFETIME)?;
        let interval = bounded_duration(wire.interval, MAX_DEVICE_POLL_INTERVAL)?;
        let verification_uri = verification_url(&wire.verification_uri)?;
        let verification_uri_complete = wire
            .verification_uri_complete
            .as_deref()
            .map(verification_url)
            .transpose()?;
        Ok(Self {
            device_code: Zeroizing::new(wire.device_code),
            token_endpoint,
            issuer,
            user_code,
            verification_uri,
            verification_uri_complete,
            issued_at,
            expires_in,
            interval,
        })
    }
}

#[derive(Deserialize)]
struct AccessTokenWire {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

fn bounded_duration(seconds: u64, maximum: Duration) -> Result<Duration, ClassifiedError> {
    let duration = Duration::from_secs(seconds);
    if duration.is_zero() || duration > maximum {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(duration)
}

fn verification_url(value: &str) -> Result<Url, ClassifiedError> {
    if value.is_empty() || value.len() > MAX_VERIFICATION_URL_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let url = Url::parse(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.scheme() != "https"
        || url.host_str().is_none()
    {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(url)
}

fn form_body(parameters: &[(&str, &str)]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(parameters.iter().copied());
    serializer.finish().into_bytes()
}

/// Native GitHub Copilot usage adapter.
pub struct CopilotProvider {
    client: FixedApiClient,
}

impl CopilotProvider {
    /// Resolves the explicit environment token supported by the pinned provider.
    ///
    /// Device-flow and Secret Service precedence are orchestrated above this
    /// adapter so environment credentials remain ephemeral.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error for an unusable token.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &[TOKEN_KEY])
    }

    /// Creates an exact-origin OAuth-token client for GitHub or GitHub Enterprise.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for an invalid enterprise host or transport.
    pub fn new(
        scope: AccountScope,
        credential: ApiKeyCredential,
        enterprise_host: Option<&str>,
    ) -> Result<Self, ClassifiedError> {
        let base_url = usage_base_url(enterprise_host)?;
        let endpoint_class =
            classify_https_endpoint(&base_url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if endpoint_class == EndpointClass::LoopbackDevelopment {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let client = FixedApiClient::new_authorization_scheme(
            scope,
            base_url,
            endpoint_class,
            "token",
            credential,
            transport_config()?,
        )?
        .with_source(ProviderSource::OAuth)?;
        Self::from_client(client)
    }

    /// Wraps an already validated OAuth-bound account client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider or
    /// is not bound to Copilot's OAuth source.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Copilot
            || client.source() != ProviderSource::OAuth
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches and normalizes one deterministic Copilot usage snapshot.
    ///
    /// # Errors
    ///
    /// Returns stable authentication, transport, or parse errors without
    /// exposing the OAuth token or provider response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("copilot_internal/user")?;
        let response = self
            .client
            .get_json_with_public_headers_and_status_map(
                context,
                url,
                &[
                    ("editor-version", "vscode/1.96.2"),
                    ("editor-plugin-version", "copilot-chat/0.26.7"),
                    ("user-agent", "GitHubCopilotChat/0.26.7"),
                    ("x-github-api-version", "2025-04-01"),
                ],
                |status| (status == 403).then_some(ErrorKind::AuthenticationExpired),
            )
            .await?;
        if response.status() != 200 {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let payload: Value = response.json()?;
        normalize(context.scope().clone(), fetched_at, &payload)
    }
}

impl ProviderAdapter for CopilotProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Copilot)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Clone)]
struct QuotaSnapshot {
    entitlement: f64,
    remaining: f64,
    credits_used: Option<f64>,
    percent_remaining: f64,
    has_percent_remaining: bool,
    unlimited: bool,
    decoded: DecodedQuotaFields,
}

#[derive(Clone, Copy)]
struct DecodedQuotaFields {
    entitlement: bool,
    remaining: bool,
}

impl QuotaSnapshot {
    fn parse(value: &Value) -> Result<Self, ClassifiedError> {
        let root = value
            .as_object()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
        let entitlement = optional_number(root.get("entitlement"))?;
        let remaining = optional_number(root.get("remaining"))?;
        let credits_used = optional_number(root.get("credits_used"))?;
        let decoded_percent = optional_number(root.get("percent_remaining"))?;
        let unlimited = match root.get("unlimited") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
        };
        if root
            .get("quota_id")
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        let (percent_remaining, has_percent_remaining) = if unlimited {
            (100.0, true)
        } else if let Some(percent) = decoded_percent {
            (percent, true)
        } else if let (Some(entitlement), Some(remaining)) = (entitlement, remaining) {
            if entitlement > 0.0 {
                let percent = remaining / entitlement * 100.0;
                if !percent.is_finite() {
                    return Err(ClassifiedError::new(ErrorKind::Parse));
                }
                (percent, true)
            } else {
                (0.0, false)
            }
        } else {
            (0.0, false)
        };
        Ok(Self {
            entitlement: entitlement.unwrap_or(0.0),
            remaining: remaining.unwrap_or(0.0),
            credits_used,
            percent_remaining,
            has_percent_remaining,
            unlimited,
            decoded: DecodedQuotaFields {
                entitlement: entitlement.is_some(),
                remaining: remaining.is_some(),
            },
        })
    }

    fn is_placeholder(&self) -> bool {
        if self.unlimited {
            return false;
        }
        (!self.has_percent_remaining
            && self.entitlement == 0.0
            && self.remaining == 0.0
            && self.percent_remaining == 0.0)
            || (self.decoded.entitlement
                && self.decoded.remaining
                && self.entitlement == 0.0
                && self.remaining == 0.0)
    }

    fn usable(&self) -> bool {
        !self.is_placeholder() && self.has_percent_remaining
    }

    fn with_credits(mut self, credits: Option<f64>) -> Self {
        self.credits_used = credits;
        self
    }
}

#[derive(Default)]
struct QuotaSnapshots {
    premium: Option<QuotaSnapshot>,
    chat: Option<QuotaSnapshot>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: &Value,
) -> Result<UsageSample, ClassifiedError> {
    let root = payload
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let direct = parse_direct_snapshots(root.get("quota_snapshots"))?;
    let monthly = parse_quota_counts(root.get("monthly_quotas"))?;
    let limited = parse_quota_counts(root.get("limited_user_quotas"))?;
    let fallback = monthly_snapshots(monthly.as_ref(), limited.as_ref())?;

    let selected_premium = preferred_snapshot(direct.premium.as_ref(), fallback.premium);
    let selected_chat = preferred_snapshot(direct.chat.as_ref(), fallback.chat);
    let snapshots = if selected_premium.is_some() || selected_chat.is_some() {
        QuotaSnapshots {
            premium: selected_premium,
            chat: selected_chat,
        }
    } else {
        direct
    };

    validate_optional_string(root.get("assigned_date"))?;
    let reset = match root.get("quota_reset_date") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => parse_reset(value),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let primary = snapshots
        .premium
        .as_ref()
        .map(|snapshot| make_window(snapshot, reset))
        .transpose()?
        .flatten();
    let secondary = snapshots
        .chat
        .as_ref()
        .map(|snapshot| make_window(snapshot, reset))
        .transpose()?
        .flatten();
    let token_billing = match root.get("token_based_billing") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let has_unlimited = snapshots
        .premium
        .as_ref()
        .is_some_and(|snapshot| snapshot.unlimited)
        || snapshots
            .chat
            .as_ref()
            .is_some_and(|snapshot| snapshot.unlimited);
    if primary.is_none() && secondary.is_none() && !token_billing && !has_unlimited {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let credits = snapshots
        .premium
        .as_ref()
        .and_then(|snapshot| snapshot.credits_used)
        .or_else(|| {
            snapshots
                .chat
                .as_ref()
                .and_then(|snapshot| snapshot.credits_used)
        });
    let details = credits
        .map(|credits| credits_section(credits, reset))
        .transpose()?
        .into_iter()
        .collect();
    let plan = match root.get("copilot_plan") {
        None | Some(Value::Null) => "Unknown".to_owned(),
        Some(Value::String(value)) => capitalize(value),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };

    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .login_method(Some(plan))?
        .detail_sections(details);
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder.provenance("copilot", "oauth")?.build()
}

fn parse_direct_snapshots(value: Option<&Value>) -> Result<QuotaSnapshots, ClassifiedError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(QuotaSnapshots::default());
    };
    let root = value
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if root.len() > MAX_QUOTA_SNAPSHOTS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut premium = root
        .get("premium_interactions")
        .map(QuotaSnapshot::parse)
        .transpose()?;
    let mut chat = root.get("chat").map(QuotaSnapshot::parse).transpose()?;
    if premium
        .as_ref()
        .is_some_and(|snapshot| snapshot.is_placeholder() && snapshot.credits_used.is_none())
    {
        premium = None;
    }
    if chat
        .as_ref()
        .is_some_and(|snapshot| snapshot.is_placeholder() && snapshot.credits_used.is_none())
    {
        chat = None;
    }

    if premium.is_none() || chat.is_none() {
        let mut keys = root.keys().collect::<Vec<_>>();
        keys.sort();
        let mut fallback_premium = None;
        let mut fallback_chat = None;
        let mut first_usable = None;
        for key in keys {
            let Ok(snapshot) = QuotaSnapshot::parse(&root[key]) else {
                continue;
            };
            if snapshot.is_placeholder() && snapshot.credits_used.is_none() {
                continue;
            }
            first_usable.get_or_insert_with(|| snapshot.clone());
            let name = key.to_ascii_lowercase();
            if fallback_chat.is_none() && name.contains("chat") {
                fallback_chat = Some(snapshot);
                continue;
            }
            if fallback_premium.is_none()
                && (name.contains("premium")
                    || name.contains("completion")
                    || name.contains("code"))
            {
                fallback_premium = Some(snapshot);
            }
        }
        premium = premium.or(fallback_premium);
        chat = chat.or(fallback_chat);
        if premium.is_none() && chat.is_none() {
            chat = first_usable;
        }
    }
    Ok(QuotaSnapshots { premium, chat })
}

#[derive(Default)]
struct QuotaCounts {
    chat: Option<f64>,
    completions: Option<f64>,
}

fn parse_quota_counts(value: Option<&Value>) -> Result<Option<QuotaCounts>, ClassifiedError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let root = value
        .as_object()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(Some(QuotaCounts {
        chat: optional_number(root.get("chat"))?,
        completions: optional_number(root.get("completions"))?,
    }))
}

fn monthly_snapshots(
    monthly: Option<&QuotaCounts>,
    limited: Option<&QuotaCounts>,
) -> Result<QuotaSnapshots, ClassifiedError> {
    Ok(QuotaSnapshots {
        premium: monthly_snapshot(
            monthly.and_then(|counts| counts.completions),
            limited.and_then(|counts| counts.completions),
        )?,
        chat: monthly_snapshot(
            monthly.and_then(|counts| counts.chat),
            limited.and_then(|counts| counts.chat),
        )?,
    })
}

fn monthly_snapshot(
    monthly: Option<f64>,
    limited: Option<f64>,
) -> Result<Option<QuotaSnapshot>, ClassifiedError> {
    let (Some(monthly), Some(limited)) = (monthly, limited) else {
        return Ok(None);
    };
    let entitlement = monthly.max(0.0);
    if entitlement <= 0.0 {
        return Ok(None);
    }
    let remaining = limited.max(0.0);
    let percent_remaining = (remaining / entitlement * 100.0).clamp(0.0, 100.0);
    if !percent_remaining.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok(Some(QuotaSnapshot {
        entitlement,
        remaining,
        credits_used: None,
        percent_remaining,
        has_percent_remaining: true,
        unlimited: false,
        decoded: DecodedQuotaFields {
            entitlement: true,
            remaining: true,
        },
    }))
}

fn preferred_snapshot(
    direct: Option<&QuotaSnapshot>,
    fallback: Option<QuotaSnapshot>,
) -> Option<QuotaSnapshot> {
    if direct.is_some_and(|snapshot| snapshot.unlimited)
        && fallback.as_ref().is_some_and(QuotaSnapshot::usable)
    {
        return fallback.map(|snapshot| {
            snapshot.with_credits(direct.and_then(|snapshot| snapshot.credits_used))
        });
    }
    if let Some(direct) = direct.filter(|snapshot| snapshot.usable()) {
        return Some(direct.clone());
    }
    let fallback = fallback.filter(QuotaSnapshot::usable)?;
    Some(
        if direct.is_some_and(|snapshot| snapshot.credits_used.is_some()) {
            fallback.with_credits(direct.and_then(|snapshot| snapshot.credits_used))
        } else {
            fallback
        },
    )
}

fn make_window(
    snapshot: &QuotaSnapshot,
    resets_at: Option<Timestamp>,
) -> Result<Option<RateWindow>, ClassifiedError> {
    if snapshot.unlimited || snapshot.is_placeholder() || !snapshot.has_percent_remaining {
        return Ok(None);
    }
    let used = (100.0 - snapshot.percent_remaining).max(0.0);
    let used = UsagePercent::new(used).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let description = (used.get() > 100.0)
        .then(|| BoundedText::new(format!("{:.0}% used", used.get())))
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(used),
        None,
        resets_at,
        description,
        None,
        false,
    )
    .map(Some)
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn credits_section(
    credits: f64,
    resets_at: Option<Timestamp>,
) -> Result<DetailSection, ClassifiedError> {
    let secondary = resets_at.map(|reset| format!("Resets {reset}"));
    let row = DetailRow::new(
        "Credits used",
        format_credits(credits)?,
        secondary,
        DetailSensitivity::Public,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    DetailSection::new(Some("Credits".to_owned()), vec![row], None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn optional_number(value: Option<&Value>) -> Result<Option<f64>, ClassifiedError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse::<f64>().ok(),
        _ => None,
    };
    match parsed {
        Some(value) if value.is_finite() => Ok(Some(value)),
        Some(_) => Err(ClassifiedError::new(ErrorKind::Parse)),
        None => Ok(None),
    }
}

fn validate_optional_string(value: Option<&Value>) -> Result<(), ClassifiedError> {
    match value {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        Some(_) => Err(ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn parse_reset(value: &str) -> Option<Timestamp> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Timestamp::parse(value).ok().or_else(|| {
        (value.len() == 10)
            .then(|| Timestamp::parse(&format!("{value}T00:00:00Z")).ok())
            .flatten()
    })
}

fn format_credits(value: f64) -> Result<String, ClassifiedError> {
    if !value.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let decimal = Decimal::from_f64(value)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        .round_dp(2)
        .normalize();
    let raw = decimal.to_string();
    let (sign, raw) = raw
        .strip_prefix('-')
        .map_or(("", raw.as_str()), |digits| ("-", digits));
    let (integer, fraction) = raw
        .split_once('.')
        .map_or((raw, None), |(integer, fraction)| (integer, Some(fraction)));
    let mut output = String::with_capacity(raw.len() + raw.len() / 3 + sign.len());
    output.push_str(sign);
    for (index, byte) in integer.bytes().enumerate() {
        if index > 0 && (integer.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(char::from(byte));
    }
    if let Some(fraction) = fraction {
        output.push('.');
        output.push_str(fraction);
    }
    Ok(output)
}

fn capitalize(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut word_start = true;
    for character in value.chars() {
        if word_start {
            output.extend(character.to_uppercase());
        } else {
            output.extend(character.to_lowercase());
        }
        word_start = !character.is_alphanumeric();
    }
    output
}

/// Normalizes the pinned GitHub/GitHub Enterprise host input.
///
/// # Errors
///
/// Returns a stable API error for malformed, credential-bearing, or unbounded
/// host text.
pub fn normalize_enterprise_host(raw: Option<&str>) -> Result<String, ClassifiedError> {
    let raw = raw.map(str::trim).filter(|value| !value.is_empty());
    let Some(raw) = raw else {
        return Ok(DEFAULT_HOST.to_owned());
    };
    if raw.len() > MAX_HOST_BYTES {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    let host = url
        .host_str()
        .map(|host| host.trim_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    if host.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(url
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

fn usage_base_url(enterprise_host: Option<&str>) -> Result<Url, ClassifiedError> {
    let host = normalize_enterprise_host(enterprise_host)?;
    let (hostname, port) = split_host_port(&host);
    let api_host = if hostname.starts_with("api.") {
        hostname.to_owned()
    } else if hostname == DEFAULT_HOST {
        "api.github.com".to_owned()
    } else {
        format!("api.{hostname}")
    };
    let authority = port.map_or(api_host.clone(), |port| format!("{api_host}:{port}"));
    Url::parse(&format!("https://{authority}/")).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn device_base_url(enterprise_host: Option<&str>) -> Result<Url, ClassifiedError> {
    let host = normalize_enterprise_host(enterprise_host)?;
    Url::parse(&format!("https://{host}/")).map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

/// Returns the exact Copilot usage endpoint for a normalized enterprise host.
///
/// # Errors
///
/// Returns a stable API error when the host cannot form an approved HTTPS URL.
pub fn usage_url(enterprise_host: Option<&str>) -> Result<Url, ClassifiedError> {
    usage_base_url(enterprise_host)?
        .join("copilot_internal/user")
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn split_host_port(host: &str) -> (&str, Option<u16>) {
    host.rsplit_once(':').map_or((host, None), |(host, port)| {
        port.parse::<u16>()
            .map_or((host, None), |port| (host, Some(port)))
    })
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

fn device_transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}
