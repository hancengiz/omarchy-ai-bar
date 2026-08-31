//! `Cursor` dashboard usage adapter for an explicit manual session.

use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::manual_capture::{CaptureHeader, ManualCaptureError, ManualCapturePolicy};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, TransportConfig,
};

const ORIGIN: &str = "https://cursor.com";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Native Cursor manual-session provider.
pub struct CursorProvider {
    scope: AccountScope,
    endpoint: Url,
    cookie: Zeroizing<String>,
    transport: HttpTransport,
}

impl CursorProvider {
    /// Creates a production adapter from a Cookie header or copied cURL command.
    ///
    /// # Errors
    ///
    /// Returns a stable credential, capture, or endpoint error.
    pub fn new_manual(scope: AccountScope, raw: &str) -> Result<Self, ClassifiedError> {
        let origin = Url::parse(ORIGIN).map_err(|_| api_error())?;
        Self::from_manual_capture_at(scope, raw, origin, EndpointClass::PublicHttps)
    }

    /// Creates an adapter at an injected exact-origin test seam.
    ///
    /// # Errors
    ///
    /// Returns stable capture and transport configuration errors.
    #[doc(hidden)]
    pub fn from_manual_capture_at(
        scope: AccountScope,
        raw: &str,
        origin: Url,
        endpoint_class: EndpointClass,
    ) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Cursor {
            return Err(api_error());
        }
        let policy =
            ManualCapturePolicy::new(["cursor.com", "www.cursor.com"], [CaptureHeader::Cookie])
                .map_err(classify_capture)?
                .with_ignored_url_query();
        let capture = policy.parse(raw).map_err(classify_capture)?;
        let cookie = capture
            .header(CaptureHeader::Cookie)
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Authentication::cookie(cookie.to_owned()).map_err(|_| api_error())?;
        let endpoint = fixed_endpoint(origin, endpoint_class)?;
        let endpoints =
            EndpointPolicy::new([(endpoint.origin().ascii_serialization(), endpoint_class)])
                .map_err(|_| api_error())?;
        let transport = HttpTransport::new(endpoints, transport_config()?)
            .map_err(|error| error.classified())?;
        Ok(Self {
            scope,
            endpoint,
            cookie: Zeroizing::new(cookie.to_owned()),
            transport,
        })
    }

    /// Fetches Cursor's authoritative usage summary.
    ///
    /// # Errors
    ///
    /// Returns stable transport, authentication, and parse errors.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::ManualCookie {
            return Err(api_error());
        }
        let request = HttpRequest::get(self.endpoint.clone())
            .accept(RequestAccept::Json)
            .public_header("origin", ORIGIN)
            .map_err(|error| error.classified())?
            .public_header("referer", "https://cursor.com/dashboard?tab=usage")
            .map_err(|error| error.classified())?
            .authentication(
                Authentication::cookie(self.cookie.as_str().to_owned())
                    .map_err(|error| error.classified())?,
            );
        let response = self
            .transport
            .send(&request, context.cancellation())
            .await
            .map_err(|error| error.classified())?;
        let payload: UsageSummary = response.json()?;
        normalize(self.scope.clone(), fetched_at, payload)
    }
}

impl ProviderAdapter for CursorProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Cursor)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageSummary {
    billing_cycle_end: Option<String>,
    membership_type: Option<String>,
    individual_usage: Option<IndividualUsage>,
    team_usage: Option<TeamUsage>,
}

#[derive(Deserialize)]
struct IndividualUsage {
    plan: Option<PlanUsage>,
    overall: Option<AmountUsage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanUsage {
    used: Option<i64>,
    limit: Option<i64>,
    auto_percent_used: Option<f64>,
    api_percent_used: Option<f64>,
    total_percent_used: Option<f64>,
}

#[derive(Deserialize)]
struct AmountUsage {
    used: Option<i64>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct TeamUsage {
    pooled: Option<AmountUsage>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    payload: UsageSummary,
) -> Result<UsageSample, ClassifiedError> {
    let individual = payload.individual_usage.as_ref();
    let plan = individual.and_then(|value| value.plan.as_ref());
    let auto = plan.and_then(|value| valid_percent(value.auto_percent_used));
    let api = plan.and_then(|value| valid_percent(value.api_percent_used));
    let total = plan
        .and_then(|value| valid_percent(value.total_percent_used))
        .or_else(|| match (auto, api) {
            (Some(left), Some(right)) => Some(left.midpoint(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        })
        .or_else(|| plan.and_then(amount_percent))
        .or_else(|| {
            individual
                .and_then(|value| value.overall.as_ref())
                .and_then(amount_percent)
        })
        .or_else(|| {
            payload
                .team_usage
                .as_ref()
                .and_then(|value| value.pooled.as_ref())
                .and_then(amount_percent)
        })
        .ok_or_else(parse_error)?;
    let resets_at = payload
        .billing_cycle_end
        .as_deref()
        .map(Timestamp::parse)
        .transpose()
        .map_err(|_| parse_error())?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(window(total, resets_at)?)
        .login_method(payload.membership_type)?;
    if let Some(auto) = auto {
        builder = builder.secondary(window(auto, resets_at)?);
    }
    if let Some(api) = api {
        builder = builder.tertiary(window(api, resets_at)?);
    }
    builder.provenance("cursor", "usage-summary")?.build()
}

fn window(percent: f64, resets_at: Option<Timestamp>) -> Result<RateWindow, ClassifiedError> {
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent.clamp(0.0, 100.0)).map_err(|_| parse_error())?,
        ),
        None,
        resets_at,
        None,
        None,
        false,
    )
    .map_err(|_| parse_error())
}

fn valid_percent(value: Option<f64>) -> Option<f64> {
    value
        .filter(|value| value.is_finite())
        .map(|value| value.clamp(0.0, 100.0))
}

fn amount_percent(value: &impl Amount) -> Option<f64> {
    let used = value.used()?.max(0);
    let limit = value.limit()?;
    if limit <= 0 {
        return None;
    }
    (Decimal::from(used) * Decimal::ONE_HUNDRED / Decimal::from(limit)).to_f64()
}

trait Amount {
    fn used(&self) -> Option<i64>;
    fn limit(&self) -> Option<i64>;
}

impl Amount for PlanUsage {
    fn used(&self) -> Option<i64> {
        self.used
    }
    fn limit(&self) -> Option<i64> {
        self.limit
    }
}

impl Amount for AmountUsage {
    fn used(&self) -> Option<i64> {
        self.used
    }
    fn limit(&self) -> Option<i64> {
        self.limit
    }
}

fn fixed_endpoint(mut origin: Url, endpoint_class: EndpointClass) -> Result<Url, ClassifiedError> {
    if !origin.username().is_empty() || origin.password().is_some() || origin.query().is_some() {
        return Err(api_error());
    }
    if endpoint_class == EndpointClass::PublicHttps
        && (origin.scheme() != "https" || origin.host_str() != Some("cursor.com"))
    {
        return Err(api_error());
    }
    origin.set_path("/api/usage-summary");
    origin.set_fragment(None);
    Ok(origin)
}

fn classify_capture(error: ManualCaptureError) -> ClassifiedError {
    ClassifiedError::new(match error {
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
    })
}

fn parse_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Parse)
}
fn api_error() -> ClassifiedError {
    ClassifiedError::new(ErrorKind::Api)
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(20),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}
