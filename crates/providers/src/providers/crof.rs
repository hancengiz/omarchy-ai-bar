//! Crof credit balance and optional daily request-quota adapter.

use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, ErrorKind, ProviderId, RateWindow, Timestamp,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use serde::Deserialize;
use serde_json::Value;
use time::{Date, Duration as TimeDuration, Month, PrimitiveDateTime, Time, Weekday};
use url::Url;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::endpoint::EndpointClass;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::transport::TransportConfig;

const API_ORIGIN: &str = "https://crof.ai";
const KEY_NAMES: [&str; 2] = ["CROF_API_KEY", "CROFAI_API_KEY"];
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Native Crof provider adapter.
pub struct CrofProvider {
    client: FixedApiClient,
}

impl CrofProvider {
    /// Resolves the baseline key precedence from an environment snapshot.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when neither key is usable.
    pub fn resolve_credential(
        environment: &BTreeMap<String, String>,
    ) -> Result<ApiKeyCredential, ClassifiedError> {
        ApiKeyCredential::resolve(environment, &KEY_NAMES)
    }

    /// Creates the production fixed-origin client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error for invalid fixed configuration.
    pub fn new(scope: AccountScope, credential: ApiKeyCredential) -> Result<Self, ClassifiedError> {
        let base_url = Url::parse(API_ORIGIN).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            scope,
            base_url,
            EndpointClass::PublicHttps,
            credential,
            transport_config()?,
        )?;
        Self::from_client(client)
    }

    /// Wraps an already validated account-scoped client.
    ///
    /// # Errors
    ///
    /// Returns a stable API error if the client belongs to another provider.
    pub fn from_client(client: FixedApiClient) -> Result<Self, ClassifiedError> {
        if client.scope().provider() != ProviderId::Crof {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self { client })
    }

    /// Fetches and normalizes one deterministic sample timestamp.
    ///
    /// # Errors
    ///
    /// Returns stable classified transport or parse errors without provider
    /// response text.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        let url = self.client.url("usage_api/")?;
        let payload: CrofResponse = self.client.get_json(context, url).await?.json()?;
        normalize(context.scope().clone(), fetched_at, &payload)
    }
}

impl ProviderAdapter for CrofProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Crof)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Deserialize)]
struct CrofResponse {
    credits: Value,
    requests_plan: Option<Value>,
    usable_requests: Option<Value>,
}

fn normalize(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: &CrofResponse,
) -> Result<UsageSample, ClassifiedError> {
    let credits = required_number(&response.credits)?.max(0.0);
    let requests_plan = optional_number(response.requests_plan.as_ref())?;
    let usable_requests = optional_number(response.usable_requests.as_ref())?;
    let credits_window = credits_window(credits)?;

    let (primary, secondary) = match (requests_plan, usable_requests) {
        (Some(plan), Some(usable)) => {
            let clamped_remaining = usable.clamp(0.0, plan.max(0.0));
            let remaining_percent = if plan > 0.0 {
                ((clamped_remaining / plan) * 100.0)
                    .floor()
                    .clamp(0.0, 100.0)
            } else {
                0.0
            };
            let displayed_requests = usable.max(0.0);
            let request_text = if displayed_requests.fract() == 0.0 {
                format!("{displayed_requests:.0}")
            } else {
                format_fixed_two(displayed_requests)
            };
            let primary = RateWindow::new(
                WindowUsage::known(
                    UsagePercent::new(100.0 - remaining_percent)
                        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                ),
                Some(
                    WindowDuration::from_provider_minutes(24 * 60)
                        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                ),
                Some(next_chicago_midnight(fetched_at)?),
                Some(
                    BoundedText::new(format!("{request_text} requests left"))
                        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
                ),
                None,
                false,
            )
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
            (primary, Some(credits_window))
        }
        _ => (credits_window, None),
    };

    let mut builder = UsageSampleBuilder::new(scope, fetched_at).primary(primary);
    if let Some(secondary) = secondary {
        builder = builder.secondary(secondary);
    }
    builder
        .login_method(Some("API key".to_owned()))?
        .provenance("crof", "api")?
        .build()
}

fn required_number(value: &Value) -> Result<f64, ClassifiedError> {
    value
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn optional_number(value: Option<&Value>) -> Result<Option<f64>, ClassifiedError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => required_number(value).map(Some),
    }
}

fn credits_window(credits: f64) -> Result<RateWindow, ClassifiedError> {
    let floored = (credits * 100.0).floor() / 100.0;
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(if credits > 0.0 { 0.0 } else { 100.0 })
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        Some(
            BoundedText::new(format!("${floored:.2}"))
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn format_fixed_two(value: f64) -> String {
    let rounded = (value * 100.0).round() / 100.0;
    format!("{rounded:.2}")
}

fn next_chicago_midnight(fetched_at: Timestamp) -> Result<Timestamp, ClassifiedError> {
    let utc = fetched_at.as_offset_date_time();
    let (start, end) = chicago_dst_transition_instants(utc.year())?;
    let current_offset_hours = if utc >= start && utc < end { -5 } else { -6 };
    let local = utc
        .checked_add(TimeDuration::hours(current_offset_hours))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let next_date = local
        .date()
        .next_day()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let (start_date, end_date) = chicago_dst_dates(next_date.year())?;
    let midnight_offset_hours = if next_date > start_date && next_date <= end_date {
        -5
    } else {
        -6
    };
    let local_midnight = PrimitiveDateTime::new(next_date, Time::MIDNIGHT).assume_utc();
    let utc_midnight = local_midnight
        .checked_sub(TimeDuration::hours(midnight_offset_hours))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Timestamp::new(utc_midnight).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn chicago_dst_transition_instants(
    year: i32,
) -> Result<(time::OffsetDateTime, time::OffsetDateTime), ClassifiedError> {
    let (start, end) = chicago_dst_dates(year)?;
    let start_local = PrimitiveDateTime::new(
        start,
        Time::from_hms(2, 0, 0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
    )
    .assume_utc();
    let end_local = PrimitiveDateTime::new(
        end,
        Time::from_hms(2, 0, 0).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
    )
    .assume_utc();
    let start_utc = start_local
        .checked_add(TimeDuration::hours(6))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let end_utc = end_local
        .checked_add(TimeDuration::hours(5))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    Ok((start_utc, end_utc))
}

fn chicago_dst_dates(year: i32) -> Result<(Date, Date), ClassifiedError> {
    Ok((
        nth_weekday(year, Month::March, Weekday::Sunday, 2)?,
        nth_weekday(year, Month::November, Weekday::Sunday, 1)?,
    ))
}

fn nth_weekday(
    year: i32,
    month: Month,
    weekday: Weekday,
    occurrence: u8,
) -> Result<Date, ClassifiedError> {
    let first = Date::from_calendar_date(year, month, 1)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let leading = (7 + i16::from(weekday.number_days_from_sunday())
        - i16::from(first.weekday().number_days_from_sunday()))
        % 7;
    let days = leading + 7 * (i16::from(occurrence) - 1);
    first
        .checked_add(TimeDuration::days(i64::from(days)))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        MAX_RESPONSE_BYTES,
        3,
        RetryPolicy::one(Duration::from_millis(250), Duration::from_secs(30)),
    )
    .map_err(|error| error.classified())
}
