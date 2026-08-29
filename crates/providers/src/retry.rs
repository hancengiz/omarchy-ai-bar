//! Deterministic one-retry policy and injectable clock.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use reqwest::header::HeaderValue;

use crate::transport::TransportError;

const MAX_RETRY_DELAY: Duration = Duration::from_hours(1);

/// Clock boundary used for `Retry-After` dates and cancellable sleeps.
pub trait RetryClock: Send + Sync {
    /// Current civil time used only to project an HTTP-date delay.
    fn wall_now(&self) -> SystemTime;
    /// Sleeps for an already bounded deterministic delay.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Tokio-backed production retry clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioRetryClock;

impl RetryClock for TokioRetryClock {
    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Fixed retry budget with bounded server delay handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_retries: u8,
    base_delay: Duration,
    max_delay: Duration,
}

impl RetryPolicy {
    /// Disables automatic retry.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            max_retries: 0,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    /// Allows exactly one retry with bounded fallback/server delay.
    #[must_use]
    pub const fn one(base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries: 1,
            base_delay,
            max_delay,
        }
    }

    /// Returns the delay for the next attempt, if the one-retry budget permits it.
    #[must_use]
    pub fn delay(self, completed_retries: u8, error: &TransportError) -> Option<Duration> {
        if completed_retries >= self.max_retries || !error.is_retryable() {
            return None;
        }
        let requested = error.retry_after().unwrap_or(self.base_delay);
        Some(requested.min(self.max_delay))
    }

    /// Maximum accepted `Retry-After` duration.
    #[must_use]
    pub const fn max_delay(self) -> Duration {
        self.max_delay
    }

    pub(crate) fn is_valid(self) -> bool {
        self.base_delay <= self.max_delay && self.max_delay <= MAX_RETRY_DELAY
    }
}

/// Parses either delta-seconds or an HTTP date and clamps it to `maximum`.
#[must_use]
pub fn parse_retry_after(
    value: &HeaderValue,
    now: SystemTime,
    maximum: Duration,
) -> Option<Duration> {
    if maximum.is_zero() {
        return None;
    }
    let value = value.to_str().ok()?.trim();
    let duration = if let Ok(seconds) = value.parse::<u64>() {
        Duration::from_secs(seconds)
    } else {
        let retry_at = httpdate::parse_http_date(value).ok()?;
        retry_at.duration_since(now).unwrap_or(Duration::ZERO)
    };
    Some(duration.min(maximum))
}
