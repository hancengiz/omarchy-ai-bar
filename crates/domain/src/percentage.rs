use std::fmt::{self, Display, Formatter};
use std::num::NonZeroU64;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// A general-purpose finite floating-point value for provider measurements.
///
/// This is intentionally distinct from percentages and exact monetary values.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FiniteNumber(f64);

impl FiniteNumber {
    /// Creates a finite provider measurement without otherwise normalizing it.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is NaN or infinite.
    pub fn new(value: f64) -> Result<Self, FiniteNumberError> {
        if value.is_finite() {
            Ok(Self(if value == 0.0 { 0.0 } else { value }))
        } else {
            Err(FiniteNumberError::NonFinite)
        }
    }

    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl Display for FiniteNumber {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl Serialize for FiniteNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for FiniteNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(f64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A raw provider percentage. Any finite value is retained for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct UsagePercent(f64);

impl UsagePercent {
    /// Creates a raw usage percentage without clamping it.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is NaN or infinite.
    pub fn new(value: f64) -> Result<Self, PercentageError> {
        if value.is_finite() {
            // Normalize negative zero so equal values have one canonical JSON
            // representation and one stable diagnostic spelling.
            Ok(Self(if value == 0.0 { 0.0 } else { value }))
        } else {
            Err(PercentageError::NonFinite)
        }
    }

    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// Baseline semantics: remaining is `max(0, 100 - used)` and is not capped.
    #[must_use]
    pub fn remaining(self) -> Self {
        let remaining = (100.0 - self.0).max(0.0);
        // Subtraction can overflow only for extreme finite negative values.
        // Saturation preserves the finite-value invariant of this newtype.
        Self(if remaining.is_finite() {
            remaining
        } else {
            f64::MAX
        })
    }
}

impl Display for UsagePercent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl Serialize for UsagePercent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for UsagePercent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(f64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Percentage guaranteed to be within the display interval `0..=100`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct DisplayPercent(f64);

impl DisplayPercent {
    /// Creates an already-bounded display percentage.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is non-finite or outside `0..=100`.
    pub fn new(value: f64) -> Result<Self, PercentageError> {
        if !value.is_finite() {
            return Err(PercentageError::NonFinite);
        }
        if !(0.0..=100.0).contains(&value) {
            return Err(PercentageError::OutsideDisplayRange { value });
        }
        Ok(Self(if value == 0.0 { 0.0 } else { value }))
    }

    #[must_use]
    pub fn clamped(value: UsagePercent) -> Self {
        Self(value.get().clamp(0.0, 100.0))
    }

    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// Returns the display-bounded complement `100 - value`.
    #[must_use]
    pub fn complement(self) -> Self {
        Self(100.0 - self.0)
    }
}

impl Display for DisplayPercent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl Serialize for DisplayPercent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for DisplayPercent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(f64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WindowDuration(NonZeroU64);

impl WindowDuration {
    /// Creates a positive duration in whole seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if `seconds` is zero.
    pub fn from_seconds(seconds: u64) -> Result<Self, WindowDurationError> {
        NonZeroU64::new(seconds)
            .map(Self)
            .ok_or(WindowDurationError::Zero)
    }

    /// Maps a provider-reported signed minute count to a duration.
    ///
    /// # Errors
    ///
    /// Returns an error when `minutes` is not positive or its conversion to
    /// seconds would overflow.
    pub fn from_provider_minutes(minutes: i64) -> Result<Self, WindowDurationError> {
        let minutes = u64::try_from(minutes)
            .ok()
            .filter(|minutes| *minutes > 0)
            .ok_or(WindowDurationError::NonPositiveProviderMinutes { minutes })?;
        let seconds = minutes
            .checked_mul(60)
            .ok_or(WindowDurationError::Overflow)?;
        Self::from_seconds(seconds)
    }

    /// Canonicalizes the provider convention where zero means no duration.
    ///
    /// # Errors
    ///
    /// Returns an error for negative values or a positive conversion that
    /// overflows seconds.
    pub fn optional_from_provider_minutes(
        minutes: i64,
    ) -> Result<Option<Self>, WindowDurationError> {
        if minutes == 0 {
            Ok(None)
        } else {
            Self::from_provider_minutes(minutes).map(Some)
        }
    }

    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0.get()
    }
}

impl Serialize for WindowDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.seconds())
    }
}

impl<'de> Deserialize<'de> for WindowDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_seconds(u64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FiniteNumberError {
    #[error("number must be finite")]
    NonFinite,
}

#[derive(Debug, Clone, Copy, PartialEq, Error)]
pub enum PercentageError {
    #[error("percentage must be finite")]
    NonFinite,
    #[error("display percentage must be between 0 and 100; received {value}")]
    OutsideDisplayRange { value: f64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WindowDurationError {
    #[error("window duration must be greater than zero seconds")]
    Zero,
    #[error("provider window duration must be positive; received {minutes} minutes")]
    NonPositiveProviderMinutes { minutes: i64 },
    #[error("provider window duration overflows seconds")]
    Overflow,
}
