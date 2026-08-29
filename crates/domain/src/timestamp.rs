use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// An absolute instant serialized as canonical RFC 3339 in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Creates a UTC timestamp that is guaranteed to be RFC 3339 serializable.
    ///
    /// # Errors
    ///
    /// Returns an error when the instant is outside RFC 3339's representable
    /// calendar range.
    pub fn new(value: OffsetDateTime) -> Result<Self, TimestampError> {
        let value = value.to_offset(UtcOffset::UTC);
        value
            .format(&Rfc3339)
            .map_err(TimestampError::NotRfc3339Representable)?;
        Ok(Self(value))
    }

    /// Parses and normalizes an RFC 3339 timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error for surrounding whitespace or invalid RFC 3339 text.
    pub fn parse(value: &str) -> Result<Self, TimestampError> {
        if value != value.trim() {
            return Err(TimestampError::SurroundingWhitespace);
        }
        let value =
            OffsetDateTime::parse(value, &Rfc3339).map_err(TimestampError::InvalidRfc3339)?;
        Self::new(value)
    }

    /// Creates a timestamp from whole Unix seconds.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is outside `time`'s supported range.
    pub fn from_unix_timestamp(seconds: i64) -> Result<Self, TimestampError> {
        let value = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(TimestampError::InvalidUnixTimestamp)?;
        Self::new(value)
    }

    #[must_use]
    pub const fn as_offset_date_time(self) -> OffsetDateTime {
        self.0
    }

    #[must_use]
    pub const fn unix_timestamp(self) -> i64 {
        self.0.unix_timestamp()
    }

    fn canonical_string(self) -> Result<String, time::error::Format> {
        self.0.to_offset(UtcOffset::UTC).format(&Rfc3339)
    }
}

impl Display for Timestamp {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let value = self.canonical_string().map_err(|_| fmt::Error)?;
        formatter.write_str(&value)
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.canonical_string()
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum TimestampError {
    #[error("timestamp must not contain surrounding whitespace")]
    SurroundingWhitespace,
    #[error("invalid RFC 3339 timestamp")]
    InvalidRfc3339(#[source] time::error::Parse),
    #[error("timestamp is outside the RFC 3339 calendar range")]
    NotRfc3339Representable(#[source] time::error::Format),
    #[error("Unix timestamp is outside the supported range")]
    InvalidUnixTimestamp(#[source] time::error::ComponentRange),
}
