use std::borrow::Borrow;
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// Non-empty, trimmed text with a strict UTF-8 byte limit.
///
/// The byte limit bounds serialized and in-memory payloads regardless of the
/// number of Unicode scalar values in the input. Control characters are
/// rejected so a value remains safe for single-line UI and diagnostic fields.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedText<const MAX_BYTES: usize>(Box<str>);

impl<const MAX_BYTES: usize> BoundedText<MAX_BYTES> {
    /// Creates a canonical single-line bounded value.
    ///
    /// # Errors
    ///
    /// Returns an error when the bound is zero or the trimmed value is empty,
    /// contains a control character, or exceeds `MAX_BYTES` UTF-8 bytes.
    pub fn new(value: impl AsRef<str>) -> Result<Self, BoundedTextError> {
        if MAX_BYTES == 0 {
            return Err(BoundedTextError::ZeroCapacity);
        }

        let value = value.as_ref();
        if let Some(character) = value.chars().find(|character| character.is_control()) {
            return Err(BoundedTextError::ControlCharacter { character });
        }
        let value = value.trim();
        if value.is_empty() {
            return Err(BoundedTextError::Empty);
        }
        if value.len() > MAX_BYTES {
            return Err(BoundedTextError::TooLong {
                maximum: MAX_BYTES,
                actual: value.len(),
            });
        }

        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0.into()
    }
}

impl<const MAX_BYTES: usize> Debug for BoundedText<MAX_BYTES> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedText")
            .field("maximum_bytes", &MAX_BYTES)
            .field("actual_bytes", &self.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<const MAX_BYTES: usize> Display for BoundedText<MAX_BYTES> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<const MAX_BYTES: usize> AsRef<str> for BoundedText<MAX_BYTES> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const MAX_BYTES: usize> Borrow<str> for BoundedText<MAX_BYTES> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<const MAX_BYTES: usize> FromStr for BoundedText<MAX_BYTES> {
    type Err = BoundedTextError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<const MAX_BYTES: usize> Serialize for BoundedText<MAX_BYTES> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de, const MAX_BYTES: usize> Deserialize<'de> for BoundedText<MAX_BYTES> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BoundedTextError {
    #[error("bounded text capacity must be greater than zero")]
    ZeroCapacity,
    #[error("bounded text must not be empty")]
    Empty,
    #[error("bounded text contains control character {character:?}")]
    ControlCharacter { character: char },
    #[error("bounded text is {actual} bytes; maximum is {maximum} bytes")]
    TooLong { maximum: usize, actual: usize },
}
