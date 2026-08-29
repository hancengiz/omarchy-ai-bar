use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeStruct};
use thiserror::Error;

use crate::text::{BoundedText, BoundedTextError};

pub const MAX_PROVIDER_UNIT_BYTES: usize = 32;
pub const MAX_QUANTITY_UNIT_BYTES: usize = 32;

/// An exact base-10 value with a canonical string wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactDecimal(Decimal);

impl ExactDecimal {
    #[must_use]
    pub fn new(value: Decimal) -> Self {
        Self(value.normalize())
    }

    /// Parses an exact decimal and removes insignificant trailing zeroes.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, whitespace-padded, or invalid decimal text.
    pub fn parse(value: &str) -> Result<Self, ExactDecimalError> {
        if value.is_empty() {
            return Err(ExactDecimalError::Empty);
        }
        if value != value.trim() {
            return Err(ExactDecimalError::SurroundingWhitespace);
        }
        Decimal::from_str(value)
            .map(Self::new)
            .map_err(ExactDecimalError::Invalid)
    }

    #[must_use]
    pub const fn get(self) -> Decimal {
        self.0
    }
}

impl Display for ExactDecimal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for ExactDecimal {
    type Err = ExactDecimalError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl From<Decimal> for ExactDecimal {
    fn from(value: Decimal) -> Self {
        Self::new(value)
    }
}

impl Serialize for ExactDecimal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ExactDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// Canonical three-letter currency code (for example `USD`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CurrencyCode(Box<str>);

impl CurrencyCode {
    /// Creates a canonical uppercase three-letter currency code.
    ///
    /// # Errors
    ///
    /// Returns an error unless the input is exactly three unpadded ASCII
    /// letters.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CurrencyCodeError> {
        let value = value.as_ref();
        if value != value.trim() {
            return Err(CurrencyCodeError::SurroundingWhitespace);
        }
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(CurrencyCodeError::Invalid);
        }
        Ok(Self(value.to_ascii_uppercase().into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for CurrencyCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for CurrencyCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for CurrencyCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CurrencyCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Money {
    amount: ExactDecimal,
    currency: CurrencyCode,
}

impl Money {
    #[must_use]
    pub const fn new(amount: ExactDecimal, currency: CurrencyCode) -> Self {
        Self { amount, currency }
    }

    #[must_use]
    pub const fn amount(&self) -> ExactDecimal {
        self.amount
    }

    #[must_use]
    pub const fn currency(&self) -> &CurrencyCode {
        &self.currency
    }
}

/// A provider-defined accounting unit such as `MiniMax` `Points`.
///
/// This is intentionally distinct from [`CurrencyCode`]: provider units retain
/// their canonical casing and may be longer than an ISO-style currency code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderUnit(BoundedText<MAX_PROVIDER_UNIT_BYTES>);

impl ProviderUnit {
    /// Creates a non-empty, single-line provider unit with a bounded wire size.
    ///
    /// # Errors
    ///
    /// Returns an error when the unit fails bounded-text validation.
    pub fn new(value: impl AsRef<str>) -> Result<Self, BoundedTextError> {
        BoundedText::new(value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for ProviderUnit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for ProviderUnit {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// The unit attached to a provider cost or budget amount.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CostUnit {
    /// A strict three-letter currency code.
    Currency(CurrencyCode),
    /// A provider-defined accounting unit which is not a currency code.
    Provider(ProviderUnit),
}

impl CostUnit {
    #[must_use]
    pub const fn currency(currency: CurrencyCode) -> Self {
        Self::Currency(currency)
    }

    /// Creates a provider-defined unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the unit fails bounded-text validation.
    pub fn provider(value: impl AsRef<str>) -> Result<Self, BoundedTextError> {
        ProviderUnit::new(value).map(Self::Provider)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Currency(currency) => currency.as_str(),
            Self::Provider(unit) => unit.as_str(),
        }
    }

    #[must_use]
    pub const fn currency_code(&self) -> Option<&CurrencyCode> {
        match self {
            Self::Currency(currency) => Some(currency),
            Self::Provider(_) => None,
        }
    }

    #[must_use]
    pub const fn provider_unit(&self) -> Option<&ProviderUnit> {
        match self {
            Self::Currency(_) => None,
            Self::Provider(unit) => Some(unit),
        }
    }

    fn without_personal_information(&self) -> Self {
        match self {
            Self::Currency(currency) => Self::Currency(currency.clone()),
            Self::Provider(_) => Self::Provider(
                ProviderUnit::new("credits")
                    .expect("fixed public provider unit satisfies its bounded-text contract"),
            ),
        }
    }
}

impl Display for CostUnit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An exact cost, balance, or budget amount measured in either currency or a
/// provider-defined accounting unit.
///
/// Its wire representation contains exactly one of `currency` or
/// `provider_unit`, so values such as `USD` and `Points` cannot be conflated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostAmount {
    amount: ExactDecimal,
    unit: CostUnit,
}

impl CostAmount {
    #[must_use]
    pub const fn new(amount: ExactDecimal, unit: CostUnit) -> Self {
        Self { amount, unit }
    }

    #[must_use]
    pub const fn money(amount: ExactDecimal, currency: CurrencyCode) -> Self {
        Self::new(amount, CostUnit::Currency(currency))
    }

    /// Creates an exact amount in a provider-defined accounting unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the unit fails bounded-text validation.
    pub fn provider(amount: ExactDecimal, unit: impl AsRef<str>) -> Result<Self, BoundedTextError> {
        Ok(Self::new(amount, CostUnit::provider(unit)?))
    }

    #[must_use]
    pub const fn amount(&self) -> ExactDecimal {
        self.amount
    }

    #[must_use]
    pub const fn unit(&self) -> &CostUnit {
        &self.unit
    }

    pub(crate) fn without_personal_information(&self) -> Self {
        Self::new(self.amount, self.unit.without_personal_information())
    }
}

impl From<Money> for CostAmount {
    fn from(money: Money) -> Self {
        Self::money(money.amount, money.currency)
    }
}

impl Serialize for CostAmount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CostAmount", 2)?;
        state.serialize_field("amount", &self.amount)?;
        match &self.unit {
            CostUnit::Currency(currency) => state.serialize_field("currency", currency)?,
            CostUnit::Provider(unit) => state.serialize_field("provider_unit", unit)?,
        }
        state.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostAmountRepr {
    amount: ExactDecimal,
    currency: Option<CurrencyCode>,
    provider_unit: Option<ProviderUnit>,
}

impl<'de> Deserialize<'de> for CostAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostAmountRepr::deserialize(deserializer)?;
        let unit = match (repr.currency, repr.provider_unit) {
            (Some(currency), None) => CostUnit::Currency(currency),
            (None, Some(unit)) => CostUnit::Provider(unit),
            (None, None) => return Err(de::Error::custom(CostAmountValidationError::MissingUnit)),
            (Some(_), Some(_)) => {
                return Err(de::Error::custom(CostAmountValidationError::AmbiguousUnit));
            }
        };
        Ok(Self::new(repr.amount, unit))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quantity {
    amount: ExactDecimal,
    unit: BoundedText<MAX_QUANTITY_UNIT_BYTES>,
}

impl Quantity {
    /// Creates an exact quantity with a bounded unit name.
    ///
    /// # Errors
    ///
    /// Returns an error when the unit fails bounded-text validation.
    pub fn new(amount: ExactDecimal, unit: impl AsRef<str>) -> Result<Self, BoundedTextError> {
        Ok(Self {
            amount,
            unit: BoundedText::new(unit)?,
        })
    }

    #[must_use]
    pub const fn amount(&self) -> ExactDecimal {
        self.amount
    }

    #[must_use]
    pub const fn unit(&self) -> &BoundedText<MAX_QUANTITY_UNIT_BYTES> {
        &self.unit
    }
}

#[derive(Debug, Error)]
pub enum ExactDecimalError {
    #[error("decimal string must not be empty")]
    Empty,
    #[error("decimal string must not contain surrounding whitespace")]
    SurroundingWhitespace,
    #[error("invalid exact decimal string")]
    Invalid(#[source] rust_decimal::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CurrencyCodeError {
    #[error("currency code must not contain surrounding whitespace")]
    SurroundingWhitespace,
    #[error("currency code must contain exactly three ASCII letters")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CostAmountValidationError {
    #[error("cost amount requires a currency or provider unit")]
    MissingUnit,
    #[error("cost amount cannot contain both a currency and provider unit")]
    AmbiguousUnit,
}

#[cfg(test)]
mod tests {
    use super::{CostAmount, ExactDecimal};

    #[test]
    fn public_projection_redacts_provider_text_but_preserves_currency() {
        let provider = CostAmount::provider(
            ExactDecimal::parse("12.5").expect("exact amount"),
            "Ada's private points",
        )
        .expect("provider unit");
        let redacted = provider.without_personal_information();
        assert_eq!(redacted.unit().as_str(), "credits");

        let currency: CostAmount =
            serde_json::from_str(r#"{"amount":"12.5","currency":"USD"}"#).expect("currency amount");
        assert_eq!(
            currency.without_personal_information().unit().as_str(),
            "USD"
        );
    }
}
