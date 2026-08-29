use std::collections::BTreeSet;

use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::ids::{AccountScope, OpaqueRecordId, OpaqueRecordKind};
use crate::money::ExactDecimal;
use crate::percentage::DisplayPercent;
use crate::privacy::PrivacyKey;
use crate::text::{BoundedText, BoundedTextError};
use crate::timestamp::Timestamp;

pub const MAX_CREDIT_EVENTS: usize = 1_024;

/// One provider-reported credit spend event.
///
/// ```compile_fail
/// # use oab_domain::CreditEvent;
/// fn cannot_serialize_private_event(event: &CreditEvent) {
///     let _ = serde_json::to_string(event);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditEvent {
    scope: AccountScope,
    id: OpaqueRecordId,
    occurred_at: Timestamp,
    service: BoundedText<120>,
    used: ExactDecimal,
}

impl CreditEvent {
    /// Creates a bounded, non-negative credit event.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid text or a negative credit amount.
    pub fn from_provider(
        privacy_key: &PrivacyKey,
        scope: &AccountScope,
        source_id: Option<&str>,
        occurrence_index: u32,
        occurred_at: Timestamp,
        service: impl Into<String>,
        used: ExactDecimal,
    ) -> Result<Self, CreditValidationError> {
        require_non_negative(used)?;
        let service = BoundedText::<120>::new(service.into())?;
        let source_id = source_id.map(BoundedText::<512>::new).transpose()?;
        let occurred_at_text = occurred_at.to_string();
        let used_text = used.to_string();
        let occurrence_bytes = occurrence_index.to_be_bytes();
        let (source_tag, source_bytes): (&[u8], &[u8]) =
            source_id.as_ref().map_or((b"absent", b""), |value| {
                (b"present", value.as_str().as_bytes())
            });
        let id = OpaqueRecordId::derive(
            privacy_key,
            scope,
            OpaqueRecordKind::CreditEvent,
            &[
                source_tag,
                source_bytes,
                occurred_at_text.as_bytes(),
                service.as_str().as_bytes(),
                used_text.as_bytes(),
                &occurrence_bytes,
            ],
        );
        Ok(Self::from_parts(
            scope.clone(),
            id,
            occurred_at,
            service,
            used,
        ))
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    #[must_use]
    pub const fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    #[must_use]
    pub fn service(&self) -> &str {
        self.service.as_str()
    }

    #[must_use]
    pub const fn used(&self) -> ExactDecimal {
        self.used
    }

    fn from_parts(
        scope: AccountScope,
        id: OpaqueRecordId,
        occurred_at: Timestamp,
        service: BoundedText<120>,
        used: ExactDecimal,
    ) -> Self {
        Self {
            scope,
            id,
            occurred_at,
            service,
            used,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreditEventRepr {
    scope: AccountScope,
    id: OpaqueRecordId,
    occurred_at: Timestamp,
    service: String,
    used: ExactDecimal,
}

impl<'de> Deserialize<'de> for CreditEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CreditEventRepr::deserialize(deserializer)?;
        require_non_negative(repr.used).map_err(de::Error::custom)?;
        let service = BoundedText::new(repr.service).map_err(de::Error::custom)?;
        Ok(Self::from_parts(
            repr.scope,
            repr.id,
            repr.occurred_at,
            service,
            repr.used,
        ))
    }
}

#[derive(Debug, Clone, Copy)]
struct PrivateCreditEvent<'a>(&'a CreditEvent);

impl Serialize for PrivateCreditEvent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct CreditEventRef<'a> {
            scope: &'a AccountScope,
            id: &'a OpaqueRecordId,
            occurred_at: Timestamp,
            service: &'a BoundedText<120>,
            used: ExactDecimal,
        }

        CreditEventRef {
            scope: &self.0.scope,
            id: &self.0.id,
            occurred_at: self.0.occurred_at,
            service: &self.0.service,
            used: self.0.used,
        }
        .serialize(serializer)
    }
}

/// Provider-reported periodic credit allowance.
///
/// ```compile_fail
/// # use oab_domain::CreditLimitSnapshot;
/// fn cannot_serialize_private_limit(limit: &CreditLimitSnapshot) {
///     let _ = serde_json::to_string(limit);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CreditLimitSnapshot {
    title: BoundedText<120>,
    used: ExactDecimal,
    limit: ExactDecimal,
    remaining: ExactDecimal,
    remaining_percent: DisplayPercent,
    resets_at: Option<Timestamp>,
    updated_at: Timestamp,
}

impl CreditLimitSnapshot {
    /// Creates a consistent non-negative allowance snapshot.
    ///
    /// `remaining` is derived as `max(0, limit - used)` so provider adapters
    /// cannot publish contradictory used/remaining values.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid text, negative values, or decimal overflow.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        title: impl Into<String>,
        used: ExactDecimal,
        limit: ExactDecimal,
        remaining_percent: DisplayPercent,
        resets_at: Option<Timestamp>,
        updated_at: Timestamp,
    ) -> Result<Self, CreditValidationError> {
        require_non_negative(used)?;
        if limit.get() <= Decimal::ZERO {
            return Err(CreditValidationError::NonPositiveLimit);
        }
        let remaining = limit
            .get()
            .checked_sub(used.get())
            .ok_or(CreditValidationError::DecimalOverflow)?
            .max(Decimal::ZERO);
        let title = title.into();
        let title = title.trim();
        let title = if title.is_empty() {
            "Monthly credit limit"
        } else {
            title
        };
        Ok(Self {
            title: BoundedText::new(title)?,
            used,
            limit,
            remaining: ExactDecimal::new(remaining),
            remaining_percent,
            resets_at,
            updated_at,
        })
    }

    #[must_use]
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    #[must_use]
    pub const fn used(&self) -> ExactDecimal {
        self.used
    }

    #[must_use]
    pub const fn limit(&self) -> ExactDecimal {
        self.limit
    }

    #[must_use]
    pub const fn remaining(&self) -> ExactDecimal {
        self.remaining
    }

    #[must_use]
    pub const fn remaining_percent(&self) -> DisplayPercent {
        self.remaining_percent
    }

    #[must_use]
    pub fn used_percent(&self) -> DisplayPercent {
        self.remaining_percent.complement()
    }

    #[must_use]
    pub const fn resets_at(&self) -> Option<Timestamp> {
        self.resets_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    fn public_projection(&self) -> Self {
        let mut result = self.clone();
        result.title = BoundedText::new("Credit limit")
            .expect("fixed public credit-limit title satisfies its bound");
        result
    }

    const fn private_view(&self) -> PrivateCreditLimitSnapshot<'_> {
        PrivateCreditLimitSnapshot(self)
    }
}

#[derive(Debug, Clone, Copy)]
struct PrivateCreditLimitSnapshot<'a>(&'a CreditLimitSnapshot);

impl Serialize for PrivateCreditLimitSnapshot<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct CreditLimitSnapshotRef<'a> {
            title: &'a BoundedText<120>,
            used: ExactDecimal,
            limit: ExactDecimal,
            remaining: ExactDecimal,
            remaining_percent: DisplayPercent,
            resets_at: Option<Timestamp>,
            updated_at: Timestamp,
        }

        CreditLimitSnapshotRef {
            title: &self.0.title,
            used: self.0.used,
            limit: self.0.limit,
            remaining: self.0.remaining,
            remaining_percent: self.0.remaining_percent,
            resets_at: self.0.resets_at,
            updated_at: self.0.updated_at,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreditLimitSnapshotRepr {
    title: String,
    used: ExactDecimal,
    limit: ExactDecimal,
    remaining: ExactDecimal,
    remaining_percent: DisplayPercent,
    resets_at: Option<Timestamp>,
    updated_at: Timestamp,
}

impl<'de> Deserialize<'de> for CreditLimitSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CreditLimitSnapshotRepr::deserialize(deserializer)?;
        let snapshot = Self::new(
            repr.title,
            repr.used,
            repr.limit,
            repr.remaining_percent,
            repr.resets_at,
            repr.updated_at,
        )
        .map_err(de::Error::custom)?;
        if snapshot.remaining != repr.remaining {
            return Err(de::Error::custom(
                CreditValidationError::InconsistentRemaining,
            ));
        }
        Ok(snapshot)
    }
}

/// A private credit balance, event history, and optional periodic limit.
///
/// Serialize only through the enclosing private or projected snapshot view.
///
/// ```compile_fail
/// # use oab_domain::CreditsSnapshot;
/// fn cannot_serialize_private_credits(snapshot: &CreditsSnapshot) {
///     let _ = serde_json::to_string(snapshot);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CreditsSnapshot {
    scope: AccountScope,
    remaining: ExactDecimal,
    events: Vec<CreditEvent>,
    updated_at: Timestamp,
    limit: Option<CreditLimitSnapshot>,
}

impl CreditsSnapshot {
    /// Creates a deterministic, bounded credit snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for negative remaining credits, too many events, or
    /// duplicate event IDs.
    pub fn new(
        scope: AccountScope,
        remaining: ExactDecimal,
        mut events: Vec<CreditEvent>,
        updated_at: Timestamp,
        limit: Option<CreditLimitSnapshot>,
    ) -> Result<Self, CreditValidationError> {
        require_non_negative(remaining)?;
        if events.len() > MAX_CREDIT_EVENTS {
            return Err(CreditValidationError::TooManyEvents);
        }
        if events.iter().any(|event| event.scope != scope) {
            return Err(CreditValidationError::ScopeMismatch);
        }
        events.sort_by(|left, right| {
            right
                .occurred_at
                .cmp(&left.occurred_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        let mut seen_ids = BTreeSet::new();
        if events.iter().any(|event| !seen_ids.insert(&event.id)) {
            return Err(CreditValidationError::DuplicateEventId);
        }
        Ok(Self {
            scope,
            remaining,
            events,
            updated_at,
            limit,
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    #[must_use]
    pub const fn remaining(&self) -> ExactDecimal {
        self.remaining
    }

    #[must_use]
    pub fn events(&self) -> &[CreditEvent] {
        &self.events
    }

    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    #[must_use]
    pub const fn limit(&self) -> Option<&CreditLimitSnapshot> {
        self.limit.as_ref()
    }

    pub(crate) fn without_personal_information(&self, scope: AccountScope) -> Self {
        Self {
            scope,
            remaining: self.remaining,
            events: Vec::new(),
            updated_at: self.updated_at,
            limit: self
                .limit
                .as_ref()
                .map(CreditLimitSnapshot::public_projection),
        }
    }

    pub(crate) const fn private_view(&self) -> PrivateCreditsSnapshot<'_> {
        PrivateCreditsSnapshot(self)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PrivateCreditsSnapshot<'a>(&'a CreditsSnapshot);

impl Serialize for PrivateCreditsSnapshot<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct CreditsSnapshotRef<'a> {
            scope: &'a AccountScope,
            remaining: ExactDecimal,
            events: Vec<PrivateCreditEvent<'a>>,
            updated_at: Timestamp,
            limit: Option<PrivateCreditLimitSnapshot<'a>>,
        }

        CreditsSnapshotRef {
            scope: &self.0.scope,
            remaining: self.0.remaining,
            events: self.0.events.iter().map(PrivateCreditEvent).collect(),
            updated_at: self.0.updated_at,
            limit: self.0.limit.as_ref().map(CreditLimitSnapshot::private_view),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreditsSnapshotRepr {
    scope: AccountScope,
    remaining: ExactDecimal,
    events: Vec<CreditEvent>,
    updated_at: Timestamp,
    limit: Option<CreditLimitSnapshot>,
}

impl<'de> Deserialize<'de> for CreditsSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CreditsSnapshotRepr::deserialize(deserializer)?;
        Self::new(
            repr.scope,
            repr.remaining,
            repr.events,
            repr.updated_at,
            repr.limit,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CreditValidationError {
    #[error("credit record scope must match its enclosing snapshot")]
    ScopeMismatch,
    #[error("credit amount must be non-negative")]
    NegativeAmount,
    #[error("credit limit must be positive")]
    NonPositiveLimit,
    #[error("credit arithmetic overflowed")]
    DecimalOverflow,
    #[error("credit limit remaining amount is inconsistent")]
    InconsistentRemaining,
    #[error("credit event collection exceeds its maximum")]
    TooManyEvents,
    #[error("duplicate credit event ID")]
    DuplicateEventId,
    #[error(transparent)]
    InvalidText(#[from] BoundedTextError),
}

fn require_non_negative(value: ExactDecimal) -> Result<(), CreditValidationError> {
    if value.get().is_sign_negative() {
        Err(CreditValidationError::NegativeAmount)
    } else {
        Ok(())
    }
}
