use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::cost_usage::{CostUsageSnapshot, PrivateCostUsageSnapshot};
use crate::credits::{CreditsSnapshot, PrivateCreditsSnapshot};
use crate::error::ClassifiedError;
use crate::freshness::{Freshness, RefreshPhase};
use crate::identity::{IdentitySnapshot, PrivateIdentitySnapshot};
use crate::ids::{AccountScope, OpaqueRecordId, OpaqueRecordKind};
use crate::money::{CostAmount, ExactDecimal, Money};
use crate::percentage::FiniteNumber;
use crate::privacy::PrivacyKey;
use crate::rate_window::{NamedRateWindow, RateWindow};
use crate::status::ProviderStatus;
use crate::text::BoundedText;
use crate::timestamp::Timestamp;

pub const MAX_EXTRA_WINDOWS: usize = 16;
pub const MAX_DETAIL_SECTIONS: usize = 8;
pub const MAX_DETAIL_ROWS: usize = 24;
pub const MAX_CHART_POINTS: usize = 120;
pub const MAX_PROVENANCE_ENTRIES: usize = 16;
pub const MAX_RESET_CREDITS: usize = 64;
pub const MAX_PROVIDER_EXTENSIONS: usize = 8;
pub const MAX_SNAPSHOTS_PER_ENVELOPE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DataConfidence {
    Exact,
    Estimated,
    PercentOnly,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailSensitivity {
    Public,
    Personal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetailRow {
    label: BoundedText<120>,
    value: BoundedText<120>,
    secondary_value: Option<BoundedText<120>>,
    sensitivity: DetailSensitivity,
}

impl DetailRow {
    /// Creates one bounded provider-detail row.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::InvalidText`] when any supplied string is empty,
    /// contains a control character, or exceeds the wire-format bound.
    pub fn new(
        label: impl Into<String>,
        value: impl Into<String>,
        secondary_value: Option<String>,
        sensitivity: DetailSensitivity,
    ) -> Result<Self, SnapshotError> {
        Ok(Self {
            label: BoundedText::new(label.into())?,
            value: BoundedText::new(value.into())?,
            secondary_value: secondary_value.map(BoundedText::new).transpose()?,
            sensitivity,
        })
    }

    #[must_use]
    pub const fn sensitivity(&self) -> DetailSensitivity {
        self.sensitivity
    }

    #[must_use]
    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    #[must_use]
    pub fn secondary_value(&self) -> Option<&str> {
        self.secondary_value.as_ref().map(BoundedText::as_str)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailRowRepr {
    label: String,
    value: String,
    secondary_value: Option<String>,
    sensitivity: DetailSensitivity,
}

impl<'de> Deserialize<'de> for DetailRow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = DetailRowRepr::deserialize(deserializer)?;
        Self::new(
            repr.label,
            repr.value,
            repr.secondary_value,
            repr.sensitivity,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailChartKind {
    Bars,
    Line,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetailChartPoint {
    label: BoundedText<120>,
    value: FiniteNumber,
}

impl DetailChartPoint {
    /// Creates one bounded, finite provider-detail chart point.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid label text. Non-finite values are rejected
    /// by [`FiniteNumber`] before this constructor can be called.
    pub fn new(label: impl Into<String>, value: FiniteNumber) -> Result<Self, SnapshotError> {
        Ok(Self {
            label: BoundedText::new(label.into())?,
            value,
        })
    }

    #[must_use]
    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    #[must_use]
    pub const fn value(&self) -> FiniteNumber {
        self.value
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailChartPointRepr {
    label: String,
    value: FiniteNumber,
}

impl<'de> Deserialize<'de> for DetailChartPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = DetailChartPointRepr::deserialize(deserializer)?;
        Self::new(repr.label, repr.value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetailChart {
    kind: DetailChartKind,
    title: Option<BoundedText<120>>,
    unit: Option<BoundedText<120>>,
    points: Vec<DetailChartPoint>,
}

impl DetailChart {
    /// Creates a section-bound provider detail chart.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid optional text or more than
    /// 2,048 points.
    pub fn new(
        kind: DetailChartKind,
        title: Option<String>,
        unit: Option<String>,
        points: Vec<DetailChartPoint>,
    ) -> Result<Self, SnapshotError> {
        check_limit("detail chart points", points.len(), MAX_CHART_POINTS)?;
        Ok(Self {
            kind,
            title: title.map(BoundedText::new).transpose()?,
            unit: unit.map(BoundedText::new).transpose()?,
            points,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> DetailChartKind {
        self.kind
    }

    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub fn unit(&self) -> Option<&str> {
        self.unit.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub fn points(&self) -> &[DetailChartPoint] {
        &self.points
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailChartRepr {
    kind: DetailChartKind,
    title: Option<String>,
    unit: Option<String>,
    points: Vec<DetailChartPoint>,
}

impl<'de> Deserialize<'de> for DetailChart {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = DetailChartRepr::deserialize(deserializer)?;
        Self::new(repr.kind, repr.title, repr.unit, repr.points).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetailSection {
    title: Option<BoundedText<120>>,
    rows: Vec<DetailRow>,
    chart: Option<DetailChart>,
}

impl DetailSection {
    /// Creates one bounded provider-detail section.
    ///
    /// # Errors
    ///
    /// Returns an error when optional text is invalid or `rows` exceeds
    /// 128 rows.
    pub fn new(
        title: Option<String>,
        rows: Vec<DetailRow>,
        chart: Option<DetailChart>,
    ) -> Result<Self, SnapshotError> {
        check_limit("detail section rows", rows.len(), MAX_DETAIL_ROWS)?;
        Ok(Self {
            title: title.map(BoundedText::new).transpose()?,
            rows,
            chart,
        })
    }

    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub fn rows(&self) -> &[DetailRow] {
        &self.rows
    }

    #[must_use]
    pub const fn chart(&self) -> Option<&DetailChart> {
        self.chart.as_ref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailSectionRepr {
    title: Option<String>,
    rows: Vec<DetailRow>,
    chart: Option<DetailChart>,
}

impl<'de> Deserialize<'de> for DetailSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = DetailSectionRepr::deserialize(deserializer)?;
        Self::new(repr.title, repr.rows, repr.chart).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChartPoint {
    at: Timestamp,
    value: ExactDecimal,
}

impl ChartPoint {
    #[must_use]
    pub const fn new(at: Timestamp, value: ExactDecimal) -> Self {
        Self { at, value }
    }

    #[must_use]
    pub const fn at(&self) -> Timestamp {
        self.at
    }

    #[must_use]
    pub const fn value(&self) -> ExactDecimal {
        self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    source: BoundedText<120>,
    strategy: BoundedText<120>,
}

impl Provenance {
    /// Creates a public-safe provenance label.
    ///
    /// # Errors
    ///
    /// Returns an error when either label is empty, contains control characters,
    /// or exceeds the serialized text bound.
    pub fn new(
        source: impl Into<String>,
        strategy: impl Into<String>,
    ) -> Result<Self, SnapshotError> {
        Ok(Self {
            source: BoundedText::new(source.into())?,
            strategy: BoundedText::new(strategy.into())?,
        })
    }

    #[must_use]
    pub fn source(&self) -> &str {
        self.source.as_str()
    }

    #[must_use]
    pub fn strategy(&self) -> &str {
        self.strategy.as_str()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceRepr {
    source: String,
    strategy: String,
}

impl<'de> Deserialize<'de> for Provenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = ProvenanceRepr::deserialize(deserializer)?;
        Self::new(repr.source, repr.strategy).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostProvenance {
    ListPriceEstimate,
    VendorMetered,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostSummary {
    used: CostAmount,
    limit: ExactDecimal,
    period: Option<BoundedText<120>>,
    resets_at: Option<Timestamp>,
    next_regen_amount: Option<ExactDecimal>,
    personal_used: Option<ExactDecimal>,
    balance: Option<ExactDecimal>,
    updated_at: Timestamp,
    period_start: Option<Timestamp>,
    period_end: Option<Timestamp>,
    provenance: CostProvenance,
}

impl CostSummary {
    /// Creates a complete provider-reported spend/budget snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid period text, a half-specified comparison
    /// interval, or an interval whose end is not later than its start.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        used: impl Into<CostAmount>,
        limit: ExactDecimal,
        period: Option<String>,
        resets_at: Option<Timestamp>,
        next_regen_amount: Option<ExactDecimal>,
        personal_used: Option<ExactDecimal>,
        balance: Option<ExactDecimal>,
        updated_at: Timestamp,
        period_start: Option<Timestamp>,
        period_end: Option<Timestamp>,
        provenance: CostProvenance,
    ) -> Result<Self, SnapshotError> {
        match (period_start, period_end) {
            (Some(start), Some(end)) if end <= start => return Err(SnapshotError::InvalidPeriod),
            (Some(_), None) | (None, Some(_)) => return Err(SnapshotError::IncompletePeriod),
            _ => {}
        }
        Ok(Self {
            used: used.into(),
            limit,
            period: period.map(BoundedText::new).transpose()?,
            resets_at,
            next_regen_amount,
            personal_used,
            balance,
            updated_at,
            period_start,
            period_end,
            provenance,
        })
    }

    #[must_use]
    pub const fn used(&self) -> &CostAmount {
        &self.used
    }

    #[must_use]
    pub const fn limit(&self) -> ExactDecimal {
        self.limit
    }

    #[must_use]
    pub const fn personal_used(&self) -> Option<ExactDecimal> {
        self.personal_used
    }

    #[must_use]
    pub const fn balance(&self) -> Option<ExactDecimal> {
        self.balance
    }

    #[must_use]
    pub fn period(&self) -> Option<&str> {
        self.period.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub const fn resets_at(&self) -> Option<Timestamp> {
        self.resets_at
    }

    #[must_use]
    pub const fn next_regen_amount(&self) -> Option<ExactDecimal> {
        self.next_regen_amount
    }

    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    #[must_use]
    pub const fn period_start(&self) -> Option<Timestamp> {
        self.period_start
    }

    #[must_use]
    pub const fn period_end(&self) -> Option<Timestamp> {
        self.period_end
    }

    #[must_use]
    pub const fn provenance(&self) -> CostProvenance {
        self.provenance
    }

    pub(crate) fn without_personal_information(&self) -> Self {
        let mut result = self.clone();
        result.used = result.used.without_personal_information();
        result.period = None;
        result.personal_used = None;
        result
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostSummaryRepr {
    used: CostAmount,
    limit: ExactDecimal,
    period: Option<String>,
    resets_at: Option<Timestamp>,
    next_regen_amount: Option<ExactDecimal>,
    personal_used: Option<ExactDecimal>,
    balance: Option<ExactDecimal>,
    updated_at: Timestamp,
    period_start: Option<Timestamp>,
    period_end: Option<Timestamp>,
    provenance: CostProvenance,
}

impl<'de> Deserialize<'de> for CostSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostSummaryRepr::deserialize(deserializer)?;
        Self::new(
            repr.used,
            repr.limit,
            repr.period,
            repr.resets_at,
            repr.next_regen_amount,
            repr.personal_used,
            repr.balance,
            repr.updated_at,
            repr.period_start,
            repr.period_end,
            repr.provenance,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetCreditStatus {
    Available,
    Redeeming,
    Redeemed,
    Expired,
    Unknown(UnknownResetCreditStatus),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownResetCreditStatus(BoundedText<32>);

impl UnknownResetCreditStatus {
    /// Creates a canonical provider-specific reset status.
    ///
    /// # Errors
    ///
    /// Returns an error for surrounding whitespace, invalid bounded text, or a
    /// value reserved by a normalized [`ResetCreditStatus`] variant.
    pub fn new(value: impl Into<String>) -> Result<Self, ResetCreditStatusValidationError> {
        let value = value.into();
        if value != value.trim() {
            return Err(ResetCreditStatusValidationError::SurroundingWhitespace);
        }
        if matches!(
            value.as_str(),
            "available" | "redeeming" | "redeemed" | "expired"
        ) {
            return Err(ResetCreditStatusValidationError::Reserved(value));
        }
        Ok(Self(BoundedText::new(value)?))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Error)]
pub enum ResetCreditStatusValidationError {
    #[error("reset-credit status must not contain surrounding whitespace")]
    SurroundingWhitespace,
    #[error("{0:?} is a reserved reset-credit status")]
    Reserved(String),
    #[error(transparent)]
    InvalidText(#[from] crate::text::BoundedTextError),
}

impl Serialize for ResetCreditStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = match self {
            Self::Available => "available",
            Self::Redeeming => "redeeming",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Unknown(value) => value.as_str(),
        };
        serializer.serialize_str(value)
    }
}

impl<'de> Deserialize<'de> for ResetCreditStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value != value.trim() {
            return Err(de::Error::custom(
                "reset-credit status must not contain surrounding whitespace",
            ));
        }
        match value.as_str() {
            "available" => Ok(Self::Available),
            "redeeming" => Ok(Self::Redeeming),
            "redeemed" => Ok(Self::Redeemed),
            "expired" => Ok(Self::Expired),
            _ => UnknownResetCreditStatus::new(value)
                .map(Self::Unknown)
                .map_err(de::Error::custom),
        }
    }
}

impl ResetCreditStatus {
    fn without_personal_information(&self) -> Self {
        match self {
            Self::Available => Self::Available,
            Self::Redeeming => Self::Redeeming,
            Self::Redeemed => Self::Redeemed,
            Self::Expired => Self::Expired,
            Self::Unknown(_) => Self::Unknown(
                UnknownResetCreditStatus::new("unknown")
                    .expect("fixed public reset status satisfies validation"),
            ),
        }
    }
}

/// One private reset-credit lifecycle entry.
///
/// ```compile_fail
/// # use oab_domain::ResetCredit;
/// fn cannot_serialize_private_reset(credit: &ResetCredit) {
///     let _ = serde_json::to_string(credit);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetCredit {
    scope: AccountScope,
    id: OpaqueRecordId,
    reset_type: BoundedText<64>,
    status: ResetCreditStatus,
    granted_at: Timestamp,
    expires_at: Option<Timestamp>,
    redeem_started_at: Option<Timestamp>,
    redeemed_at: Option<Timestamp>,
    title: Option<BoundedText<120>>,
    description: Option<BoundedText<120>>,
}

impl ResetCredit {
    /// Creates one reset-credit lifecycle entry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid text or chronologically inconsistent grant,
    /// expiration, redeem-start, and redeemed timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn from_provider(
        privacy_key: &PrivacyKey,
        scope: &AccountScope,
        raw_provider_id: impl AsRef<str>,
        reset_type: impl Into<String>,
        status: ResetCreditStatus,
        granted_at: Timestamp,
        expires_at: Option<Timestamp>,
        redeem_started_at: Option<Timestamp>,
        redeemed_at: Option<Timestamp>,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<Self, SnapshotError> {
        let raw_provider_id = BoundedText::<512>::new(raw_provider_id)?;
        let id = OpaqueRecordId::derive(
            privacy_key,
            scope,
            OpaqueRecordKind::ResetCredit,
            &[raw_provider_id.as_str().as_bytes()],
        );
        Self::from_parts(
            scope.clone(),
            id,
            reset_type,
            status,
            granted_at,
            expires_at,
            redeem_started_at,
            redeemed_at,
            title,
            description,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        scope: AccountScope,
        id: OpaqueRecordId,
        reset_type: impl Into<String>,
        status: ResetCreditStatus,
        granted_at: Timestamp,
        expires_at: Option<Timestamp>,
        redeem_started_at: Option<Timestamp>,
        redeemed_at: Option<Timestamp>,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<Self, SnapshotError> {
        if expires_at.is_some_and(|value| value <= granted_at)
            || redeem_started_at.is_some_and(|value| value < granted_at)
            || redeemed_at.is_some_and(|value| value < redeem_started_at.unwrap_or(granted_at))
            || expires_at.is_some_and(|expiry| {
                redeem_started_at.is_some_and(|started| started >= expiry)
                    || redeemed_at.is_some_and(|redeemed| redeemed > expiry)
            })
        {
            return Err(SnapshotError::InvalidResetCreditTimeline);
        }
        let status_is_consistent = match &status {
            ResetCreditStatus::Available => redeem_started_at.is_none() && redeemed_at.is_none(),
            ResetCreditStatus::Redeeming => redeem_started_at.is_some() && redeemed_at.is_none(),
            ResetCreditStatus::Redeemed => redeem_started_at.is_some() && redeemed_at.is_some(),
            ResetCreditStatus::Expired => redeemed_at.is_none(),
            ResetCreditStatus::Unknown(_) => true,
        };
        if !status_is_consistent {
            return Err(SnapshotError::InvalidResetCreditState);
        }
        Ok(Self {
            scope,
            id,
            reset_type: BoundedText::new(reset_type.into())?,
            status,
            granted_at,
            expires_at,
            redeem_started_at,
            redeemed_at,
            title: title.map(BoundedText::new).transpose()?,
            description: description.map(BoundedText::new).transpose()?,
        })
    }

    #[must_use]
    pub const fn status(&self) -> &ResetCreditStatus {
        &self.status
    }

    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub fn reset_type(&self) -> &str {
        self.reset_type.as_str()
    }

    #[must_use]
    pub const fn granted_at(&self) -> Timestamp {
        self.granted_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    #[must_use]
    pub const fn redeem_started_at(&self) -> Option<Timestamp> {
        self.redeem_started_at
    }

    #[must_use]
    pub const fn redeemed_at(&self) -> Option<Timestamp> {
        self.redeemed_at
    }

    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub fn is_available_at(&self, now: Timestamp) -> bool {
        self.status == ResetCreditStatus::Available
            && self.expires_at.is_none_or(|expires_at| expires_at > now)
    }

    fn sort_key(&self) -> (bool, Option<Timestamp>, &str) {
        (self.expires_at.is_none(), self.expires_at, self.id.as_str())
    }

    pub(crate) fn without_personal_information(&self, scope: AccountScope, ordinal: usize) -> Self {
        let mut result = self.clone();
        result.scope = scope;
        result.id = OpaqueRecordId::public_ordinal(OpaqueRecordKind::ResetCredit, ordinal);
        result.reset_type =
            BoundedText::new("reset").expect("fixed reset-credit type is bounded and non-empty");
        result.status = self.status.without_personal_information();
        result.title = None;
        result.description = None;
        result
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetCreditRepr {
    scope: AccountScope,
    id: OpaqueRecordId,
    reset_type: String,
    status: ResetCreditStatus,
    granted_at: Timestamp,
    expires_at: Option<Timestamp>,
    redeem_started_at: Option<Timestamp>,
    redeemed_at: Option<Timestamp>,
    title: Option<String>,
    description: Option<String>,
}

impl<'de> Deserialize<'de> for ResetCredit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = ResetCreditRepr::deserialize(deserializer)?;
        Self::from_parts(
            repr.scope,
            repr.id,
            repr.reset_type,
            repr.status,
            repr.granted_at,
            repr.expires_at,
            repr.redeem_started_at,
            repr.redeemed_at,
            repr.title,
            repr.description,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy)]
struct PrivateResetCredit<'a>(&'a ResetCredit);

impl Serialize for PrivateResetCredit<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ResetCreditRef<'a> {
            scope: &'a AccountScope,
            id: &'a OpaqueRecordId,
            reset_type: &'a BoundedText<64>,
            status: &'a ResetCreditStatus,
            granted_at: Timestamp,
            expires_at: Option<Timestamp>,
            redeem_started_at: Option<Timestamp>,
            redeemed_at: Option<Timestamp>,
            title: Option<&'a BoundedText<120>>,
            description: Option<&'a BoundedText<120>>,
        }

        ResetCreditRef {
            scope: &self.0.scope,
            id: &self.0.id,
            reset_type: &self.0.reset_type,
            status: &self.0.status,
            granted_at: self.0.granted_at,
            expires_at: self.0.expires_at,
            redeem_started_at: self.0.redeem_started_at,
            redeemed_at: self.0.redeemed_at,
            title: self.0.title.as_ref(),
            description: self.0.description.as_ref(),
        }
        .serialize(serializer)
    }
}

pub const MAX_REPORTED_AVAILABLE_RESET_CREDITS: u16 = 4_096;

/// A private provider-reported reset-credit inventory.
///
/// The reported count is retained independently from the locally filtered
/// entries because the baseline uses equality only as strong confirmation
/// evidence, not as a universal invariant.
///
/// ```compile_fail
/// # use oab_domain::ResetCreditsSnapshot;
/// fn cannot_serialize_private_inventory(snapshot: &ResetCreditsSnapshot) {
///     let _ = serde_json::to_string(snapshot);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetCreditsSnapshot {
    scope: AccountScope,
    credits: Vec<ResetCredit>,
    reported_available_count: u16,
    updated_at: Timestamp,
}

impl ResetCreditsSnapshot {
    /// Creates one bounded, deterministic reset-credit inventory.
    ///
    /// # Errors
    ///
    /// Returns an error for too many entries, a duplicate opaque ID, or an
    /// implausibly large provider-reported count.
    pub fn new(
        scope: AccountScope,
        mut credits: Vec<ResetCredit>,
        reported_available_count: u16,
        updated_at: Timestamp,
    ) -> Result<Self, SnapshotError> {
        check_limit("reset credits", credits.len(), MAX_RESET_CREDITS)?;
        if reported_available_count > MAX_REPORTED_AVAILABLE_RESET_CREDITS {
            return Err(SnapshotError::ReportedResetCreditCountTooLarge);
        }
        if credits.iter().any(|credit| credit.scope != scope) {
            return Err(SnapshotError::ScopeMismatch);
        }
        let mut seen_ids = BTreeSet::new();
        if credits.iter().any(|credit| !seen_ids.insert(&credit.id)) {
            return Err(SnapshotError::Duplicate("reset credit id"));
        }
        credits.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        Ok(Self {
            scope,
            credits,
            reported_available_count,
            updated_at,
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    #[must_use]
    pub fn credits(&self) -> &[ResetCredit] {
        &self.credits
    }

    #[must_use]
    pub const fn reported_available_count(&self) -> u16 {
        self.reported_available_count
    }

    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    #[must_use]
    pub fn available_credits_at(&self, at: Timestamp) -> Vec<&ResetCredit> {
        self.credits
            .iter()
            .filter(|credit| credit.is_available_at(at))
            .collect()
    }

    #[must_use]
    pub fn reported_count_matches_inventory_at(&self, at: Timestamp) -> bool {
        usize::from(self.reported_available_count) == self.available_credits_at(at).len()
    }

    pub(crate) fn without_personal_information(&self, scope: &AccountScope) -> Self {
        Self {
            scope: scope.clone(),
            credits: self
                .credits
                .iter()
                .enumerate()
                .map(|(ordinal, credit)| {
                    credit.without_personal_information(scope.clone(), ordinal)
                })
                .collect(),
            reported_available_count: self.reported_available_count,
            updated_at: self.updated_at,
        }
    }

    const fn private_view(&self) -> PrivateResetCreditsSnapshot<'_> {
        PrivateResetCreditsSnapshot(self)
    }
}

#[derive(Debug, Clone, Copy)]
struct PrivateResetCreditsSnapshot<'a>(&'a ResetCreditsSnapshot);

impl Serialize for PrivateResetCreditsSnapshot<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ResetCreditsSnapshotRef<'a> {
            scope: &'a AccountScope,
            credits: Vec<PrivateResetCredit<'a>>,
            reported_available_count: u16,
            updated_at: Timestamp,
        }

        ResetCreditsSnapshotRef {
            scope: &self.0.scope,
            credits: self.0.credits.iter().map(PrivateResetCredit).collect(),
            reported_available_count: self.0.reported_available_count,
            updated_at: self.0.updated_at,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetCreditsSnapshotRepr {
    scope: AccountScope,
    credits: Vec<ResetCredit>,
    reported_available_count: u16,
    updated_at: Timestamp,
}

impl<'de> Deserialize<'de> for ResetCreditsSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = ResetCreditsSnapshotRepr::deserialize(deserializer)?;
        Self::new(
            repr.scope,
            repr.credits,
            repr.reported_available_count,
            repr.updated_at,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderExtensionKind {
    OpenAiApiUsage,
    MistralUsage,
    OpenCodeGoUsage,
    DeepSeekUsage,
    CommandCodeMarkers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionValue {
    Text { value: BoundedText<120> },
    Decimal { value: ExactDecimal },
    Boolean { value: bool },
    Timestamp { value: Timestamp },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtensionFact {
    key: BoundedText<64>,
    label: BoundedText<120>,
    value: ExtensionValue,
    sensitivity: DetailSensitivity,
}

impl ExtensionFact {
    /// Creates one bounded provider-specific fact.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid key or label text.
    pub fn new(
        key: impl Into<String>,
        label: impl Into<String>,
        value: ExtensionValue,
        sensitivity: DetailSensitivity,
    ) -> Result<Self, SnapshotError> {
        Ok(Self {
            key: BoundedText::new(key.into())?,
            label: BoundedText::new(label.into())?,
            value,
            sensitivity,
        })
    }

    #[must_use]
    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    #[must_use]
    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    #[must_use]
    pub const fn value(&self) -> &ExtensionValue {
        &self.value
    }

    #[must_use]
    pub const fn sensitivity(&self) -> DetailSensitivity {
        self.sensitivity
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtensionFactRepr {
    key: String,
    label: String,
    value: ExtensionValue,
    sensitivity: DetailSensitivity,
}

impl<'de> Deserialize<'de> for ExtensionFact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = ExtensionFactRepr::deserialize(deserializer)?;
        Self::new(repr.key, repr.label, repr.value, repr.sensitivity).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProviderExtension {
    kind: ProviderExtensionKind,
    facts: Vec<ExtensionFact>,
    sections: Vec<DetailSection>,
}

impl ProviderExtension {
    /// Creates a bounded provider-specific extension payload.
    ///
    /// # Errors
    ///
    /// Returns an error when facts or sections exceed their bounds or fact keys
    /// are duplicated.
    pub fn new(
        kind: ProviderExtensionKind,
        mut facts: Vec<ExtensionFact>,
        sections: Vec<DetailSection>,
    ) -> Result<Self, SnapshotError> {
        check_limit("extension facts", facts.len(), 64)?;
        check_limit("extension sections", sections.len(), MAX_DETAIL_SECTIONS)?;
        facts.sort_by(|left, right| left.key.cmp(&right.key));
        ensure_unique(
            facts.iter().map(|fact| fact.key.as_str()),
            "extension fact key",
        )?;
        Ok(Self {
            kind,
            facts,
            sections,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> ProviderExtensionKind {
        self.kind
    }

    #[must_use]
    pub fn facts(&self) -> &[ExtensionFact] {
        &self.facts
    }

    #[must_use]
    pub fn sections(&self) -> &[DetailSection] {
        &self.sections
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderExtensionRepr {
    kind: ProviderExtensionKind,
    facts: Vec<ExtensionFact>,
    sections: Vec<DetailSection>,
}

impl<'de> Deserialize<'de> for ProviderExtension {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = ProviderExtensionRepr::deserialize(deserializer)?;
        Self::new(repr.kind, repr.facts, repr.sections).map_err(de::Error::custom)
    }
}

/// A private provider sample; serialize only through its enclosing explicit
/// envelope view.
///
/// ```compile_fail
/// # use oab_domain::UsageSample;
/// fn cannot_serialize_private_sample(sample: &UsageSample) {
///     let _ = serde_json::to_string(sample);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct UsageSample {
    scope: AccountScope,
    identity: IdentitySnapshot,
    fetched_at: Timestamp,
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
    tertiary: Option<RateWindow>,
    extra_windows: Vec<NamedRateWindow>,
    credits: Option<CreditsSnapshot>,
    balance: Option<Money>,
    cost: Option<CostSummary>,
    cost_usage: Option<CostUsageSnapshot>,
    subscription_renews_at: Option<Timestamp>,
    subscription_expires_at: Option<Timestamp>,
    reset_credits: Option<ResetCreditsSnapshot>,
    detail_sections: Vec<DetailSection>,
    extensions: Vec<ProviderExtension>,
    chart_points: Vec<ChartPoint>,
    provenance: Vec<Provenance>,
    confidence: DataConfidence,
    status: ProviderStatus,
}

#[derive(Serialize)]
struct PrivateUsageSample<'a> {
    scope: &'a AccountScope,
    identity: PrivateIdentitySnapshot<'a>,
    fetched_at: Timestamp,
    primary: Option<&'a RateWindow>,
    secondary: Option<&'a RateWindow>,
    tertiary: Option<&'a RateWindow>,
    extra_windows: &'a [NamedRateWindow],
    credits: Option<PrivateCreditsSnapshot<'a>>,
    balance: Option<&'a Money>,
    cost: Option<&'a CostSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cost_usage: Option<PrivateCostUsageSnapshot<'a>>,
    subscription_renews_at: Option<Timestamp>,
    subscription_expires_at: Option<Timestamp>,
    reset_credits: Option<PrivateResetCreditsSnapshot<'a>>,
    detail_sections: &'a [DetailSection],
    extensions: &'a [ProviderExtension],
    chart_points: &'a [ChartPoint],
    provenance: &'a [Provenance],
    confidence: DataConfidence,
    status: &'a ProviderStatus,
}

impl<'a> From<&'a UsageSample> for PrivateUsageSample<'a> {
    fn from(sample: &'a UsageSample) -> Self {
        Self {
            scope: &sample.scope,
            identity: sample.identity.private_view(),
            fetched_at: sample.fetched_at,
            primary: sample.primary.as_ref(),
            secondary: sample.secondary.as_ref(),
            tertiary: sample.tertiary.as_ref(),
            extra_windows: &sample.extra_windows,
            credits: sample.credits.as_ref().map(CreditsSnapshot::private_view),
            balance: sample.balance.as_ref(),
            cost: sample.cost.as_ref(),
            cost_usage: sample
                .cost_usage
                .as_ref()
                .map(CostUsageSnapshot::private_view),
            subscription_renews_at: sample.subscription_renews_at,
            subscription_expires_at: sample.subscription_expires_at,
            reset_credits: sample
                .reset_credits
                .as_ref()
                .map(ResetCreditsSnapshot::private_view),
            detail_sections: &sample.detail_sections,
            extensions: &sample.extensions,
            chart_points: &sample.chart_points,
            provenance: &sample.provenance,
            confidence: sample.confidence,
            status: &sample.status,
        }
    }
}

impl UsageSample {
    /// Constructs and deterministically normalizes one provider/account sample.
    ///
    /// # Errors
    ///
    /// Returns an error when identity scope differs from `scope`, a bounded
    /// collection exceeds its limit, or an ID/timestamp key is duplicated.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: AccountScope,
        identity: IdentitySnapshot,
        fetched_at: Timestamp,
        primary: Option<RateWindow>,
        secondary: Option<RateWindow>,
        tertiary: Option<RateWindow>,
        mut extra_windows: Vec<NamedRateWindow>,
        credits: Option<CreditsSnapshot>,
        balance: Option<Money>,
        cost: Option<CostSummary>,
        subscription_renews_at: Option<Timestamp>,
        subscription_expires_at: Option<Timestamp>,
        reset_credits: Option<ResetCreditsSnapshot>,
        detail_sections: Vec<DetailSection>,
        mut extensions: Vec<ProviderExtension>,
        mut chart_points: Vec<ChartPoint>,
        provenance: Vec<Provenance>,
        confidence: DataConfidence,
        status: ProviderStatus,
    ) -> Result<Self, SnapshotError> {
        if identity.scope() != &scope
            || credits
                .as_ref()
                .is_some_and(|credits| credits.scope() != &scope)
            || reset_credits
                .as_ref()
                .is_some_and(|inventory| inventory.scope() != &scope)
        {
            return Err(SnapshotError::ScopeMismatch);
        }
        check_limit("extra windows", extra_windows.len(), MAX_EXTRA_WINDOWS)?;
        check_limit(
            "detail sections",
            detail_sections.len(),
            MAX_DETAIL_SECTIONS,
        )?;
        check_limit("chart points", chart_points.len(), MAX_CHART_POINTS)?;
        check_limit("provenance", provenance.len(), MAX_PROVENANCE_ENTRIES)?;
        check_limit(
            "provider extensions",
            extensions.len(),
            MAX_PROVIDER_EXTENSIONS,
        )?;

        extra_windows.sort_by(|left, right| left.id().cmp(right.id()));
        ensure_unique(
            extra_windows.iter().map(|window| window.id().as_str()),
            "extra window id",
        )?;
        extensions.sort_by_key(ProviderExtension::kind);
        if extensions
            .windows(2)
            .any(|items| items[0].kind == items[1].kind)
        {
            return Err(SnapshotError::Duplicate("provider extension kind"));
        }
        chart_points.sort_by_key(ChartPoint::at);
        if chart_points
            .windows(2)
            .any(|points| points[0].at == points[1].at)
        {
            return Err(SnapshotError::Duplicate("chart timestamp"));
        }

        Ok(Self {
            scope,
            identity,
            fetched_at,
            primary,
            secondary,
            tertiary,
            extra_windows,
            credits,
            balance,
            cost,
            cost_usage: None,
            subscription_renews_at,
            subscription_expires_at,
            reset_credits,
            detail_sections,
            extensions,
            chart_points,
            provenance,
            confidence,
            status,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AccountScope {
        &self.scope
    }

    #[must_use]
    pub const fn identity(&self) -> &IdentitySnapshot {
        &self.identity
    }

    #[must_use]
    pub const fn fetched_at(&self) -> Timestamp {
        self.fetched_at
    }

    #[must_use]
    pub const fn primary(&self) -> Option<&RateWindow> {
        self.primary.as_ref()
    }

    #[must_use]
    pub const fn secondary(&self) -> Option<&RateWindow> {
        self.secondary.as_ref()
    }

    #[must_use]
    pub const fn tertiary(&self) -> Option<&RateWindow> {
        self.tertiary.as_ref()
    }

    #[must_use]
    pub fn extra_windows(&self) -> &[NamedRateWindow] {
        &self.extra_windows
    }

    #[must_use]
    pub const fn cost(&self) -> Option<&CostSummary> {
        self.cost.as_ref()
    }

    /// Returns the typed token-cost and history snapshot, when the provider or
    /// local scanner supplied one.
    #[must_use]
    pub const fn cost_usage(&self) -> Option<&CostUsageSnapshot> {
        self.cost_usage.as_ref()
    }

    /// Attaches an already validated typed cost/history snapshot.
    #[must_use]
    pub fn with_cost_usage(mut self, cost_usage: CostUsageSnapshot) -> Self {
        self.cost_usage = Some(cost_usage);
        self
    }

    #[must_use]
    pub const fn credits(&self) -> Option<&CreditsSnapshot> {
        self.credits.as_ref()
    }

    #[must_use]
    pub const fn balance(&self) -> Option<&Money> {
        self.balance.as_ref()
    }

    #[must_use]
    pub const fn subscription_renews_at(&self) -> Option<Timestamp> {
        self.subscription_renews_at
    }

    #[must_use]
    pub const fn subscription_expires_at(&self) -> Option<Timestamp> {
        self.subscription_expires_at
    }

    /// Attaches inventory only when it belongs to this exact account scope.
    ///
    /// # Errors
    /// Returns an error if the inventory belongs to another account.
    pub fn with_reset_credits(
        mut self,
        inventory: ResetCreditsSnapshot,
    ) -> Result<Self, SnapshotError> {
        if inventory.scope() != &self.scope {
            return Err(SnapshotError::ScopeMismatch);
        }
        self.reset_credits = Some(inventory);
        Ok(self)
    }

    #[must_use]
    pub const fn reset_credits(&self) -> Option<&ResetCreditsSnapshot> {
        self.reset_credits.as_ref()
    }

    #[must_use]
    pub fn available_reset_credits(&self, now: Timestamp) -> Vec<&ResetCredit> {
        self.reset_credits
            .as_ref()
            .map_or_else(Vec::new, |inventory| inventory.available_credits_at(now))
    }

    #[must_use]
    pub fn detail_sections(&self) -> &[DetailSection] {
        &self.detail_sections
    }

    #[must_use]
    pub fn extensions(&self) -> &[ProviderExtension] {
        &self.extensions
    }

    #[must_use]
    pub fn chart_points(&self) -> &[ChartPoint] {
        &self.chart_points
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }

    #[must_use]
    pub const fn confidence(&self) -> DataConfidence {
        self.confidence
    }

    #[must_use]
    pub const fn status(&self) -> &ProviderStatus {
        &self.status
    }

    /// Backfills missing reset metadata from an exact-scope cached sample.
    ///
    /// Fresh usage, regeneration, and synthetic-placeholder values always win;
    /// only a still-future cached reset and its duration/description can fill a
    /// missing value.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::ScopeMismatch`] unless provider, instance, and
    /// account identity all match.
    pub fn backfilling_reset_times(
        &self,
        cached: &Self,
        now: Timestamp,
    ) -> Result<Self, SnapshotError> {
        if self.scope != cached.scope {
            return Err(SnapshotError::ScopeMismatch);
        }
        let mut result = self.clone();
        result.primary = self
            .primary
            .as_ref()
            .map(|fresh| fresh.backfilling_reset_time(cached.primary.as_ref(), now));
        result.secondary = self
            .secondary
            .as_ref()
            .map(|fresh| fresh.backfilling_reset_time(cached.secondary.as_ref(), now));
        result.tertiary = self
            .tertiary
            .as_ref()
            .map(|fresh| fresh.backfilling_reset_time(cached.tertiary.as_ref(), now));
        result.extra_windows = self
            .extra_windows
            .iter()
            .map(|fresh| {
                let cached_window = cached
                    .extra_windows
                    .iter()
                    .find(|candidate| candidate.id() == fresh.id())
                    .map(NamedRateWindow::window);
                NamedRateWindow::new(
                    fresh.id().clone(),
                    fresh.title().clone(),
                    fresh.window().backfilling_reset_time(cached_window, now),
                )
            })
            .collect();
        Ok(result)
    }

    pub(crate) fn redacted(&self, scope: &AccountScope) -> Self {
        Self {
            scope: scope.clone(),
            identity: IdentitySnapshot::redacted_for_scope(scope.clone()),
            fetched_at: self.fetched_at,
            primary: self
                .primary
                .as_ref()
                .map(RateWindow::without_personal_information),
            secondary: self
                .secondary
                .as_ref()
                .map(RateWindow::without_personal_information),
            tertiary: self
                .tertiary
                .as_ref()
                .map(RateWindow::without_personal_information),
            extra_windows: NamedRateWindow::public_projection(&self.extra_windows),
            credits: self
                .credits
                .as_ref()
                .map(|credits| credits.without_personal_information(scope.clone())),
            balance: self.balance.clone(),
            cost: self
                .cost
                .as_ref()
                .map(CostSummary::without_personal_information),
            cost_usage: self
                .cost_usage
                .as_ref()
                .map(CostUsageSnapshot::without_personal_information),
            subscription_renews_at: self.subscription_renews_at,
            subscription_expires_at: self.subscription_expires_at,
            reset_credits: self
                .reset_credits
                .as_ref()
                .map(|inventory| inventory.without_personal_information(scope)),
            detail_sections: Vec::new(),
            extensions: Vec::new(),
            chart_points: self.chart_points.clone(),
            provenance: Vec::new(),
            confidence: self.confidence,
            status: self.status.without_personal_information(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageSampleRepr {
    scope: AccountScope,
    identity: IdentitySnapshot,
    fetched_at: Timestamp,
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
    tertiary: Option<RateWindow>,
    extra_windows: Vec<NamedRateWindow>,
    credits: Option<CreditsSnapshot>,
    balance: Option<Money>,
    cost: Option<CostSummary>,
    #[serde(default)]
    cost_usage: Option<CostUsageSnapshot>,
    subscription_renews_at: Option<Timestamp>,
    subscription_expires_at: Option<Timestamp>,
    reset_credits: Option<ResetCreditsSnapshot>,
    detail_sections: Vec<DetailSection>,
    extensions: Vec<ProviderExtension>,
    chart_points: Vec<ChartPoint>,
    provenance: Vec<Provenance>,
    confidence: DataConfidence,
    status: ProviderStatus,
}

impl<'de> Deserialize<'de> for UsageSample {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = UsageSampleRepr::deserialize(deserializer)?;
        let cost_usage = repr.cost_usage;
        let sample = Self::new(
            repr.scope,
            repr.identity,
            repr.fetched_at,
            repr.primary,
            repr.secondary,
            repr.tertiary,
            repr.extra_windows,
            repr.credits,
            repr.balance,
            repr.cost,
            repr.subscription_renews_at,
            repr.subscription_expires_at,
            repr.reset_credits,
            repr.detail_sections,
            repr.extensions,
            repr.chart_points,
            repr.provenance,
            repr.confidence,
            repr.status,
        )
        .map_err(de::Error::custom)?;
        Ok(match cost_usage {
            Some(cost_usage) => sample.with_cost_usage(cost_usage),
            None => sample,
        })
    }
}

/// A normalized provider state whose ready variant can only be constructed
/// after validating freshness/error invariants.
///
/// ```compile_fail
/// # use oab_domain::ProviderSnapshot;
/// fn cannot_serialize_private_state(snapshot: &ProviderSnapshot) {
///     let _ = serde_json::to_string(snapshot);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderSnapshot {
    Loading(LoadingSnapshot),
    Ready(ReadySnapshot),
    Unavailable(UnavailableSnapshot),
}

/// A provider/account scope for which the initial fetch is still pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadingSnapshot {
    scope: AccountScope,
}

/// A validated last-known-good sample plus its current refresh state.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadySnapshot {
    last_known_good: Box<UsageSample>,
    freshness: Freshness,
    refresh: RefreshPhase,
    error: Option<ClassifiedError>,
}

/// A provider/account scope with no sample that can safely be displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnavailableSnapshot {
    scope: AccountScope,
    error: ClassifiedError,
}

impl ProviderSnapshot {
    #[must_use]
    pub const fn loading(scope: AccountScope) -> Self {
        Self::Loading(LoadingSnapshot { scope })
    }

    /// Creates a validated ready snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if stale time precedes the sample fetch time or an
    /// error is paired with a non-stale snapshot.
    pub fn ready(
        last_known_good: UsageSample,
        freshness: Freshness,
        refresh: RefreshPhase,
        error: Option<ClassifiedError>,
    ) -> Result<Self, SnapshotError> {
        if let Freshness::Stale { since } = freshness
            && since < last_known_good.fetched_at()
        {
            return Err(SnapshotError::StaleBeforeFetch);
        }
        if error.is_some() && !matches!(freshness, Freshness::Stale { .. }) {
            return Err(SnapshotError::ErrorRequiresStaleSnapshot);
        }
        Ok(Self::Ready(ReadySnapshot {
            last_known_good: Box::new(last_known_good),
            freshness,
            refresh,
            error,
        }))
    }

    #[must_use]
    pub const fn unavailable(scope: AccountScope, error: ClassifiedError) -> Self {
        Self::Unavailable(UnavailableSnapshot { scope, error })
    }

    #[must_use]
    pub fn scope(&self) -> &AccountScope {
        match self {
            Self::Loading(snapshot) => &snapshot.scope,
            Self::Ready(snapshot) => snapshot.last_known_good.scope(),
            Self::Unavailable(snapshot) => &snapshot.scope,
        }
    }

    #[must_use]
    pub fn last_known_good(&self) -> Option<&UsageSample> {
        match self {
            Self::Ready(snapshot) => Some(snapshot.last_known_good.as_ref()),
            Self::Loading(_) | Self::Unavailable(_) => None,
        }
    }

    #[must_use]
    pub const fn error(&self) -> Option<&ClassifiedError> {
        match self {
            Self::Ready(snapshot) => snapshot.error.as_ref(),
            Self::Unavailable(snapshot) => Some(&snapshot.error),
            Self::Loading(_) => None,
        }
    }

    #[must_use]
    pub const fn freshness(&self) -> Option<Freshness> {
        match self {
            Self::Ready(snapshot) => Some(snapshot.freshness),
            Self::Loading(_) | Self::Unavailable(_) => None,
        }
    }

    #[must_use]
    pub const fn refresh_phase(&self) -> Option<RefreshPhase> {
        match self {
            Self::Ready(snapshot) => Some(snapshot.refresh),
            Self::Loading(_) | Self::Unavailable(_) => None,
        }
    }

    /// Overlays a classified refresh error without modifying cached data.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is a ready snapshot and `scope` exactly
    /// matches its provider, instance, and account routing scope.
    pub fn with_error_overlay(
        &self,
        scope: &AccountScope,
        error: ClassifiedError,
        stale_since: Timestamp,
    ) -> Result<Self, SnapshotError> {
        let Self::Ready(snapshot) = self else {
            return Err(SnapshotError::NoLastKnownGood);
        };
        if snapshot.last_known_good.scope() != scope {
            return Err(SnapshotError::ScopeMismatch);
        }
        Self::ready(
            snapshot.last_known_good.as_ref().clone(),
            Freshness::Stale { since: stale_since },
            RefreshPhase::Idle,
            Some(error),
        )
    }

    pub(crate) fn redacted(&self, privacy_key: &PrivacyKey) -> Self {
        let scope = self.scope().public_projection(privacy_key);
        match self {
            Self::Loading(_) => Self::loading(scope),
            Self::Ready(snapshot) => Self::ready(
                snapshot.last_known_good.redacted(&scope),
                snapshot.freshness,
                snapshot.refresh,
                snapshot
                    .error
                    .as_ref()
                    .map(ClassifiedError::public_projection),
            )
            .expect("redaction preserves ready-snapshot invariants"),
            Self::Unavailable(snapshot) => {
                Self::unavailable(scope, snapshot.error.public_projection())
            }
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ProviderSnapshotRef<'a> {
    Loading {
        scope: &'a AccountScope,
    },
    Ready {
        last_known_good: Box<PrivateUsageSample<'a>>,
        freshness: Freshness,
        refresh: RefreshPhase,
        error: Option<&'a ClassifiedError>,
    },
    Unavailable {
        scope: &'a AccountScope,
        error: &'a ClassifiedError,
    },
}

struct PrivateProviderSnapshot<'a>(&'a ProviderSnapshot);

impl Serialize for PrivateProviderSnapshot<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            ProviderSnapshot::Loading(snapshot) => ProviderSnapshotRef::Loading {
                scope: &snapshot.scope,
            },
            ProviderSnapshot::Ready(snapshot) => ProviderSnapshotRef::Ready {
                last_known_good: Box::new(PrivateUsageSample::from(
                    snapshot.last_known_good.as_ref(),
                )),
                freshness: snapshot.freshness,
                refresh: snapshot.refresh,
                error: snapshot.error.as_ref(),
            },
            ProviderSnapshot::Unavailable(snapshot) => ProviderSnapshotRef::Unavailable {
                scope: &snapshot.scope,
                error: &snapshot.error,
            },
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ProviderSnapshotRepr {
    Loading {
        scope: AccountScope,
    },
    Ready {
        last_known_good: Box<UsageSample>,
        freshness: Freshness,
        refresh: RefreshPhase,
        error: Option<ClassifiedError>,
    },
    Unavailable {
        scope: AccountScope,
        error: ClassifiedError,
    },
}

impl<'de> Deserialize<'de> for ProviderSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ProviderSnapshotRepr::deserialize(deserializer)? {
            ProviderSnapshotRepr::Loading { scope } => Ok(Self::loading(scope)),
            ProviderSnapshotRepr::Ready {
                last_known_good,
                freshness,
                refresh,
                error,
            } => {
                Self::ready(*last_known_good, freshness, refresh, error).map_err(de::Error::custom)
            }
            ProviderSnapshotRepr::Unavailable { scope, error } => {
                Ok(Self::unavailable(scope, error))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchemaVersion1;

impl Serialize for SchemaVersion1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u8::deserialize(deserializer)?;
        if version == 1 {
            Ok(Self)
        } else {
            Err(de::Error::custom(format!(
                "unsupported snapshot schema version: {version}"
            )))
        }
    }
}

/// Version-one private snapshot aggregate.
///
/// ```compile_fail
/// # use oab_domain::SnapshotEnvelopeV1;
/// fn cannot_serialize_private_envelope(envelope: &SnapshotEnvelopeV1) {
///     let _ = serde_json::to_string(envelope);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotEnvelopeV1 {
    schema_version: SchemaVersion1,
    generated_at: Timestamp,
    snapshots: Vec<ProviderSnapshot>,
}

impl SnapshotEnvelopeV1 {
    /// Creates a deterministic version-one envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when too many snapshots are supplied or two snapshots
    /// share the same exact account scope.
    pub fn new(
        generated_at: Timestamp,
        mut snapshots: Vec<ProviderSnapshot>,
    ) -> Result<Self, SnapshotError> {
        check_limit("snapshots", snapshots.len(), MAX_SNAPSHOTS_PER_ENVELOPE)?;
        snapshots.sort_by(|left, right| left.scope().cmp(right.scope()));
        if snapshots
            .windows(2)
            .any(|items| items[0].scope() == items[1].scope())
        {
            return Err(SnapshotError::Duplicate("account scope"));
        }
        Ok(Self {
            schema_version: SchemaVersion1,
            generated_at,
            snapshots,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        match self.schema_version {
            SchemaVersion1 => 1,
        }
    }

    #[must_use]
    pub const fn generated_at(&self) -> Timestamp {
        self.generated_at
    }

    #[must_use]
    pub fn snapshots(&self) -> &[ProviderSnapshot] {
        &self.snapshots
    }

    /// Borrows this aggregate for an explicitly private persistence encoding.
    ///
    /// Public, hook, server, diagnostics, export, and fleet boundaries must use
    /// [`crate::ProjectedSnapshotEnvelope`] instead.
    #[must_use]
    pub const fn private_view(&self) -> PrivateSnapshotEnvelope<'_> {
        PrivateSnapshotEnvelope(self)
    }

    pub(crate) const fn redacted_view(&self) -> RedactedSnapshotEnvelope<'_> {
        RedactedSnapshotEnvelope(self)
    }

    pub(crate) fn redacted(&self, privacy_key: &PrivacyKey) -> Self {
        Self {
            schema_version: SchemaVersion1,
            generated_at: self.generated_at,
            snapshots: self
                .snapshots
                .iter()
                .map(|snapshot| snapshot.redacted(privacy_key))
                .collect(),
        }
    }
}

/// An explicitly private serialization view for trusted local persistence.
///
/// The domain aggregate itself deliberately does not implement [`Serialize`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PrivateSnapshotEnvelope<'a>(&'a SnapshotEnvelopeV1);

impl<'a> PrivateSnapshotEnvelope<'a> {
    pub(crate) const fn envelope(self) -> &'a SnapshotEnvelopeV1 {
        self.0
    }
}

pub(crate) struct RedactedSnapshotEnvelope<'a>(&'a SnapshotEnvelopeV1);

#[derive(Serialize)]
struct SnapshotEnvelopeRef<'a> {
    schema_version: SchemaVersion1,
    generated_at: Timestamp,
    snapshots: Vec<PrivateProviderSnapshot<'a>>,
}

impl Serialize for PrivateSnapshotEnvelope<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SnapshotEnvelopeRef {
            schema_version: self.0.schema_version,
            generated_at: self.0.generated_at,
            snapshots: self
                .0
                .snapshots
                .iter()
                .map(PrivateProviderSnapshot)
                .collect(),
        }
        .serialize(serializer)
    }
}

impl Serialize for RedactedSnapshotEnvelope<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct RedactedSnapshotEnvelopeRef<'a> {
            schema_version: SchemaVersion1,
            privacy: &'static str,
            generated_at: Timestamp,
            snapshots: Vec<PrivateProviderSnapshot<'a>>,
        }

        RedactedSnapshotEnvelopeRef {
            schema_version: self.0.schema_version,
            privacy: "redacted",
            generated_at: self.0.generated_at,
            snapshots: self
                .0
                .snapshots
                .iter()
                .map(PrivateProviderSnapshot)
                .collect(),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotEnvelopeRepr {
    schema_version: SchemaVersion1,
    generated_at: Timestamp,
    snapshots: Vec<ProviderSnapshot>,
}

impl<'de> Deserialize<'de> for SnapshotEnvelopeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = SnapshotEnvelopeRepr::deserialize(deserializer)?;
        let _ = repr.schema_version;
        Self::new(repr.generated_at, repr.snapshots).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SnapshotError {
    #[error("provider, instance, and account scope must match exactly")]
    ScopeMismatch,
    #[error("snapshot state has no last-known-good sample")]
    NoLastKnownGood,
    #[error("{field} exceeds the maximum of {maximum}")]
    LimitExceeded { field: &'static str, maximum: usize },
    #[error("duplicate {0}")]
    Duplicate(&'static str),
    #[error("cost period end must be later than its start")]
    InvalidPeriod,
    #[error("cost period start and end must either both be present or both be absent")]
    IncompletePeriod,
    #[error("reset-credit timestamps are chronologically inconsistent")]
    InvalidResetCreditTimeline,
    #[error("reset-credit status is inconsistent with its redemption timestamps")]
    InvalidResetCreditState,
    #[error("provider-reported available reset-credit count exceeds its maximum")]
    ReportedResetCreditCountTooLarge,
    #[error("stale timestamp cannot precede the fetched sample")]
    StaleBeforeFetch,
    #[error("a ready snapshot with an error must be stale")]
    ErrorRequiresStaleSnapshot,
    #[error(transparent)]
    InvalidText(#[from] crate::text::BoundedTextError),
}

fn check_limit(field: &'static str, actual: usize, maximum: usize) -> Result<(), SnapshotError> {
    if actual > maximum {
        Err(SnapshotError::LimitExceeded { field, maximum })
    } else {
        Ok(())
    }
}

fn ensure_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    field: &'static str,
) -> Result<(), SnapshotError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().all(|value| seen.insert(value)) {
        Ok(())
    } else {
        Err(SnapshotError::Duplicate(field))
    }
}
