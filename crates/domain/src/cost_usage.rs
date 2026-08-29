use std::collections::BTreeSet;

use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;
use time::{Date, Month};

use crate::money::{CostUnit, ExactDecimal, ProviderUnit};
use crate::snapshot::CostProvenance;
use crate::text::{BoundedText, BoundedTextError};
use crate::timestamp::Timestamp;

pub const MAX_COST_HISTORY_DAYS: u16 = 365;
pub const MAX_COST_DAILY_BUCKETS: usize = 365;
pub const MAX_COST_MODELS: usize = 128;
pub const MAX_COST_LINE_ITEMS: usize = 128;
pub const MAX_COST_PROJECTS: usize = 128;
pub const MAX_COST_PROJECT_SOURCES: usize = 32;
pub const MAX_COST_SESSIONS: usize = 512;
pub const MAX_COST_HOURLY_BUCKETS: usize = 24 * MAX_COST_HISTORY_DAYS as usize;

const COST_LABEL_BYTES: usize = 160;
const COST_PATH_BYTES: usize = 1024;
const CREDENTIAL_FINGERPRINT_BYTES: usize = 160;

/// Optional token classes. `None` means the source did not establish that
/// class; it is deliberately distinct from a measured zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct CostUsageTokenMix {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_creation_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
}

impl CostUsageTokenMix {
    #[must_use]
    pub const fn new(
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cache_read_tokens: Option<u64>,
        cache_creation_tokens: Option<u64>,
        reasoning_tokens: Option<u64>,
    ) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_creation_tokens,
            reasoning_tokens,
        }
    }

    #[must_use]
    pub const fn input_tokens(self) -> Option<u64> {
        self.input_tokens
    }

    #[must_use]
    pub const fn output_tokens(self) -> Option<u64> {
        self.output_tokens
    }

    #[must_use]
    pub const fn cache_read_tokens(self) -> Option<u64> {
        self.cache_read_tokens
    }

    #[must_use]
    pub const fn cache_creation_tokens(self) -> Option<u64> {
        self.cache_creation_tokens
    }

    #[must_use]
    pub const fn reasoning_tokens(self) -> Option<u64> {
        self.reasoning_tokens
    }
}

/// Independent request-coverage categories for a cost window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CostUsageCoverage {
    priced: u64,
    unpriced: u64,
    unmetered: u64,
    estimated: u64,
}

impl CostUsageCoverage {
    /// Creates coverage counts whose total is representable.
    ///
    /// # Errors
    ///
    /// Returns an error if summing the four categories overflows `u64`.
    pub fn new(
        priced: u64,
        unpriced: u64,
        unmetered: u64,
        estimated: u64,
    ) -> Result<Self, CostUsageError> {
        let result = Self {
            priced,
            unpriced,
            unmetered,
            estimated,
        };
        result.total().ok_or(CostUsageError::CoverageOverflow)?;
        Ok(result)
    }

    #[must_use]
    pub const fn priced(self) -> u64 {
        self.priced
    }

    #[must_use]
    pub const fn unpriced(self) -> u64 {
        self.unpriced
    }

    #[must_use]
    pub const fn unmetered(self) -> u64 {
        self.unmetered
    }

    #[must_use]
    pub const fn estimated(self) -> u64 {
        self.estimated
    }

    #[must_use]
    pub fn total(self) -> Option<u64> {
        self.priced
            .checked_add(self.unpriced)?
            .checked_add(self.unmetered)?
            .checked_add(self.estimated)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageCoverageRepr {
    priced: u64,
    unpriced: u64,
    unmetered: u64,
    estimated: u64,
}

impl<'de> Deserialize<'de> for CostUsageCoverage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageCoverageRepr::deserialize(deserializer)?;
        Self::new(repr.priced, repr.unpriced, repr.unmetered, repr.estimated)
            .map_err(de::Error::custom)
    }
}

/// Reusable optional numeric mechanics for a cost window or breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostUsageMetrics {
    token_mix: CostUsageTokenMix,
    total_tokens: Option<u64>,
    request_count: Option<u64>,
    amount: Option<ExactDecimal>,
    coverage: CostUsageCoverage,
}

impl CostUsageMetrics {
    /// Creates one set of usage metrics without collapsing unknown values to
    /// zero.
    ///
    /// # Errors
    ///
    /// Returns an error for a negative amount or coverage counts larger than a
    /// known request count.
    pub fn new(
        token_mix: CostUsageTokenMix,
        total_tokens: Option<u64>,
        request_count: Option<u64>,
        amount: Option<ExactDecimal>,
        coverage: CostUsageCoverage,
    ) -> Result<Self, CostUsageError> {
        ensure_nonnegative("usage amount", amount)?;
        if request_count.is_some_and(|requests| {
            coverage
                .total()
                .is_some_and(|coverage_total| coverage_total > requests)
        }) {
            return Err(CostUsageError::CoverageExceedsRequests);
        }
        Ok(Self {
            token_mix,
            total_tokens,
            request_count,
            amount,
            coverage,
        })
    }

    #[must_use]
    pub const fn token_mix(&self) -> CostUsageTokenMix {
        self.token_mix
    }

    #[must_use]
    pub const fn total_tokens(&self) -> Option<u64> {
        self.total_tokens
    }

    #[must_use]
    pub const fn request_count(&self) -> Option<u64> {
        self.request_count
    }

    #[must_use]
    pub const fn amount(&self) -> Option<ExactDecimal> {
        self.amount
    }

    #[must_use]
    pub const fn coverage(&self) -> CostUsageCoverage {
        self.coverage
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageMetricsRepr {
    token_mix: CostUsageTokenMix,
    total_tokens: Option<u64>,
    request_count: Option<u64>,
    amount: Option<ExactDecimal>,
    coverage: CostUsageCoverage,
}

impl<'de> Deserialize<'de> for CostUsageMetrics {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageMetricsRepr::deserialize(deserializer)?;
        Self::new(
            repr.token_mix,
            repr.total_tokens,
            repr.request_count,
            repr.amount,
            repr.coverage,
        )
        .map_err(de::Error::custom)
    }
}

/// A provider bucket's exact half-open time interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CostUsageInterval {
    start: Timestamp,
    end: Timestamp,
}

impl CostUsageInterval {
    /// Creates a non-empty half-open interval.
    ///
    /// # Errors
    ///
    /// Returns an error unless `end` is strictly later than `start`.
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, CostUsageError> {
        if end <= start {
            return Err(CostUsageError::InvalidInterval);
        }
        Ok(Self { start, end })
    }

    #[must_use]
    pub const fn start(self) -> Timestamp {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> Timestamp {
        self.end
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageIntervalRepr {
    start: Timestamp,
    end: Timestamp,
}

impl<'de> Deserialize<'de> for CostUsageInterval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageIntervalRepr::deserialize(deserializer)?;
        Self::new(repr.start, repr.end).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostUsageLineItem {
    name: BoundedText<COST_LABEL_BYTES>,
    amount: ExactDecimal,
}

impl CostUsageLineItem {
    /// Creates a named provider cost line item.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid text or a negative amount.
    pub fn new(name: impl AsRef<str>, amount: ExactDecimal) -> Result<Self, CostUsageError> {
        ensure_nonnegative("line-item amount", Some(amount))?;
        Ok(Self {
            name: BoundedText::new(name)?,
            amount,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[must_use]
    pub const fn amount(&self) -> ExactDecimal {
        self.amount
    }

    fn without_personal_information(&self, ordinal: usize) -> Self {
        Self {
            name: public_ordinal("line-item", ordinal),
            amount: self.amount,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageLineItemRepr {
    name: String,
    amount: ExactDecimal,
}

impl<'de> Deserialize<'de> for CostUsageLineItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageLineItemRepr::deserialize(deserializer)?;
        Self::new(repr.name, repr.amount).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostUsageModelBreakdown {
    name: BoundedText<COST_LABEL_BYTES>,
    metrics: CostUsageMetrics,
    standard_amount: Option<ExactDecimal>,
    priority_amount: Option<ExactDecimal>,
    standard_tokens: Option<u64>,
    priority_tokens: Option<u64>,
}

impl CostUsageModelBreakdown {
    /// Creates a per-model breakdown, including optional service-tier splits.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid text or a negative amount.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl AsRef<str>,
        metrics: CostUsageMetrics,
        standard_amount: Option<ExactDecimal>,
        priority_amount: Option<ExactDecimal>,
        standard_tokens: Option<u64>,
        priority_tokens: Option<u64>,
    ) -> Result<Self, CostUsageError> {
        ensure_nonnegative("standard amount", standard_amount)?;
        ensure_nonnegative("priority amount", priority_amount)?;
        Ok(Self {
            name: BoundedText::new(name)?,
            metrics,
            standard_amount,
            priority_amount,
            standard_tokens,
            priority_tokens,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[must_use]
    pub const fn metrics(&self) -> &CostUsageMetrics {
        &self.metrics
    }

    #[must_use]
    pub const fn standard_amount(&self) -> Option<ExactDecimal> {
        self.standard_amount
    }

    #[must_use]
    pub const fn priority_amount(&self) -> Option<ExactDecimal> {
        self.priority_amount
    }

    #[must_use]
    pub const fn standard_tokens(&self) -> Option<u64> {
        self.standard_tokens
    }

    #[must_use]
    pub const fn priority_tokens(&self) -> Option<u64> {
        self.priority_tokens
    }

    fn without_personal_information(&self, ordinal: usize) -> Self {
        let mut result = self.clone();
        result.name = public_ordinal("model", ordinal);
        result
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageModelBreakdownRepr {
    name: String,
    metrics: CostUsageMetrics,
    standard_amount: Option<ExactDecimal>,
    priority_amount: Option<ExactDecimal>,
    standard_tokens: Option<u64>,
    priority_tokens: Option<u64>,
}

impl<'de> Deserialize<'de> for CostUsageModelBreakdown {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageModelBreakdownRepr::deserialize(deserializer)?;
        Self::new(
            repr.name,
            repr.metrics,
            repr.standard_amount,
            repr.priority_amount,
            repr.standard_tokens,
            repr.priority_tokens,
        )
        .map_err(de::Error::custom)
    }
}

/// One normalized local-day record. `OpenAI` Admin data additionally populates
/// `interval`, `line_items`, and complete per-model request/token mechanics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostUsageDailyBucket {
    day: BoundedText<10>,
    interval: Option<CostUsageInterval>,
    metrics: CostUsageMetrics,
    models_used: Vec<BoundedText<COST_LABEL_BYTES>>,
    models: Vec<CostUsageModelBreakdown>,
    line_items: Vec<CostUsageLineItem>,
}

impl CostUsageDailyBucket {
    /// Creates and canonically sorts one daily cost bucket.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-calendar `YYYY-MM-DD` day, invalid labels,
    /// oversized collections, or duplicate model/line-item names.
    pub fn new(
        day: impl AsRef<str>,
        interval: Option<CostUsageInterval>,
        metrics: CostUsageMetrics,
        models_used: Vec<String>,
        mut models: Vec<CostUsageModelBreakdown>,
        mut line_items: Vec<CostUsageLineItem>,
    ) -> Result<Self, CostUsageError> {
        let day = validate_day(day.as_ref())?;
        check_limit("models used", models_used.len(), MAX_COST_MODELS)?;
        check_limit("model breakdowns", models.len(), MAX_COST_MODELS)?;
        check_limit("line items", line_items.len(), MAX_COST_LINE_ITEMS)?;

        let mut models_used = models_used
            .into_iter()
            .map(BoundedText::new)
            .collect::<Result<Vec<BoundedText<COST_LABEL_BYTES>>, _>>()?;
        models_used.sort();
        ensure_unique(models_used.iter().map(BoundedText::as_str), "model label")?;
        models.sort_by(|left, right| left.name.cmp(&right.name));
        ensure_unique(models.iter().map(CostUsageModelBreakdown::name), "model")?;
        line_items.sort_by(|left, right| left.name.cmp(&right.name));
        ensure_unique(line_items.iter().map(CostUsageLineItem::name), "line item")?;

        Ok(Self {
            day,
            interval,
            metrics,
            models_used,
            models,
            line_items,
        })
    }

    #[must_use]
    pub fn day(&self) -> &str {
        self.day.as_str()
    }

    #[must_use]
    pub const fn interval(&self) -> Option<CostUsageInterval> {
        self.interval
    }

    #[must_use]
    pub const fn metrics(&self) -> &CostUsageMetrics {
        &self.metrics
    }

    #[must_use]
    pub fn models_used(&self) -> impl ExactSizeIterator<Item = &str> {
        self.models_used.iter().map(BoundedText::as_str)
    }

    #[must_use]
    pub fn models(&self) -> &[CostUsageModelBreakdown] {
        &self.models
    }

    #[must_use]
    pub fn line_items(&self) -> &[CostUsageLineItem] {
        &self.line_items
    }

    fn without_personal_information(&self) -> Self {
        Self {
            day: self.day.clone(),
            interval: self.interval,
            metrics: self.metrics.clone(),
            models_used: self
                .models_used
                .iter()
                .enumerate()
                .map(|(ordinal, _)| public_ordinal("model", ordinal))
                .collect(),
            models: self
                .models
                .iter()
                .enumerate()
                .map(|(ordinal, model)| model.without_personal_information(ordinal))
                .collect(),
            line_items: self
                .line_items
                .iter()
                .enumerate()
                .map(|(ordinal, item)| item.without_personal_information(ordinal))
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageDailyBucketRepr {
    day: String,
    interval: Option<CostUsageInterval>,
    metrics: CostUsageMetrics,
    models_used: Vec<String>,
    models: Vec<CostUsageModelBreakdown>,
    line_items: Vec<CostUsageLineItem>,
}

impl<'de> Deserialize<'de> for CostUsageDailyBucket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageDailyBucketRepr::deserialize(deserializer)?;
        Self::new(
            repr.day,
            repr.interval,
            repr.metrics,
            repr.models_used,
            repr.models,
            repr.line_items,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostUsageProjectSourceBreakdown {
    name: BoundedText<COST_LABEL_BYTES>,
    path: Option<BoundedText<COST_PATH_BYTES>>,
    metrics: CostUsageMetrics,
    daily: Vec<CostUsageDailyBucket>,
    models: Vec<CostUsageModelBreakdown>,
}

impl CostUsageProjectSourceBreakdown {
    /// Creates a typed source contribution within a project.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid personal labels/paths, oversized history,
    /// or duplicate day/model keys.
    pub fn new(
        name: impl AsRef<str>,
        path: Option<String>,
        metrics: CostUsageMetrics,
        mut daily: Vec<CostUsageDailyBucket>,
        mut models: Vec<CostUsageModelBreakdown>,
    ) -> Result<Self, CostUsageError> {
        normalize_daily(&mut daily)?;
        normalize_models(&mut models)?;
        Ok(Self {
            name: BoundedText::new(name)?,
            path: path.map(BoundedText::new).transpose()?,
            metrics,
            daily,
            models,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub const fn metrics(&self) -> &CostUsageMetrics {
        &self.metrics
    }

    #[must_use]
    pub fn daily(&self) -> &[CostUsageDailyBucket] {
        &self.daily
    }

    #[must_use]
    pub fn models(&self) -> &[CostUsageModelBreakdown] {
        &self.models
    }

    fn sort_key(&self) -> (&str, Option<&str>) {
        (self.name(), self.path())
    }

    fn without_personal_information(&self, ordinal: usize) -> Self {
        Self {
            name: public_ordinal("source", ordinal),
            path: None,
            metrics: self.metrics.clone(),
            daily: self
                .daily
                .iter()
                .map(CostUsageDailyBucket::without_personal_information)
                .collect(),
            models: self
                .models
                .iter()
                .enumerate()
                .map(|(model_ordinal, model)| model.without_personal_information(model_ordinal))
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageProjectSourceBreakdownRepr {
    name: String,
    path: Option<String>,
    metrics: CostUsageMetrics,
    daily: Vec<CostUsageDailyBucket>,
    models: Vec<CostUsageModelBreakdown>,
}

impl<'de> Deserialize<'de> for CostUsageProjectSourceBreakdown {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageProjectSourceBreakdownRepr::deserialize(deserializer)?;
        Self::new(repr.name, repr.path, repr.metrics, repr.daily, repr.models)
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostUsageProjectBreakdown {
    name: BoundedText<COST_LABEL_BYTES>,
    path: Option<BoundedText<COST_PATH_BYTES>>,
    metrics: CostUsageMetrics,
    daily: Vec<CostUsageDailyBucket>,
    models: Vec<CostUsageModelBreakdown>,
    sources: Vec<CostUsageProjectSourceBreakdown>,
}

impl CostUsageProjectBreakdown {
    /// Creates a project-level usage breakdown with typed source ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid personal labels/paths, oversized
    /// collections, or duplicate day/model/source keys.
    pub fn new(
        name: impl AsRef<str>,
        path: Option<String>,
        metrics: CostUsageMetrics,
        mut daily: Vec<CostUsageDailyBucket>,
        mut models: Vec<CostUsageModelBreakdown>,
        mut sources: Vec<CostUsageProjectSourceBreakdown>,
    ) -> Result<Self, CostUsageError> {
        normalize_daily(&mut daily)?;
        normalize_models(&mut models)?;
        check_limit("project sources", sources.len(), MAX_COST_PROJECT_SOURCES)?;
        sources.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        if sources
            .windows(2)
            .any(|items| items[0].sort_key() == items[1].sort_key())
        {
            return Err(CostUsageError::Duplicate("project source"));
        }
        Ok(Self {
            name: BoundedText::new(name)?,
            path: path.map(BoundedText::new).transpose()?,
            metrics,
            daily,
            models,
            sources,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub const fn metrics(&self) -> &CostUsageMetrics {
        &self.metrics
    }

    #[must_use]
    pub fn daily(&self) -> &[CostUsageDailyBucket] {
        &self.daily
    }

    #[must_use]
    pub fn models(&self) -> &[CostUsageModelBreakdown] {
        &self.models
    }

    #[must_use]
    pub fn sources(&self) -> &[CostUsageProjectSourceBreakdown] {
        &self.sources
    }

    fn sort_key(&self) -> (&str, Option<&str>) {
        (self.name(), self.path())
    }

    fn without_personal_information(&self, ordinal: usize) -> Self {
        Self {
            name: public_ordinal("project", ordinal),
            path: None,
            metrics: self.metrics.clone(),
            daily: self
                .daily
                .iter()
                .map(CostUsageDailyBucket::without_personal_information)
                .collect(),
            models: self
                .models
                .iter()
                .enumerate()
                .map(|(model_ordinal, model)| model.without_personal_information(model_ordinal))
                .collect(),
            sources: self
                .sources
                .iter()
                .enumerate()
                .map(|(source_ordinal, source)| source.without_personal_information(source_ordinal))
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageProjectBreakdownRepr {
    name: String,
    path: Option<String>,
    metrics: CostUsageMetrics,
    daily: Vec<CostUsageDailyBucket>,
    models: Vec<CostUsageModelBreakdown>,
    sources: Vec<CostUsageProjectSourceBreakdown>,
}

impl<'de> Deserialize<'de> for CostUsageProjectBreakdown {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageProjectBreakdownRepr::deserialize(deserializer)?;
        Self::new(
            repr.name,
            repr.path,
            repr.metrics,
            repr.daily,
            repr.models,
            repr.sources,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostUsageSessionBreakdown {
    session_id: BoundedText<COST_LABEL_BYTES>,
    last_activity: Timestamp,
    metrics: CostUsageMetrics,
    models: Vec<CostUsageModelBreakdown>,
}

impl CostUsageSessionBreakdown {
    /// Creates a local session breakdown.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid session ID, too many models, or
    /// duplicate model names.
    pub fn new(
        session_id: impl AsRef<str>,
        last_activity: Timestamp,
        metrics: CostUsageMetrics,
        mut models: Vec<CostUsageModelBreakdown>,
    ) -> Result<Self, CostUsageError> {
        normalize_models(&mut models)?;
        Ok(Self {
            session_id: BoundedText::new(session_id)?,
            last_activity,
            metrics,
            models,
        })
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        self.session_id.as_str()
    }

    #[must_use]
    pub const fn last_activity(&self) -> Timestamp {
        self.last_activity
    }

    #[must_use]
    pub const fn metrics(&self) -> &CostUsageMetrics {
        &self.metrics
    }

    #[must_use]
    pub fn models(&self) -> &[CostUsageModelBreakdown] {
        &self.models
    }

    fn without_personal_information(&self, ordinal: usize) -> Self {
        Self {
            session_id: public_ordinal("session", ordinal),
            last_activity: self.last_activity,
            metrics: self.metrics.clone(),
            models: self
                .models
                .iter()
                .enumerate()
                .map(|(model_ordinal, model)| model.without_personal_information(model_ordinal))
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageSessionBreakdownRepr {
    session_id: String,
    last_activity: Timestamp,
    metrics: CostUsageMetrics,
    models: Vec<CostUsageModelBreakdown>,
}

impl<'de> Deserialize<'de> for CostUsageSessionBreakdown {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageSessionBreakdownRepr::deserialize(deserializer)?;
        Self::new(
            repr.session_id,
            repr.last_activity,
            repr.metrics,
            repr.models,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostUsageHourlyBucket {
    hour: Timestamp,
    metrics: CostUsageMetrics,
}

impl CostUsageHourlyBucket {
    #[must_use]
    pub const fn new(hour: Timestamp, metrics: CostUsageMetrics) -> Self {
        Self { hour, metrics }
    }

    #[must_use]
    pub const fn hour(&self) -> Timestamp {
        self.hour
    }

    #[must_use]
    pub const fn metrics(&self) -> &CostUsageMetrics {
        &self.metrics
    }
}

/// A normalized private cost/history aggregate.
///
/// Personal project paths, session IDs, credential fingerprints, and model or
/// line-item labels are intentionally held behind the same explicit
/// serialization boundary as [`crate::UsageSample`].
///
/// ```compile_fail
/// # use oab_domain::CostUsageSnapshot;
/// fn cannot_serialize_private_cost_usage(snapshot: &CostUsageSnapshot) {
///     let _ = serde_json::to_string(snapshot);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostUsageSnapshot {
    unit: CostUnit,
    session: CostUsageMetrics,
    history: CostUsageMetrics,
    metered_amount: Option<ExactDecimal>,
    history_days: u16,
    history_coverage_established: bool,
    history_label: Option<BoundedText<COST_LABEL_BYTES>>,
    credential_scope_fingerprint: Option<BoundedText<CREDENTIAL_FINGERPRINT_BYTES>>,
    daily: Vec<CostUsageDailyBucket>,
    projects: Vec<CostUsageProjectBreakdown>,
    sessions: Vec<CostUsageSessionBreakdown>,
    hourly: Vec<CostUsageHourlyBucket>,
    updated_at: Timestamp,
    provenance: CostProvenance,
}

#[derive(Serialize)]
pub(crate) struct PrivateCostUsageSnapshot<'a> {
    unit: CostUsageUnitRef<'a>,
    session: &'a CostUsageMetrics,
    history: &'a CostUsageMetrics,
    metered_amount: Option<ExactDecimal>,
    history_days: u16,
    history_coverage_established: bool,
    history_label: Option<&'a BoundedText<COST_LABEL_BYTES>>,
    credential_scope_fingerprint: Option<&'a BoundedText<CREDENTIAL_FINGERPRINT_BYTES>>,
    daily: &'a [CostUsageDailyBucket],
    projects: &'a [CostUsageProjectBreakdown],
    sessions: &'a [CostUsageSessionBreakdown],
    hourly: &'a [CostUsageHourlyBucket],
    updated_at: Timestamp,
    provenance: CostProvenance,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CostUsageUnitRef<'a> {
    Currency {
        code: &'a crate::money::CurrencyCode,
    },
    Provider {
        unit: &'a ProviderUnit,
    },
}

impl<'a> From<&'a CostUnit> for CostUsageUnitRef<'a> {
    fn from(unit: &'a CostUnit) -> Self {
        match unit {
            CostUnit::Currency(code) => Self::Currency { code },
            CostUnit::Provider(unit) => Self::Provider { unit },
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CostUsageUnitRepr {
    Currency { code: crate::money::CurrencyCode },
    Provider { unit: ProviderUnit },
}

impl From<CostUsageUnitRepr> for CostUnit {
    fn from(unit: CostUsageUnitRepr) -> Self {
        match unit {
            CostUsageUnitRepr::Currency { code } => Self::Currency(code),
            CostUsageUnitRepr::Provider { unit } => Self::Provider(unit),
        }
    }
}

impl CostUsageSnapshot {
    /// Creates a fully typed, deterministic cost/history snapshot.
    ///
    /// `history_days` uses the same one-through-365 semantics as the baseline.
    /// Every optional count or amount remains optional, so unknown data is
    /// never silently converted to zero.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid history window, negative metered amount,
    /// invalid private text, oversized collections, or duplicate keys.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        unit: CostUnit,
        session: CostUsageMetrics,
        history: CostUsageMetrics,
        metered_amount: Option<ExactDecimal>,
        history_days: u16,
        history_coverage_established: bool,
        history_label: Option<String>,
        credential_scope_fingerprint: Option<String>,
        mut daily: Vec<CostUsageDailyBucket>,
        mut projects: Vec<CostUsageProjectBreakdown>,
        mut sessions: Vec<CostUsageSessionBreakdown>,
        mut hourly: Vec<CostUsageHourlyBucket>,
        updated_at: Timestamp,
        provenance: CostProvenance,
    ) -> Result<Self, CostUsageError> {
        if !(1..=MAX_COST_HISTORY_DAYS).contains(&history_days) {
            return Err(CostUsageError::InvalidHistoryDays);
        }
        ensure_nonnegative("metered amount", metered_amount)?;
        normalize_daily(&mut daily)?;

        check_limit("projects", projects.len(), MAX_COST_PROJECTS)?;
        projects.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        if projects
            .windows(2)
            .any(|items| items[0].sort_key() == items[1].sort_key())
        {
            return Err(CostUsageError::Duplicate("project"));
        }

        check_limit("sessions", sessions.len(), MAX_COST_SESSIONS)?;
        sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        ensure_unique(
            sessions.iter().map(CostUsageSessionBreakdown::session_id),
            "session",
        )?;

        check_limit("hourly buckets", hourly.len(), MAX_COST_HOURLY_BUCKETS)?;
        hourly.sort_by_key(CostUsageHourlyBucket::hour);
        if hourly
            .windows(2)
            .any(|items| items[0].hour == items[1].hour)
        {
            return Err(CostUsageError::Duplicate("hourly timestamp"));
        }

        Ok(Self {
            unit,
            session,
            history,
            metered_amount,
            history_days,
            history_coverage_established,
            history_label: history_label.map(BoundedText::new).transpose()?,
            credential_scope_fingerprint: credential_scope_fingerprint
                .map(BoundedText::new)
                .transpose()?,
            daily,
            projects,
            sessions,
            hourly,
            updated_at,
            provenance,
        })
    }

    #[must_use]
    pub const fn unit(&self) -> &CostUnit {
        &self.unit
    }

    #[must_use]
    pub const fn session(&self) -> &CostUsageMetrics {
        &self.session
    }

    #[must_use]
    pub const fn history(&self) -> &CostUsageMetrics {
        &self.history
    }

    #[must_use]
    pub const fn metered_amount(&self) -> Option<ExactDecimal> {
        self.metered_amount
    }

    #[must_use]
    pub const fn history_days(&self) -> u16 {
        self.history_days
    }

    #[must_use]
    pub const fn history_coverage_is_established(&self) -> bool {
        self.history_coverage_established
    }

    #[must_use]
    pub fn history_label(&self) -> Option<&str> {
        self.history_label.as_ref().map(BoundedText::as_str)
    }

    #[must_use]
    pub fn credential_scope_fingerprint(&self) -> Option<&str> {
        self.credential_scope_fingerprint
            .as_ref()
            .map(BoundedText::as_str)
    }

    #[must_use]
    pub fn daily(&self) -> &[CostUsageDailyBucket] {
        &self.daily
    }

    #[must_use]
    pub fn projects(&self) -> &[CostUsageProjectBreakdown] {
        &self.projects
    }

    #[must_use]
    pub fn sessions(&self) -> &[CostUsageSessionBreakdown] {
        &self.sessions
    }

    #[must_use]
    pub fn hourly(&self) -> &[CostUsageHourlyBucket] {
        &self.hourly
    }

    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    #[must_use]
    pub const fn provenance(&self) -> CostProvenance {
        self.provenance
    }

    pub(crate) fn private_view(&self) -> PrivateCostUsageSnapshot<'_> {
        PrivateCostUsageSnapshot {
            unit: CostUsageUnitRef::from(&self.unit),
            session: &self.session,
            history: &self.history,
            metered_amount: self.metered_amount,
            history_days: self.history_days,
            history_coverage_established: self.history_coverage_established,
            history_label: self.history_label.as_ref(),
            credential_scope_fingerprint: self.credential_scope_fingerprint.as_ref(),
            daily: &self.daily,
            projects: &self.projects,
            sessions: &self.sessions,
            hourly: &self.hourly,
            updated_at: self.updated_at,
            provenance: self.provenance,
        }
    }

    pub(crate) fn without_personal_information(&self) -> Self {
        Self {
            unit: match &self.unit {
                CostUnit::Currency(currency) => CostUnit::Currency(currency.clone()),
                CostUnit::Provider(_) => CostUnit::Provider(
                    ProviderUnit::new("credits")
                        .expect("fixed public provider unit satisfies its text bound"),
                ),
            },
            session: self.session.clone(),
            history: self.history.clone(),
            metered_amount: self.metered_amount,
            history_days: self.history_days,
            history_coverage_established: self.history_coverage_established,
            history_label: None,
            credential_scope_fingerprint: None,
            daily: self
                .daily
                .iter()
                .map(CostUsageDailyBucket::without_personal_information)
                .collect(),
            projects: self
                .projects
                .iter()
                .enumerate()
                .map(|(ordinal, project)| project.without_personal_information(ordinal))
                .collect(),
            sessions: self
                .sessions
                .iter()
                .enumerate()
                .map(|(ordinal, session)| session.without_personal_information(ordinal))
                .collect(),
            hourly: self.hourly.clone(),
            updated_at: self.updated_at,
            provenance: self.provenance,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CostUsageSnapshotRepr {
    unit: CostUsageUnitRepr,
    session: CostUsageMetrics,
    history: CostUsageMetrics,
    metered_amount: Option<ExactDecimal>,
    history_days: u16,
    history_coverage_established: bool,
    history_label: Option<String>,
    credential_scope_fingerprint: Option<String>,
    daily: Vec<CostUsageDailyBucket>,
    projects: Vec<CostUsageProjectBreakdown>,
    sessions: Vec<CostUsageSessionBreakdown>,
    hourly: Vec<CostUsageHourlyBucket>,
    updated_at: Timestamp,
    provenance: CostProvenance,
}

impl<'de> Deserialize<'de> for CostUsageSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = CostUsageSnapshotRepr::deserialize(deserializer)?;
        Self::new(
            repr.unit.into(),
            repr.session,
            repr.history,
            repr.metered_amount,
            repr.history_days,
            repr.history_coverage_established,
            repr.history_label,
            repr.credential_scope_fingerprint,
            repr.daily,
            repr.projects,
            repr.sessions,
            repr.hourly,
            repr.updated_at,
            repr.provenance,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum CostUsageError {
    #[error("cost-history days must be between 1 and 365")]
    InvalidHistoryDays,
    #[error("cost-usage interval end must be later than its start")]
    InvalidInterval,
    #[error("cost-usage day must be a valid YYYY-MM-DD calendar date")]
    InvalidDay,
    #[error("{0} must not be negative")]
    NegativeAmount(&'static str),
    #[error("cost-coverage total overflowed")]
    CoverageOverflow,
    #[error("cost-coverage counts exceed the known request count")]
    CoverageExceedsRequests,
    #[error("too many {collection}: maximum {maximum}, actual {actual}")]
    LimitExceeded {
        collection: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("duplicate {0}")]
    Duplicate(&'static str),
    #[error(transparent)]
    InvalidText(#[from] BoundedTextError),
}

fn ensure_nonnegative(
    field: &'static str,
    value: Option<ExactDecimal>,
) -> Result<(), CostUsageError> {
    if value.is_some_and(|value| value.get() < Decimal::ZERO) {
        return Err(CostUsageError::NegativeAmount(field));
    }
    Ok(())
}

fn check_limit(
    collection: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), CostUsageError> {
    if actual > maximum {
        return Err(CostUsageError::LimitExceeded {
            collection,
            maximum,
            actual,
        });
    }
    Ok(())
}

fn ensure_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    field: &'static str,
) -> Result<(), CostUsageError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(CostUsageError::Duplicate(field));
    }
    Ok(())
}

fn normalize_daily(daily: &mut [CostUsageDailyBucket]) -> Result<(), CostUsageError> {
    check_limit("daily buckets", daily.len(), MAX_COST_DAILY_BUCKETS)?;
    daily.sort_by(|left, right| left.day.cmp(&right.day));
    ensure_unique(daily.iter().map(CostUsageDailyBucket::day), "daily bucket")
}

fn normalize_models(models: &mut [CostUsageModelBreakdown]) -> Result<(), CostUsageError> {
    check_limit("model breakdowns", models.len(), MAX_COST_MODELS)?;
    models.sort_by(|left, right| left.name.cmp(&right.name));
    ensure_unique(models.iter().map(CostUsageModelBreakdown::name), "model")
}

fn validate_day(value: &str) -> Result<BoundedText<10>, CostUsageError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err(CostUsageError::InvalidDay);
    }
    let year = value[0..4]
        .parse::<i32>()
        .map_err(|_| CostUsageError::InvalidDay)?;
    if year == 0 {
        return Err(CostUsageError::InvalidDay);
    }
    let month = value[5..7]
        .parse::<u8>()
        .ok()
        .and_then(|month| Month::try_from(month).ok())
        .ok_or(CostUsageError::InvalidDay)?;
    let day = value[8..10]
        .parse::<u8>()
        .map_err(|_| CostUsageError::InvalidDay)?;
    Date::from_calendar_date(year, month, day).map_err(|_| CostUsageError::InvalidDay)?;
    BoundedText::new(value).map_err(CostUsageError::from)
}

fn public_ordinal(prefix: &str, ordinal: usize) -> BoundedText<COST_LABEL_BYTES> {
    BoundedText::new(format!("{prefix}-{}", ordinal.saturating_add(1)))
        .expect("fixed public ordinal label satisfies its text bound")
}
