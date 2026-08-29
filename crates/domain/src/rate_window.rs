use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{BoundedText, Timestamp, UsagePercent, WindowDuration};

/// Maximum length of a provider-assigned named quota-window identifier.
pub const MAX_NAMED_WINDOW_ID_LENGTH: usize = 128;
/// Maximum length of text which may be displayed for a quota window.
pub const MAX_WINDOW_TEXT_LENGTH: usize = 120;

/// Whether a provider established the percentage for a quota lane.
///
/// `Unknown` is intentionally not represented as zero: providers can report a
/// reset for a lane before they report its consumption.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowUsage {
    Known { used_percent: UsagePercent },
    Unknown,
}

impl WindowUsage {
    #[must_use]
    pub const fn known(used_percent: UsagePercent) -> Self {
        Self::Known { used_percent }
    }

    #[must_use]
    pub const fn unknown() -> Self {
        Self::Unknown
    }

    #[must_use]
    pub const fn used_percent(self) -> Option<UsagePercent> {
        match self {
            Self::Known { used_percent } => Some(used_percent),
            Self::Unknown => None,
        }
    }

    #[must_use]
    pub const fn is_known(self) -> bool {
        matches!(self, Self::Known { .. })
    }
}

/// A single provider quota lane. Percentages remain raw, including diagnostic
/// over-quota and negative values; only presentation code may clamp them.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateWindow {
    usage: WindowUsage,
    #[serde(rename = "duration_seconds")]
    duration: Option<WindowDuration>,
    resets_at: Option<Timestamp>,
    reset_description: Option<BoundedText<MAX_WINDOW_TEXT_LENGTH>>,
    next_regen_percent: Option<UsagePercent>,
    synthetic_placeholder: bool,
}

impl RateWindow {
    /// Creates a quota lane, rejecting the only ambiguous representation: a
    /// synthetic placeholder without a known zero-percent value.
    ///
    /// # Errors
    ///
    /// Returns an error when a synthetic placeholder does not retain its
    /// baseline known-zero usage marker.
    pub fn new(
        usage: WindowUsage,
        duration: Option<WindowDuration>,
        resets_at: Option<Timestamp>,
        reset_description: Option<BoundedText<MAX_WINDOW_TEXT_LENGTH>>,
        next_regen_percent: Option<UsagePercent>,
        synthetic_placeholder: bool,
    ) -> Result<Self, RateWindowValidationError> {
        if synthetic_placeholder
            && !matches!(usage, WindowUsage::Known { used_percent } if used_percent.get() == 0.0)
        {
            return Err(RateWindowValidationError::SyntheticPlaceholderMustBeKnownZero);
        }

        Ok(Self {
            usage,
            duration,
            resets_at,
            reset_description,
            next_regen_percent,
            synthetic_placeholder,
        })
    }

    #[must_use]
    pub const fn usage(&self) -> WindowUsage {
        self.usage
    }

    #[must_use]
    pub const fn used_percent(&self) -> Option<UsagePercent> {
        self.usage.used_percent()
    }

    /// The unbounded raw used percentage transformed to remaining capacity.
    /// Unknown usage stays unknown rather than becoming a fictitious 100%.
    #[must_use]
    pub fn remaining_percent(&self) -> Option<UsagePercent> {
        self.used_percent().map(UsagePercent::remaining)
    }

    #[must_use]
    pub const fn duration(&self) -> Option<WindowDuration> {
        self.duration
    }

    #[must_use]
    pub const fn resets_at(&self) -> Option<Timestamp> {
        self.resets_at
    }

    #[must_use]
    pub const fn reset_description(&self) -> Option<&BoundedText<MAX_WINDOW_TEXT_LENGTH>> {
        self.reset_description.as_ref()
    }

    #[must_use]
    pub const fn next_regen_percent(&self) -> Option<UsagePercent> {
        self.next_regen_percent
    }

    #[must_use]
    pub const fn is_synthetic_placeholder(&self) -> bool {
        self.synthetic_placeholder
    }

    /// Retains a still-future reset from a same-account cached lane when a
    /// fresh provider response temporarily omits it.
    ///
    /// Raw usage, next-regeneration metadata, and the synthetic-placeholder
    /// marker always come from `self`; only absent reset metadata is filled.
    #[must_use]
    pub(crate) fn backfilling_reset_time(&self, cached: Option<&Self>, now: Timestamp) -> Self {
        if self.resets_at.is_some() {
            return self.clone();
        }
        let Some(cached) = cached else {
            return self.clone();
        };
        let Some(cached_reset) = cached.resets_at else {
            return self.clone();
        };
        if cached_reset <= now {
            return self.clone();
        }

        Self {
            usage: self.usage,
            duration: self.duration.or(cached.duration),
            resets_at: Some(cached_reset),
            reset_description: self
                .reset_description
                .clone()
                .or_else(|| cached.reset_description.clone()),
            next_regen_percent: self.next_regen_percent,
            synthetic_placeholder: self.synthetic_placeholder,
        }
    }

    /// Removes free-form reset text for public, notification, hook, and
    /// export projections while retaining safe quota mechanics.
    #[must_use]
    pub fn without_personal_information(&self) -> Self {
        Self {
            usage: self.usage,
            duration: self.duration,
            resets_at: self.resets_at,
            reset_description: None,
            next_regen_percent: self.next_regen_percent,
            synthetic_placeholder: self.synthetic_placeholder,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RateWindowWire {
    usage: WindowUsage,
    #[serde(rename = "duration_seconds")]
    duration: Option<WindowDuration>,
    resets_at: Option<Timestamp>,
    reset_description: Option<BoundedText<MAX_WINDOW_TEXT_LENGTH>>,
    next_regen_percent: Option<UsagePercent>,
    synthetic_placeholder: bool,
}

impl<'de> Deserialize<'de> for RateWindow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RateWindowWire::deserialize(deserializer)?;
        Self::new(
            wire.usage,
            wire.duration,
            wire.resets_at,
            wire.reset_description,
            wire.next_regen_percent,
            wire.synthetic_placeholder,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// A provider-defined quota lane beyond the primary, secondary, and tertiary
/// display slots.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedRateWindow {
    id: BoundedText<MAX_NAMED_WINDOW_ID_LENGTH>,
    title: BoundedText<MAX_WINDOW_TEXT_LENGTH>,
    window: RateWindow,
}

impl NamedRateWindow {
    #[must_use]
    pub const fn new(
        id: BoundedText<MAX_NAMED_WINDOW_ID_LENGTH>,
        title: BoundedText<MAX_WINDOW_TEXT_LENGTH>,
        window: RateWindow,
    ) -> Self {
        Self { id, title, window }
    }

    #[must_use]
    pub const fn id(&self) -> &BoundedText<MAX_NAMED_WINDOW_ID_LENGTH> {
        &self.id
    }

    #[must_use]
    pub const fn title(&self) -> &BoundedText<MAX_WINDOW_TEXT_LENGTH> {
        &self.title
    }

    #[must_use]
    pub const fn window(&self) -> &RateWindow {
        &self.window
    }

    /// Validates that named lanes have stable, non-duplicated IDs before they
    /// are admitted to a normalized snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if two windows use the same provider-assigned ID.
    pub fn validate_unique_ids(windows: &[Self]) -> Result<(), RateWindowValidationError> {
        let mut ids = BTreeSet::new();
        for window in windows {
            if !ids.insert(window.id.as_str()) {
                return Err(RateWindowValidationError::DuplicateNamedWindowId);
            }
        }
        Ok(())
    }

    /// Produces a safe public representation. Provider-supplied window IDs
    /// and labels can contain account, project, or model data, so they are
    /// replaced with deterministic local labels rather than heuristically
    /// scrubbed.
    ///
    /// # Panics
    ///
    /// Panics only if an internally generated `usize` label cannot satisfy a
    /// 128-byte bounded-text field, which is impossible on supported targets.
    #[must_use]
    pub fn without_personal_information(&self, ordinal: usize) -> Self {
        let ordinal = ordinal.saturating_add(1);
        let id = BoundedText::new(format!("window-{ordinal}"))
            .expect("generated named-window ID is bounded and non-empty");
        let title = BoundedText::new(format!("Window {ordinal}"))
            .expect("generated named-window title is bounded and non-empty");
        Self {
            id,
            title,
            window: self.window.without_personal_information(),
        }
    }

    /// Projects a list of named windows with deterministic replacement labels.
    #[must_use]
    pub fn public_projection(windows: &[Self]) -> Vec<Self> {
        windows
            .iter()
            .enumerate()
            .map(|(ordinal, window)| window.without_personal_information(ordinal))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateWindowValidationError {
    SyntheticPlaceholderMustBeKnownZero,
    DuplicateNamedWindowId,
}

impl Display for RateWindowValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyntheticPlaceholderMustBeKnownZero => {
                formatter.write_str("synthetic placeholder usage must be known zero percent")
            }
            Self::DuplicateNamedWindowId => formatter.write_str("duplicate named rate-window id"),
        }
    }
}

impl std::error::Error for RateWindowValidationError {}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn timestamp(value: &str) -> Timestamp {
        Timestamp::parse(value).expect("valid timestamp")
    }

    fn window(
        used_percent: f64,
        duration: Option<u64>,
        resets_at: Option<Timestamp>,
        reset_description: Option<&str>,
        next_regen_percent: Option<f64>,
        synthetic_placeholder: bool,
    ) -> RateWindow {
        RateWindow::new(
            WindowUsage::known(UsagePercent::new(used_percent).expect("finite usage")),
            duration
                .map(|seconds| WindowDuration::from_seconds(seconds).expect("positive duration")),
            resets_at,
            reset_description.map(|description| {
                BoundedText::new(description).expect("bounded reset description")
            }),
            next_regen_percent.map(|value| UsagePercent::new(value).expect("finite regeneration")),
            synthetic_placeholder,
        )
        .expect("valid window")
    }

    #[test]
    fn backfill_preserves_fresh_fields_and_requires_a_future_cached_reset() {
        let now = timestamp("2026-08-29T10:00:00Z");
        let cached = window(
            12.0,
            Some(300),
            Some(timestamp("2026-08-29T11:00:00Z")),
            Some("cached reset"),
            Some(9.0),
            false,
        );
        let fresh = window(62.0, None, None, None, Some(4.0), false);
        let merged = fresh.backfilling_reset_time(Some(&cached), now);
        assert_eq!(merged.used_percent().expect("known").get(), 62.0);
        assert_eq!(merged.next_regen_percent().expect("fresh regen").get(), 4.0);
        assert_eq!(merged.duration().expect("cached duration").seconds(), 300);
        assert_eq!(merged.resets_at(), Some(timestamp("2026-08-29T11:00:00Z")));

        let expired = window(
            1.0,
            Some(600),
            Some(timestamp("2026-08-29T09:59:59Z")),
            Some("expired"),
            None,
            false,
        );
        assert_eq!(fresh.backfilling_reset_time(Some(&expired), now), fresh);
    }

    #[test]
    fn backfill_never_replaces_fresh_reset_or_synthetic_marker() {
        let now = timestamp("2026-08-29T10:00:00Z");
        let cached = window(
            12.0,
            Some(300),
            Some(timestamp("2026-08-29T12:00:00Z")),
            Some("cached"),
            None,
            false,
        );
        let fresh = window(
            2.0,
            Some(60),
            Some(timestamp("2026-08-29T10:30:00Z")),
            Some("fresh"),
            None,
            false,
        );
        assert_eq!(fresh.backfilling_reset_time(Some(&cached), now), fresh);

        let placeholder = window(0.0, Some(300), None, None, None, true)
            .backfilling_reset_time(Some(&cached), now);
        assert!(placeholder.is_synthetic_placeholder());
        assert_eq!(placeholder.used_percent().expect("known zero").get(), 0.0);
    }
}
