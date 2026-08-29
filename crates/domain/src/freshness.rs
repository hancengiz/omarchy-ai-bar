use serde::{Deserialize, Serialize};

use crate::Timestamp;

/// How current a last-known-good provider sample is.
///
/// This is internally tagged so the stable JSON shape is, for example,
/// `{ "state": "fresh" }` or `{ "state": "stale", "since": "..." }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Freshness {
    Fresh,
    Stale { since: Timestamp },
    Unknown,
}

impl Freshness {
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// The current refresh operation, independent from the freshness of the
/// last-known-good sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefreshPhase {
    Idle,
    Scheduled { at: Timestamp },
    Refreshing { started_at: Timestamp },
}

impl RefreshPhase {
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Refreshing { .. })
    }
}
