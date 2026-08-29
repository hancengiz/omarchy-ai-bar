use oab_domain::{AccountScope, ClassifiedError};

use crate::command::RefreshTrigger;

/// A bounded, public-safe runtime lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    /// A provider/account worker began.
    RefreshStarted {
        scope: AccountScope,
        generation: u64,
        trigger: RefreshTrigger,
    },
    /// Required usage was published before optional enrichment began.
    RequiredUsagePublished {
        scope: AccountScope,
        generation: u64,
    },
    /// Required usage failed and the snapshot store retained any last-good data.
    RequiredUsageFailed {
        scope: AccountScope,
        generation: u64,
        error: ClassifiedError,
    },
    /// Optional cost/history enrichment was attached to the required sample.
    OptionalEnrichmentPublished {
        scope: AccountScope,
        generation: u64,
    },
    /// Optional enrichment failed without changing the required display state.
    OptionalEnrichmentFailed {
        scope: AccountScope,
        generation: u64,
        error: ClassifiedError,
    },
    /// One active generation ended and released its concurrency slot.
    RefreshFinished {
        scope: AccountScope,
        generation: u64,
    },
}
