//! Shared domain models.

mod cost_usage;
mod credits;
mod error;
mod freshness;
mod identity;
mod ids;
mod money;
mod percentage;
mod privacy;
mod provider_id;
mod rate_window;
mod snapshot;
mod status;
mod text;
mod timestamp;

pub use cost_usage::{
    CostUsageCoverage, CostUsageDailyBucket, CostUsageError, CostUsageHourlyBucket,
    CostUsageInterval, CostUsageLineItem, CostUsageMetrics, CostUsageModelBreakdown,
    CostUsageProjectBreakdown, CostUsageProjectSourceBreakdown, CostUsageSessionBreakdown,
    CostUsageSnapshot, CostUsageTokenMix, MAX_COST_DAILY_BUCKETS, MAX_COST_HISTORY_DAYS,
    MAX_COST_HOURLY_BUCKETS, MAX_COST_LINE_ITEMS, MAX_COST_MODELS, MAX_COST_PROJECT_SOURCES,
    MAX_COST_PROJECTS, MAX_COST_SESSIONS,
};
pub use credits::{
    CreditEvent, CreditLimitSnapshot, CreditValidationError, CreditsSnapshot, MAX_CREDIT_EVENTS,
};
pub use error::{
    AuthImplication, ClassifiedError, ClassifiedErrorValidationError, ErrorKind, RetryEligibility,
};
pub use freshness::{Freshness, RefreshPhase};
pub use identity::IdentitySnapshot;
pub use ids::{AccountKey, AccountScope, ProviderInstanceId, ScopeIdError};
pub use money::{
    CostAmount, CostAmountValidationError, CostUnit, CurrencyCode, CurrencyCodeError, ExactDecimal,
    ExactDecimalError, Money, ProviderUnit, Quantity,
};
pub use percentage::{
    DisplayPercent, FiniteNumber, FiniteNumberError, PercentageError, UsagePercent, WindowDuration,
    WindowDurationError,
};
pub use privacy::{
    PrivacyKey, PrivacyPolicy, PrivacySurface, ProjectedSnapshotEnvelope, SurfaceSnapshotEnvelope,
};
pub use provider_id::{ParseProviderIdError, ProviderId};
pub use rate_window::{NamedRateWindow, RateWindow, RateWindowValidationError, WindowUsage};
pub use snapshot::{
    ChartPoint, CostProvenance, CostSummary, DataConfidence, DetailChart, DetailChartKind,
    DetailChartPoint, DetailRow, DetailSection, DetailSensitivity, ExtensionFact, ExtensionValue,
    LoadingSnapshot, MAX_REPORTED_AVAILABLE_RESET_CREDITS, PrivateSnapshotEnvelope, Provenance,
    ProviderExtension, ProviderExtensionKind, ProviderSnapshot, ReadySnapshot, ResetCredit,
    ResetCreditStatus, ResetCreditStatusValidationError, ResetCreditsSnapshot, SnapshotEnvelopeV1,
    SnapshotError, UnavailableSnapshot, UnknownResetCreditStatus, UsageSample,
};
pub use status::{
    ProviderHealth, ProviderIncident, ProviderStatus, ProviderStatusValidationError,
    StatusComponent,
};
pub use text::{BoundedText, BoundedTextError};
pub use timestamp::{Timestamp, TimestampError};
