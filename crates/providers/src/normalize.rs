//! Shared fail-closed normalization helpers for native providers.

use std::time::{SystemTime, UNIX_EPOCH};

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostSummary, CostUsageSnapshot, DataConfidence,
    ErrorKind, IdentitySnapshot, Money, NamedRateWindow, Provenance, ProviderHealth,
    ProviderStatus, RateWindow, Timestamp, UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;

/// Current UTC time projected to the bounded domain timestamp.
///
/// # Errors
///
/// Returns a stable API error if the host clock predates the Unix epoch or is
/// outside the domain's RFC 3339 range.
pub fn system_timestamp() -> Result<Timestamp, ClassifiedError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
        .as_secs();
    let seconds = i64::try_from(seconds).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    timestamp_from_unix(seconds)
}

/// Converts whole Unix seconds without exposing provider input in failures.
///
/// # Errors
///
/// Returns a stable parse error for out-of-range timestamps.
pub fn timestamp_from_unix(seconds: i64) -> Result<Timestamp, ClassifiedError> {
    Timestamp::from_unix_timestamp(seconds).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

/// Reproduces baseline display-clamped count percentages.
///
/// # Errors
///
/// Returns a stable parse error if floating-point conversion is non-finite.
pub fn count_percent(used: i64, limit: i64) -> Result<UsagePercent, ClassifiedError> {
    let value = if limit > 0 {
        (Decimal::from(used) * Decimal::from(100_u8) / Decimal::from(limit))
            .to_f64()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
            .clamp(0.0, 100.0)
    } else {
        0.0
    };
    UsagePercent::new(value).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

/// Builds a normalized count-based rate window.
///
/// # Errors
///
/// Returns a stable parse error when percentage or bounded text validation
/// fails.
pub fn count_window(
    used: i64,
    limit: i64,
    resets_at: Option<Timestamp>,
    description: Option<String>,
) -> Result<RateWindow, ClassifiedError> {
    let description = description
        .map(BoundedText::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(count_percent(used, limit)?),
        None,
        resets_at,
        description,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

/// Locale-independent grouping used by provider count summaries.
#[must_use]
pub fn format_integer(value: i64) -> String {
    let value = value.to_string();
    let (sign, digits) = value
        .strip_prefix('-')
        .map_or(("", value.as_str()), |digits| ("-", digits));
    let mut grouped = String::with_capacity(value.len() + value.len() / 3);
    grouped.push_str(sign);
    for (index, byte) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(byte));
    }
    grouped
}

/// Small normalized sample builder shared by provider parsers.
pub struct UsageSampleBuilder {
    scope: AccountScope,
    fetched_at: Timestamp,
    primary: Option<RateWindow>,
    secondary: Option<RateWindow>,
    extra_windows: Vec<NamedRateWindow>,
    organization: Option<BoundedText<256>>,
    login_method: Option<BoundedText<256>>,
    balance: Option<Money>,
    cost: Option<CostSummary>,
    cost_usage: Option<CostUsageSnapshot>,
    provenance: Vec<Provenance>,
}

impl UsageSampleBuilder {
    /// Starts an exact account-scoped sample.
    #[must_use]
    pub const fn new(scope: AccountScope, fetched_at: Timestamp) -> Self {
        Self {
            scope,
            fetched_at,
            primary: None,
            secondary: None,
            extra_windows: Vec::new(),
            organization: None,
            login_method: None,
            balance: None,
            cost: None,
            cost_usage: None,
            provenance: Vec::new(),
        }
    }

    /// Sets the primary quota lane.
    #[must_use]
    pub fn primary(mut self, primary: RateWindow) -> Self {
        self.primary = Some(primary);
        self
    }

    /// Sets the provider's secondary quota lane.
    #[must_use]
    pub fn secondary(mut self, secondary: RateWindow) -> Self {
        self.secondary = Some(secondary);
        self
    }

    /// Replaces provider-defined additional quota lanes.
    #[must_use]
    pub fn extra_windows(mut self, extra_windows: Vec<NamedRateWindow>) -> Self {
        self.extra_windows = extra_windows;
        self
    }

    /// Adds a bounded provider organization/project label.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error when provider text violates domain bounds.
    pub fn organization(mut self, value: Option<String>) -> Result<Self, ClassifiedError> {
        self.organization = value
            .map(BoundedText::new)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(self)
    }

    /// Adds a bounded plan/login label.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error when provider text violates domain bounds.
    pub fn login_method(mut self, value: Option<String>) -> Result<Self, ClassifiedError> {
        self.login_method = value
            .map(BoundedText::new)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(self)
    }

    /// Attaches a native-currency balance.
    #[must_use]
    pub fn balance(mut self, balance: Money) -> Self {
        self.balance = Some(balance);
        self
    }

    /// Attaches the provider's current cost summary.
    #[must_use]
    pub fn cost(mut self, cost: CostSummary) -> Self {
        self.cost = Some(cost);
        self
    }

    /// Attaches the complete typed cost/history model.
    #[must_use]
    pub fn cost_usage(mut self, cost_usage: CostUsageSnapshot) -> Self {
        self.cost_usage = Some(cost_usage);
        self
    }

    /// Adds a public-safe fixed provenance pair.
    ///
    /// # Errors
    ///
    /// Returns a stable API error only if application-owned labels violate
    /// their compile-time domain bounds.
    pub fn provenance(
        mut self,
        source: &'static str,
        strategy: &'static str,
    ) -> Result<Self, ClassifiedError> {
        let provenance =
            Provenance::new(source, strategy).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        self.provenance.push(provenance);
        Ok(self)
    }

    /// Finalizes the normalized exact-confidence sample.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error if nested provider values violate domain
    /// invariants.
    pub fn build(self) -> Result<UsageSample, ClassifiedError> {
        let identity = IdentitySnapshot::new(
            self.scope.clone(),
            None,
            None,
            self.organization,
            None,
            None,
            self.login_method,
        );
        let status = ProviderStatus::new(
            ProviderHealth::Operational,
            None,
            Some(self.fetched_at),
            Vec::new(),
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let cost_usage = self.cost_usage;
        let sample = UsageSample::new(
            self.scope,
            identity,
            self.fetched_at,
            self.primary,
            self.secondary,
            None,
            self.extra_windows,
            None,
            self.balance,
            self.cost,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            self.provenance,
            DataConfidence::Exact,
            status,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(match cost_usage {
            Some(cost_usage) => sample.with_cost_usage(cost_usage),
            None => sample,
        })
    }
}
