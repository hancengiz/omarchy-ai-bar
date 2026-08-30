//! Shared fail-closed normalization helpers for native providers.

use std::time::{SystemTime, UNIX_EPOCH};

use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostSummary, CostUsageSnapshot, CreditsSnapshot,
    DataConfidence, DetailSection, ErrorKind, IdentitySnapshot, Money, NamedRateWindow, Provenance,
    ProviderExtension, ProviderHealth, ProviderStatus, RateWindow, Timestamp, UsagePercent,
    UsageSample, WindowUsage,
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
    tertiary: Option<RateWindow>,
    extra_windows: Vec<NamedRateWindow>,
    credits: Option<CreditsSnapshot>,
    provider_account_id: Option<BoundedText<256>>,
    email: Option<BoundedText<256>>,
    organization: Option<BoundedText<256>>,
    login_method: Option<BoundedText<256>>,
    balance: Option<Money>,
    cost: Option<CostSummary>,
    cost_usage: Option<CostUsageSnapshot>,
    subscription_renews_at: Option<Timestamp>,
    subscription_expires_at: Option<Timestamp>,
    detail_sections: Vec<DetailSection>,
    extensions: Vec<ProviderExtension>,
    provenance: Vec<Provenance>,
    confidence: DataConfidence,
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
            tertiary: None,
            extra_windows: Vec::new(),
            credits: None,
            provider_account_id: None,
            email: None,
            organization: None,
            login_method: None,
            balance: None,
            cost: None,
            cost_usage: None,
            subscription_renews_at: None,
            subscription_expires_at: None,
            detail_sections: Vec::new(),
            extensions: Vec::new(),
            provenance: Vec::new(),
            confidence: DataConfidence::Exact,
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

    /// Sets the provider's tertiary quota lane.
    #[must_use]
    pub fn tertiary(mut self, tertiary: RateWindow) -> Self {
        self.tertiary = Some(tertiary);
        self
    }

    /// Replaces provider-defined additional quota lanes.
    #[must_use]
    pub fn extra_windows(mut self, extra_windows: Vec<NamedRateWindow>) -> Self {
        self.extra_windows = extra_windows;
        self
    }

    /// Attaches provider credit state for this exact account scope.
    ///
    /// The nested scope is validated when [`Self::build`] finalizes the sample.
    #[must_use]
    pub fn credits(mut self, credits: CreditsSnapshot) -> Self {
        self.credits = Some(credits);
        self
    }

    /// Adds a bounded provider-owned account identifier.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error when provider text violates domain bounds.
    pub fn provider_account_id(mut self, value: Option<String>) -> Result<Self, ClassifiedError> {
        self.provider_account_id = value
            .map(BoundedText::new)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(self)
    }

    /// Adds a bounded provider-reported account email.
    ///
    /// # Errors
    ///
    /// Returns a stable parse error when provider text violates domain bounds.
    pub fn email(mut self, value: Option<String>) -> Result<Self, ClassifiedError> {
        self.email = value
            .map(BoundedText::new)
            .transpose()
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(self)
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

    /// Replaces provider-defined detail sections.
    #[must_use]
    pub fn detail_sections(mut self, detail_sections: Vec<DetailSection>) -> Self {
        self.detail_sections = detail_sections;
        self
    }

    /// Replaces provider-specific typed extension payloads.
    #[must_use]
    pub fn extensions(mut self, extensions: Vec<ProviderExtension>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Sets the provider's confidence after bounded/truncation analysis.
    #[must_use]
    pub fn confidence(mut self, confidence: DataConfidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets a provider-reported subscription renewal timestamp.
    #[must_use]
    pub fn subscription_renews_at(mut self, value: Option<Timestamp>) -> Self {
        self.subscription_renews_at = value;
        self
    }

    /// Sets a provider-reported subscription or credential expiry timestamp.
    #[must_use]
    pub fn subscription_expires_at(mut self, value: Option<Timestamp>) -> Self {
        self.subscription_expires_at = value;
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
            self.provider_account_id,
            self.email,
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
            self.tertiary,
            self.extra_windows,
            self.credits,
            self.balance,
            self.cost,
            self.subscription_renews_at,
            self.subscription_expires_at,
            None,
            self.detail_sections,
            self.extensions,
            Vec::new(),
            self.provenance,
            self.confidence,
            status,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        Ok(match cost_usage {
            Some(cost_usage) => sample.with_cost_usage(cost_usage),
            None => sample,
        })
    }
}
