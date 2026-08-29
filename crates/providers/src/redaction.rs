//! Fail-closed provider diagnostic text boundary.

use std::fmt::{self, Display, Formatter};

/// Opaque replacement for arbitrary provider-controlled diagnostic text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RedactedProviderText;

impl RedactedProviderText {
    /// Discards arbitrary provider text rather than attempting pattern-only cleanup.
    #[must_use]
    pub const fn from_untrusted(_value: &str) -> Self {
        Self
    }
}

impl fmt::Debug for RedactedProviderText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactedProviderText(<redacted>)")
    }
}

impl Display for RedactedProviderText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-provider-diagnostic>")
    }
}
