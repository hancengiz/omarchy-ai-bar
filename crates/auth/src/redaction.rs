//! Last-resort diagnostic redaction helpers.
//!
//! Callers should avoid formatting secrets in the first place. This module is
//! for sanitizing opaque provider errors before they cross a log, diagnostic,
//! CLI, or export boundary.

use crate::secret_store::SecretValue;

/// Replacement marker used for exact secret occurrences.
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Replaces exact UTF-8 secret occurrences in diagnostic text.
///
/// Binary secrets that cannot occur in a Rust UTF-8 string are skipped. Secret
/// values are borrowed and never retained by the returned string.
#[must_use]
pub fn redact_text(text: &str, secrets: &[&SecretValue]) -> String {
    let mut redacted = text.to_owned();
    for secret in secrets {
        if let Ok(needle) = std::str::from_utf8(secret.expose_secret()) {
            redacted = redacted.replace(needle, REDACTION_MARKER);
        }
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_secret_canaries_are_removed() {
        let secret = SecretValue::new("canary-token".as_bytes().to_vec()).expect("secret");
        let output = redact_text("provider rejected canary-token", &[&secret]);
        assert_eq!(output, "provider rejected [REDACTED]");
        assert!(!format!("{secret:?}").contains("canary-token"));
    }
}
