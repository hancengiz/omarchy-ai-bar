//! Output-mode selection and data-only machine-readable writers.

use std::io::{self, Write};

use clap::ValueEnum;
use serde::Serialize;

/// Supported presentation formats for data-producing commands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-oriented text.
    #[default]
    Human,
    /// Compact JSON followed by one line feed.
    Json,
    /// Token-Oriented Object Notation.
    Toon,
}

impl OutputFormat {
    /// Returns true for formats whose standard output is a data stream and
    /// must never contain diagnostics or log records.
    #[must_use]
    pub const fn is_machine_readable(self) -> bool {
        matches!(self, Self::Json | Self::Toon)
    }
}

/// Writes one compact JSON value and exactly one terminating line feed.
///
/// # Errors
///
/// Returns an I/O error if serialization or writing fails. Callers must route
/// diagnostics separately; this function writes only the supplied value.
pub fn write_json_line(
    writer: &mut impl Write,
    value: &(impl Serialize + ?Sized),
) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn json_writer_emits_only_one_compact_data_record() {
        let mut bytes = Vec::new();
        write_json_line(&mut bytes, &json!({"ready": true})).expect("write JSON");
        assert_eq!(bytes, b"{\"ready\":true}\n");
    }

    #[test]
    fn machine_readable_formats_are_explicit() {
        assert!(!OutputFormat::Human.is_machine_readable());
        assert!(OutputFormat::Json.is_machine_readable());
        assert!(OutputFormat::Toon.is_machine_readable());
    }
}
