//! Output-mode selection and data-only machine-readable writers.

use std::io::{self, Write};

use clap::ValueEnum;
use serde::Serialize;
use serde_json::Value;

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

/// Writes a deterministic TOON document for an already validated JSON value.
///
/// This deliberately uses TOON's non-tabular object/array form. It preserves
/// every JSON field while avoiding a second data model in the CLI boundary.
///
/// # Errors
///
/// Returns an I/O error when the destination cannot be written.
pub fn write_toon(writer: &mut impl Write, value: &Value) -> io::Result<()> {
    write_toon_value(writer, value, 0, None, false)?;
    writer.write_all(b"\n")
}

fn write_toon_value(
    writer: &mut impl Write,
    value: &Value,
    depth: usize,
    key: Option<&str>,
    list_item: bool,
) -> io::Result<()> {
    let indent = "  ".repeat(depth);
    let prefix = if list_item { "- " } else { "" };
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            write!(writer, "{indent}{prefix}")?;
            if let Some(key) = key {
                write!(writer, "{}: ", toon_key(key))?;
            }
            write!(writer, "{}", toon_scalar(value))?;
        }
        Value::Object(fields) => {
            if let Some(key) = key {
                writeln!(writer, "{indent}{prefix}{}:", toon_key(key))?;
            } else if list_item {
                writeln!(writer, "{indent}-")?;
            }
            let child_depth = depth + usize::from(key.is_some() || list_item);
            for (index, (name, child)) in fields.iter().enumerate() {
                write_toon_value(writer, child, child_depth, Some(name), false)?;
                if index + 1 < fields.len() {
                    writer.write_all(b"\n")?;
                }
            }
        }
        Value::Array(items) => {
            if let Some(key) = key {
                if items.is_empty() {
                    write!(writer, "{indent}{prefix}{}: []", toon_key(key))?;
                    return Ok(());
                }
                writeln!(
                    writer,
                    "{indent}{prefix}{}[{}]:",
                    toon_key(key),
                    items.len()
                )?;
            } else if items.is_empty() {
                write!(writer, "{indent}{prefix}[]")?;
                return Ok(());
            }
            let child_depth = depth + usize::from(key.is_some());
            for (index, child) in items.iter().enumerate() {
                write_toon_value(writer, child, child_depth, None, true)?;
                if index + 1 < items.len() {
                    writer.write_all(b"\n")?;
                }
            }
        }
    }
    Ok(())
}

fn toon_key(value: &str) -> String {
    if is_plain_toon(value) {
        value.to_owned()
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
    }
}

fn toon_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) if is_plain_toon(value) && !is_reserved_scalar(value) => value.clone(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into()),
        Value::Array(_) | Value::Object(_) => unreachable!("containers are rendered recursively"),
    }
}

fn is_plain_toon(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
}

fn is_reserved_scalar(value: &str) -> bool {
    matches!(value, "true" | "false" | "null") || value.parse::<f64>().is_ok()
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

    #[test]
    fn toon_writer_preserves_nested_fields_without_json_syntax() {
        let mut bytes = Vec::new();
        write_toon(
            &mut bytes,
            &serde_json::json!({
                "generated_at": "2026-08-31T00:00:00Z",
                "snapshots": [
                    {"provider": "codex", "used_percent": 42},
                    {"provider": "claude", "state": "missing credential"}
                ]
            }),
        )
        .expect("write TOON");
        let output = String::from_utf8(bytes).expect("UTF-8 TOON");
        assert!(output.contains("snapshots[2]:"));
        assert!(output.contains("provider: codex"));
        assert!(output.contains("state: \"missing credential\""));
        assert!(!output.contains('{'));
    }
}
