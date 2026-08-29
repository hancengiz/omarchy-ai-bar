//! Bounded, rollback-friendly configuration schema migrations.
//!
//! Schema v1 is returned byte-for-byte so merely opening a current document
//! never rewrites its formatting. The intentionally small legacy-v0 scaffold
//! accepts one Codex account and emits canonical schema-v1 JSON. Every
//! successful migration retains the exact original bytes for caller-managed
//! rollback until the new document has been validated and committed.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

use oab_domain::AccountKey;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use crate::config::{CURRENT_SCHEMA_VERSION, MAX_CONFIG_BYTES};

/// A safe configuration migration failure.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// The byte limit was exceeded before parsing.
    #[error("configuration exceeds the migration byte limit")]
    InputTooLarge,

    /// The input was not one valid JSON object.
    #[error("configuration is not valid migration JSON")]
    InvalidJson,

    /// `schema_version` was missing from a non-legacy shape or had a bad type.
    #[error("configuration schema version is malformed")]
    MalformedVersion,

    /// The document was produced by a newer schema.
    #[error("configuration schema version {found} is newer than supported version {current}")]
    FutureVersion {
        /// Numeric version found in the document.
        found: u64,
        /// Maximum version supported by this build.
        current: u32,
    },

    /// The legacy-v0 object was not the deliberately supported minimal shape.
    #[error("legacy configuration does not match the supported v0 scaffold")]
    InvalidLegacy,

    /// Only the built-in Codex provider can be represented by the v0 scaffold.
    #[error("legacy configuration names an unsupported provider")]
    UnsupportedLegacyProvider,

    /// The legacy account identifier cannot be represented safely in v1.
    #[error("legacy configuration has an invalid account identifier")]
    InvalidLegacyAccount,

    /// Canonical v1 serialization failed.
    #[error("could not serialize migrated schema v1")]
    Serialization,

    /// A current-version document failed typed schema or security validation.
    #[error("current configuration does not match the supported schema")]
    InvalidCurrent,
}

/// A migration result that retains exact rollback bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct Migration {
    original: Vec<u8>,
    current: Vec<u8>,
    from_version: u32,
}

impl Debug for Migration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Migration")
            .field("from_version", &self.from_version)
            .field("original_len", &self.original.len())
            .field("current_len", &self.current.len())
            .field("was_migrated", &self.was_migrated())
            .finish()
    }
}

impl Migration {
    /// Exact bytes supplied by the caller, retained for rollback.
    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Current-schema bytes to validate and commit.
    #[must_use]
    pub fn current_bytes(&self) -> &[u8] {
        &self.current
    }

    /// Whether conversion, rather than byte-for-byte pass-through, occurred.
    #[must_use]
    pub fn was_migrated(&self) -> bool {
        self.from_version != CURRENT_SCHEMA_VERSION
    }

    /// Consumes the rollback envelope and returns the current-schema bytes.
    #[must_use]
    pub fn into_current_bytes(self) -> Vec<u8> {
        self.current
    }
}

/// Detects a bounded document's schema version.
///
/// A missing version identifies the single supported legacy-v0 scaffold. A
/// current version is accepted, a newer version is reported distinctly, and
/// negative, fractional, null, string, duplicate, or otherwise malformed
/// version fields are rejected.
///
/// # Errors
///
/// Returns an error when the input exceeds the byte limit, is not one JSON
/// object, has a malformed version, or names a future schema version.
pub fn detect_schema_version(bytes: &[u8]) -> Result<u32, MigrationError> {
    ensure_bounded(bytes)?;
    let parsed: Value = serde_json::from_slice(bytes).map_err(|_| MigrationError::InvalidJson)?;
    if !parsed.is_object() {
        return Err(MigrationError::InvalidJson);
    }
    let probe: VersionProbe =
        serde_json::from_slice(bytes).map_err(|_| MigrationError::MalformedVersion)?;
    match probe.schema_version {
        VersionField::Missing | VersionField::Unsigned(0) => Ok(0),
        VersionField::Unsigned(version) if version == u64::from(CURRENT_SCHEMA_VERSION) => {
            Ok(CURRENT_SCHEMA_VERSION)
        }
        VersionField::Unsigned(version) if version > u64::from(CURRENT_SCHEMA_VERSION) => {
            Err(MigrationError::FutureVersion {
                found: version,
                current: CURRENT_SCHEMA_VERSION,
            })
        }
        VersionField::Unsigned(_) => Err(MigrationError::MalformedVersion),
    }
}

/// Migrates a bounded document while retaining exact original bytes.
///
/// # Errors
///
/// Returns an error for any detection failure or when legacy v0 does not match
/// the supported non-secret Codex-account scaffold and valid v1 constraints.
pub fn migrate(bytes: &[u8]) -> Result<Migration, MigrationError> {
    let version = detect_schema_version(bytes)?;
    if version == CURRENT_SCHEMA_VERSION {
        crate::config::load_config_bytes(bytes).map_err(|_| MigrationError::InvalidCurrent)?;
        return Ok(Migration {
            original: bytes.to_vec(),
            current: bytes.to_vec(),
            from_version: version,
        });
    }

    let legacy: LegacyV0 =
        serde_json::from_slice(bytes).map_err(|_| MigrationError::InvalidLegacy)?;
    if legacy.provider != "codex" {
        return Err(MigrationError::UnsupportedLegacyProvider);
    }
    let account =
        AccountKey::new(&legacy.account).map_err(|_| MigrationError::InvalidLegacyAccount)?;

    let current = CurrentV1 {
        schema_version: CURRENT_SCHEMA_VERSION,
        providers: vec![CurrentProvider {
            id: legacy.provider.clone(),
            instance_id: "default",
            enabled: true,
            accounts: vec![CurrentAccount {
                id: account.as_str().to_owned(),
                enabled: true,
            }],
        }],
        provider_order: vec![legacy.provider],
    };
    let current = serde_json::to_vec(&current).map_err(|_| MigrationError::Serialization)?;
    crate::config::load_config_bytes(&current).map_err(|_| MigrationError::InvalidLegacyAccount)?;
    Ok(Migration {
        original: bytes.to_vec(),
        current,
        from_version: 0,
    })
}

/// Convenience wrapper returning only the current-schema bytes.
///
/// # Errors
///
/// Returns the same errors as [`migrate`].
pub fn migrate_to_current(bytes: &[u8]) -> Result<Vec<u8>, MigrationError> {
    migrate(bytes).map(Migration::into_current_bytes)
}

fn ensure_bounded(bytes: &[u8]) -> Result<(), MigrationError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        Err(MigrationError::InputTooLarge)
    } else {
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct VersionProbe {
    #[serde(default)]
    schema_version: VersionField,
    #[serde(flatten)]
    _remaining: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Default)]
enum VersionField {
    #[default]
    Missing,
    Unsigned(u64),
}

impl<'de> Deserialize<'de> for VersionField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        value
            .as_u64()
            .map(Self::Unsigned)
            .ok_or_else(|| serde::de::Error::custom("schema version must be an unsigned integer"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV0 {
    #[serde(default, rename = "schema_version")]
    _schema_version: LegacyVersion,
    provider: String,
    account: String,
}

#[derive(Clone, Copy, Debug, Default)]
enum LegacyVersion {
    #[default]
    Missing,
    Zero,
}

impl<'de> Deserialize<'de> for LegacyVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 {
            Ok(Self::Zero)
        } else {
            Err(serde::de::Error::custom(
                "legacy schema version must be zero",
            ))
        }
    }
}

#[derive(Debug, Serialize)]
struct CurrentV1 {
    schema_version: u32,
    providers: Vec<CurrentProvider>,
    provider_order: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CurrentProvider {
    id: String,
    instance_id: &'static str,
    enabled: bool,
    accounts: Vec<CurrentAccount>,
}

#[derive(Debug, Serialize)]
struct CurrentAccount {
    id: String,
    enabled: bool,
}
