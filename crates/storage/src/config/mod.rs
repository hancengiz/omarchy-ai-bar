//! Typed, bounded, non-secret application configuration.

mod schema;
mod validation;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde_json::Value;

pub use schema::{
    AccountConfig, AppConfig, CURRENT_SCHEMA_VERSION, MAX_ACCOUNTS_PER_INSTANCE,
    MAX_ENDPOINT_BYTES, MAX_PROVIDER_INSTANCES, MAX_PROVIDER_PATH_BYTES, MAX_TOTAL_ACCOUNTS,
    ProviderConfig,
};
pub use validation::validate_config;

/// Maximum accepted size of an ordinary configuration document.
pub const MAX_CONFIG_BYTES: usize = 256 * 1_024;

/// Parses and validates one complete schema-v1 JSON document.
///
/// The input is bounded before parsing. Secret-like object keys are rejected
/// before typed deserialization, including when they occur inside an otherwise
/// unknown object. Returned errors never contain input, parser, provider,
/// endpoint, or path text.
///
/// # Errors
///
/// Returns a [`ConfigError`] with a stable, non-sensitive diagnostic code for
/// every rejected document.
pub fn load_config_bytes(bytes: &[u8]) -> Result<AppConfig, ConfigError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(DiagnosticCode::ConfigTooLarge));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ConfigError::new(DiagnosticCode::JsonInvalid))?;
    if contains_secret_like_field(&value) {
        return Err(ConfigError::new(DiagnosticCode::SecretField));
    }
    match value.get("schema_version") {
        Some(Value::Number(version))
            if version.as_u64() == Some(u64::from(CURRENT_SCHEMA_VERSION)) => {}
        Some(Value::Number(_)) => {
            return Err(ConfigError::new(DiagnosticCode::UnsupportedSchemaVersion));
        }
        _ => return Err(ConfigError::new(DiagnosticCode::SchemaInvalid)),
    }
    let config: AppConfig = serde_json::from_slice(bytes)
        .map_err(|_| ConfigError::new(DiagnosticCode::SchemaInvalid))?;
    validate_config(&config)?;
    Ok(config)
}

fn contains_secret_like_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| secret_like_key(key) || contains_secret_like_field(value)),
        Value::Array(values) => values.iter().any(contains_secret_like_field),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn secret_like_key(key: &str) -> bool {
    let normalized: String = key
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect();
    [
        "apikey",
        "accesstoken",
        "refreshtoken",
        "bearertoken",
        "token",
        "password",
        "passwd",
        "secret",
        "privatekey",
        "credential",
        "authorization",
        "cookie",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

/// Stable, path-free reason code for a configuration rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticCode {
    /// The byte limit was exceeded before parsing.
    ConfigTooLarge,
    /// The input is not one complete JSON value.
    JsonInvalid,
    /// JSON fields or types do not match schema v1.
    SchemaInvalid,
    /// The numeric schema version is not supported by this build.
    UnsupportedSchemaVersion,
    /// Ordinary configuration contained a secret-like field name.
    SecretField,
    /// A bounded collection exceeded its limit.
    CollectionTooLarge,
    /// A bounded endpoint or provider path exceeded its limit.
    TextTooLong,
    /// A provider or account route is not in canonical form.
    InvalidIdentifier,
    /// The same provider and instance route occurs more than once.
    DuplicateProvider,
    /// A provider occurs more than once in the group order.
    DuplicateProviderOrder,
    /// The group order is not the exact set of configured providers.
    ProviderOrderMismatch,
    /// An account ID conflicts within one provider instance.
    ConflictingAccountId,
    /// An endpoint violates transport or URL restrictions.
    InvalidEndpoint,
    /// A provider-owned path is not absolute and lexically safe.
    UnsafeProviderPath,
    /// The live configuration file could not be read safely.
    ConfigReadFailed,
}

impl DiagnosticCode {
    /// Returns the stable machine-facing spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigTooLarge => "config_too_large",
            Self::JsonInvalid => "json_invalid",
            Self::SchemaInvalid => "schema_invalid",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::SecretField => "secret_field",
            Self::CollectionTooLarge => "collection_too_large",
            Self::TextTooLong => "text_too_long",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::DuplicateProvider => "duplicate_provider",
            Self::DuplicateProviderOrder => "duplicate_provider_order",
            Self::ProviderOrderMismatch => "provider_order_mismatch",
            Self::ConflictingAccountId => "conflicting_account_id",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::UnsafeProviderPath => "unsafe_provider_path",
            Self::ConfigReadFailed => "config_read_failed",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::ConfigTooLarge => "configuration exceeds the byte limit",
            Self::JsonInvalid => "configuration is not valid JSON",
            Self::SchemaInvalid => "configuration does not match schema v1",
            Self::UnsupportedSchemaVersion => "configuration schema version is unsupported",
            Self::SecretField => "ordinary configuration must not contain secret fields",
            Self::CollectionTooLarge => "a configuration collection exceeds its limit",
            Self::TextTooLong => "a configuration text field exceeds its limit",
            Self::InvalidIdentifier => "a configuration identifier is not canonical",
            Self::DuplicateProvider => "a provider instance route is duplicated",
            Self::DuplicateProviderOrder => "the provider order contains a duplicate",
            Self::ProviderOrderMismatch => "the provider order does not match configured providers",
            Self::ConflictingAccountId => {
                "an account identifier conflicts within a provider instance"
            }
            Self::InvalidEndpoint => "a provider endpoint is not allowed",
            Self::UnsafeProviderPath => "a provider path is not lexically safe",
            Self::ConfigReadFailed => "the configuration file could not be read safely",
        }
    }
}

impl Display for DiagnosticCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Non-sensitive configuration error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    code: DiagnosticCode,
}

impl ConfigError {
    pub(crate) const fn new(code: DiagnosticCode) -> Self {
        Self { code }
    }

    /// Returns the stable machine-facing diagnostic code.
    #[must_use]
    pub const fn code(self) -> DiagnosticCode {
        self.code
    }
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl Error for ConfigError {}
