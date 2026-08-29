//! Locked JSON schema types for ordinary, non-secret configuration.

use std::path::PathBuf;

use oab_domain::{AccountKey, ProviderId, ProviderInstanceId};
use serde::{Deserialize, Serialize};

/// The only configuration schema version accepted by this build.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Maximum number of provider instances in one configuration.
pub const MAX_PROVIDER_INSTANCES: usize = 256;

/// Maximum number of accounts in one provider instance.
pub const MAX_ACCOUNTS_PER_INSTANCE: usize = 64;

/// Maximum number of accounts across one configuration.
pub const MAX_TOTAL_ACCOUNTS: usize = 2_048;

/// Maximum encoded endpoint length.
pub const MAX_ENDPOINT_BYTES: usize = 2_048;

/// Maximum encoded provider-owned path length.
pub const MAX_PROVIDER_PATH_BYTES: usize = 4_096;

/// Version 1 of the ordinary, non-secret configuration document.
///
/// Semantic validation is performed by [`super::load_config_bytes`] or
/// [`super::validate_config`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Numeric schema discriminator. It must equal
    /// [`CURRENT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Configured provider-instance routes.
    pub providers: Vec<ProviderConfig>,
    /// Display and refresh order for distinct provider groups.
    pub provider_order: Vec<ProviderId>,
}

/// One configured instance of a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Closed provider identifier from the domain registry.
    pub id: ProviderId,
    /// Canonical route identifier for this provider instance.
    pub instance_id: ProviderInstanceId,
    /// Whether this route participates in collection.
    pub enabled: bool,
    /// Optional provider API base endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional absolute path to provider-owned configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
    /// Accounts routed through this provider instance.
    pub accounts: Vec<AccountConfig>,
}

/// One non-secret account routing entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Canonical account routing identifier.
    pub id: AccountKey,
    /// Whether this account participates in collection.
    pub enabled: bool,
}
