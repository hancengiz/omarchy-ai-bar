//! Locked JSON schema types for ordinary, non-secret configuration.

use std::collections::BTreeMap;
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

/// Maximum encoded length of one common provider option.
pub const MAX_PROVIDER_OPTION_TEXT_BYTES: usize = 2_048;

/// Maximum number of entries in one provider-specific option object or array.
pub const MAX_PROVIDER_OPTION_ENTRIES: usize = 64;

/// Maximum encoded length of one provider-specific option key.
pub const MAX_PROVIDER_OPTION_KEY_BYTES: usize = 128;

/// Maximum encoded length of one provider-specific string value.
pub const MAX_PROVIDER_OPTION_VALUE_BYTES: usize = 4_096;

/// Maximum aggregate key and string bytes in one provider-specific option map.
pub const MAX_PROVIDER_OPTION_TOTAL_TEXT_BYTES: usize = 64 * 1_024;

/// Maximum number of values in one provider-specific option map, including
/// nested array and object values.
pub const MAX_PROVIDER_OPTION_NODES: usize = 512;

/// Maximum nesting depth below a provider-specific option map.
pub const MAX_PROVIDER_OPTION_DEPTH: usize = 6;

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
    /// Typed, ordinary provider behavior and routing options. Authentication
    /// material belongs in the credential store, never in this object.
    #[serde(default, skip_serializing_if = "ProviderOptions::is_empty")]
    pub options: ProviderOptions,
    /// Accounts routed through this provider instance.
    pub accounts: Vec<AccountConfig>,
}

/// Provider data-source preference, matching the common `CodexBar` fetch modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSourceMode {
    /// Let the provider choose the best available source.
    Auto,
    /// Use an authenticated browser session.
    Web,
    /// Use the provider's local command-line client.
    Cli,
    /// Use a non-secret OAuth credential resolved by the authentication layer.
    Oauth,
    /// Use an API credential resolved by the authentication layer.
    Api,
    /// Use a Codex personal access token resolved by the authentication layer.
    /// This remains distinct from a generic API credential.
    Pat,
    /// Use a provider API key resolved by the authentication layer.
    ApiKey,
    /// Use an explicitly configured, validated provider endpoint.
    ConfigurableEndpoint,
    /// Use a manually managed browser credential from the credential store.
    ManualCookie,
    /// Use isolated browser-profile session discovery.
    BrowserSession,
    /// Read provider-owned local data without invoking its CLI.
    Local,
    /// Use signed cloud-profile, workload, or service-account credentials.
    CloudCredentials,
}

/// Browser-cookie discovery preference. The cookie itself is deliberately not
/// representable in ordinary configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderCookieSource {
    /// Discover an authenticated browser profile when available.
    Auto,
    /// Use a manually managed credential from the credential store.
    Manual,
    /// Do not use browser cookies for this provider.
    Off,
}

/// Common, non-secret options for one provider instance.
///
/// Unknown common fields are rejected. Provider-specific extensions must live
/// below [`Self::extensions`], where their shape is recursively bounded
/// and secret-like keys are rejected during semantic validation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOptions {
    /// Preferred usage source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ProviderSourceMode>,
    /// Browser-cookie discovery preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_source: Option<ProviderCookieSource>,
    /// Whether optional usage and balance enrichments should be collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extras_enabled: Option<bool>,
    /// Provider-defined deployment region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Provider-defined workspace selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// Provider-defined project selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Provider-defined organization selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Provider-defined team selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// Provider-defined enterprise host or base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_host: Option<String>,
    /// Provider-defined deployment selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    /// Extensible, recursively bounded provider-specific options.
    #[serde(
        default,
        rename = "provider_options",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub extensions: BTreeMap<String, ProviderOptionValue>,
}

impl ProviderOptions {
    /// Returns whether this object has no explicit overrides.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source.is_none()
            && self.cookie_source.is_none()
            && self.extras_enabled.is_none()
            && self.region.is_none()
            && self.workspace.is_none()
            && self.project.is_none()
            && self.organization.is_none()
            && self.team.is_none()
            && self.enterprise_host.is_none()
            && self.deployment.is_none()
            && self.extensions.is_empty()
    }
}

/// One JSON-compatible, non-null provider-specific option value.
///
/// Recursive collections are accepted for provider evolution but are bounded
/// by [`super::validate_config`]. JSON numbers use [`serde_json::Number`] so
/// equality and round trips do not rely on lossy floating-point conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderOptionValue {
    /// A Boolean switch.
    Boolean(bool),
    /// An integer or finite decimal JSON number.
    Number(serde_json::Number),
    /// A bounded string.
    Text(String),
    /// A bounded list of option values.
    Array(Vec<Self>),
    /// A bounded object of option values.
    Object(BTreeMap<String, Self>),
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
