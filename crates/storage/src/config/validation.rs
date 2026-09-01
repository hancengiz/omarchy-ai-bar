//! Semantic validation for configuration schema v1.

use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;

use oab_domain::ProviderId;
use url::{Host, Url};

use super::schema::{
    AppConfig, CURRENT_SCHEMA_VERSION, MAX_ACCOUNTS_PER_INSTANCE, MAX_ENDPOINT_BYTES,
    MAX_PROVIDER_INSTANCES, MAX_PROVIDER_OPTION_DEPTH, MAX_PROVIDER_OPTION_ENTRIES,
    MAX_PROVIDER_OPTION_KEY_BYTES, MAX_PROVIDER_OPTION_NODES, MAX_PROVIDER_OPTION_TEXT_BYTES,
    MAX_PROVIDER_OPTION_TOTAL_TEXT_BYTES, MAX_PROVIDER_OPTION_VALUE_BYTES, MAX_PROVIDER_PATH_BYTES,
    MAX_TOTAL_ACCOUNTS, ProviderOptionValue, ProviderOptions,
};
use super::{ConfigError, DiagnosticCode, strict_secret_like_key};

/// Validates all bounded routing, endpoint, path, and provider-option
/// invariants for schema v1.
///
/// # Errors
///
/// Returns an error carrying only a stable diagnostic code. Configuration
/// values are never copied into the error.
pub fn validate_config(config: &AppConfig) -> Result<(), ConfigError> {
    if config.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(ConfigError::new(DiagnosticCode::UnsupportedSchemaVersion));
    }
    if config.providers.len() > MAX_PROVIDER_INSTANCES
        || config.provider_order.len() > ProviderId::ALL.len()
    {
        return Err(ConfigError::new(DiagnosticCode::CollectionTooLarge));
    }

    let mut routes = BTreeSet::new();
    let mut configured_providers = BTreeSet::new();
    let mut total_accounts = 0_usize;

    for provider in &config.providers {
        if !canonical_identifier(provider.instance_id.as_str(), true) {
            return Err(ConfigError::new(DiagnosticCode::InvalidIdentifier));
        }
        if !routes.insert((provider.id, provider.instance_id.as_str())) {
            return Err(ConfigError::new(DiagnosticCode::DuplicateProvider));
        }
        configured_providers.insert(provider.id);

        if provider.accounts.len() > MAX_ACCOUNTS_PER_INSTANCE {
            return Err(ConfigError::new(DiagnosticCode::CollectionTooLarge));
        }
        total_accounts = total_accounts
            .checked_add(provider.accounts.len())
            .ok_or_else(|| ConfigError::new(DiagnosticCode::CollectionTooLarge))?;
        if total_accounts > MAX_TOTAL_ACCOUNTS {
            return Err(ConfigError::new(DiagnosticCode::CollectionTooLarge));
        }

        let mut account_ids = BTreeSet::new();
        for account in &provider.accounts {
            if !canonical_identifier(account.id.as_str(), false) {
                return Err(ConfigError::new(DiagnosticCode::InvalidIdentifier));
            }
            if !account_ids.insert(account.id.as_str()) {
                return Err(ConfigError::new(DiagnosticCode::ConflictingAccountId));
            }
        }

        if let Some(endpoint) = &provider.endpoint {
            validate_endpoint(provider.id, endpoint)?;
        }
        if let Some(path) = &provider.config_path {
            validate_provider_path(path)?;
        }
        validate_provider_options(&provider.options)?;
    }

    let mut ordered_providers = BTreeSet::new();
    for provider in &config.provider_order {
        if !ordered_providers.insert(*provider) {
            return Err(ConfigError::new(DiagnosticCode::DuplicateProviderOrder));
        }
    }
    if ordered_providers != configured_providers {
        return Err(ConfigError::new(DiagnosticCode::ProviderOrderMismatch));
    }

    Ok(())
}

fn validate_provider_options(options: &ProviderOptions) -> Result<(), ConfigError> {
    for value in [
        options.region.as_deref(),
        options.workspace.as_deref(),
        options.project.as_deref(),
        options.organization.as_deref(),
        options.team.as_deref(),
        options.enterprise_host.as_deref(),
        options.deployment.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_common_option_text(value)?;
    }

    let mut budget = ProviderOptionBudget::default();
    validate_provider_option_map(&options.extensions, 0, &mut budget)
}

fn validate_common_option_text(value: &str) -> Result<(), ConfigError> {
    if value.len() > MAX_PROVIDER_OPTION_TEXT_BYTES {
        return Err(ConfigError::new(DiagnosticCode::TextTooLong));
    }
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ConfigError::new(DiagnosticCode::InvalidProviderOption));
    }
    Ok(())
}

#[derive(Default)]
struct ProviderOptionBudget {
    nodes: usize,
    text_bytes: usize,
}

impl ProviderOptionBudget {
    fn add_node(&mut self) -> Result<(), ConfigError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| ConfigError::new(DiagnosticCode::CollectionTooLarge))?;
        if self.nodes > MAX_PROVIDER_OPTION_NODES {
            return Err(ConfigError::new(DiagnosticCode::CollectionTooLarge));
        }
        Ok(())
    }

    fn add_text(&mut self, bytes: usize) -> Result<(), ConfigError> {
        self.text_bytes = self
            .text_bytes
            .checked_add(bytes)
            .ok_or_else(|| ConfigError::new(DiagnosticCode::TextTooLong))?;
        if self.text_bytes > MAX_PROVIDER_OPTION_TOTAL_TEXT_BYTES {
            return Err(ConfigError::new(DiagnosticCode::TextTooLong));
        }
        Ok(())
    }
}

fn validate_provider_option_map(
    options: &std::collections::BTreeMap<String, ProviderOptionValue>,
    depth: usize,
    budget: &mut ProviderOptionBudget,
) -> Result<(), ConfigError> {
    if depth > MAX_PROVIDER_OPTION_DEPTH || options.len() > MAX_PROVIDER_OPTION_ENTRIES {
        return Err(ConfigError::new(DiagnosticCode::CollectionTooLarge));
    }
    for (key, value) in options {
        validate_provider_option_key(key, budget)?;
        validate_provider_option_value(value, depth, budget)?;
    }
    Ok(())
}

fn validate_provider_option_key(
    key: &str,
    budget: &mut ProviderOptionBudget,
) -> Result<(), ConfigError> {
    if key.len() > MAX_PROVIDER_OPTION_KEY_BYTES {
        return Err(ConfigError::new(DiagnosticCode::TextTooLong));
    }
    budget.add_text(key.len())?;
    if strict_secret_like_key(key) {
        return Err(ConfigError::new(DiagnosticCode::SecretField));
    }

    let bytes = key.as_bytes();
    if bytes.is_empty()
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || key.contains("..")
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ConfigError::new(DiagnosticCode::InvalidProviderOption));
    }
    Ok(())
}

fn validate_provider_option_value(
    value: &ProviderOptionValue,
    depth: usize,
    budget: &mut ProviderOptionBudget,
) -> Result<(), ConfigError> {
    budget.add_node()?;
    match value {
        ProviderOptionValue::Boolean(_) | ProviderOptionValue::Number(_) => Ok(()),
        ProviderOptionValue::Text(value) => {
            if value.len() > MAX_PROVIDER_OPTION_VALUE_BYTES {
                return Err(ConfigError::new(DiagnosticCode::TextTooLong));
            }
            if value.chars().any(char::is_control) {
                return Err(ConfigError::new(DiagnosticCode::InvalidProviderOption));
            }
            budget.add_text(value.len())
        }
        ProviderOptionValue::Array(values) => {
            if values.len() > MAX_PROVIDER_OPTION_ENTRIES {
                return Err(ConfigError::new(DiagnosticCode::CollectionTooLarge));
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or_else(|| ConfigError::new(DiagnosticCode::CollectionTooLarge))?;
            if child_depth > MAX_PROVIDER_OPTION_DEPTH {
                return Err(ConfigError::new(DiagnosticCode::CollectionTooLarge));
            }
            for child in values {
                validate_provider_option_value(child, child_depth, budget)?;
            }
            Ok(())
        }
        ProviderOptionValue::Object(values) => {
            let child_depth = depth
                .checked_add(1)
                .ok_or_else(|| ConfigError::new(DiagnosticCode::CollectionTooLarge))?;
            validate_provider_option_map(values, child_depth, budget)
        }
    }
}

fn canonical_identifier(value: &str, allow_at: bool) -> bool {
    if value.is_empty() || value == "." || value == ".." || value.contains("..") {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'+')
            || (allow_at && *byte == b'@')
    })
}

fn validate_endpoint(provider: ProviderId, endpoint: &str) -> Result<(), ConfigError> {
    if endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(ConfigError::new(DiagnosticCode::TextTooLong));
    }
    let parsed =
        Url::parse(endpoint).map_err(|_| ConfigError::new(DiagnosticCode::InvalidEndpoint))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !has_nonempty_authority(endpoint)
        || authority_contains_at_sign(endpoint)
    {
        return Err(ConfigError::new(DiagnosticCode::InvalidEndpoint));
    }
    let host = parsed
        .host()
        .ok_or_else(|| ConfigError::new(DiagnosticCode::InvalidEndpoint))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http"
            if matches!(
                provider,
                ProviderId::Ollama | ProviderId::Sub2Api | ProviderId::Wayfinder
            ) && is_canonical_loopback(endpoint, &host) =>
        {
            Ok(())
        }
        "http"
            if matches!(provider, ProviderId::LiteLlm | ProviderId::LlmProxy)
                && is_canonical_private_network(endpoint, &host) =>
        {
            Ok(())
        }
        _ => Err(ConfigError::new(DiagnosticCode::InvalidEndpoint)),
    }
}

fn has_nonempty_authority(endpoint: &str) -> bool {
    endpoint
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split('/').next())
        .is_some_and(|authority| !authority.is_empty())
}

fn authority_contains_at_sign(endpoint: &str) -> bool {
    endpoint
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split('/').next())
        .is_some_and(|authority| authority.contains('@'))
}

fn is_canonical_loopback(endpoint: &str, host: &Host<&str>) -> bool {
    let Some(raw_host) = raw_http_host(endpoint) else {
        return false;
    };

    match host {
        Host::Domain(domain) => {
            domain.eq_ignore_ascii_case("localhost") && raw_host.eq_ignore_ascii_case(domain)
        }
        Host::Ipv4(address) => address.is_loopback() && raw_host == address.to_string(),
        Host::Ipv6(address) => address.is_loopback() && raw_host == address.to_string(),
    }
}

fn is_canonical_private_network(endpoint: &str, host: &Host<&str>) -> bool {
    if is_canonical_loopback(endpoint, host) {
        return true;
    }
    let Some(raw_host) = raw_http_host(endpoint) else {
        return false;
    };
    match host {
        Host::Domain(domain) => {
            let without_root = domain.trim_end_matches('.');
            without_root
                .rsplit_once('.')
                .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("local"))
                && raw_host.eq_ignore_ascii_case(domain)
        }
        Host::Ipv4(address) => {
            (address.is_private() || address.is_link_local()) && raw_host == address.to_string()
        }
        Host::Ipv6(address) => {
            let first = address.segments()[0];
            (first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80)
                && raw_host == address.to_string()
        }
    }
}

fn raw_http_host(endpoint: &str) -> Option<&str> {
    let authority = endpoint
        .strip_prefix("http://")?
        .split('/')
        .next()
        .filter(|authority| !authority.is_empty())?;
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']')?;
        if suffix.is_empty()
            || suffix.strip_prefix(':').is_some_and(|port| {
                !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Some(host);
        }
        return None;
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(host)
    } else {
        Some(authority)
    }
}

fn validate_provider_path(path: &std::path::Path) -> Result<(), ConfigError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_PROVIDER_PATH_BYTES {
        return Err(ConfigError::new(DiagnosticCode::TextTooLong));
    }
    if !path.is_absolute()
        || bytes.len() < 2
        || bytes.starts_with(b"//")
        || bytes.ends_with(b"/")
        || bytes.iter().any(u8::is_ascii_control)
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(ConfigError::new(DiagnosticCode::UnsafeProviderPath));
    }
    Ok(())
}
