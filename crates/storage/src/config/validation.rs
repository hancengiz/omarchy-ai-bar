//! Semantic validation for configuration schema v1.

use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;

use oab_domain::ProviderId;
use url::{Host, Url};

use super::schema::{
    AppConfig, CURRENT_SCHEMA_VERSION, MAX_ACCOUNTS_PER_INSTANCE, MAX_ENDPOINT_BYTES,
    MAX_PROVIDER_INSTANCES, MAX_PROVIDER_PATH_BYTES, MAX_TOTAL_ACCOUNTS,
};
use super::{ConfigError, DiagnosticCode};

/// Validates all bounded, routing, endpoint, and path invariants for schema v1.
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
            if matches!(provider, ProviderId::Ollama | ProviderId::LiteLlm)
                && is_canonical_loopback(endpoint, &host) =>
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
    let Some(authority) = endpoint
        .strip_prefix("http://")
        .and_then(|remainder| remainder.split('/').next())
    else {
        return false;
    };
    let raw_host = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        if !suffix.is_empty()
            && !suffix.strip_prefix(':').is_some_and(|port| {
                !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return false;
        }
        host
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        host
    } else {
        authority
    };

    match host {
        Host::Domain(domain) => *domain == "localhost" && raw_host == "localhost",
        Host::Ipv4(address) => address.octets()[0] == 127 && raw_host == address.to_string(),
        Host::Ipv6(address) => address.is_loopback() && raw_host == "::1",
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
