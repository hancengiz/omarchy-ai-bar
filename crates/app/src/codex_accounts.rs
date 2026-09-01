//! CodexBar-compatible managed Codex account lifecycle for Linux.
//!
//! Every managed login receives an isolated `CODEX_HOME`. Ordinary config
//! stores only the opaque routing ID; OAuth material remains in the
//! provider-owned `auth.json` inside the private application data directory.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use getrandom::getrandom;
use oab_domain::{AccountKey, ProviderId, ProviderInstanceId};
use oab_providers::executable::resolve_executable;
use oab_providers::providers::codex_files::{CodexCredentialPaths, load_bearer_for_usage};
use oab_storage::atomic_file::{atomic_write, read_private_file};
use oab_storage::config::{
    AccountConfig, AppConfig, CURRENT_SCHEMA_VERSION, MAX_CONFIG_BYTES, ProviderConfig,
    ProviderOptionValue, ProviderOptions, validate_config,
};
use oab_storage::paths::AppPaths;
use serde::Serialize;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub(crate) const AMBIENT_ACCOUNT_ID: &str = "ambient";
pub(crate) const ACTIVE_ACCOUNT_OPTION: &str = "active_account";
const ACCOUNT_ID_RANDOM_BYTES: usize = 12;
const ACCOUNT_ID_ATTEMPTS: usize = 32;

#[derive(Debug, Error)]
pub(crate) enum ManagedCodexAccountError {
    #[error("managed Codex account storage is unavailable")]
    Storage,
    #[error("Codex executable is unavailable")]
    MissingExecutable,
    #[error("Codex login did not complete")]
    LoginFailed,
    #[error("Codex login did not produce a usable OAuth identity")]
    MissingIdentity,
    #[error("managed Codex account is unknown")]
    UnknownAccount,
    #[error("managed Codex account identifier is invalid")]
    InvalidAccount,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ManagedCodexAccountSummary {
    pub(crate) id: String,
    pub(crate) email: Option<String>,
    pub(crate) provider_account_id: Option<String>,
    pub(crate) active: bool,
    pub(crate) enabled: bool,
    pub(crate) ambient: bool,
}

pub(crate) fn load_config(paths: &AppPaths) -> Result<AppConfig, ManagedCodexAccountError> {
    match fs::symlink_metadata(paths.config_file()) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(empty_config()),
        Err(_) => return Err(ManagedCodexAccountError::Storage),
        Ok(_) => {}
    }
    match read_private_file(paths.config_file(), MAX_CONFIG_BYTES)
        .map_err(|_| ManagedCodexAccountError::Storage)?
    {
        Some(bytes) => oab_storage::config::load_config_bytes(&bytes)
            .map_err(|_| ManagedCodexAccountError::Storage),
        None => Ok(empty_config()),
    }
}

fn empty_config() -> AppConfig {
    AppConfig {
        schema_version: CURRENT_SCHEMA_VERSION,
        providers: Vec::new(),
        provider_order: Vec::new(),
    }
}

pub(crate) fn write_config(
    paths: &AppPaths,
    config: &AppConfig,
) -> Result<(), ManagedCodexAccountError> {
    validate_config(config).map_err(|_| ManagedCodexAccountError::Storage)?;
    let mut bytes =
        serde_json::to_vec_pretty(config).map_err(|_| ManagedCodexAccountError::Storage)?;
    bytes.push(b'\n');
    atomic_write(paths.config_file(), &bytes).map_err(|_| ManagedCodexAccountError::Storage)
}

pub(crate) fn account_home(
    paths: &AppPaths,
    account: &AccountKey,
) -> Result<PathBuf, ManagedCodexAccountError> {
    if account.as_str() == AMBIENT_ACCOUNT_ID {
        return Err(ManagedCodexAccountError::InvalidAccount);
    }
    Ok(accounts_root(paths).join(account.as_str()))
}

pub(crate) fn configured_managed_accounts(config: Option<&AppConfig>) -> Vec<AccountConfig> {
    codex_route(config)
        .map(|route| route.accounts.clone())
        .unwrap_or_default()
}

pub(crate) fn active_account_id(config: Option<&AppConfig>) -> &str {
    codex_route(config)
        .and_then(|route| route.options.extensions.get(ACTIVE_ACCOUNT_OPTION))
        .and_then(|value| match value {
            ProviderOptionValue::Text(value) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or(AMBIENT_ACCOUNT_ID)
}

pub(crate) fn list(
    paths: &AppPaths,
) -> Result<Vec<ManagedCodexAccountSummary>, ManagedCodexAccountError> {
    let config = load_config(paths)?;
    let active = active_account_id(Some(&config));
    let mut accounts = vec![ambient_summary(paths, active)];
    for account in configured_managed_accounts(Some(&config)) {
        let identity = managed_identity(paths, &account.id).ok();
        accounts.push(ManagedCodexAccountSummary {
            id: account.id.as_str().to_owned(),
            email: identity
                .as_ref()
                .and_then(|identity| identity.email.clone()),
            provider_account_id: identity.and_then(|identity| identity.provider_account_id),
            active: active == account.id.as_str(),
            enabled: account.enabled,
            ambient: false,
        });
    }
    Ok(accounts)
}

pub(crate) fn login(
    paths: &AppPaths,
) -> Result<ManagedCodexAccountSummary, ManagedCodexAccountError> {
    paths
        .create_private_directories()
        .map_err(|_| ManagedCodexAccountError::Storage)?;
    let root = accounts_root(paths);
    ensure_private_directory(&root)?;
    let account = allocate_account_id(&root)?;
    let home = account_home(paths, &account)?;
    ensure_private_directory(&home)?;

    let executable = resolve_executable(
        "codex",
        env::var("OMARCHY_AI_BAR_CODEX_EXECUTABLE").ok().as_deref(),
        env::var_os("PATH").as_deref(),
        &[],
    )
    .map_err(|_| ManagedCodexAccountError::MissingExecutable)?
    .ok_or(ManagedCodexAccountError::MissingExecutable)?;

    println!("Sign in to the Codex account you want Omarchy AI Bar to manage.");
    println!("This login is isolated and will not replace ~/.codex/auth.json.");
    let status = Command::new(executable.as_path())
        .arg("login")
        .env("CODEX_HOME", &home)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|_| ManagedCodexAccountError::LoginFailed)?;
    if !status.success() {
        remove_failed_home(&home);
        return Err(ManagedCodexAccountError::LoginFailed);
    }

    let identity = match managed_identity(paths, &account) {
        Ok(identity) if identity.email.is_some() || identity.provider_account_id.is_some() => {
            identity
        }
        _ => {
            remove_failed_home(&home);
            return Err(ManagedCodexAccountError::MissingIdentity);
        }
    };
    let mut config = load_config(paths)?;
    let duplicate_accounts = duplicate_accounts(paths, &config, &identity);
    let route = codex_route_mut(&mut config);
    route.enabled = true;
    route
        .accounts
        .retain(|candidate| !duplicate_accounts.contains(&candidate.id));
    route.accounts.push(AccountConfig {
        id: account.clone(),
        enabled: true,
    });
    route.options.extensions.insert(
        ACTIVE_ACCOUNT_OPTION.to_owned(),
        ProviderOptionValue::Text(account.as_str().to_owned()),
    );
    if !config.provider_order.contains(&ProviderId::Codex) {
        config.provider_order.push(ProviderId::Codex);
    }
    if let Err(error) = write_config(paths, &config) {
        remove_failed_home(&home);
        return Err(error);
    }
    for duplicate in duplicate_accounts {
        archive_managed_home(paths, &duplicate)?;
    }

    Ok(ManagedCodexAccountSummary {
        id: account.as_str().to_owned(),
        email: identity.email,
        provider_account_id: identity.provider_account_id,
        active: true,
        enabled: true,
        ambient: false,
    })
}

pub(crate) fn activate(paths: &AppPaths, requested: &str) -> Result<(), ManagedCodexAccountError> {
    let mut config = load_config(paths)?;
    if requested != AMBIENT_ACCOUNT_ID
        && !configured_managed_accounts(Some(&config))
            .iter()
            .any(|account| account.id.as_str() == requested)
    {
        return Err(ManagedCodexAccountError::UnknownAccount);
    }
    let route = codex_route_mut(&mut config);
    route.options.extensions.insert(
        ACTIVE_ACCOUNT_OPTION.to_owned(),
        ProviderOptionValue::Text(requested.to_owned()),
    );
    write_config(paths, &config)
}

pub(crate) fn remove(paths: &AppPaths, requested: &str) -> Result<(), ManagedCodexAccountError> {
    let account =
        AccountKey::new(requested).map_err(|_| ManagedCodexAccountError::InvalidAccount)?;
    if account.as_str() == AMBIENT_ACCOUNT_ID {
        return Err(ManagedCodexAccountError::InvalidAccount);
    }
    let mut config = load_config(paths)?;
    let active = active_account_id(Some(&config)).to_owned();
    let route = codex_route_mut(&mut config);
    let before = route.accounts.len();
    route.accounts.retain(|candidate| candidate.id != account);
    if route.accounts.len() == before {
        return Err(ManagedCodexAccountError::UnknownAccount);
    }
    if active == account.as_str() {
        route.options.extensions.insert(
            ACTIVE_ACCOUNT_OPTION.to_owned(),
            ProviderOptionValue::Text(AMBIENT_ACCOUNT_ID.to_owned()),
        );
    }
    write_config(paths, &config)?;

    archive_managed_home(paths, &account)
}

#[derive(Debug)]
struct ManagedIdentity {
    email: Option<String>,
    provider_account_id: Option<String>,
}

fn managed_identity(
    paths: &AppPaths,
    account: &AccountKey,
) -> Result<ManagedIdentity, ManagedCodexAccountError> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ManagedCodexAccountError::Storage)?;
    let managed_home = account_home(paths, account)?;
    let credentials = CodexCredentialPaths::resolve(
        &home,
        Some(managed_home.as_os_str()),
        env::var_os("XDG_DATA_HOME").as_deref(),
    )
    .map_err(|_| ManagedCodexAccountError::MissingIdentity)?;
    identity_from_paths(&credentials)
}

fn identity_from_paths(
    credentials: &CodexCredentialPaths,
) -> Result<ManagedIdentity, ManagedCodexAccountError> {
    let bearer = load_bearer_for_usage(credentials, false, &CancellationToken::new())
        .map_err(|_| ManagedCodexAccountError::MissingIdentity)?;
    let hints = bearer.identity_hints();
    Ok(ManagedIdentity {
        email: hints.email().map(str::to_owned),
        provider_account_id: bearer.account_id().map(str::to_owned),
    })
}

fn ambient_summary(_paths: &AppPaths, active: &str) -> ManagedCodexAccountSummary {
    let identity = ambient_identity().ok();
    ManagedCodexAccountSummary {
        id: AMBIENT_ACCOUNT_ID.to_owned(),
        email: identity
            .as_ref()
            .and_then(|identity| identity.email.clone()),
        provider_account_id: identity.and_then(|identity| identity.provider_account_id),
        active: active == AMBIENT_ACCOUNT_ID,
        enabled: true,
        ambient: true,
    }
}

fn ambient_identity() -> Result<ManagedIdentity, ManagedCodexAccountError> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ManagedCodexAccountError::Storage)?;
    let credentials = CodexCredentialPaths::resolve(
        &home,
        env::var_os("CODEX_HOME").as_deref(),
        env::var_os("XDG_DATA_HOME").as_deref(),
    )
    .map_err(|_| ManagedCodexAccountError::MissingIdentity)?;
    identity_from_paths(&credentials)
}

fn duplicate_accounts(
    paths: &AppPaths,
    config: &AppConfig,
    identity: &ManagedIdentity,
) -> Vec<AccountKey> {
    configured_managed_accounts(Some(config))
        .into_iter()
        .filter_map(|account| {
            let existing = managed_identity(paths, &account.id).ok()?;
            same_identity(identity, &existing).then_some(account.id)
        })
        .collect()
}

fn same_identity(left: &ManagedIdentity, right: &ManagedIdentity) -> bool {
    match (
        left.provider_account_id.as_deref(),
        right.provider_account_id.as_deref(),
    ) {
        (Some(left), Some(right)) => left == right,
        (None, None) => match (left.email.as_deref(), right.email.as_deref()) {
            (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
            _ => false,
        },
        _ => false,
    }
}

fn codex_route(config: Option<&AppConfig>) -> Option<&ProviderConfig> {
    config.and_then(|config| {
        config
            .providers
            .iter()
            .find(|route| route.id == ProviderId::Codex && route.instance_id.as_str() == "default")
    })
}

fn codex_route_mut(config: &mut AppConfig) -> &mut ProviderConfig {
    let default = ProviderInstanceId::new("default").expect("fixed route is canonical");
    if let Some(index) = config
        .providers
        .iter()
        .position(|route| route.id == ProviderId::Codex && route.instance_id == default)
    {
        return &mut config.providers[index];
    }
    config.providers.push(ProviderConfig {
        id: ProviderId::Codex,
        instance_id: default,
        enabled: true,
        endpoint: None,
        config_path: None,
        options: ProviderOptions::default(),
        accounts: Vec::new(),
    });
    config
        .providers
        .last_mut()
        .expect("Codex route was inserted")
}

fn accounts_root(paths: &AppPaths) -> PathBuf {
    paths.data_dir().join("codex/managed-accounts")
}

fn allocate_account_id(root: &Path) -> Result<AccountKey, ManagedCodexAccountError> {
    for _ in 0..ACCOUNT_ID_ATTEMPTS {
        let mut random = [0_u8; ACCOUNT_ID_RANDOM_BYTES];
        getrandom(&mut random).map_err(|_| ManagedCodexAccountError::Storage)?;
        let mut encoded = String::with_capacity(5 + ACCOUNT_ID_RANDOM_BYTES * 2);
        encoded.push_str("acct-");
        for byte in random {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        let account = AccountKey::new(encoded).map_err(|_| ManagedCodexAccountError::Storage)?;
        if !root.join(account.as_str()).exists() {
            return Ok(account);
        }
    }
    Err(ManagedCodexAccountError::Storage)
}

fn ensure_private_directory(path: &Path) -> Result<(), ManagedCodexAccountError> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        ensure_private_directory(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == nix::unistd::geteuid().as_raw() =>
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| ManagedCodexAccountError::Storage)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| ManagedCodexAccountError::Storage)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| ManagedCodexAccountError::Storage)
        }
        Ok(_) | Err(_) => Err(ManagedCodexAccountError::Storage),
    }
}

fn remove_failed_home(home: &Path) {
    if home.parent().is_some_and(|parent| {
        parent
            .file_name()
            .is_some_and(|name| name == "managed-accounts")
    }) {
        let _ = fs::remove_dir_all(home);
    }
}

fn archive_managed_home(
    paths: &AppPaths,
    account: &AccountKey,
) -> Result<(), ManagedCodexAccountError> {
    let home = account_home(paths, account)?;
    if !home.exists() {
        return Ok(());
    }
    let removed_root = paths.data_dir().join("codex/removed-accounts");
    ensure_private_directory(&removed_root)?;
    let destination = (0_u16..=u16::MAX)
        .map(|suffix| {
            if suffix == 0 {
                removed_root.join(account.as_str())
            } else {
                removed_root.join(format!("{}-{suffix}", account.as_str()))
            }
        })
        .find(|candidate| !candidate.exists())
        .ok_or(ManagedCodexAccountError::Storage)?;
    fs::rename(home, destination).map_err(|_| ManagedCodexAccountError::Storage)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;

    use tempfile::TempDir;

    use super::*;

    fn test_paths() -> (TempDir, AppPaths) {
        let root = tempfile::tempdir().expect("temporary root");
        let mut environment = BTreeMap::<String, OsString>::new();
        environment.insert("HOME".into(), root.path().join("home").into_os_string());
        environment.insert(
            "XDG_CONFIG_HOME".into(),
            root.path().join("config").into_os_string(),
        );
        environment.insert(
            "XDG_DATA_HOME".into(),
            root.path().join("data").into_os_string(),
        );
        environment.insert(
            "XDG_CACHE_HOME".into(),
            root.path().join("cache").into_os_string(),
        );
        environment.insert(
            "XDG_RUNTIME_DIR".into(),
            root.path().join("runtime").into_os_string(),
        );
        for path in environment.values() {
            fs::create_dir_all(path).expect("create XDG root");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private XDG root");
        }
        let paths = AppPaths::from_env_map(&environment).expect("app paths");
        paths
            .create_private_directories()
            .expect("private app paths");
        (root, paths)
    }

    fn config_with(account: &AccountKey) -> AppConfig {
        AppConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            providers: vec![ProviderConfig {
                id: ProviderId::Codex,
                instance_id: ProviderInstanceId::new("default").expect("default"),
                enabled: true,
                endpoint: None,
                config_path: None,
                options: ProviderOptions::default(),
                accounts: vec![AccountConfig {
                    id: account.clone(),
                    enabled: true,
                }],
            }],
            provider_order: vec![ProviderId::Codex],
        }
    }

    #[test]
    fn activation_selects_managed_and_ambient_accounts() {
        let (_root, paths) = test_paths();
        let account = AccountKey::new("acct-0123456789abcdef01234567").expect("account");
        write_config(&paths, &config_with(&account)).expect("write config");

        activate(&paths, account.as_str()).expect("activate managed");
        let config = load_config(&paths).expect("read managed activation");
        assert_eq!(active_account_id(Some(&config)), account.as_str());

        activate(&paths, AMBIENT_ACCOUNT_ID).expect("activate ambient");
        let config = load_config(&paths).expect("read ambient activation");
        assert_eq!(active_account_id(Some(&config)), AMBIENT_ACCOUNT_ID);
    }

    #[test]
    fn removal_is_recoverable_and_never_accepts_ambient() {
        let (_root, paths) = test_paths();
        let account = AccountKey::new("acct-0123456789abcdef01234567").expect("account");
        write_config(&paths, &config_with(&account)).expect("write config");
        let home = account_home(&paths, &account).expect("managed home");
        ensure_private_directory(&home).expect("create managed home");

        remove(&paths, account.as_str()).expect("remove managed account");
        assert!(!home.exists());
        assert!(
            paths
                .data_dir()
                .join("codex/removed-accounts")
                .join(account.as_str())
                .is_dir()
        );
        assert!(matches!(
            remove(&paths, AMBIENT_ACCOUNT_ID),
            Err(ManagedCodexAccountError::InvalidAccount)
        ));
    }

    #[test]
    fn duplicate_detection_prefers_provider_account_id_and_uses_email_only_as_fallback() {
        let provider_match = ManagedIdentity {
            email: Some("new@example.com".into()),
            provider_account_id: Some("account-1".into()),
        };
        let same_provider = ManagedIdentity {
            email: Some("old@example.com".into()),
            provider_account_id: Some("account-1".into()),
        };
        assert!(same_identity(&provider_match, &same_provider));

        let different_provider = ManagedIdentity {
            email: Some("new@example.com".into()),
            provider_account_id: Some("account-2".into()),
        };
        assert!(!same_identity(&provider_match, &different_provider));

        let email_only = ManagedIdentity {
            email: Some("USER@example.com".into()),
            provider_account_id: None,
        };
        let same_email_only = ManagedIdentity {
            email: Some("user@example.com".into()),
            provider_account_id: None,
        };
        assert!(same_identity(&email_only, &same_email_only));
        assert!(!same_identity(&provider_match, &same_email_only));
    }
}
