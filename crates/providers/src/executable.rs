//! Bounded Linux executable discovery for provider-owned command-line tools.

use std::ffi::OsStr;
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::configured_endpoint::clean_setting;

const MAX_NAME_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_PATH_ENVIRONMENT_BYTES: usize = 64 * 1024;
const MAX_PATH_ENTRIES: usize = 256;
const MAX_FALLBACKS: usize = 32;

/// Safe executable-discovery failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableLookupError {
    /// A command name, configured override, PATH, or fallback exceeded its
    /// closed validation boundary.
    #[error("executable lookup configuration is invalid")]
    InvalidConfiguration,
}

/// An absolute executable path whose debug representation is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutablePath(PathBuf);

impl ExecutablePath {
    /// Returns the validated absolute executable path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consumes the wrapper and returns the validated absolute path.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl Debug for ExecutablePath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutablePath(<redacted>)")
    }
}

/// Resolves one executable without invoking a shell.
///
/// A nonempty configured override is authoritative: if it does not identify
/// an executable, this returns `Ok(None)` without consulting PATH or fallback
/// locations. Otherwise, absolute PATH entries are searched in order followed
/// by the caller's ordered absolute fallbacks. Relative PATH entries are
/// ignored so lookup never depends on the daemon's working directory.
///
/// # Errors
///
/// Returns [`ExecutableLookupError::InvalidConfiguration`] when the command
/// name is not a simple bounded ASCII filename, an explicit override is not
/// absolute, PATH exceeds 64 KiB or 256 entries, or a fallback is not a bounded
/// absolute path ending in the requested filename.
pub fn resolve_executable(
    name: &str,
    configured_override: Option<&str>,
    path_environment: Option<&OsStr>,
    fallbacks: &[PathBuf],
) -> Result<Option<ExecutablePath>, ExecutableLookupError> {
    validate_name(name)?;
    if fallbacks.len() > MAX_FALLBACKS {
        return Err(ExecutableLookupError::InvalidConfiguration);
    }

    if let Some(configured) = configured_override.and_then(clean_setting) {
        let path = PathBuf::from(configured);
        validate_absolute_path(&path)?;
        return Ok(executable(&path).then_some(ExecutablePath(path)));
    }

    if let Some(path_environment) = path_environment {
        if path_environment.as_encoded_bytes().len() > MAX_PATH_ENVIRONMENT_BYTES {
            return Err(ExecutableLookupError::InvalidConfiguration);
        }
        for (index, directory) in std::env::split_paths(path_environment).enumerate() {
            if index == MAX_PATH_ENTRIES {
                return Err(ExecutableLookupError::InvalidConfiguration);
            }
            if !directory.is_absolute() {
                continue;
            }
            validate_absolute_path(&directory)?;
            let candidate = directory.join(name);
            validate_absolute_path(&candidate)?;
            if executable(&candidate) {
                return Ok(Some(ExecutablePath(candidate)));
            }
        }
    }

    for fallback in fallbacks {
        validate_absolute_path(fallback)?;
        if fallback.file_name() != Some(OsStr::new(name)) {
            return Err(ExecutableLookupError::InvalidConfiguration);
        }
        if executable(fallback) {
            return Ok(Some(ExecutablePath(fallback.clone())));
        }
    }
    Ok(None)
}

fn validate_name(name: &str) -> Result<(), ExecutableLookupError> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
        || matches!(name, "." | "..")
    {
        return Err(ExecutableLookupError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), ExecutableLookupError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute() || bytes.is_empty() || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0)
    {
        return Err(ExecutableLookupError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    path.is_file()
}
