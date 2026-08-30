//! Safe path resolution and read-only loading for Codex-owned credentials.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Formatter};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::codex::{
    CodexBearerCredentials, CodexCredentialError, CodexCredentialSource, CodexPatCredentials,
    CodexPatHomeScope, parse_codex_bearer, parse_native_codex_pat,
};
use crate::provider_files::{ProviderFileContents, ProviderFileError, ProviderFileRoot};

const AUTH_FILE: &str = "auth.json";
const MAX_AUTH_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_ROOT_COMPONENTS: usize = 64;

/// Stable, path-free credential acquisition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodexCredentialLoadError {
    /// Provider credential discovery or parsing failed.
    #[error(transparent)]
    Credential(#[from] CodexCredentialError),
    /// Cooperative cancellation stopped credential acquisition.
    #[error("Codex credential acquisition was cancelled")]
    Cancelled,
}

struct CodexCredentialLocation {
    root: PathBuf,
}

impl CodexCredentialLocation {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl Debug for CodexCredentialLocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodexCredentialLocation(<redacted>)")
    }
}

/// Closed set of native and opt-in external Codex credential locations.
pub struct CodexCredentialPaths {
    native: CodexCredentialLocation,
    ambient: CodexCredentialLocation,
    legacy: CodexCredentialLocation,
    opencode: CodexCredentialLocation,
    explicit_codex_home: bool,
}

impl CodexCredentialPaths {
    /// Resolves provider-owned roots from trusted user-home and injected environment values.
    ///
    /// A blank `CODEX_HOME` is absent. An explicit value accepts an absolute path or exact
    /// `~`/`~/...` expansion; any other explicit value fails closed. Invalid `XDG_DATA_HOME`
    /// falls back to `$HOME/.local/share`, matching `OpenCode`'s baseline location policy.
    ///
    /// # Errors
    ///
    /// Returns a path-free unreadable-credential failure for an invalid trusted home or
    /// explicit `CODEX_HOME`.
    pub fn resolve(
        home: impl AsRef<Path>,
        codex_home: Option<&OsStr>,
        xdg_data_home: Option<&OsStr>,
    ) -> Result<Self, CodexCredentialLoadError> {
        let home = home.as_ref();
        if !is_narrow_absolute_root(home) {
            return Err(CodexCredentialError::Unreadable.into());
        }
        let ambient_root = home.join(".codex");
        let explicit = codex_home.and_then(trimmed_os_bytes);
        let native_root = if let Some(raw) = explicit {
            expand_home_path(raw, home)
                .filter(|path| is_narrow_absolute_root(path))
                .ok_or(CodexCredentialError::Unreadable)?
        } else {
            ambient_root.clone()
        };
        let data_root = xdg_data_home
            .and_then(trimmed_os_bytes)
            .and_then(|raw| expand_home_path(raw, home))
            .filter(|path| is_narrow_absolute_root(path))
            .unwrap_or_else(|| home.join(".local/share"));

        Ok(Self {
            native: CodexCredentialLocation::new(native_root),
            ambient: CodexCredentialLocation::new(ambient_root),
            legacy: CodexCredentialLocation::new(home.join(".config/codex")),
            opencode: CodexCredentialLocation::new(data_root.join("opencode")),
            explicit_codex_home: explicit.is_some(),
        })
    }

    /// Whether a nonblank `CODEX_HOME` selected an authoritative native scope.
    #[must_use]
    pub const fn has_explicit_codex_home(&self) -> bool {
        self.explicit_codex_home
    }
}

impl Debug for CodexCredentialPaths {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexCredentialPaths")
            .field("native", &self.native)
            .field("ambient", &self.ambient)
            .field("legacy", &self.legacy)
            .field("opencode", &self.opencode)
            .field("explicit_codex_home", &self.explicit_codex_home)
            .finish()
    }
}

/// One identity-pinned native auth file whose PAT and bearer lanes can be parsed independently.
pub struct CodexNativeAuthFile {
    contents: ProviderFileContents,
}

impl CodexNativeAuthFile {
    /// Parses only the native PAT lane.
    ///
    /// # Errors
    ///
    /// Returns a stable bounded parser failure without exposing file bytes.
    pub fn pat(&self) -> Result<CodexPatCredentials, CodexCredentialError> {
        parse_native_codex_pat(self.contents.as_bytes())
    }

    /// Parses only the native OAuth/API-key bearer lane.
    ///
    /// # Errors
    ///
    /// Returns a stable bounded parser failure without exposing file bytes.
    pub fn bearer(&self) -> Result<CodexBearerCredentials, CodexCredentialError> {
        parse_codex_bearer(self.contents.as_bytes(), CodexCredentialSource::Native)
    }
}

impl Debug for CodexNativeAuthFile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodexNativeAuthFile(<redacted>)")
    }
}

/// Reads the authoritative native auth file once into zeroizing memory.
///
/// # Errors
///
/// Returns a stable path-free credential or cancellation failure.
pub fn load_native_auth_file(
    paths: &CodexCredentialPaths,
    cancellation: &CancellationToken,
) -> Result<CodexNativeAuthFile, CodexCredentialLoadError> {
    read_location(&paths.native, cancellation).map(|contents| CodexNativeAuthFile { contents })
}

/// Loads the PAT authority for one routed Codex-home scope.
///
/// Managed, fail-closed, and ambient scopes always use `$HOME/.codex`. A profile PAT wins only
/// when it parses successfully; any non-cancellation profile failure falls back to ambient.
///
/// # Errors
///
/// Returns the final path-free credential failure or cooperative cancellation.
pub fn load_pat_for_scope(
    paths: &CodexCredentialPaths,
    scope: CodexPatHomeScope,
    cancellation: &CancellationToken,
) -> Result<CodexPatCredentials, CodexCredentialLoadError> {
    if scope == CodexPatHomeScope::Profile {
        match read_and_parse_pat(&paths.native, cancellation) {
            Ok(credentials) => return Ok(credentials),
            Err(CodexCredentialLoadError::Cancelled) => {
                return Err(CodexCredentialLoadError::Cancelled);
            }
            Err(CodexCredentialLoadError::Credential(_)) => {}
        }
    }
    read_and_parse_pat(&paths.ambient, cancellation)
}

/// Loads native OAuth/API-key credentials, then the opt-in read-only external sources.
///
/// External lookup occurs only after an absent native file and without explicit `CODEX_HOME`.
/// Legacy precedes `OpenCode`. Each external read/parse failure is suppressed; cancellation is
/// never suppressed, and total external failure returns the original native `NotFound`.
///
/// # Errors
///
/// Returns a stable path-free credential or cancellation failure.
pub fn load_bearer_for_usage(
    paths: &CodexCredentialPaths,
    allow_external: bool,
    cancellation: &CancellationToken,
) -> Result<CodexBearerCredentials, CodexCredentialLoadError> {
    match read_and_parse_bearer(&paths.native, CodexCredentialSource::Native, cancellation) {
        Ok(credentials) => return Ok(credentials),
        Err(CodexCredentialLoadError::Cancelled) => {
            return Err(CodexCredentialLoadError::Cancelled);
        }
        Err(CodexCredentialLoadError::Credential(error))
            if error == CodexCredentialError::NotFound
                && allow_external
                && !paths.explicit_codex_home => {}
        Err(error) => return Err(error),
    }

    for (location, source) in [
        (&paths.legacy, CodexCredentialSource::Legacy),
        (&paths.opencode, CodexCredentialSource::OpenCode),
    ] {
        match read_and_parse_bearer(location, source, cancellation) {
            Ok(credentials) => return Ok(credentials),
            Err(CodexCredentialLoadError::Cancelled) => {
                return Err(CodexCredentialLoadError::Cancelled);
            }
            Err(CodexCredentialLoadError::Credential(_)) => {}
        }
    }
    Err(CodexCredentialError::NotFound.into())
}

fn read_and_parse_pat(
    location: &CodexCredentialLocation,
    cancellation: &CancellationToken,
) -> Result<CodexPatCredentials, CodexCredentialLoadError> {
    let contents = read_location(location, cancellation)?;
    parse_native_codex_pat(contents.as_bytes()).map_err(Into::into)
}

fn read_and_parse_bearer(
    location: &CodexCredentialLocation,
    source: CodexCredentialSource,
    cancellation: &CancellationToken,
) -> Result<CodexBearerCredentials, CodexCredentialLoadError> {
    let contents = read_location(location, cancellation)?;
    parse_codex_bearer(contents.as_bytes(), source).map_err(Into::into)
}

fn read_location(
    location: &CodexCredentialLocation,
    cancellation: &CancellationToken,
) -> Result<ProviderFileContents, CodexCredentialLoadError> {
    if cancellation.is_cancelled() {
        return Err(CodexCredentialLoadError::Cancelled);
    }
    let root = ProviderFileRoot::open(&location.root).map_err(map_file_error)?;
    root.read(AUTH_FILE, MAX_AUTH_DOCUMENT_BYTES, cancellation)
        .map_err(map_file_error)
}

const fn map_file_error(error: ProviderFileError) -> CodexCredentialLoadError {
    match error {
        ProviderFileError::Cancelled => CodexCredentialLoadError::Cancelled,
        ProviderFileError::Missing | ProviderFileError::InvalidRoot => {
            CodexCredentialLoadError::Credential(CodexCredentialError::NotFound)
        }
        ProviderFileError::InvalidRelativePath
        | ProviderFileError::InvalidLimits
        | ProviderFileError::UnsafeLayout
        | ProviderFileError::WrongOwner
        | ProviderFileError::TooLarge
        | ProviderFileError::TooManyEntries
        | ProviderFileError::TooDeep
        | ProviderFileError::WrongRoot
        | ProviderFileError::Changed
        | ProviderFileError::Read => {
            CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
        }
    }
}

fn trimmed_os_bytes(value: &OsStr) -> Option<&[u8]> {
    let bytes = value.as_bytes();
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace())?;
    let end = bytes.iter().rposition(|byte| !byte.is_ascii_whitespace())? + 1;
    Some(&bytes[start..end])
}

fn expand_home_path(raw: &[u8], home: &Path) -> Option<PathBuf> {
    if raw == b"~" {
        return Some(home.to_path_buf());
    }
    if let Some(relative) = raw.strip_prefix(b"~/") {
        if relative.starts_with(b"/") {
            return None;
        }
        return Some(home.join(OsStr::from_bytes(relative)));
    }
    if raw.starts_with(b"~") {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(raw.to_vec())))
}

fn is_narrow_absolute_root(path: &Path) -> bool {
    let raw = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path == Path::new("/")
        || raw.len() > MAX_PATH_BYTES
        || raw.strip_prefix(b"/").is_none_or(|tail| {
            tail.split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || matches!(component, b"." | b".."))
        })
    {
        return false;
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return false;
    }
    let mut count = 0_usize;
    for component in components {
        let Component::Normal(name) = component else {
            return false;
        };
        count += 1;
        if count > MAX_ROOT_COMPONENTS
            || name.is_empty()
            || name.as_bytes().len() > MAX_COMPONENT_BYTES
        {
            return false;
        }
    }
    count != 0
}
