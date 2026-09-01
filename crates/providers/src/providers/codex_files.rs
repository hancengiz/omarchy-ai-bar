//! Safe path resolution and read-only loading for Codex-owned credentials.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Formatter};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use oab_domain::{ClassifiedError, ErrorKind};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::codex::{
    CodexAttemptFailure, CodexBearerCredentials, CodexCredentialError, CodexCredentialSource,
    CodexPatCredentials, CodexPatHomeScope, CodexPatRoot, parse_codex_bearer,
    parse_native_codex_pat,
};
use crate::provider_files::{ProviderFileContents, ProviderFileError, ProviderFileRoot};

const AUTH_FILE: &str = "auth.json";
const CONFIG_FILE: &str = "config.toml";
const MAX_AUTH_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_DOCUMENT_BYTES: usize = 256 * 1024;
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

impl CodexCredentialLoadError {
    /// Credential failure consumed by the closed Codex source planner.
    ///
    /// Cancellation is deliberately not projected into a fallback class, so callers must
    /// preserve it as a terminal control-flow outcome.
    #[must_use]
    pub const fn attempt_failure(self) -> Option<CodexAttemptFailure> {
        match self {
            Self::Credential(error) => Some(CodexAttemptFailure::Credential(error)),
            Self::Cancelled => None,
        }
    }

    /// Public-safe domain projection for credential failures.
    ///
    /// Cancellation remains outside the public error vocabulary and must be propagated by the
    /// caller rather than presented as an authentication or transport failure.
    #[must_use]
    pub fn classified(self) -> Option<ClassifiedError> {
        let Self::Credential(error) = self else {
            return None;
        };
        let kind = match error {
            CodexCredentialError::NotFound
            | CodexCredentialError::Unreadable
            | CodexCredentialError::MissingTokens => ErrorKind::MissingCredential,
            CodexCredentialError::Invalid => ErrorKind::Parse,
            CodexCredentialError::NativeRefreshRequired | CodexCredentialError::ReadOnlySource => {
                ErrorKind::AuthenticationExpired
            }
        };
        Some(ClassifiedError::new(kind))
    }
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
    home: PathBuf,
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
            home: home.to_path_buf(),
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

    /// Provider-owned Codex root selected for credentials and local history.
    #[must_use]
    pub fn native_root(&self) -> &Path {
        &self.native.root
    }

    pub(crate) fn cli_environment_roots(&self) -> Option<(&str, &str)> {
        Some((self.home.to_str()?, self.native.root.to_str()?))
    }
}

impl Debug for CodexCredentialPaths {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexCredentialPaths")
            .field("home", &"<redacted>")
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

struct CodexConfigFile {
    contents: Zeroizing<String>,
}

impl CodexConfigFile {
    fn from_contents(contents: &ProviderFileContents) -> Result<Self, CodexCredentialLoadError> {
        let contents = std::str::from_utf8(contents.as_bytes())
            .map_err(|_| CodexCredentialError::Unreadable)?
            .to_owned();
        Ok(Self {
            contents: Zeroizing::new(contents),
        })
    }

    fn as_str(&self) -> &str {
        self.contents.as_str()
    }
}

impl Debug for CodexConfigFile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodexConfigFile(<redacted>)")
    }
}

/// A native Codex PAT and the optional config bound to its selected authority.
pub struct CodexPatCredentialBundle {
    credentials: CodexPatCredentials,
    config: Option<CodexConfigFile>,
    root: CodexPatRoot,
}

impl CodexPatCredentialBundle {
    /// Borrows the selected personal access token credentials.
    #[must_use]
    pub const fn credentials(&self) -> &CodexPatCredentials {
        &self.credentials
    }

    /// Borrows the bounded UTF-8 `config.toml`, when the selected authority has one.
    #[must_use]
    pub fn config_toml(&self) -> Option<&str> {
        self.config.as_ref().map(CodexConfigFile::as_str)
    }

    /// Winning profile or ambient PAT authority, without exposing its filesystem path.
    #[must_use]
    pub const fn root(&self) -> CodexPatRoot {
        self.root
    }

    /// Discards the optional config and transfers the selected credentials.
    #[must_use]
    pub fn into_credentials(self) -> CodexPatCredentials {
        self.credentials
    }
}

impl Debug for CodexPatCredentialBundle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexPatCredentialBundle")
            .field("source", &self.credentials.source())
            .field("has_config", &self.config.is_some())
            .field("root", &self.root)
            .finish()
    }
}

/// Native or read-only external Codex bearer credentials with native config authority.
pub struct CodexBearerCredentialBundle {
    credentials: CodexBearerCredentials,
    config: Option<CodexConfigFile>,
}

impl CodexBearerCredentialBundle {
    /// Borrows the selected OAuth or embedded API-key credentials.
    #[must_use]
    pub const fn credentials(&self) -> &CodexBearerCredentials {
        &self.credentials
    }

    /// Borrows the bounded UTF-8 native `config.toml`, when present.
    #[must_use]
    pub fn config_toml(&self) -> Option<&str> {
        self.config.as_ref().map(CodexConfigFile::as_str)
    }

    /// Discards the optional config and transfers the selected credentials.
    #[must_use]
    pub fn into_credentials(self) -> CodexBearerCredentials {
        self.credentials
    }
}

impl Debug for CodexBearerCredentialBundle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexBearerCredentialBundle")
            .field("source", &self.credentials.source())
            .field("kind", &self.credentials.kind())
            .field("has_config", &self.config.is_some())
            .finish()
    }
}

/// Bearer credentials pinned to the native config authority selected by the same read.
///
/// Freshness and ownership may be inspected before loading HTTP configuration. This
/// preserves the Codex CLI owner's recovery path when an unrelated `config.toml` is unsafe.
pub struct CodexBearerCredentialSelection {
    credentials: CodexBearerCredentials,
    config_root: Option<ProviderFileRoot>,
}

impl CodexBearerCredentialSelection {
    /// Borrows the selected OAuth or embedded API-key credentials.
    #[must_use]
    pub const fn credentials(&self) -> &CodexBearerCredentials {
        &self.credentials
    }

    /// Loads the optional config from the authority pinned during credential selection.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration or cancellation failure without changing credential source.
    pub fn bind_config(
        self,
        cancellation: &CancellationToken,
    ) -> Result<CodexBearerCredentialBundle, CodexCredentialLoadError> {
        bind_bearer_config(self.config_root.as_ref(), self.credentials, cancellation)
    }

    /// Discards config authority and transfers the selected credentials.
    #[must_use]
    pub fn into_credentials(self) -> CodexBearerCredentials {
        self.credentials
    }
}

impl Debug for CodexBearerCredentialSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexBearerCredentialSelection")
            .field("source", &self.credentials.source())
            .field("kind", &self.credentials.kind())
            .field("has_config_authority", &self.config_root.is_some())
            .finish()
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
    let root = open_location(&paths.native, cancellation)?;
    read_auth_from_root(&root, cancellation).map(|contents| CodexNativeAuthFile { contents })
}

/// Loads the PAT authority for one routed Codex-home scope.
///
/// Managed, fail-closed, and ambient scopes always use `$HOME/.codex`. A profile PAT wins only
/// when it parses successfully; any non-cancellation profile auth failure falls back to ambient.
/// Once a PAT authority is selected, its unsafe config fails closed.
///
/// # Errors
///
/// Returns the final path-free credential failure or cooperative cancellation.
pub fn load_pat_for_scope(
    paths: &CodexCredentialPaths,
    scope: CodexPatHomeScope,
    cancellation: &CancellationToken,
) -> Result<CodexPatCredentials, CodexCredentialLoadError> {
    load_pat_bundle_for_scope(paths, scope, cancellation)
        .map(CodexPatCredentialBundle::into_credentials)
}

/// Loads a PAT and the optional `config.toml` from its exact selected authority.
///
/// A successfully parsed profile PAT pins the profile root for its config. Profile auth failures
/// still fall back to ambient, but an unsafe or non-UTF-8 config on a selected authority fails
/// closed instead of changing identity. Managed, fail-closed, and ambient scopes use the ambient
/// root for both files.
///
/// # Errors
///
/// Returns a path-free credential/configuration failure or cooperative cancellation.
pub fn load_pat_bundle_for_scope(
    paths: &CodexCredentialPaths,
    scope: CodexPatHomeScope,
    cancellation: &CancellationToken,
) -> Result<CodexPatCredentialBundle, CodexCredentialLoadError> {
    if scope == CodexPatHomeScope::Profile {
        match open_and_parse_pat(&paths.native, cancellation) {
            Ok((root, credentials)) => {
                return bind_pat_config(&root, credentials, CodexPatRoot::Profile, cancellation);
            }
            Err(CodexCredentialLoadError::Cancelled) => {
                return Err(CodexCredentialLoadError::Cancelled);
            }
            Err(CodexCredentialLoadError::Credential(_)) => {}
        }
    }
    let (root, credentials) = open_and_parse_pat(&paths.ambient, cancellation)?;
    bind_pat_config(&root, credentials, CodexPatRoot::Ambient, cancellation)
}

/// Loads native OAuth/API-key credentials, then the opt-in read-only external sources.
///
/// External lookup occurs only after an absent native file and without explicit `CODEX_HOME`.
/// Legacy precedes `OpenCode`. Each external read/parse failure is suppressed; cancellation is
/// never suppressed, and total external failure returns the original native `NotFound`. This
/// credentials-only API deliberately does not inspect HTTP configuration.
///
/// # Errors
///
/// Returns a stable path-free credential or cancellation failure.
pub fn load_bearer_for_usage(
    paths: &CodexCredentialPaths,
    allow_external: bool,
    cancellation: &CancellationToken,
) -> Result<CodexBearerCredentials, CodexCredentialLoadError> {
    load_bearer_selection_for_usage(paths, allow_external, cancellation)
        .map(CodexBearerCredentialSelection::into_credentials)
}

/// Loads bearer credentials and binds them to the selected native `config.toml` authority.
///
/// Native credentials and config share one already-opened root. Opt-in external credentials never
/// supply config: they retain the ambient/native root observed before external lookup, or no config
/// when that root was absent. This prevents a later root replacement from switching configuration
/// underneath the chosen credential source.
///
/// # Errors
///
/// Returns a path-free credential/configuration failure or cooperative cancellation.
pub fn load_bearer_bundle_for_usage(
    paths: &CodexCredentialPaths,
    allow_external: bool,
    cancellation: &CancellationToken,
) -> Result<CodexBearerCredentialBundle, CodexCredentialLoadError> {
    load_bearer_selection_for_usage(paths, allow_external, cancellation)?.bind_config(cancellation)
}

/// Selects bearer credentials and pins their native config authority without reading config.
///
/// Native credentials win. External credentials remain missing-only, explicitly enabled,
/// read-only fallbacks and retain the native root observed during the same selection. Callers
/// can inspect freshness/ownership before [`CodexBearerCredentialSelection::bind_config`].
///
/// # Errors
///
/// Returns a stable path-free credential or cancellation failure.
pub fn load_bearer_selection_for_usage(
    paths: &CodexCredentialPaths,
    allow_external: bool,
    cancellation: &CancellationToken,
) -> Result<CodexBearerCredentialSelection, CodexCredentialLoadError> {
    let native_root = match open_location(&paths.native, cancellation) {
        Ok(root) => match read_and_parse_bearer_from_root(
            &root,
            CodexCredentialSource::Native,
            cancellation,
        ) {
            Ok(credentials) => {
                return Ok(CodexBearerCredentialSelection {
                    credentials,
                    config_root: Some(root),
                });
            }
            Err(CodexCredentialLoadError::Cancelled) => {
                return Err(CodexCredentialLoadError::Cancelled);
            }
            Err(CodexCredentialLoadError::Credential(error))
                if error == CodexCredentialError::NotFound
                    && allow_external
                    && !paths.explicit_codex_home =>
            {
                Some(root)
            }
            Err(error) => return Err(error),
        },
        Err(CodexCredentialLoadError::Cancelled) => {
            return Err(CodexCredentialLoadError::Cancelled);
        }
        Err(CodexCredentialLoadError::Credential(error))
            if error == CodexCredentialError::NotFound
                && allow_external
                && !paths.explicit_codex_home =>
        {
            None
        }
        Err(error) => return Err(error),
    };

    for (location, source) in [
        (&paths.legacy, CodexCredentialSource::Legacy),
        (&paths.opencode, CodexCredentialSource::OpenCode),
    ] {
        match open_and_parse_bearer(location, source, cancellation) {
            Ok((_external_root, credentials)) => {
                return Ok(CodexBearerCredentialSelection {
                    credentials,
                    config_root: native_root,
                });
            }
            Err(CodexCredentialLoadError::Cancelled) => {
                return Err(CodexCredentialLoadError::Cancelled);
            }
            Err(CodexCredentialLoadError::Credential(_)) => {}
        }
    }
    Err(CodexCredentialError::NotFound.into())
}

fn open_and_parse_pat(
    location: &CodexCredentialLocation,
    cancellation: &CancellationToken,
) -> Result<(ProviderFileRoot, CodexPatCredentials), CodexCredentialLoadError> {
    let root = open_location(location, cancellation)?;
    let contents = read_auth_from_root(&root, cancellation)?;
    let credentials = parse_native_codex_pat(contents.as_bytes())?;
    Ok((root, credentials))
}

fn open_and_parse_bearer(
    location: &CodexCredentialLocation,
    source: CodexCredentialSource,
    cancellation: &CancellationToken,
) -> Result<(ProviderFileRoot, CodexBearerCredentials), CodexCredentialLoadError> {
    let root = open_location(location, cancellation)?;
    let credentials = read_and_parse_bearer_from_root(&root, source, cancellation)?;
    Ok((root, credentials))
}

fn read_and_parse_bearer_from_root(
    root: &ProviderFileRoot,
    source: CodexCredentialSource,
    cancellation: &CancellationToken,
) -> Result<CodexBearerCredentials, CodexCredentialLoadError> {
    let contents = read_auth_from_root(root, cancellation)?;
    parse_codex_bearer(contents.as_bytes(), source).map_err(Into::into)
}

fn open_location(
    location: &CodexCredentialLocation,
    cancellation: &CancellationToken,
) -> Result<ProviderFileRoot, CodexCredentialLoadError> {
    if cancellation.is_cancelled() {
        return Err(CodexCredentialLoadError::Cancelled);
    }
    ProviderFileRoot::open(&location.root).map_err(map_file_error)
}

fn read_auth_from_root(
    root: &ProviderFileRoot,
    cancellation: &CancellationToken,
) -> Result<ProviderFileContents, CodexCredentialLoadError> {
    root.read(AUTH_FILE, MAX_AUTH_DOCUMENT_BYTES, cancellation)
        .map_err(map_file_error)
}

fn read_optional_config(
    root: &ProviderFileRoot,
    cancellation: &CancellationToken,
) -> Result<Option<CodexConfigFile>, CodexCredentialLoadError> {
    match root.read(CONFIG_FILE, MAX_CONFIG_DOCUMENT_BYTES, cancellation) {
        Ok(contents) => CodexConfigFile::from_contents(&contents).map(Some),
        Err(ProviderFileError::Missing) => Ok(None),
        Err(ProviderFileError::Cancelled) => Err(CodexCredentialLoadError::Cancelled),
        Err(
            ProviderFileError::InvalidRoot
            | ProviderFileError::InvalidRelativePath
            | ProviderFileError::InvalidLimits
            | ProviderFileError::UnsafeLayout
            | ProviderFileError::WrongOwner
            | ProviderFileError::TooLarge
            | ProviderFileError::TooManyEntries
            | ProviderFileError::TooDeep
            | ProviderFileError::WrongRoot
            | ProviderFileError::Changed
            | ProviderFileError::Read,
        ) => Err(CodexCredentialError::Unreadable.into()),
    }
}

fn bind_pat_config(
    root: &ProviderFileRoot,
    credentials: CodexPatCredentials,
    authority: CodexPatRoot,
    cancellation: &CancellationToken,
) -> Result<CodexPatCredentialBundle, CodexCredentialLoadError> {
    let config = read_optional_config(root, cancellation)?;
    Ok(CodexPatCredentialBundle {
        credentials,
        config,
        root: authority,
    })
}

fn bind_bearer_config(
    root: Option<&ProviderFileRoot>,
    credentials: CodexBearerCredentials,
    cancellation: &CancellationToken,
) -> Result<CodexBearerCredentialBundle, CodexCredentialLoadError> {
    if cancellation.is_cancelled() {
        return Err(CodexCredentialLoadError::Cancelled);
    }
    let config = root
        .map(|root| read_optional_config(root, cancellation))
        .transpose()?
        .flatten();
    Ok(CodexBearerCredentialBundle {
        credentials,
        config,
    })
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
