//! Bounded Linux browser-profile discovery for provider-owned session data.
//!
//! Discovery is disabled by default and never reads browser cookies. Callers
//! must provide isolated roots or an injected environment explicitly.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{OFlag, open};
use nix::sys::stat::{Mode, SFlag, fstat};
use thiserror::Error;

const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const MAX_PROFILES_PER_ROOT: usize = 128;
const MAX_DISCOVERED_PROFILES: usize = 512;
const MAX_PROFILES_INI_BYTES: usize = 64 * 1024;
const MAX_PROFILES_INI_BYTES_U64: u64 = 64 * 1024;
const MAX_INI_LINE_BYTES: usize = 4 * 1024;
const MAX_INI_ENTRIES: usize = 512;
const MAX_INI_SECTIONS: usize = 256;
const MAX_CHROMIUM_PROFILE_NAME_BYTES: usize = 80;

/// Browser families with supported Linux profile layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BrowserKind {
    /// Open-source Chromium.
    Chromium,
    /// Google Chrome stable.
    GoogleChrome,
    /// Brave Browser stable.
    Brave,
    /// Brave Origin stable, used by current Omarchy releases.
    BraveOrigin,
    /// Microsoft Edge stable.
    MicrosoftEdge,
    /// Mozilla Firefox.
    Firefox,
    /// Zen Browser.
    Zen,
}

impl BrowserKind {
    const ALL: [Self; 7] = [
        Self::Chromium,
        Self::GoogleChrome,
        Self::Brave,
        Self::BraveOrigin,
        Self::MicrosoftEdge,
        Self::Firefox,
        Self::Zen,
    ];

    /// Stable human-readable browser name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chromium => "Chromium",
            Self::GoogleChrome => "Google Chrome",
            Self::Brave => "Brave",
            Self::BraveOrigin => "Brave Origin",
            Self::MicrosoftEdge => "Microsoft Edge",
            Self::Firefox => "Firefox",
            Self::Zen => "Zen",
        }
    }
}

impl Display for BrowserKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Installation boundary that supplied a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BrowserProfileOrigin {
    /// Profile from the native Linux user directories.
    Native,
    /// Profile from an explicitly enabled per-user Flatpak root.
    Flatpak,
}

impl Display for BrowserProfileOrigin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Native => "native",
            Self::Flatpak => "Flatpak",
        })
    }
}

/// A validated existing browser profile directory.
#[derive(Clone, PartialEq, Eq)]
pub struct BrowserProfile {
    browser: BrowserKind,
    origin: BrowserProfileOrigin,
    path: PathBuf,
}

impl BrowserProfile {
    /// Browser owning this profile.
    #[must_use]
    pub const fn browser(&self) -> BrowserKind {
        self.browser
    }

    /// Native or Flatpak source boundary.
    #[must_use]
    pub const fn origin(&self) -> BrowserProfileOrigin {
        self.origin
    }

    /// Canonical profile directory for a later provider-owned reader.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Debug for BrowserProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserProfile")
            .field("browser", &self.browser)
            .field("origin", &self.origin)
            .field("path", &"<redacted>")
            .finish()
    }
}

impl Display for BrowserProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} profile ({})", self.browser, self.origin)
    }
}

/// Safe classification for a skipped browser source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserProfileIssueKind {
    /// A path resolved outside its injected trust root.
    UnsafePath,
    /// A required directory or metadata file had an unsupported file type.
    UnsupportedFileType,
    /// A directory or metadata file could not be read safely.
    Unreadable,
    /// A profile root or INI file exceeded a fixed bound.
    TooManyEntries,
    /// `profiles.ini` exceeded its byte budget.
    OversizedProfilesIni,
    /// `profiles.ini` was not UTF-8.
    NonUtf8ProfilesIni,
    /// `profiles.ini` did not match the conservative accepted grammar.
    MalformedProfilesIni,
    /// The process-wide discovery result reached its fixed profile cap.
    ProfileLimit,
}

impl Display for BrowserProfileIssueKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "unsafe path",
            Self::UnsupportedFileType => "unsupported file type",
            Self::Unreadable => "unreadable source",
            Self::TooManyEntries => "entry limit exceeded",
            Self::OversizedProfilesIni => "profiles.ini is too large",
            Self::NonUtf8ProfilesIni => "profiles.ini is not UTF-8",
            Self::MalformedProfilesIni => "profiles.ini is malformed",
            Self::ProfileLimit => "profile limit reached",
        })
    }
}

/// Redacted diagnostic for a skipped source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrowserProfileIssue {
    browser: BrowserKind,
    origin: BrowserProfileOrigin,
    kind: BrowserProfileIssueKind,
}

impl BrowserProfileIssue {
    /// Browser associated with the issue.
    #[must_use]
    pub const fn browser(self) -> BrowserKind {
        self.browser
    }

    /// Source boundary associated with the issue.
    #[must_use]
    pub const fn origin(self) -> BrowserProfileOrigin {
        self.origin
    }

    /// Stable issue classification.
    #[must_use]
    pub const fn kind(self) -> BrowserProfileIssueKind {
        self.kind
    }
}

impl Display for BrowserProfileIssue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} profile source: {}",
            self.browser, self.origin, self.kind
        )
    }
}

/// Bounded discovery output. Paths remain available only through each profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrowserProfileReport {
    profiles: Vec<BrowserProfile>,
    issues: Vec<BrowserProfileIssue>,
}

impl BrowserProfileReport {
    /// Validated profiles in deterministic precedence order.
    #[must_use]
    pub fn profiles(&self) -> &[BrowserProfile] {
        &self.profiles
    }

    /// Redacted diagnostics for rejected roots or metadata.
    #[must_use]
    pub fn issues(&self) -> &[BrowserProfileIssue] {
        &self.issues
    }

    /// Whether no usable profiles were found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

/// Controls whether inferred per-user Flatpak roots are considered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FlatpakProfileDiscovery {
    /// Do not inspect any Flatpak application roots.
    #[default]
    Disabled,
    /// Inspect the fixed supported application roots below `$HOME/.var/app`.
    Enabled,
}

/// Invalid injected discovery configuration.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrowserProfileConfigError {
    /// `HOME` was absent or empty.
    #[error("browser profile discovery requires an injected HOME")]
    MissingHome,
    /// A supplied root was not a bounded absolute UTF-8 path.
    #[error("browser profile discovery received an invalid root")]
    InvalidRoot,
}

/// Validated lexical roots. Construction performs no filesystem access.
#[derive(Clone, PartialEq, Eq)]
pub struct BrowserProfileRoots {
    home: PathBuf,
    config_home: PathBuf,
    flatpak_root: Option<PathBuf>,
}

impl BrowserProfileRoots {
    /// Builds explicit roots without probing them.
    ///
    /// # Errors
    ///
    /// Returns an invalid-root error unless every supplied root is an absolute,
    /// bounded UTF-8 path without parent traversal.
    pub fn new(
        home: impl AsRef<Path>,
        config_home: impl AsRef<Path>,
        flatpak_root: Option<impl AsRef<Path>>,
    ) -> Result<Self, BrowserProfileConfigError> {
        let home = validate_lexical_root(home.as_ref())?;
        let config_home = validate_lexical_root(config_home.as_ref())?;
        let flatpak_root = flatpak_root
            .map(|path| validate_lexical_root(path.as_ref()))
            .transpose()?;
        Ok(Self {
            home,
            config_home,
            flatpak_root,
        })
    }

    /// Resolves roots from an injected environment without ambient reads.
    ///
    /// `XDG_CONFIG_HOME` must be absolute when supplied. When absent, the
    /// native config root is `$HOME/.config`.
    ///
    /// # Errors
    ///
    /// Returns a missing-home or invalid-root error for unsafe input.
    pub fn from_environment(
        environment: &BTreeMap<String, String>,
        flatpak: FlatpakProfileDiscovery,
    ) -> Result<Self, BrowserProfileConfigError> {
        let home = environment
            .get("HOME")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(BrowserProfileConfigError::MissingHome)?;
        let config_home = environment
            .get("XDG_CONFIG_HOME")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(|| Path::new(home).join(".config"), PathBuf::from);
        let flatpak_root =
            (flatpak == FlatpakProfileDiscovery::Enabled).then(|| Path::new(home).join(".var/app"));
        Self::new(home, config_home, flatpak_root)
    }
}

impl Debug for BrowserProfileRoots {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserProfileRoots")
            .field("home", &"<redacted>")
            .field("config_home", &"<redacted>")
            .field("flatpak_enabled", &self.flatpak_root.is_some())
            .finish()
    }
}

/// Explicit, non-ambient browser discovery boundary.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BrowserProfileDiscovery {
    roots: Option<BrowserProfileRoots>,
}

impl BrowserProfileDiscovery {
    /// Creates a disabled discovery boundary. Calling `discover` performs no IO.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { roots: None }
    }

    /// Enables discovery for already validated injected roots.
    #[must_use]
    pub const fn with_roots(roots: BrowserProfileRoots) -> Self {
        Self { roots: Some(roots) }
    }

    /// Enables discovery from an injected environment.
    ///
    /// # Errors
    ///
    /// Returns a configuration error without probing the filesystem.
    pub fn enabled_from_environment(
        environment: &BTreeMap<String, String>,
        flatpak: FlatpakProfileDiscovery,
    ) -> Result<Self, BrowserProfileConfigError> {
        BrowserProfileRoots::from_environment(environment, flatpak).map(Self::with_roots)
    }

    /// Discovers profiles below the injected roots only.
    #[must_use]
    pub fn discover(&self) -> BrowserProfileReport {
        let Some(roots) = &self.roots else {
            return BrowserProfileReport::default();
        };
        let mut state = DiscoveryState::default();
        for browser in BrowserKind::ALL {
            scan_location(&mut state, &native_location(roots, browser));
        }
        if let Some(flatpak_root) = &roots.flatpak_root {
            for browser in BrowserKind::ALL {
                for location in flatpak_locations(flatpak_root, browser) {
                    scan_location(&mut state, &location);
                }
            }
        }
        state.report
    }
}

impl Debug for BrowserProfileDiscovery {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserProfileDiscovery")
            .field("enabled", &self.roots.is_some())
            .field(
                "flatpak_enabled",
                &self
                    .roots
                    .as_ref()
                    .is_some_and(|roots| roots.flatpak_root.is_some()),
            )
            .finish()
    }
}

#[derive(Clone, Copy)]
enum ProfileFamily {
    Chromium,
    Gecko,
}

struct ProfileLocation {
    browser: BrowserKind,
    origin: BrowserProfileOrigin,
    anchor: PathBuf,
    root: PathBuf,
    family: ProfileFamily,
}

fn native_location(roots: &BrowserProfileRoots, browser: BrowserKind) -> ProfileLocation {
    let (anchor, relative, family) = match browser {
        BrowserKind::Chromium => (&roots.config_home, "chromium", ProfileFamily::Chromium),
        BrowserKind::GoogleChrome => (&roots.config_home, "google-chrome", ProfileFamily::Chromium),
        BrowserKind::Brave => (
            &roots.config_home,
            "BraveSoftware/Brave-Browser",
            ProfileFamily::Chromium,
        ),
        BrowserKind::BraveOrigin => (
            &roots.config_home,
            "BraveSoftware/Brave-Origin",
            ProfileFamily::Chromium,
        ),
        BrowserKind::MicrosoftEdge => (
            &roots.config_home,
            "microsoft-edge",
            ProfileFamily::Chromium,
        ),
        BrowserKind::Firefox => (&roots.home, ".mozilla/firefox", ProfileFamily::Gecko),
        BrowserKind::Zen => (&roots.home, ".zen", ProfileFamily::Gecko),
    };
    ProfileLocation {
        browser,
        origin: BrowserProfileOrigin::Native,
        anchor: anchor.clone(),
        root: anchor.join(relative),
        family,
    }
}

fn flatpak_locations(flatpak_root: &Path, browser: BrowserKind) -> Vec<ProfileLocation> {
    let paths: &[(&str, ProfileFamily)] = match browser {
        BrowserKind::Chromium => &[(
            "org.chromium.Chromium/config/chromium",
            ProfileFamily::Chromium,
        )],
        BrowserKind::GoogleChrome => &[(
            "com.google.Chrome/config/google-chrome",
            ProfileFamily::Chromium,
        )],
        BrowserKind::Brave => &[(
            "com.brave.Browser/config/BraveSoftware/Brave-Browser",
            ProfileFamily::Chromium,
        )],
        BrowserKind::BraveOrigin => &[(
            "com.brave.Origin/config/BraveSoftware/Brave-Origin",
            ProfileFamily::Chromium,
        )],
        BrowserKind::MicrosoftEdge => &[(
            "com.microsoft.Edge/config/microsoft-edge",
            ProfileFamily::Chromium,
        )],
        BrowserKind::Firefox => &[("org.mozilla.firefox/.mozilla/firefox", ProfileFamily::Gecko)],
        BrowserKind::Zen => &[
            ("app.zen_browser.zen/.zen", ProfileFamily::Gecko),
            ("io.github.zen_browser.zen/.zen", ProfileFamily::Gecko),
        ],
    };
    paths
        .iter()
        .map(|(relative, family)| ProfileLocation {
            browser,
            origin: BrowserProfileOrigin::Flatpak,
            anchor: flatpak_root.to_path_buf(),
            root: flatpak_root.join(relative),
            family: *family,
        })
        .collect()
}

#[derive(Default)]
struct DiscoveryState {
    report: BrowserProfileReport,
    seen: BTreeSet<PathBuf>,
    profile_limit_reported: bool,
}

fn scan_location(state: &mut DiscoveryState, location: &ProfileLocation) {
    if state.report.profiles.len() >= MAX_DISCOVERED_PROFILES {
        push_profile_limit(state, location);
        return;
    }
    let root = match trusted_directory(&location.root, &location.anchor) {
        Ok(Some(root)) => root,
        Ok(None) => return,
        Err(kind) => {
            push_issue(state, location, kind);
            return;
        }
    };
    match location.family {
        ProfileFamily::Chromium => scan_chromium_root(state, location, &root),
        ProfileFamily::Gecko => scan_gecko_root(state, location, &root),
    }
}

fn scan_chromium_root(state: &mut DiscoveryState, location: &ProfileLocation, root: &Path) {
    let entries = match bounded_directory_names(root) {
        Ok(entries) => entries,
        Err(kind) => {
            push_issue(state, location, kind);
            return;
        }
    };
    let mut names = entries
        .into_iter()
        .filter(|name| valid_chromium_profile_name(name))
        .collect::<Vec<_>>();
    names.sort_by(|left, right| {
        (left != "Default", left.as_str()).cmp(&(right != "Default", right.as_str()))
    });
    if names.len() > MAX_PROFILES_PER_ROOT {
        push_issue(state, location, BrowserProfileIssueKind::TooManyEntries);
        return;
    }
    for name in names {
        add_profile_directory(state, location, root, &root.join(name));
    }
}

fn scan_gecko_root(state: &mut DiscoveryState, location: &ProfileLocation, root: &Path) {
    let bytes = match read_profiles_ini(&root.join("profiles.ini")) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return,
        Err(kind) => {
            push_issue(state, location, kind);
            return;
        }
    };
    let profiles = match parse_profiles_ini(&bytes) {
        Ok(profiles) => profiles,
        Err(kind) => {
            push_issue(state, location, kind);
            return;
        }
    };
    for profile in profiles {
        let value = Path::new(&profile.path);
        let candidate = if profile.relative {
            if !safe_relative_path(value) {
                push_issue(state, location, BrowserProfileIssueKind::UnsafePath);
                continue;
            }
            root.join(value)
        } else {
            if !value.is_absolute() || !bounded_utf8_path(value) {
                push_issue(state, location, BrowserProfileIssueKind::UnsafePath);
                continue;
            }
            value.to_path_buf()
        };
        add_profile_directory(state, location, root, &candidate);
    }
}

fn add_profile_directory(
    state: &mut DiscoveryState,
    location: &ProfileLocation,
    trusted_root: &Path,
    candidate: &Path,
) {
    if state.report.profiles.len() >= MAX_DISCOVERED_PROFILES {
        push_profile_limit(state, location);
        return;
    }
    let profile = match canonical_child_directory(candidate, trusted_root) {
        Ok(Some(profile)) => profile,
        Ok(None) => return,
        Err(kind) => {
            push_issue(state, location, kind);
            return;
        }
    };
    if state.seen.insert(profile.clone()) {
        state.report.profiles.push(BrowserProfile {
            browser: location.browser,
            origin: location.origin,
            path: profile,
        });
    }
}

fn push_issue(
    state: &mut DiscoveryState,
    location: &ProfileLocation,
    kind: BrowserProfileIssueKind,
) {
    state.report.issues.push(BrowserProfileIssue {
        browser: location.browser,
        origin: location.origin,
        kind,
    });
}

fn push_profile_limit(state: &mut DiscoveryState, location: &ProfileLocation) {
    if !state.profile_limit_reported {
        push_issue(state, location, BrowserProfileIssueKind::ProfileLimit);
        state.profile_limit_reported = true;
    }
}

fn trusted_directory(
    path: &Path,
    anchor: &Path,
) -> Result<Option<PathBuf>, BrowserProfileIssueKind> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BrowserProfileIssueKind::Unreadable),
    }
    let canonical_anchor =
        fs::canonicalize(anchor).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if !bounded_utf8_path(&canonical_anchor) {
        return Err(BrowserProfileIssueKind::UnsafePath);
    }
    if !fs::metadata(&canonical_anchor)
        .map_err(|_| BrowserProfileIssueKind::Unreadable)?
        .is_dir()
    {
        return Err(BrowserProfileIssueKind::UnsupportedFileType);
    }
    let canonical_path = fs::canonicalize(path).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if !bounded_utf8_path(&canonical_path) || !canonical_path.starts_with(&canonical_anchor) {
        return Err(BrowserProfileIssueKind::UnsafePath);
    }
    let metadata =
        fs::metadata(&canonical_path).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if !metadata.is_dir() {
        return Err(BrowserProfileIssueKind::UnsupportedFileType);
    }
    Ok(Some(canonical_path))
}

fn canonical_child_directory(
    path: &Path,
    trusted_root: &Path,
) -> Result<Option<PathBuf>, BrowserProfileIssueKind> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BrowserProfileIssueKind::Unreadable),
    }
    let canonical = fs::canonicalize(path).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if !bounded_utf8_path(&canonical) || !canonical.starts_with(trusted_root) {
        return Err(BrowserProfileIssueKind::UnsafePath);
    }
    let metadata = fs::metadata(&canonical).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if !metadata.is_dir() {
        return Err(BrowserProfileIssueKind::UnsupportedFileType);
    }
    Ok(Some(canonical))
}

fn bounded_directory_names(root: &Path) -> Result<Vec<String>, BrowserProfileIssueKind> {
    let entries = fs::read_dir(root).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    let mut names = Vec::new();
    let mut saw_non_utf8 = false;
    let mut entry_count = 0_usize;
    for entry in entries {
        entry_count += 1;
        if entry_count > MAX_DIRECTORY_ENTRIES {
            return Err(BrowserProfileIssueKind::TooManyEntries);
        }
        let entry = entry.map_err(|_| BrowserProfileIssueKind::Unreadable)?;
        match entry.file_name().into_string() {
            Ok(name) => names.push(name),
            Err(_) => saw_non_utf8 = true,
        }
    }
    if saw_non_utf8 {
        return Err(BrowserProfileIssueKind::Unreadable);
    }
    Ok(names)
}

fn valid_chromium_profile_name(name: &str) -> bool {
    name.len() <= MAX_CHROMIUM_PROFILE_NAME_BYTES
        && (name == "Default"
            || name.strip_prefix("Profile ").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            }))
}

fn read_profiles_ini(path: &Path) -> Result<Option<Vec<u8>>, BrowserProfileIssueKind> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BrowserProfileIssueKind::Unreadable),
    };
    if !metadata.file_type().is_file() {
        return Err(BrowserProfileIssueKind::UnsupportedFileType);
    }
    if metadata.len() > MAX_PROFILES_INI_BYTES_U64 {
        return Err(BrowserProfileIssueKind::OversizedProfilesIni);
    }
    let descriptor = open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    let stat = fstat(&descriptor).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
        return Err(BrowserProfileIssueKind::UnsupportedFileType);
    }
    let size = u64::try_from(stat.st_size).map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if size > MAX_PROFILES_INI_BYTES_U64 {
        return Err(BrowserProfileIssueKind::OversizedProfilesIni);
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(MAX_PROFILES_INI_BYTES_U64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BrowserProfileIssueKind::Unreadable)?;
    if bytes.len() > MAX_PROFILES_INI_BYTES {
        return Err(BrowserProfileIssueKind::OversizedProfilesIni);
    }
    Ok(Some(bytes))
}

#[derive(Default)]
struct IniProfile {
    index: u16,
    path: Option<String>,
    relative: Option<bool>,
    default: Option<bool>,
}

struct ParsedProfile {
    path: String,
    relative: bool,
    default: bool,
    index: u16,
}

fn parse_profiles_ini(bytes: &[u8]) -> Result<Vec<ParsedProfile>, BrowserProfileIssueKind> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| BrowserProfileIssueKind::NonUtf8ProfilesIni)?;
    if text.contains('\0') {
        return Err(BrowserProfileIssueKind::MalformedProfilesIni);
    }
    let mut profiles = BTreeMap::<u16, IniProfile>::new();
    let mut current_profile = None;
    let mut section_count = 0_usize;
    let mut entry_count = 0_usize;
    for raw_line in text.lines() {
        if raw_line.len() > MAX_INI_LINE_BYTES {
            return Err(BrowserProfileIssueKind::MalformedProfilesIni);
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            current_profile = parse_ini_section(line, &mut profiles)?;
            section_count += 1;
            if section_count > MAX_INI_SECTIONS {
                return Err(BrowserProfileIssueKind::TooManyEntries);
            }
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(BrowserProfileIssueKind::MalformedProfilesIni)?;
        if !valid_ini_key(key.trim()) || value.chars().any(char::is_control) {
            return Err(BrowserProfileIssueKind::MalformedProfilesIni);
        }
        entry_count += 1;
        if entry_count > MAX_INI_ENTRIES {
            return Err(BrowserProfileIssueKind::TooManyEntries);
        }
        if let Some(index) = current_profile {
            apply_profile_entry(
                profiles
                    .get_mut(&index)
                    .ok_or(BrowserProfileIssueKind::MalformedProfilesIni)?,
                key.trim(),
                value.trim(),
            )?;
        }
    }
    if profiles.len() > MAX_PROFILES_PER_ROOT {
        return Err(BrowserProfileIssueKind::TooManyEntries);
    }
    let mut parsed = profiles
        .into_values()
        .map(|profile| {
            let path = profile
                .path
                .filter(|path| !path.is_empty() && path.len() <= MAX_PATH_BYTES)
                .ok_or(BrowserProfileIssueKind::MalformedProfilesIni)?;
            Ok(ParsedProfile {
                path,
                relative: profile.relative.unwrap_or(true),
                default: profile.default.unwrap_or(false),
                index: profile.index,
            })
        })
        .collect::<Result<Vec<_>, BrowserProfileIssueKind>>()?;
    parsed.sort_by_key(|profile| (!profile.default, profile.index));
    Ok(parsed)
}

fn parse_ini_section(
    line: &str,
    profiles: &mut BTreeMap<u16, IniProfile>,
) -> Result<Option<u16>, BrowserProfileIssueKind> {
    if !line.ends_with(']')
        || line[1..line.len() - 1].contains('[')
        || line[1..line.len() - 1].contains(']')
    {
        return Err(BrowserProfileIssueKind::MalformedProfilesIni);
    }
    let section = &line[1..line.len() - 1];
    if section.is_empty()
        || section.len() > 128
        || !section.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(BrowserProfileIssueKind::MalformedProfilesIni);
    }
    let Some(index) = section.strip_prefix("Profile") else {
        return Ok(None);
    };
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BrowserProfileIssueKind::MalformedProfilesIni);
    }
    let index = index
        .parse::<u16>()
        .map_err(|_| BrowserProfileIssueKind::MalformedProfilesIni)?;
    if profiles
        .insert(
            index,
            IniProfile {
                index,
                ..IniProfile::default()
            },
        )
        .is_some()
    {
        return Err(BrowserProfileIssueKind::MalformedProfilesIni);
    }
    Ok(Some(index))
}

fn apply_profile_entry(
    profile: &mut IniProfile,
    key: &str,
    value: &str,
) -> Result<(), BrowserProfileIssueKind> {
    match key {
        "Path" if profile.path.is_none() => profile.path = Some(value.to_owned()),
        "IsRelative" if profile.relative.is_none() => {
            profile.relative = Some(parse_ini_bool(value)?);
        }
        "Default" if profile.default.is_none() => {
            profile.default = Some(parse_ini_bool(value)?);
        }
        "Path" | "IsRelative" | "Default" => {
            return Err(BrowserProfileIssueKind::MalformedProfilesIni);
        }
        _ => {}
    }
    Ok(())
}

fn parse_ini_bool(value: &str) -> Result<bool, BrowserProfileIssueKind> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(BrowserProfileIssueKind::MalformedProfilesIni),
    }
}

fn valid_ini_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && bounded_utf8_path(path)
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_lexical_root(path: &Path) -> Result<PathBuf, BrowserProfileConfigError> {
    if !path.is_absolute()
        || !bounded_utf8_path(path)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(BrowserProfileConfigError::InvalidRoot);
    }
    Ok(path.to_path_buf())
}

fn bounded_utf8_path(path: &Path) -> bool {
    path.to_str().is_some()
        && !path.as_os_str().is_empty()
        && path.as_os_str().as_bytes().len() <= MAX_PATH_BYTES
        && !path.as_os_str().as_bytes().contains(&0)
}
