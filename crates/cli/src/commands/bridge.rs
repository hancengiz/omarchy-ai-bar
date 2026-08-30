//! Transactional lifecycle management for the packaged Omarchy QML bridge.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use nix::fcntl::{AT_FDCWD, RenameFlags, renameat2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Stable identifier declared by the Omarchy plugin manifest.
pub const PLUGIN_ID: &str = "local.omarchy-ai-bar";
/// Current bridge protocol major shipped by this package.
pub const CURRENT_BRIDGE_PROTOCOL_MAJOR: u16 = 1;
/// Oldest backend major accepted during a package/plugin rolling update.
pub const MINIMUM_BRIDGE_PROTOCOL_MAJOR: u16 = CURRENT_BRIDGE_PROTOCOL_MAJOR - 1;
/// Packaged location used by Arch and direct-release installations.
pub const PACKAGED_PLUGIN_PATH: &str = "/usr/share/omarchy-ai-bar/omarchy-plugin";

const MANAGED_MARKER: &str = ".omarchy-ai-bar-managed.json";
const MARKER_SCHEMA_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_MARKER_BYTES: u64 = 16 * 1024;
const MAX_PAYLOAD_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PAYLOAD_FILES: usize = 4_096;
const ENABLE_DISCOVERY_ATTEMPTS: usize = 20;
const ENABLE_DISCOVERY_INTERVAL: Duration = Duration::from_millis(100);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Stable failures surfaced by bridge lifecycle commands.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// No packaged QML payload was found.
    #[error("the packaged Omarchy bridge payload is unavailable")]
    MissingPayload,
    /// The package payload contains an unsafe path, type, size, or manifest.
    #[error("the packaged Omarchy bridge payload failed safety checks")]
    UnsafePayload,
    /// The destination already exists and was not created by this application.
    #[error("the Omarchy bridge destination is not application-managed")]
    UnrecognizedTree,
    /// An intact application-managed bridge is already present.
    #[error("the Omarchy bridge is already installed")]
    AlreadyInstalled,
    /// A managed payload was edited after installation.
    #[error("the installed Omarchy bridge has local modifications")]
    ModifiedTree,
    /// No per-user bridge is installed.
    #[error("the Omarchy bridge is not installed")]
    NotInstalled,
    /// A bridge is too old or too new for a safe rolling update.
    #[error("the installed Omarchy bridge protocol is incompatible")]
    IncompatibleProtocol,
    /// Omarchy refused validation or a lifecycle operation.
    #[error("Omarchy rejected the bridge lifecycle operation")]
    OmarchyCommand,
    /// A bounded local filesystem operation failed.
    #[error("the bridge lifecycle filesystem operation failed")]
    Filesystem(#[source] io::Error),
}

impl From<io::Error> for BridgeError {
    fn from(error: io::Error) -> Self {
        Self::Filesystem(error)
    }
}

/// Non-mutating state returned by [`BridgeManager::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeStatus {
    /// The application plugin path does not exist.
    NotInstalled,
    /// The path is managed, intact, and protocol-compatible.
    Installed {
        /// Version recorded from the installed manifest.
        payload_version: String,
        /// Bridge protocol major recorded at installation.
        protocol_major: u16,
        /// Whether an available packaged payload differs; `None` means it is absent.
        update_available: Option<bool>,
    },
    /// The marker is valid but application-owned files have changed.
    Modified,
    /// The destination exists without a valid application marker.
    Unrecognized,
    /// The marker is valid but outside the supported rolling window.
    Incompatible {
        /// Protocol major found in the installed marker.
        protocol_major: u16,
    },
}

/// Supported Omarchy operations, abstracted for deterministic lifecycle tests.
pub trait OmarchyPluginCommands {
    /// Validate a complete staged plugin folder.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::OmarchyCommand`] when Omarchy rejects the payload.
    fn validate(&self, plugin_dir: &Path) -> Result<(), BridgeError>;
    /// Ask the running shell to rediscover plugin manifests.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::OmarchyCommand`] when the shell cannot rescan.
    fn rescan(&self) -> Result<(), BridgeError>;
    /// Enable a discovered plugin using its manifest default placement.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::OmarchyCommand`] when the plugin cannot be enabled.
    fn enable(&self, plugin_id: &str) -> Result<(), BridgeError>;
    /// Disable a plugin before its app-owned files are removed.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::OmarchyCommand`] when the plugin cannot be disabled.
    fn disable(&self, plugin_id: &str) -> Result<(), BridgeError>;
}

/// Production adapter for the supported Omarchy command-line contract.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemOmarchyCommands;

impl OmarchyPluginCommands for SystemOmarchyCommands {
    fn validate(&self, plugin_dir: &Path) -> Result<(), BridgeError> {
        run_command(
            omarchy_executable(),
            [
                OsStr::new("plugin"),
                OsStr::new("validate"),
                plugin_dir.as_os_str(),
            ],
        )
    }

    fn rescan(&self) -> Result<(), BridgeError> {
        run_command(
            omarchy_shell_executable(),
            [OsStr::new("shell"), OsStr::new("rescanPlugins")],
        )
    }

    fn enable(&self, plugin_id: &str) -> Result<(), BridgeError> {
        let arguments = [
            OsStr::new("plugin"),
            OsStr::new("enable"),
            OsStr::new(plugin_id),
        ];
        for attempt in 0..ENABLE_DISCOVERY_ATTEMPTS {
            let status = Command::new(omarchy_executable())
                .args(arguments)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map_err(|_| BridgeError::OmarchyCommand)?;
            if status.success() {
                return Ok(());
            }
            if attempt + 1 < ENABLE_DISCOVERY_ATTEMPTS {
                thread::sleep(ENABLE_DISCOVERY_INTERVAL);
            }
        }
        Err(BridgeError::OmarchyCommand)
    }

    fn disable(&self, plugin_id: &str) -> Result<(), BridgeError> {
        run_command(
            omarchy_executable(),
            [
                OsStr::new("plugin"),
                OsStr::new("disable"),
                OsStr::new(plugin_id),
            ],
        )
    }
}

/// Owns the explicit package-to-user bridge lifecycle.
pub struct BridgeManager<C> {
    source: PathBuf,
    config_home: PathBuf,
    commands: C,
}

impl<C: OmarchyPluginCommands> BridgeManager<C> {
    /// Creates a manager using an explicit packaged source and temporary-safe config root.
    #[must_use]
    pub fn new(source: impl Into<PathBuf>, config_home: impl Into<PathBuf>, commands: C) -> Self {
        Self {
            source: source.into(),
            config_home: config_home.into(),
            commands,
        }
    }

    /// Returns the only user plugin directory this manager may mutate.
    #[must_use]
    pub fn destination(&self) -> PathBuf {
        self.plugins_dir().join(PLUGIN_ID)
    }

    /// Stages, validates, atomically installs, rescans, and enables the bridge.
    ///
    /// # Errors
    ///
    /// Returns a stable [`BridgeError`] when the source or destination is unsafe,
    /// validation fails, activation fails, or a bounded filesystem operation fails.
    pub fn install(&self) -> Result<(), BridgeError> {
        let destination = self.destination();
        if path_entry_exists(&destination)? {
            return Err(match self.inspect_existing()? {
                ExistingState::Modified => BridgeError::ModifiedTree,
                ExistingState::Installed { .. } | ExistingState::Incompatible(_) => {
                    BridgeError::AlreadyInstalled
                }
                ExistingState::Absent | ExistingState::Unrecognized => {
                    BridgeError::UnrecognizedTree
                }
            });
        }

        let plugins_dir = self.prepare_plugins_dir()?;
        let (mut stage, _marker) = self.stage_payload(&plugins_dir)?;
        self.commands.validate(stage.path())?;
        let installed_identity = directory_identity(stage.path())?;
        atomic_install_no_replace(stage.path(), &destination)?;
        require_identity(&destination, installed_identity)?;
        stage.disarm();

        if let Err(error) = self.commands.rescan() {
            Self::rollback_new_install(&destination, &plugins_dir, installed_identity)?;
            return Err(error);
        }
        if let Err(error) = self.commands.enable(PLUGIN_ID) {
            let _ignored = self.commands.disable(PLUGIN_ID);
            Self::rollback_new_install(&destination, &plugins_dir, installed_identity)?;
            let _ignored = self.commands.rescan();
            return Err(error);
        }
        Ok(())
    }

    /// Replaces an intact compatible payload while leaving Omarchy state untouched.
    ///
    /// # Errors
    ///
    /// Returns a stable [`BridgeError`] when the installed tree is absent, edited,
    /// foreign, incompatible, rejected by Omarchy, or cannot be atomically replaced.
    pub fn update(&self) -> Result<(), BridgeError> {
        let identity = match self.inspect_existing()? {
            ExistingState::Absent => return Err(BridgeError::NotInstalled),
            ExistingState::Unrecognized => return Err(BridgeError::UnrecognizedTree),
            ExistingState::Modified => return Err(BridgeError::ModifiedTree),
            ExistingState::Incompatible(_) => return Err(BridgeError::IncompatibleProtocol),
            ExistingState::Installed { identity, .. } => identity,
        };

        let destination = self.destination();
        let plugins_dir = self.prepare_plugins_dir()?;
        let (mut stage, _marker) = self.stage_payload(&plugins_dir)?;
        self.commands.validate(stage.path())?;

        require_identity(&destination, identity)?;
        atomic_exchange(stage.path(), &destination)?;
        if require_identity(stage.path(), identity).is_err() {
            if atomic_exchange(stage.path(), &destination).is_err() {
                stage.disarm();
            }
            return Err(BridgeError::ModifiedTree);
        }
        if let Err(error) = self.commands.rescan() {
            if atomic_exchange(stage.path(), &destination).is_err() {
                stage.disarm();
            }
            return Err(error);
        }
        fs::remove_dir_all(stage.path())?;
        stage.disarm();
        Ok(())
    }

    /// Reports ownership, integrity, compatibility, and package drift without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Filesystem`] when the status cannot be inspected safely.
    pub fn status(&self) -> Result<BridgeStatus, BridgeError> {
        match self.inspect_existing()? {
            ExistingState::Absent => Ok(BridgeStatus::NotInstalled),
            ExistingState::Modified => Ok(BridgeStatus::Modified),
            ExistingState::Unrecognized => Ok(BridgeStatus::Unrecognized),
            ExistingState::Incompatible(marker) => Ok(BridgeStatus::Incompatible {
                protocol_major: marker.protocol_major,
            }),
            ExistingState::Installed { marker, .. } => {
                let update_available = inspect_payload(&self.source).ok().map(|payload| {
                    payload.version != marker.payload_version
                        || payload.digest != marker.payload_sha256
                });
                Ok(BridgeStatus::Installed {
                    payload_version: marker.payload_version,
                    protocol_major: marker.protocol_major,
                    update_available,
                })
            }
        }
    }

    /// Disables and atomically detaches only an intact application-owned tree.
    ///
    /// # Errors
    ///
    /// Returns a stable [`BridgeError`] when the installed tree is absent, edited,
    /// foreign, incompatible, cannot be disabled, or cannot be safely removed.
    pub fn uninstall(&self) -> Result<(), BridgeError> {
        let identity = match self.inspect_existing()? {
            ExistingState::Absent => return Err(BridgeError::NotInstalled),
            ExistingState::Unrecognized => return Err(BridgeError::UnrecognizedTree),
            ExistingState::Modified => return Err(BridgeError::ModifiedTree),
            ExistingState::Incompatible(_) => return Err(BridgeError::IncompatibleProtocol),
            ExistingState::Installed { identity, .. } => identity,
        };

        let destination = self.destination();
        let plugins_dir = self.prepare_plugins_dir()?;
        let tombstone = unique_path(&plugins_dir, "remove")?;
        require_identity(&destination, identity)?;
        self.commands.disable(PLUGIN_ID)?;
        if let Err(error) = require_identity(&destination, identity) {
            let _ignored = self.commands.enable(PLUGIN_ID);
            return Err(error);
        }
        if let Err(error) = atomic_install_no_replace(&destination, &tombstone) {
            let _ignored = self.commands.enable(PLUGIN_ID);
            return Err(error);
        }
        if require_identity(&tombstone, identity).is_err() {
            let _ignored = atomic_install_no_replace(&tombstone, &destination);
            let _ignored = self.commands.enable(PLUGIN_ID);
            return Err(BridgeError::ModifiedTree);
        }
        if let Err(error) = self.commands.rescan() {
            let _ignored = atomic_install_no_replace(&tombstone, &destination);
            let _ignored = self.commands.enable(PLUGIN_ID);
            return Err(error);
        }
        fs::remove_dir_all(tombstone)?;
        Ok(())
    }

    fn plugins_dir(&self) -> PathBuf {
        self.config_home.join("omarchy/plugins")
    }

    fn prepare_plugins_dir(&self) -> Result<PathBuf, BridgeError> {
        let plugins_dir = self.plugins_dir();
        fs::create_dir_all(&plugins_dir)?;
        let metadata = fs::symlink_metadata(&plugins_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BridgeError::UnsafePayload);
        }
        Ok(plugins_dir)
    }

    fn stage_payload(&self, plugins_dir: &Path) -> Result<(TempTree, ManagedMarker), BridgeError> {
        let payload = inspect_payload(&self.source)?;
        let stage_path = unique_path(plugins_dir, "stage")?;
        fs::create_dir(&stage_path)?;
        fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o755))?;
        let stage = TempTree::new(stage_path);
        copy_payload(&self.source, stage.path())?;

        let marker = ManagedMarker {
            schema_version: MARKER_SCHEMA_VERSION,
            plugin_id: PLUGIN_ID.into(),
            payload_version: payload.version,
            protocol_major: CURRENT_BRIDGE_PROTOCOL_MAJOR,
            minimum_backend_major: MINIMUM_BRIDGE_PROTOCOL_MAJOR,
            payload_sha256: payload.digest,
        };
        let encoded = serde_json::to_vec_pretty(&marker).map_err(|_| BridgeError::UnsafePayload)?;
        fs::write(stage.path().join(MANAGED_MARKER), encoded)?;
        fs::set_permissions(
            stage.path().join(MANAGED_MARKER),
            fs::Permissions::from_mode(0o644),
        )?;
        Ok((stage, marker))
    }

    fn inspect_existing(&self) -> Result<ExistingState, BridgeError> {
        let destination = self.destination();
        if !path_entry_exists(&destination)? {
            return Ok(ExistingState::Absent);
        }
        let root_metadata = fs::symlink_metadata(&destination)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Ok(ExistingState::Unrecognized);
        }
        let identity = TreeIdentity::from_metadata(&root_metadata);

        let marker_path = destination.join(MANAGED_MARKER);
        let marker_bytes = match read_bounded(&marker_path, MAX_MARKER_BYTES) {
            Ok(bytes) => bytes,
            Err(BridgeError::Filesystem(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ExistingState::Unrecognized);
            }
            Err(error) => return Err(error),
        };
        let marker: ManagedMarker = match serde_json::from_slice(&marker_bytes) {
            Ok(marker) => marker,
            Err(_) => return Ok(ExistingState::Unrecognized),
        };
        if marker.schema_version != MARKER_SCHEMA_VERSION || marker.plugin_id != PLUGIN_ID {
            return Ok(ExistingState::Unrecognized);
        }
        if !(MINIMUM_BRIDGE_PROTOCOL_MAJOR..=CURRENT_BRIDGE_PROTOCOL_MAJOR)
            .contains(&marker.protocol_major)
        {
            return Ok(ExistingState::Incompatible(marker));
        }

        let digest = match digest_tree(&destination, Some(MANAGED_MARKER)) {
            Ok(digest) => digest,
            Err(BridgeError::UnsafePayload) => return Ok(ExistingState::Modified),
            Err(error) => return Err(error),
        };
        if digest != marker.payload_sha256 {
            return Ok(ExistingState::Modified);
        }
        Ok(ExistingState::Installed { marker, identity })
    }

    fn rollback_new_install(
        destination: &Path,
        plugins_dir: &Path,
        identity: TreeIdentity,
    ) -> Result<(), BridgeError> {
        let tombstone = unique_path(plugins_dir, "rollback")?;
        require_identity(destination, identity)?;
        atomic_install_no_replace(destination, &tombstone)?;
        if require_identity(&tombstone, identity).is_err() {
            let _ignored = atomic_install_no_replace(&tombstone, destination);
            return Err(BridgeError::ModifiedTree);
        }
        fs::remove_dir_all(tombstone)?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedMarker {
    schema_version: u16,
    plugin_id: String,
    payload_version: String,
    protocol_major: u16,
    minimum_backend_major: u16,
    payload_sha256: String,
}

enum ExistingState {
    Absent,
    Installed {
        marker: ManagedMarker,
        identity: TreeIdentity,
    },
    Modified,
    Unrecognized,
    Incompatible(ManagedMarker),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TreeIdentity {
    device: u64,
    inode: u64,
}

impl TreeIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct PayloadInspection {
    version: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestIdentity {
    schema_version: u16,
    id: String,
    version: String,
    #[serde(flatten)]
    _remainder: serde_json::Map<String, serde_json::Value>,
}

fn inspect_payload(source: &Path) -> Result<PayloadInspection, BridgeError> {
    let metadata = fs::symlink_metadata(source).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            BridgeError::MissingPayload
        } else {
            BridgeError::Filesystem(error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BridgeError::UnsafePayload);
    }
    let manifest_bytes = read_bounded(&source.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest: ManifestIdentity =
        serde_json::from_slice(&manifest_bytes).map_err(|_| BridgeError::UnsafePayload)?;
    if manifest.schema_version != 1 || manifest.id != PLUGIN_ID || manifest.version.is_empty() {
        return Err(BridgeError::UnsafePayload);
    }
    Ok(PayloadInspection {
        version: manifest.version,
        digest: digest_tree(source, Some(MANAGED_MARKER))?,
    })
}

fn copy_payload(source: &Path, destination: &Path) -> Result<(), BridgeError> {
    let mut entries = sorted_entries(source)?;
    for entry in entries.drain(..) {
        let name = entry.file_name();
        if name == OsStr::new(MANAGED_MARKER) {
            return Err(BridgeError::UnsafePayload);
        }
        let source_path = entry.path();
        let destination_path = destination.join(&name);
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(BridgeError::UnsafePayload);
        }
        if metadata.is_dir() {
            fs::create_dir(&destination_path)?;
            let mode = metadata.permissions().mode() & 0o777;
            fs::set_permissions(&destination_path, fs::Permissions::from_mode(mode))?;
            copy_payload(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            if metadata.len() > MAX_PAYLOAD_FILE_BYTES {
                return Err(BridgeError::UnsafePayload);
            }
            fs::copy(&source_path, &destination_path)?;
            let mode = metadata.permissions().mode() & 0o777;
            fs::set_permissions(&destination_path, fs::Permissions::from_mode(mode))?;
        } else {
            return Err(BridgeError::UnsafePayload);
        }
    }
    Ok(())
}

fn digest_tree(root: &Path, excluded_root_name: Option<&str>) -> Result<String, BridgeError> {
    let mut records = Vec::new();
    collect_records(root, root, excluded_root_name, &mut records)?;
    if records.len() > MAX_PAYLOAD_FILES {
        return Err(BridgeError::UnsafePayload);
    }
    records.sort_by(|left, right| left.relative.cmp(&right.relative));

    let mut total = 0_u64;
    let mut digest = Sha256::new();
    for record in records {
        digest.update(if record.is_directory { b"D" } else { b"F" });
        digest.update(record.relative.as_bytes());
        digest.update([0]);
        digest.update(record.mode.to_be_bytes());
        if !record.is_directory {
            let metadata = fs::symlink_metadata(&record.absolute)?;
            if metadata.len() > MAX_PAYLOAD_FILE_BYTES {
                return Err(BridgeError::UnsafePayload);
            }
            total = total
                .checked_add(metadata.len())
                .ok_or(BridgeError::UnsafePayload)?;
            if total > MAX_PAYLOAD_BYTES {
                return Err(BridgeError::UnsafePayload);
            }
            let mut file = File::open(&record.absolute)?;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

struct TreeRecord {
    absolute: PathBuf,
    relative: String,
    mode: u32,
    is_directory: bool,
}

fn collect_records(
    root: &Path,
    current: &Path,
    excluded_root_name: Option<&str>,
    records: &mut Vec<TreeRecord>,
) -> Result<(), BridgeError> {
    for entry in sorted_entries(current)? {
        let name = entry.file_name();
        if current == root
            && excluded_root_name.is_some_and(|excluded| name == OsStr::new(excluded))
        {
            continue;
        }
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)?;
        if metadata.file_type().is_symlink() {
            return Err(BridgeError::UnsafePayload);
        }
        let relative = absolute
            .strip_prefix(root)
            .map_err(|_| BridgeError::UnsafePayload)?
            .to_str()
            .ok_or(BridgeError::UnsafePayload)?
            .to_owned();
        if metadata.is_dir() {
            records.push(TreeRecord {
                absolute: absolute.clone(),
                relative,
                mode: metadata.permissions().mode() & 0o777,
                is_directory: true,
            });
            collect_records(root, &absolute, excluded_root_name, records)?;
        } else if metadata.is_file() {
            records.push(TreeRecord {
                absolute,
                relative,
                mode: metadata.permissions().mode() & 0o777,
                is_directory: false,
            });
        } else {
            return Err(BridgeError::UnsafePayload);
        }
        if records.len() > MAX_PAYLOAD_FILES {
            return Err(BridgeError::UnsafePayload);
        }
    }
    Ok(())
}

fn sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>, BridgeError> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, BridgeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(BridgeError::UnsafePayload);
    }
    fs::read(path).map_err(BridgeError::from)
}

fn unique_path(parent: &Path, purpose: &str) -> Result<PathBuf, BridgeError> {
    for _attempt in 0..64 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{PLUGIN_ID}.{purpose}.{}.{}",
            std::process::id(),
            sequence
        ));
        if !path_entry_exists(&candidate)? {
            return Ok(candidate);
        }
    }
    Err(BridgeError::Filesystem(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a bridge staging path",
    )))
}

fn path_entry_exists(path: &Path) -> Result<bool, BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn require_identity(path: &Path, expected: TreeIdentity) -> Result<(), BridgeError> {
    if directory_identity(path)? != expected {
        return Err(BridgeError::ModifiedTree);
    }
    Ok(())
}

fn directory_identity(path: &Path) -> Result<TreeIdentity, BridgeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BridgeError::ModifiedTree);
    }
    Ok(TreeIdentity::from_metadata(&metadata))
}

fn atomic_install_no_replace(source: &Path, destination: &Path) -> Result<(), BridgeError> {
    renameat2(
        AT_FDCWD,
        source,
        AT_FDCWD,
        destination,
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|error| BridgeError::Filesystem(io::Error::from_raw_os_error(error as i32)))
}

fn atomic_exchange(left: &Path, right: &Path) -> Result<(), BridgeError> {
    renameat2(
        AT_FDCWD,
        left,
        AT_FDCWD,
        right,
        RenameFlags::RENAME_EXCHANGE,
    )
    .map_err(|error| BridgeError::Filesystem(io::Error::from_raw_os_error(error as i32)))
}

fn run_command<I, S>(program: &Path, arguments: I) -> Result<(), BridgeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(program)
        .args(arguments)
        .status()
        .map_err(|_| BridgeError::OmarchyCommand)?;
    if status.success() {
        Ok(())
    } else {
        Err(BridgeError::OmarchyCommand)
    }
}

fn omarchy_executable() -> &'static Path {
    let installed = Path::new("/usr/share/omarchy/bin/omarchy");
    if installed.is_file() {
        installed
    } else {
        Path::new("omarchy")
    }
}

fn omarchy_shell_executable() -> &'static Path {
    let installed = Path::new("/usr/share/omarchy/bin/omarchy-shell");
    if installed.is_file() {
        installed
    } else {
        Path::new("omarchy-shell")
    }
}

struct TempTree {
    path: PathBuf,
    armed: bool,
}

impl TempTree {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.armed {
            let _ignored = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_window_includes_exactly_current_and_previous_major() {
        assert_eq!(CURRENT_BRIDGE_PROTOCOL_MAJOR, 1);
        assert_eq!(MINIMUM_BRIDGE_PROTOCOL_MAJOR, 0);
        assert!((MINIMUM_BRIDGE_PROTOCOL_MAJOR..=CURRENT_BRIDGE_PROTOCOL_MAJOR).contains(&0));
        assert!((MINIMUM_BRIDGE_PROTOCOL_MAJOR..=CURRENT_BRIDGE_PROTOCOL_MAJOR).contains(&1));
        assert!(!(MINIMUM_BRIDGE_PROTOCOL_MAJOR..=CURRENT_BRIDGE_PROTOCOL_MAJOR).contains(&2));
    }
}
