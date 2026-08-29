//! Deterministic XDG path resolution for application-owned state.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat, mkdirat};
use nix::unistd::geteuid;
use thiserror::Error;

/// The only namespace used for application-owned files.
pub const APP_NAMESPACE: &str = "omarchy-ai-bar";

const CONFIG_FILE_NAME: &str = "config.json";
const HISTORY_DATABASE_NAME: &str = "history.sqlite3";
const SOCKET_FILE_NAME: &str = "daemon.sock";

/// Resolved application paths under explicit or standard XDG roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    config: PathBuf,
    data: PathBuf,
    cache: PathBuf,
    runtime: PathBuf,
}

impl AppPaths {
    /// Resolves paths from a caller-owned environment map.
    ///
    /// This function never reads or mutates the process environment. Empty XDG
    /// values are treated as unset. Runtime state intentionally has no HOME
    /// fallback.
    ///
    /// # Errors
    ///
    /// Returns an error when a required fallback is missing or a supplied root
    /// is not absolute.
    pub fn from_env_map(environment: &BTreeMap<String, OsString>) -> Result<Self, PathError> {
        let config_root = xdg_or_home(
            environment,
            "XDG_CONFIG_HOME",
            RootKind::Config,
            Path::new(".config"),
        )?;
        let data_root = xdg_or_home(
            environment,
            "XDG_DATA_HOME",
            RootKind::Data,
            Path::new(".local/share"),
        )?;
        let cache_root = xdg_or_home(
            environment,
            "XDG_CACHE_HOME",
            RootKind::Cache,
            Path::new(".cache"),
        )?;
        let runtime_root = optional_absolute(environment, "XDG_RUNTIME_DIR", RootKind::Runtime)?
            .ok_or(PathError::MissingRuntimeDirectory)?;

        Ok(Self {
            config: config_root.join(APP_NAMESPACE),
            data: data_root.join(APP_NAMESPACE),
            cache: cache_root.join(APP_NAMESPACE),
            runtime: runtime_root.join(APP_NAMESPACE),
        })
    }

    /// Returns the private configuration directory.
    #[must_use]
    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    /// Returns the schema-versioned JSON configuration file.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config.join(CONFIG_FILE_NAME)
    }

    /// Returns the private durable-data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data
    }

    /// Returns the durable history database path.
    #[must_use]
    pub fn history_database(&self) -> PathBuf {
        self.data.join(HISTORY_DATABASE_NAME)
    }

    /// Returns the private cache directory.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache
    }

    /// Returns the private runtime directory.
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime
    }

    /// Returns the daemon's private Unix-socket path.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.runtime.join(SOCKET_FILE_NAME)
    }

    /// Returns all application-owned directory roots.
    #[must_use]
    pub fn private_directories(&self) -> [&Path; 4] {
        [&self.config, &self.data, &self.cache, &self.runtime]
    }

    /// Creates and secures every application-owned directory root.
    ///
    /// Existing namespace directories are opened and checked before their mode
    /// is tightened to `0700`. Symbolic links, non-directories, directories not
    /// owned by the effective user, and identity changes during the check are
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns a path-free error describing the failing root category.
    pub fn create_private_directories(&self) -> Result<(), PathError> {
        for (kind, directory) in [
            (RootKind::Config, &self.config),
            (RootKind::Data, &self.data),
            (RootKind::Cache, &self.cache),
            (RootKind::Runtime, &self.runtime),
        ] {
            create_private_directory(directory, kind)?;
        }
        Ok(())
    }
}

fn xdg_or_home(
    environment: &BTreeMap<String, OsString>,
    variable: &'static str,
    kind: RootKind,
    suffix: &Path,
) -> Result<PathBuf, PathError> {
    if let Some(root) = optional_absolute(environment, variable, kind)? {
        return Ok(root);
    }
    let home = optional_absolute(environment, "HOME", RootKind::Home)?
        .ok_or(PathError::MissingHomeDirectory)?;
    Ok(normalize_absolute(&home.join(suffix)))
}

fn optional_absolute(
    environment: &BTreeMap<String, OsString>,
    variable: &'static str,
    kind: RootKind,
) -> Result<Option<PathBuf>, PathError> {
    let Some(value) = environment.get(variable).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(PathError::RootNotAbsolute { kind });
    }
    Ok(Some(normalize_absolute(path)))
}

fn normalize_absolute(path: &Path) -> PathBuf {
    debug_assert!(path.is_absolute());
    let mut normalized = PathBuf::from(OsStr::new("/"));
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
            Component::Prefix(_) => unreachable!("Unix absolute paths do not have prefixes"),
        }
    }
    normalized
}

fn create_private_directory(path: &Path, kind: RootKind) -> Result<(), PathError> {
    let root = open(
        Path::new("/"),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PathError::RootOperationFailed { kind })?;
    let mut directory = File::from(root);
    let mut components = path.components().peekable();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(PathError::RootNotAbsolute { kind });
    }

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(PathError::RootOperationFailed { kind });
        };
        let final_component = components.peek().is_none();
        match fstatat(&directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) => validate_directory_stat(&stat, kind, final_component)?,
            Err(Errno::ENOENT) => {
                match mkdirat(&directory, name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(_) => return Err(PathError::RootOperationFailed { kind }),
                }
            }
            Err(_) => return Err(PathError::RootOperationFailed { kind }),
        }

        let opened = openat(
            &directory,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| PathError::RootChanged { kind })?;
        directory = File::from(opened);
        let stat = fstat(&directory).map_err(|_| PathError::RootOperationFailed { kind })?;
        validate_directory_stat(&stat, kind, final_component)?;
    }

    fchmod(&directory, Mode::from_bits_truncate(0o700))
        .map_err(|_| PathError::RootOperationFailed { kind })?;
    let secured = fstat(&directory).map_err(|_| PathError::RootOperationFailed { kind })?;
    if secured.st_mode & 0o777 != 0o700 {
        return Err(PathError::RootOperationFailed { kind });
    }
    Ok(())
}

fn validate_directory_stat(
    stat: &nix::libc::stat,
    kind: RootKind,
    require_owner: bool,
) -> Result<(), PathError> {
    let file_type = SFlag::from_bits_truncate(stat.st_mode);
    if file_type.contains(SFlag::S_IFLNK) {
        return Err(PathError::RootIsSymlink { kind });
    }
    if !file_type.contains(SFlag::S_IFDIR) {
        return Err(PathError::RootWrongType { kind });
    }
    if require_owner && stat.st_uid != geteuid().as_raw() {
        return Err(PathError::RootWrongOwner { kind });
    }
    Ok(())
}

/// A non-sensitive category for an XDG or application directory root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKind {
    /// HOME fallback root.
    Home,
    /// Configuration root.
    Config,
    /// Durable-data root.
    Data,
    /// Cache root.
    Cache,
    /// Runtime root.
    Runtime,
}

/// Safe path-resolution and private-directory error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PathError {
    /// Neither an explicit XDG root nor HOME can resolve a standard root.
    #[error("HOME is required when a standard XDG root is unset")]
    MissingHomeDirectory,
    /// Runtime state cannot use a HOME fallback.
    #[error("XDG_RUNTIME_DIR is required")]
    MissingRuntimeDirectory,
    /// A supplied root is relative.
    #[error("an environment root must be absolute")]
    RootNotAbsolute {
        /// Non-sensitive root category.
        kind: RootKind,
    },
    /// An application or XDG root is a symbolic link.
    #[error("a directory root must not be a symbolic link")]
    RootIsSymlink {
        /// Non-sensitive root category.
        kind: RootKind,
    },
    /// An application or XDG root is not a directory.
    #[error("a directory root has the wrong file type")]
    RootWrongType {
        /// Non-sensitive root category.
        kind: RootKind,
    },
    /// An application or XDG root belongs to a different user.
    #[error("a directory root has the wrong owner")]
    RootWrongOwner {
        /// Non-sensitive root category.
        kind: RootKind,
    },
    /// A checked directory changed identity before it could be secured.
    #[error("a directory root changed during validation")]
    RootChanged {
        /// Non-sensitive root category.
        kind: RootKind,
    },
    /// A filesystem operation on a root failed.
    #[error("a directory root operation failed")]
    RootOperationFailed {
        /// Non-sensitive root category.
        kind: RootKind,
    },
}
