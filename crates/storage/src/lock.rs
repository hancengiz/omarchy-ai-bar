//! Symlink-safe, process-wide advisory locking for private storage files.
//!
//! Paths are resolved one directory descriptor at a time with `O_NOFOLLOW`.
//! This keeps validation tied to the directory actually used for opening the
//! lock, rather than validating one path and later reopening another.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::geteuid;
use thiserror::Error;

const PRIVATE_FILE_MODE: Mode = Mode::from_bits_truncate(0o600);
const UNSAFE_DIRECTORY_WRITE_BITS: u32 = 0o022;

/// A failure to resolve or lock a private storage file safely.
#[derive(Debug, Error)]
pub enum LockError {
    /// The supplied pathname is not an absolute, normalized file pathname.
    #[error("unsafe storage path {path}: {reason}")]
    UnsafePath {
        /// Path rejected by validation.
        path: PathBuf,
        /// Stable, secret-free reason for rejection.
        reason: &'static str,
    },

    /// A managed entry exists but is not a regular file owned by this user.
    #[error("unsafe storage entry {path}: {reason}")]
    UnsafeEntry {
        /// Entry rejected by validation.
        path: PathBuf,
        /// Stable, secret-free reason for rejection.
        reason: &'static str,
    },

    /// A filesystem or locking operation failed.
    #[error("could not {operation} {path}: {source}")]
    Io {
        /// Short operation description.
        operation: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },
}

/// An exclusive advisory lock released automatically on drop.
///
/// All writers of a document must use the same lock pathname. `atomic_file`
/// derives that pathname as `<target>.lock` and holds it from staging through
/// the durable directory sync.
#[derive(Debug)]
pub struct ExclusiveLock {
    _file: Flock<File>,
    path: PathBuf,
}

impl ExclusiveLock {
    /// Opens `path` without following symlinks, forces mode `0600`, and waits
    /// for an exclusive advisory lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or existing entry is unsafe, the lock
    /// file cannot be opened privately, or the advisory lock cannot be taken.
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, LockError> {
        let path = path.as_ref();
        let parent = SafeParent::open(path)?;
        Self::acquire_at(&parent.directory, &parent.file_name, path)
    }

    /// Returns the pathname used to identify this lock.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn acquire_at(
        directory: &File,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<Self, LockError> {
        validate_regular_or_absent(directory, name, display_path)?;

        let fd = openat(
            directory,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            PRIVATE_FILE_MODE,
        )
        .map_err(|error| nix_io("open lock", display_path, error))?;
        let file = File::from(fd);
        validate_open_regular(&file, display_path)?;
        fchmod(&file, PRIVATE_FILE_MODE)
            .map_err(|error| nix_io("set private lock permissions on", display_path, error))?;

        let locked = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_file, error)| nix_io("acquire exclusive lock on", display_path, error))?;
        Ok(Self {
            _file: locked,
            path: display_path.to_path_buf(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct SafeParent {
    pub(crate) directory: File,
    pub(crate) file_name: OsString,
}

impl SafeParent {
    pub(crate) fn open(path: &Path) -> Result<Self, LockError> {
        let components = absolute_file_components(path)?;
        let Some((file_name, parent_components)) = components.split_last() else {
            return Err(LockError::UnsafePath {
                path: path.to_path_buf(),
                reason: "path must name a file",
            });
        };

        let root_fd = open(
            Path::new("/"),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| nix_io("open filesystem root for", path, error))?;
        let mut directory = File::from(root_fd);

        for component in parent_components {
            let fd = openat(
                &directory,
                component.as_os_str(),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| match error {
                Errno::ELOOP | Errno::ENOTDIR => LockError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "parent components must be real directories, not symbolic links",
                },
                other => nix_io("open storage parent for", path, other),
            })?;
            directory = File::from(fd);
        }

        let metadata = directory.metadata().map_err(|source| LockError::Io {
            operation: "inspect storage parent for",
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(LockError::UnsafePath {
                path: path.to_path_buf(),
                reason: "parent is not a directory",
            });
        }
        if metadata.uid() != geteuid().as_raw() {
            return Err(LockError::UnsafePath {
                path: path.to_path_buf(),
                reason: "final parent directory is not owned by the current user",
            });
        }
        if metadata.mode() & UNSAFE_DIRECTORY_WRITE_BITS != 0 {
            return Err(LockError::UnsafePath {
                path: path.to_path_buf(),
                reason: "final parent directory is writable by another user",
            });
        }

        Ok(Self {
            directory,
            file_name: file_name.clone(),
        })
    }
}

pub(crate) fn absolute_file_components(path: &Path) -> Result<Vec<OsString>, LockError> {
    if !path.is_absolute() {
        return Err(LockError::UnsafePath {
            path: path.to_path_buf(),
            reason: "path must be absolute",
        });
    }

    let raw = path.as_os_str().as_bytes();
    if raw.len() < 2
        || raw.starts_with(b"//")
        || raw.ends_with(b"/")
        || raw.iter().any(u8::is_ascii_control)
        || raw[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(LockError::UnsafePath {
            path: path.to_path_buf(),
            reason: "path must use a canonical absolute file spelling",
        });
    }

    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(LockError::UnsafePath {
            path: path.to_path_buf(),
            reason: "path must begin at the filesystem root",
        });
    }

    let mut normal = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => normal.push(name.to_os_string()),
            Component::CurDir | Component::ParentDir => {
                return Err(LockError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "dot and parent traversal components are forbidden",
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(LockError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "path has an invalid component",
                });
            }
        }
    }

    if normal.is_empty() {
        return Err(LockError::UnsafePath {
            path: path.to_path_buf(),
            reason: "path must name a file",
        });
    }
    Ok(normal)
}

pub(crate) fn validate_regular_or_absent(
    directory: &File,
    name: &OsStr,
    display_path: &Path,
) -> Result<Option<nix::libc::stat>, LockError> {
    match fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
            if kind != SFlag::S_IFREG {
                return Err(LockError::UnsafeEntry {
                    path: display_path.to_path_buf(),
                    reason: "entry must be a regular file and may not be a symbolic link",
                });
            }
            if stat.st_uid != geteuid().as_raw() {
                return Err(LockError::UnsafeEntry {
                    path: display_path.to_path_buf(),
                    reason: "entry is not owned by the current user",
                });
            }
            Ok(Some(stat))
        }
        Err(Errno::ENOENT) => Ok(None),
        Err(error) => Err(nix_io("inspect storage entry", display_path, error)),
    }
}

pub(crate) fn validate_open_regular(file: &File, display_path: &Path) -> Result<(), LockError> {
    let stat =
        fstat(file).map_err(|error| nix_io("inspect opened storage entry", display_path, error))?;
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    if kind != SFlag::S_IFREG {
        return Err(LockError::UnsafeEntry {
            path: display_path.to_path_buf(),
            reason: "opened entry is not a regular file",
        });
    }
    if stat.st_uid != geteuid().as_raw() {
        return Err(LockError::UnsafeEntry {
            path: display_path.to_path_buf(),
            reason: "opened entry is not owned by the current user",
        });
    }
    Ok(())
}

pub(crate) fn nix_io(operation: &'static str, path: &Path, error: Errno) -> LockError {
    LockError::Io {
        operation,
        path: path.to_path_buf(),
        source: io::Error::from_raw_os_error(error as i32),
    }
}
