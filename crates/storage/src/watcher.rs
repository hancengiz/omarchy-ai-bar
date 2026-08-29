//! Deterministic polling reloader with last-valid retention.

use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::config::{AppConfig, ConfigError, DiagnosticCode, MAX_CONFIG_BYTES, load_config_bytes};
use crate::lock::{SafeParent, validate_open_regular, validate_regular_or_absent};

/// Result of one deterministic configuration poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The observed file state is byte-for-byte equivalent to the previous
    /// poll, including a repeated rejection state.
    Unchanged,
    /// A new valid configuration replaced the in-memory value.
    Reloaded,
    /// A new observation was rejected and the prior valid value was retained.
    Rejected(DiagnosticCode),
}

/// Polling configuration reloader that never exposes rejected bytes.
pub struct ConfigReloader {
    path: PathBuf,
    current: AppConfig,
    last_observation: ObservationFingerprint,
}

impl Debug for ConfigReloader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigReloader(<private>)")
    }
}

impl ConfigReloader {
    /// Loads the required initial valid configuration.
    ///
    /// # Errors
    ///
    /// Returns a safe configuration error when the path cannot be read as a
    /// bounded regular file or its contents fail schema validation.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let observation = observe(&path);
        let bytes = observation.result.map_err(ConfigError::new)?;
        let current = load_config_bytes(&bytes)?;
        Ok(Self {
            path,
            current,
            last_observation: observation.fingerprint,
        })
    }

    /// Returns the last valid configuration.
    #[must_use]
    pub const fn current(&self) -> &AppConfig {
        &self.current
    }

    /// Polls once without blocking or sleeping.
    ///
    /// Invalid edits update only the non-sensitive observation fingerprint;
    /// the last-valid configuration remains available through [`Self::current`].
    #[must_use]
    pub fn poll(&mut self) -> ReloadOutcome {
        let observation = observe(&self.path);
        if observation.fingerprint == self.last_observation {
            return ReloadOutcome::Unchanged;
        }
        self.last_observation = observation.fingerprint;
        let bytes = match observation.result {
            Ok(bytes) => bytes,
            Err(code) => return ReloadOutcome::Rejected(code),
        };
        match load_config_bytes(&bytes) {
            Ok(config) => {
                self.current = config;
                ReloadOutcome::Reloaded
            }
            Err(error) => ReloadOutcome::Rejected(error.code()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationFingerprint {
    Content { length: usize, digest: [u8; 32] },
    Failure(DiagnosticCode),
}

struct Observation {
    fingerprint: ObservationFingerprint,
    result: Result<Vec<u8>, DiagnosticCode>,
}

fn observe(path: &Path) -> Observation {
    match read_bounded_regular_file(path) {
        Some(bytes) => {
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let fingerprint = ObservationFingerprint::Content {
                length: bytes.len(),
                digest,
            };
            if bytes.len() > MAX_CONFIG_BYTES {
                Observation {
                    fingerprint,
                    result: Err(DiagnosticCode::ConfigTooLarge),
                }
            } else {
                Observation {
                    fingerprint,
                    result: Ok(bytes),
                }
            }
        }
        None => Observation {
            fingerprint: ObservationFingerprint::Failure(DiagnosticCode::ConfigReadFailed),
            result: Err(DiagnosticCode::ConfigReadFailed),
        },
    }
}

fn read_bounded_regular_file(path: &Path) -> Option<Vec<u8>> {
    let parent = SafeParent::open(path).ok()?;
    let before = validate_regular_or_absent(&parent.directory, &parent.file_name, path).ok()??;
    let descriptor = nix::fcntl::openat(
        &parent.directory,
        parent.file_name.as_os_str(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NOFOLLOW,
        nix::sys::stat::Mode::empty(),
    )
    .ok()?;
    let file = File::from(descriptor);
    validate_open_regular(&file, path).ok()?;
    let opened = file.metadata().ok()?;
    if !opened.is_file()
        || before.st_dev != opened.dev()
        || before.st_ino != opened.ino()
        || opened.uid() != nix::unistd::geteuid().as_raw()
        || opened.mode() & 0o7777 != 0o600
    {
        return None;
    }
    let maximum =
        u64::try_from(MAX_CONFIG_BYTES).expect("the configuration byte bound fits in u64") + 1;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len().min(maximum)).expect("bounded length fits in usize"),
    );
    (&file).take(maximum).read_to_end(&mut bytes).ok()?;
    let after = file.metadata().ok()?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || opened.uid() != after.uid()
        || opened.mode() != after.mode()
        || opened.ctime() != after.ctime()
        || opened.ctime_nsec() != after.ctime_nsec()
        || opened.modified().ok()? != after.modified().ok()?
    {
        return None;
    }
    Some(bytes)
}
