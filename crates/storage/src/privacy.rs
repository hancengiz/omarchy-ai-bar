//! Installation-local key for stable, private provider record identifiers.

use std::path::Path;

use oab_domain::PrivacyKey;
use thiserror::Error;

use crate::atomic_file::{atomic_write_without_predecessor, read_private_file};
use crate::lock::ExclusiveLock;

/// A path-free failure to load or initialize the installation key.
#[derive(Debug, Error)]
#[error("private record key storage is unavailable")]
pub struct PrivacyKeyError;

/// Loads or creates a private key in an existing application data directory.
///
/// # Errors
/// Returns an error for unsafe storage, invalid key length, or unavailable randomness.
pub fn load_or_create(data_dir: &Path) -> Result<PrivacyKey, PrivacyKeyError> {
    let _lock = ExclusiveLock::acquire(data_dir.join("privacy-key.init.lock"))
        .map_err(|_| PrivacyKeyError)?;
    let path = data_dir.join("privacy-key");
    if let Some(bytes) = read_private_file(&path, 32).map_err(|_| PrivacyKeyError)? {
        return bytes
            .try_into()
            .map(PrivacyKey::from_bytes)
            .map_err(|_| PrivacyKeyError);
    }
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| PrivacyKeyError)?;
    atomic_write_without_predecessor(path, &bytes).map_err(|_| PrivacyKeyError)?;
    Ok(PrivacyKey::from_bytes(bytes))
}
