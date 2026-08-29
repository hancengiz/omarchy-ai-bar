//! Explicitly acknowledged, filesystem-protected credential storage.
//!
//! The file is not encrypted. It is a headless fallback for users who accept
//! that limitation when Secret Service is unavailable. The fixed filename,
//! private parent directory, exact `0600` mode, single-link check, and
//! no-predecessor atomic replacement keep it separate from ordinary settings
//! and prevent accidental plaintext backups.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use oab_storage::atomic_file::{
    AtomicWriteError, atomic_write_without_predecessor, read_private_file,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::secret_store::{SecretFuture, SecretKey, SecretStore, SecretStoreError, SecretValue};

/// Required basename for the opt-in plaintext credential file.
pub const PROTECTED_FILE_NAME: &str = "protected-credentials.json";
/// Warning acknowledged before filesystem-protected persistence is enabled.
pub const PROTECTED_FILE_WARNING: &str = "The protected credential file is not encrypted; its protection depends on local filesystem permissions.";

const DOCUMENT_VERSION: u16 = 1;
const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 64;

/// Proof that the caller explicitly accepted [`PROTECTED_FILE_WARNING`].
///
/// Construction is deliberately verbose so headless fallback persistence
/// cannot be enabled as an incidental default.
#[derive(Debug)]
pub struct ProtectedFileAcknowledgement(());

impl ProtectedFileAcknowledgement {
    /// Explicitly acknowledges that the protected file is permission-protected,
    /// not encrypted.
    #[must_use]
    pub const fn acknowledge_unencrypted_storage_warning() -> Self {
        Self(())
    }
}

/// An explicitly enabled credential store backed by one dedicated private file.
pub struct ProtectedFileStore {
    path: PathBuf,
    operation: Mutex<()>,
}

impl ProtectedFileStore {
    /// Enables the protected-file adapter for the fixed dedicated filename.
    ///
    /// The parent directory must already exist and be private when the first
    /// operation occurs. Keeping directory creation outside this API prevents
    /// it from silently choosing a persistence location.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedFileError::DedicatedNameRequired`] unless `path` is
    /// absolute and ends in [`PROTECTED_FILE_NAME`].
    pub fn open(
        path: impl Into<PathBuf>,
        _acknowledgement: ProtectedFileAcknowledgement,
    ) -> Result<Self, ProtectedFileError> {
        let path = path.into();
        if !path.is_absolute()
            || path.file_name().and_then(|name| name.to_str()) != Some(PROTECTED_FILE_NAME)
        {
            return Err(ProtectedFileError::DedicatedNameRequired);
        }
        Ok(Self {
            path,
            operation: Mutex::new(()),
        })
    }

    /// Returns the dedicated credential pathname.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<ProtectedDocument, ProtectedFileError> {
        let Some(contents) = read_private_file(&self.path, MAX_DOCUMENT_BYTES)? else {
            return Ok(ProtectedDocument::default());
        };
        let contents = Zeroizing::new(contents);
        let document: ProtectedDocument =
            serde_json::from_slice(&contents).map_err(|_| ProtectedFileError::InvalidDocument)?;
        document.validate()?;
        Ok(document)
    }

    fn save(&self, document: &mut ProtectedDocument) -> Result<(), ProtectedFileError> {
        document.entries.sort_by(|left, right| {
            (&left.provider, &left.account, &left.purpose).cmp(&(
                &right.provider,
                &right.account,
                &right.purpose,
            ))
        });
        let contents = Zeroizing::new(
            serde_json::to_vec(document).map_err(|_| ProtectedFileError::InvalidDocument)?,
        );
        if contents.len() > MAX_DOCUMENT_BYTES {
            return Err(ProtectedFileError::TooManyEntries);
        }
        atomic_write_without_predecessor(&self.path, &contents)?;
        Ok(())
    }

    fn get_sync(&self, key: &SecretKey) -> Result<Option<SecretValue>, ProtectedFileError> {
        let _guard = self
            .operation
            .lock()
            .map_err(|_| ProtectedFileError::OperationPoisoned)?;
        let mut document = self.load()?;
        let Some(entry) = document.entries.iter_mut().find(|entry| entry.matches(key)) else {
            return Ok(None);
        };
        let secret = std::mem::take(&mut entry.secret);
        SecretValue::new(secret)
            .map(Some)
            .map_err(|_| ProtectedFileError::InvalidDocument)
    }

    fn put_sync(&self, key: &SecretKey, secret: SecretValue) -> Result<(), ProtectedFileError> {
        let _guard = self
            .operation
            .lock()
            .map_err(|_| ProtectedFileError::OperationPoisoned)?;
        let mut document = self.load()?;
        let mut secret = secret.into_bytes();
        if let Some(entry) = document.entries.iter_mut().find(|entry| entry.matches(key)) {
            entry.secret.zeroize();
            entry.secret = std::mem::take(&mut *secret);
        } else {
            if document.entries.len() >= MAX_ENTRIES {
                return Err(ProtectedFileError::TooManyEntries);
            }
            document.entries.push(ProtectedEntry {
                provider: key.provider().to_owned(),
                account: key.account().to_owned(),
                purpose: key.purpose().to_owned(),
                secret: std::mem::take(&mut *secret),
            });
        }
        self.save(&mut document)
    }

    fn delete_sync(&self, key: &SecretKey) -> Result<(), ProtectedFileError> {
        let _guard = self
            .operation
            .lock()
            .map_err(|_| ProtectedFileError::OperationPoisoned)?;
        let mut document = self.load()?;
        let before = document.entries.len();
        document.entries.retain(|entry| !entry.matches(key));
        if document.entries.len() != before {
            self.save(&mut document)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ProtectedFileStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedFileStore")
            .field("path", &self.path)
            .field("contents", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SecretStore for ProtectedFileStore {
    fn get<'a>(
        &'a self,
        key: &'a SecretKey,
    ) -> SecretFuture<'a, Result<Option<SecretValue>, SecretStoreError>> {
        Box::pin(async move {
            self.get_sync(key).map_err(|error| match error {
                ProtectedFileError::InvalidDocument => SecretStoreError::InvalidData,
                _ => SecretStoreError::Operation,
            })
        })
    }

    fn put<'a>(
        &'a self,
        key: &'a SecretKey,
        secret: SecretValue,
    ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.put_sync(key, secret)
                .map_err(|_| SecretStoreError::Operation)
        })
    }

    fn delete<'a>(&'a self, key: &'a SecretKey) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.delete_sync(key)
                .map_err(|_| SecretStoreError::Operation)
        })
    }
}

/// Protected-file configuration and storage failures.
#[derive(Debug, Error)]
pub enum ProtectedFileError {
    /// The path did not use the fixed filename or was not absolute.
    #[error("protected credentials require a dedicated absolute file named {PROTECTED_FILE_NAME}")]
    DedicatedNameRequired,
    /// The document was malformed, unsupported, duplicated, or out of bounds.
    #[error("protected credential document is invalid")]
    InvalidDocument,
    /// The entry or encoded-document bound was exceeded.
    #[error("protected credential document exceeds its entry limit")]
    TooManyEntries,
    /// An earlier panic poisoned the in-process operation lock.
    #[error("protected credential operation lock is unavailable")]
    OperationPoisoned,
    /// A private-filesystem invariant or operation failed.
    #[error("protected credential filesystem operation failed")]
    Storage(#[source] AtomicWriteError),
}

impl From<AtomicWriteError> for ProtectedFileError {
    fn from(error: AtomicWriteError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Serialize, Deserialize)]
struct ProtectedDocument {
    version: u16,
    entries: Vec<ProtectedEntry>,
}

impl Default for ProtectedDocument {
    fn default() -> Self {
        Self {
            version: DOCUMENT_VERSION,
            entries: Vec::new(),
        }
    }
}

impl ProtectedDocument {
    fn validate(&self) -> Result<(), ProtectedFileError> {
        if self.version != DOCUMENT_VERSION || self.entries.len() > MAX_ENTRIES {
            return Err(ProtectedFileError::InvalidDocument);
        }
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if self.entries[..index]
                .iter()
                .any(|previous| previous.same_identity(entry))
            {
                return Err(ProtectedFileError::InvalidDocument);
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct ProtectedEntry {
    provider: String,
    account: String,
    purpose: String,
    secret: Vec<u8>,
}

impl ProtectedEntry {
    fn matches(&self, key: &SecretKey) -> bool {
        self.provider == key.provider()
            && self.account == key.account()
            && self.purpose == key.purpose()
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.provider == other.provider
            && self.account == other.account
            && self.purpose == other.purpose
    }

    fn validate(&self) -> Result<(), ProtectedFileError> {
        SecretKey::new(&self.provider, &self.account, &self.purpose)
            .map_err(|_| ProtectedFileError::InvalidDocument)?;
        SecretValue::new(self.secret.clone())
            .map(|_| ())
            .map_err(|_| ProtectedFileError::InvalidDocument)
    }
}

impl Drop for ProtectedEntry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
