//! Deterministic credential-source precedence and persistence policy.

use std::fmt;

use thiserror::Error;

use crate::secret_store::{
    SecretKey, SecretStore, SecretStoreError, SecretValue, SecretValueError,
};

/// Credential sources in strict resolution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    /// A credential explicitly submitted for this invocation.
    OneShotOverride,
    /// A process environment override, which is always ephemeral.
    Environment,
    /// A selected desktop Secret Service item.
    SecretService,
    /// A provider-owned credential file discovered read-only.
    ProviderOwnedFile,
    /// A manually selected browser session.
    BrowserSession,
    /// A provider command-line or device-login session.
    ProviderCli,
}

impl CredentialSource {
    const fn rank(self) -> u8 {
        match self {
            Self::OneShotOverride => 0,
            Self::Environment => 1,
            Self::SecretService => 2,
            Self::ProviderOwnedFile => 3,
            Self::BrowserSession => 4,
            Self::ProviderCli => 5,
        }
    }
}

/// Whether a selected credential may cross into persistent storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPersistence {
    /// Persistence may occur only through a separately authorized store call.
    Persistable,
    /// The value must remain in memory for the current process lifetime.
    Ephemeral,
}

/// One available credential and its provenance.
pub struct CredentialCandidate {
    source: CredentialSource,
    secret: SecretValue,
}

impl CredentialCandidate {
    /// Wraps an already validated credential with its source.
    #[must_use]
    pub const fn new(source: CredentialSource, secret: SecretValue) -> Self {
        Self { source, secret }
    }

    /// Moves an optional environment value into a non-persistable candidate.
    ///
    /// # Errors
    ///
    /// Returns [`SecretValueError`] when the supplied value is empty or too large.
    pub fn from_environment(value: Option<String>) -> Result<Option<Self>, SecretValueError> {
        value
            .map(String::into_bytes)
            .map(SecretValue::new)
            .transpose()
            .map(|candidate| {
                candidate.map(|secret| Self::new(CredentialSource::Environment, secret))
            })
    }

    /// Source provenance.
    #[must_use]
    pub const fn source(&self) -> CredentialSource {
        self.source
    }
}

impl fmt::Debug for CredentialCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialCandidate")
            .field("source", &self.source)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// The highest-precedence available credential.
pub struct ResolvedCredential {
    source: CredentialSource,
    persistence: CredentialPersistence,
    secret: SecretValue,
}

impl ResolvedCredential {
    /// Source that won deterministic resolution.
    #[must_use]
    pub const fn source(&self) -> CredentialSource {
        self.source
    }

    /// Persistence policy derived from provenance.
    #[must_use]
    pub const fn persistence(&self) -> CredentialPersistence {
        self.persistence
    }

    /// Borrows the selected credential bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.secret.expose_secret()
    }
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedCredential")
            .field("source", &self.source)
            .field("persistence", &self.persistence)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Selects the highest-precedence candidate, independent of input order.
#[must_use]
pub fn resolve(candidates: Vec<CredentialCandidate>) -> Option<ResolvedCredential> {
    candidates
        .into_iter()
        .min_by_key(|candidate| candidate.source.rank())
        .map(|candidate| ResolvedCredential {
            source: candidate.source,
            persistence: if candidate.source == CredentialSource::Environment {
                CredentialPersistence::Ephemeral
            } else {
                CredentialPersistence::Persistable
            },
            secret: candidate.secret,
        })
}

/// Persists a resolved credential only when its provenance permits it.
///
/// Environment overrides are rejected before the store is invoked, ensuring
/// they cannot be copied into Secret Service or the protected-file fallback.
///
/// # Errors
///
/// Returns [`CredentialPersistenceError::EphemeralSource`] for environment
/// credentials, or wraps a stable storage failure.
pub async fn persist_resolved(
    store: &dyn SecretStore,
    key: &SecretKey,
    credential: ResolvedCredential,
) -> Result<(), CredentialPersistenceError> {
    if credential.persistence == CredentialPersistence::Ephemeral {
        return Err(CredentialPersistenceError::EphemeralSource);
    }
    store
        .put(key, credential.secret)
        .await
        .map_err(CredentialPersistenceError::Store)
}

/// Failures while applying provenance-aware persistence.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPersistenceError {
    /// Ephemeral values may never cross into persistent storage.
    #[error("credential source is ephemeral and cannot be persisted")]
    EphemeralSource,
    /// The selected persistent store rejected the operation.
    #[error("credential persistence failed")]
    Store(#[source] SecretStoreError),
}
