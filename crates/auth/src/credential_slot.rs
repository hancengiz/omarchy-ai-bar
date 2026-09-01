//! Closed, account-scoped identities for application-owned credential slots.

use std::fmt;

use oab_domain::AccountScope;
use thiserror::Error;

use crate::secret_store::{SecretKey, SecretKeyError};

/// Maximum byte length of one canonical credential-slot name.
pub const MAX_CREDENTIAL_SLOT_NAME_BYTES: usize = 64;

const SLOT_PURPOSE_PREFIX: &str = "credential-slot/v1/";

/// One exact application-owned credential slot.
///
/// Provider, instance, and account identity come from a validated
/// [`AccountScope`]. Slot names use one canonical lower-kebab spelling. The
/// derived [`SecretKey`] remains compatible with every existing
/// [`crate::secret_store::SecretStore`] implementation:
///
/// - `provider` is the closed provider identifier;
/// - `account` is the exact account key;
/// - `purpose` is `credential-slot/v1/<instance>/<slot>`.
///
/// The versioned purpose namespace keeps named slots disjoint from legacy
/// purposes such as `manual-session` and Copilot's `oauth-token`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialSlotId {
    scope: AccountScope,
    slot: Box<str>,
    secret_key: SecretKey,
}

impl CredentialSlotId {
    /// Creates one exact provider-instance-account-slot identity.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialSlotIdError`] when `slot` is empty, exceeds
    /// [`MAX_CREDENTIAL_SLOT_NAME_BYTES`], is not canonical lower-kebab text,
    /// or cannot fit the bounded [`SecretKey`] representation.
    pub fn new(scope: AccountScope, slot: impl AsRef<str>) -> Result<Self, CredentialSlotIdError> {
        let slot = slot.as_ref();
        validate_slot_name(slot)?;
        let purpose = format!(
            "{SLOT_PURPOSE_PREFIX}{}/{}",
            scope.instance().as_str(),
            slot
        );
        let secret_key =
            SecretKey::new(scope.provider().as_str(), scope.account().as_str(), purpose)
                .map_err(CredentialSlotIdError::Encoding)?;
        Ok(Self {
            scope,
            slot: slot.into(),
            secret_key,
        })
    }

    /// Exact provider, instance, and account scope for this slot.
    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    /// Canonical lower-kebab slot name.
    #[must_use]
    pub fn slot(&self) -> &str {
        &self.slot
    }

    /// Exact logical key accepted by any [`crate::secret_store::SecretStore`].
    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Consumes the typed slot identity and returns its storage key.
    #[must_use]
    pub fn into_secret_key(self) -> SecretKey {
        self.secret_key
    }
}

impl AsRef<SecretKey> for CredentialSlotId {
    fn as_ref(&self) -> &SecretKey {
        self.secret_key()
    }
}

impl From<CredentialSlotId> for SecretKey {
    fn from(slot: CredentialSlotId) -> Self {
        slot.into_secret_key()
    }
}

impl fmt::Debug for CredentialSlotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSlotId(<redacted>)")
    }
}

fn validate_slot_name(value: &str) -> Result<(), CredentialSlotIdError> {
    if value.is_empty() {
        return Err(CredentialSlotIdError::Empty);
    }
    if value.len() > MAX_CREDENTIAL_SLOT_NAME_BYTES {
        return Err(CredentialSlotIdError::TooLarge);
    }
    let mut components = value.split('-');
    if components.any(|component| {
        component.is_empty()
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return Err(CredentialSlotIdError::NonCanonical);
    }
    Ok(())
}

/// Stable, value-free failures for credential-slot identity construction.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSlotIdError {
    /// The slot name was empty.
    #[error("credential slot name must not be empty")]
    Empty,
    /// The slot name exceeded its fixed bound.
    #[error("credential slot name exceeds its size limit")]
    TooLarge,
    /// The slot was not canonical lower-kebab text.
    #[error("credential slot name must use canonical lower-kebab characters")]
    NonCanonical,
    /// A validated identity could not fit the stable Secret Service key.
    #[error("credential slot identity cannot be encoded")]
    Encoding(#[source] SecretKeyError),
}
