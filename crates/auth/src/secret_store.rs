//! Secret-store contracts and the desktop Secret Service adapter.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum size of a credential accepted by storage adapters.
pub const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_KEY_FIELD_BYTES: usize = 256;
const MAX_BATCH_KEYS: usize = 256;
const MAX_BATCH_ITEMS: usize = 512;
const APPLICATION_ATTRIBUTE: &str = "omarchy-ai-bar";

/// A validated logical credential identifier.
///
/// Debug output deliberately omits every field because account identifiers can
/// be personal information.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretKey {
    provider: String,
    account: String,
    purpose: String,
}

impl SecretKey {
    /// Creates a key from bounded, printable, non-empty fields.
    ///
    /// # Errors
    ///
    /// Returns [`SecretKeyError`] when any field is empty, too large, or
    /// contains control characters.
    pub fn new(
        provider: impl Into<String>,
        account: impl Into<String>,
        purpose: impl Into<String>,
    ) -> Result<Self, SecretKeyError> {
        let provider = checked_key_field(provider.into())?;
        let account = checked_key_field(account.into())?;
        let purpose = checked_key_field(purpose.into())?;
        Ok(Self {
            provider,
            account,
            purpose,
        })
    }

    /// Provider identifier used for exact Secret Service matching.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Account identifier used for exact Secret Service matching.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Credential purpose used for exact Secret Service matching.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    fn attributes(&self) -> [(&str, &str); 4] {
        [
            ("application", APPLICATION_ATTRIBUTE),
            ("provider", self.provider()),
            ("account", self.account()),
            ("purpose", self.purpose()),
        ]
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey(<redacted>)")
    }
}

fn checked_key_field(value: String) -> Result<String, SecretKeyError> {
    if value.is_empty() {
        return Err(SecretKeyError::Empty);
    }
    if value.len() > MAX_KEY_FIELD_BYTES {
        return Err(SecretKeyError::TooLarge);
    }
    if value.chars().any(char::is_control) {
        return Err(SecretKeyError::ControlCharacter);
    }
    Ok(value)
}

/// Validation failures for a logical credential identifier.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretKeyError {
    /// A field was empty.
    #[error("secret key fields must not be empty")]
    Empty,
    /// A field exceeded its fixed bound.
    #[error("secret key field exceeds its size limit")]
    TooLarge,
    /// A field contained a control character.
    #[error("secret key fields must not contain control characters")]
    ControlCharacter,
}

/// An in-memory credential erased when dropped.
///
/// This type is intentionally neither cloneable nor serializable. Plaintext is
/// available only through the explicitly named [`Self::expose_secret`] method.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Creates a bounded, non-empty secret.
    ///
    /// # Errors
    ///
    /// Returns [`SecretValueError`] for empty or oversized values.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, SecretValueError> {
        Self::from_zeroizing(Zeroizing::new(value.into()))
    }

    /// Adopts bytes that are already protected by a zeroizing allocation.
    ///
    /// This avoids a transient unprotected copy when another credential owner
    /// transfers a secret into persistent storage.
    ///
    /// # Errors
    ///
    /// Returns [`SecretValueError`] for empty or oversized values.
    pub fn from_zeroizing(value: Zeroizing<Vec<u8>>) -> Result<Self, SecretValueError> {
        if value.is_empty() {
            return Err(SecretValueError::Empty);
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(SecretValueError::TooLarge);
        }
        Ok(Self(value))
    }

    /// Borrows the credential bytes. Keep this borrow short-lived and never log it.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Secret-value validation failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretValueError {
    /// The value had no bytes.
    #[error("secret must not be empty")]
    Empty,
    /// The value exceeded [`MAX_SECRET_BYTES`].
    #[error("secret exceeds its size limit")]
    TooLarge,
}

/// A boxed asynchronous secret-store operation.
pub type SecretFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe credential persistence contract.
pub trait SecretStore: Send + Sync {
    /// Retrieves an exact logical credential.
    fn get<'a>(
        &'a self,
        key: &'a SecretKey,
    ) -> SecretFuture<'a, Result<Option<SecretValue>, SecretStoreError>>;

    /// Creates or replaces an exact logical credential.
    fn put<'a>(
        &'a self,
        key: &'a SecretKey,
        secret: SecretValue,
    ) -> SecretFuture<'a, Result<(), SecretStoreError>>;

    /// Deletes every stored item matching the exact logical credential.
    fn delete<'a>(&'a self, key: &'a SecretKey) -> SecretFuture<'a, Result<(), SecretStoreError>>;
}

/// Stable, secret-free errors exposed by secret stores.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretStoreError {
    /// The desktop service or backing store could not be reached.
    #[error("secret storage is unavailable")]
    Unavailable,
    /// The selected collection could not be unlocked.
    #[error("secret storage is locked")]
    Locked,
    /// Stored content violated the bounded secret contract.
    #[error("secret storage returned invalid data")]
    InvalidData,
    /// A storage operation failed without exposing backend diagnostics.
    #[error("secret storage operation failed")]
    Operation,
}

/// Tokio-backed adapter for the desktop Secret Service default collection.
#[derive(Debug)]
pub struct SecretServiceStore {
    keyring: oo7::Keyring,
}

impl SecretServiceStore {
    /// Connects to the desktop Secret Service or the sandbox portal backend.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStoreError::Unavailable`] when no supported service can
    /// be opened.
    pub async fn connect() -> Result<Self, SecretStoreError> {
        let keyring = oo7::Keyring::new()
            .await
            .map_err(|_| SecretStoreError::Unavailable)?;
        Ok(Self { keyring })
    }

    /// Retrieves a bounded set of exact application-owned credentials with a
    /// single Secret Service search.
    ///
    /// This is used during daemon bootstrap, where performing one D-Bus search
    /// per provider would make the startup deadline grow with the provider
    /// catalog. Unknown application items are ignored. Duplicate exact keys or
    /// malformed stored values fail closed.
    ///
    /// # Errors
    ///
    /// Returns a stable store error when the collection cannot be searched or
    /// unlocked, an exact requested key is duplicated, or a selected secret is
    /// invalid.
    pub async fn get_many(
        &self,
        keys: &[SecretKey],
    ) -> Result<Vec<(SecretKey, SecretValue)>, SecretStoreError> {
        if keys.len() > MAX_BATCH_KEYS
            || keys
                .iter()
                .enumerate()
                .any(|(index, key)| keys[..index].contains(key))
        {
            return Err(SecretStoreError::InvalidData);
        }
        let mut items = self
            .keyring
            .search_items(&[("application", APPLICATION_ATTRIBUTE)])
            .await
            .map_err(|_| SecretStoreError::Operation)?;
        if items.len() > MAX_BATCH_ITEMS {
            return Err(SecretStoreError::InvalidData);
        }
        let mut seen = vec![false; keys.len()];
        let mut values = Vec::with_capacity(keys.len().min(items.len()));

        for item in items.drain(..) {
            item.unlock().await.map_err(|_| SecretStoreError::Locked)?;
            let attributes = item
                .attributes()
                .await
                .map_err(|_| SecretStoreError::Operation)?;
            let Some(index) = keys.iter().position(|key| {
                attributes.get("application").map(String::as_str) == Some(APPLICATION_ATTRIBUTE)
                    && attributes.get("provider").map(String::as_str) == Some(key.provider())
                    && attributes.get("account").map(String::as_str) == Some(key.account())
                    && attributes.get("purpose").map(String::as_str) == Some(key.purpose())
            }) else {
                continue;
            };
            if seen[index] {
                return Err(SecretStoreError::InvalidData);
            }
            seen[index] = true;
            let secret = item
                .secret()
                .await
                .map_err(|_| SecretStoreError::Operation)?;
            let value = SecretValue::new(secret.as_bytes().to_vec())
                .map_err(|_| SecretStoreError::InvalidData)?;
            values.push((keys[index].clone(), value));
        }
        Ok(values)
    }
}

impl SecretStore for SecretServiceStore {
    fn get<'a>(
        &'a self,
        key: &'a SecretKey,
    ) -> SecretFuture<'a, Result<Option<SecretValue>, SecretStoreError>> {
        Box::pin(async move {
            let mut items = self
                .keyring
                .search_items(&key.attributes())
                .await
                .map_err(|_| SecretStoreError::Operation)?;
            let item = match items.len() {
                0 => return Ok(None),
                1 => items.pop().expect("length checked"),
                _ => return Err(SecretStoreError::InvalidData),
            };
            item.unlock().await.map_err(|_| SecretStoreError::Locked)?;
            let secret = item
                .secret()
                .await
                .map_err(|_| SecretStoreError::Operation)?;
            SecretValue::new(secret.as_bytes().to_vec())
                .map(Some)
                .map_err(|_| SecretStoreError::InvalidData)
        })
    }

    fn put<'a>(
        &'a self,
        key: &'a SecretKey,
        secret: SecretValue,
    ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.keyring
                .unlock()
                .await
                .map_err(|_| SecretStoreError::Locked)?;
            self.keyring
                .create_item(
                    "omarchy-ai-bar credential",
                    &key.attributes(),
                    oo7::Secret::blob(secret.expose_secret()),
                    true,
                )
                .await
                .map_err(|_| SecretStoreError::Operation)
        })
    }

    fn delete<'a>(&'a self, key: &'a SecretKey) -> SecretFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.keyring
                .delete(&key.attributes())
                .await
                .map_err(|_| SecretStoreError::Operation)
        })
    }
}
