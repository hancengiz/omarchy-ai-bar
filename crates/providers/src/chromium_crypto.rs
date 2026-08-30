//! Bounded Linux Chromium `v10`/`v11` cookie decryption.
//!
//! This module implements Chromium's legacy Linux AES-128-CBC envelope. It
//! does not discover Safe Storage secrets: callers must inject each browser's
//! `v11` secret explicitly. The fixed `v10` password remains enabled by
//! default for compatibility with Chromium's Linux format.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::browser_cookie::{ChromiumCookieDecryptionError, ChromiumCookieDecryptor};
use crate::browser_profile::BrowserKind;

const KEY_BYTES: usize = 16;
const AES_BLOCK_BYTES: usize = 16;
const TAG_BYTES: usize = 3;
const V10_TAG: &[u8; TAG_BYTES] = b"v10";
const V11_TAG: &[u8; TAG_BYTES] = b"v11";
const V10_PASSWORD: &[u8] = b"peanuts";
const EMPTY_PASSWORD: &[u8] = b"";
const PBKDF2_SALT: &[u8] = b"saltysalt";
const PBKDF2_ITERATIONS: u32 = 1;
const FIXED_IV: [u8; AES_BLOCK_BYTES] = [b' '; AES_BLOCK_BYTES];
const MAX_SAFE_STORAGE_SECRET_BYTES: usize = 4 * 1024;

/// Maximum accepted tagged Chromium ciphertext size.
pub const MAX_CHROMIUM_ENCRYPTED_VALUE_BYTES: usize = 64 * 1024;

type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;

/// Invalid configuration supplied to [`LinuxChromiumCookieCrypto`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ChromiumCryptoConfigError {
    /// Firefox and Zen do not use Chromium's Linux cookie envelope.
    #[error("browser does not support Chromium cookie encryption")]
    UnsupportedBrowser,
    /// A Safe Storage secret was empty or exceeded the fixed input bound.
    #[error("Chromium Safe Storage secret is invalid")]
    InvalidSecret,
}

/// Stable, secret-free Chromium envelope failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ChromiumCryptoError {
    /// Firefox and Zen do not use Chromium's Linux cookie envelope.
    #[error("browser does not support Chromium cookie encryption")]
    UnsupportedBrowser,
    /// The envelope did not begin with exactly `v10` or `v11`.
    #[error("Chromium cookie encryption tag is unsupported")]
    InvalidTag,
    /// The tagged value was too large, empty, or not block aligned.
    #[error("Chromium cookie ciphertext has an invalid size")]
    InvalidSize,
    /// No secret was injected for this exact browser's `v11` values.
    #[error("Chromium cookie decryption is unavailable")]
    Unavailable,
    /// CBC decryption did not contain strict PKCS#7 padding.
    #[error("Chromium cookie ciphertext has invalid padding")]
    InvalidPadding,
}

/// Linux Chromium cookie decryptor with browser-isolated `v11` keys.
///
/// `v10` uses Chromium's fixed legacy password and is always available.
/// Each `v11` key is derived only from the explicitly injected Safe Storage
/// secret for the corresponding browser.
#[derive(Default)]
pub struct LinuxChromiumCookieCrypto {
    v11_keys: BTreeMap<BrowserKind, Zeroizing<[u8; KEY_BYTES]>>,
}

impl LinuxChromiumCookieCrypto {
    /// Creates a decryptor with `v10` enabled and no `v11` keys.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            v11_keys: BTreeMap::new(),
        }
    }

    /// Derives and installs one browser's `v11` key.
    ///
    /// The owned input is zeroized on every return path. Replacing an existing
    /// key also zeroizes the old derived key.
    ///
    /// # Errors
    ///
    /// Returns [`ChromiumCryptoConfigError::UnsupportedBrowser`] for a
    /// non-Chromium browser and [`ChromiumCryptoConfigError::InvalidSecret`]
    /// when the secret is empty or exceeds the fixed bound.
    pub fn set_v11_secret(
        &mut self,
        browser: BrowserKind,
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<(), ChromiumCryptoConfigError> {
        ensure_chromium_browser(browser)
            .map_err(|_| ChromiumCryptoConfigError::UnsupportedBrowser)?;
        if secret.is_empty() || secret.len() > MAX_SAFE_STORAGE_SECRET_BYTES {
            return Err(ChromiumCryptoConfigError::InvalidSecret);
        }

        let key = derive_key(secret.as_slice());
        drop(secret);
        self.v11_keys.insert(browser, key);
        Ok(())
    }

    /// Removes and zeroizes one browser's derived `v11` key.
    ///
    /// Returns whether a key was present.
    pub fn clear_v11_secret(&mut self, browser: BrowserKind) -> bool {
        self.v11_keys.remove(&browser).is_some()
    }

    /// Reports whether this exact browser has an injected `v11` key.
    #[must_use]
    pub fn has_v11_secret(&self, browser: BrowserKind) -> bool {
        self.v11_keys.contains_key(&browser)
    }

    /// Decrypts one bounded tagged Chromium value into raw bytes.
    ///
    /// The returned bytes intentionally retain any Chromium v24 host digest;
    /// the cookie importer owns digest verification and stripping.
    ///
    /// # Errors
    ///
    /// Returns a stable [`ChromiumCryptoError`] for unsupported browsers,
    /// invalid tags, invalid sizes, unavailable `v11` keys, or bad padding.
    pub fn decrypt_raw(
        &self,
        browser: BrowserKind,
        encrypted_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChromiumCryptoError> {
        ensure_chromium_browser(browser)?;
        if encrypted_value.len() > MAX_CHROMIUM_ENCRYPTED_VALUE_BYTES {
            return Err(ChromiumCryptoError::InvalidSize);
        }

        let (tag, ciphertext) = encrypted_value
            .split_at_checked(TAG_BYTES)
            .ok_or(ChromiumCryptoError::InvalidTag)?;
        if tag != V10_TAG && tag != V11_TAG {
            return Err(ChromiumCryptoError::InvalidTag);
        }
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(AES_BLOCK_BYTES) {
            return Err(ChromiumCryptoError::InvalidSize);
        }

        if tag == V10_TAG {
            let key = derive_key(V10_PASSWORD);
            decrypt_with_compatibility_fallback(&key, ciphertext)
        } else {
            let key = self
                .v11_keys
                .get(&browser)
                .ok_or(ChromiumCryptoError::Unavailable)?;
            decrypt_with_compatibility_fallback(key, ciphertext)
        }
    }
}

impl Debug for LinuxChromiumCookieCrypto {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxChromiumCookieCrypto")
            .field("configured_v11_key_count", &self.v11_keys.len())
            .finish()
    }
}

impl ChromiumCookieDecryptor for LinuxChromiumCookieCrypto {
    fn decrypt(
        &self,
        browser: BrowserKind,
        encrypted_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ChromiumCookieDecryptionError> {
        self.decrypt_raw(browser, encrypted_value).map_err(|error| {
            if error == ChromiumCryptoError::Unavailable {
                ChromiumCookieDecryptionError::Unavailable
            } else {
                ChromiumCookieDecryptionError::Failed
            }
        })
    }
}

fn ensure_chromium_browser(browser: BrowserKind) -> Result<(), ChromiumCryptoError> {
    match browser {
        BrowserKind::Chromium
        | BrowserKind::GoogleChrome
        | BrowserKind::Brave
        | BrowserKind::BraveOrigin
        | BrowserKind::MicrosoftEdge => Ok(()),
        BrowserKind::Firefox | BrowserKind::Zen => Err(ChromiumCryptoError::UnsupportedBrowser),
    }
}

fn derive_key(password: &[u8]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    pbkdf2_hmac::<Sha1>(password, PBKDF2_SALT, PBKDF2_ITERATIONS, &mut *key);
    key
}

fn decrypt_cbc(
    key: &[u8; KEY_BYTES],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ChromiumCryptoError> {
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    let decrypted_len = Aes128CbcDecryptor::new(key.into(), (&FIXED_IV).into())
        .decrypt_padded_mut::<Pkcs7>(&mut plaintext)
        .map_err(|_| ChromiumCryptoError::InvalidPadding)?
        .len();
    plaintext.truncate(decrypted_len);
    Ok(plaintext)
}

fn decrypt_with_compatibility_fallback(
    selected_key: &[u8; KEY_BYTES],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ChromiumCryptoError> {
    match decrypt_cbc(selected_key, ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(ChromiumCryptoError::InvalidPadding) => {
            // Chromium retries the historical empty-password key after a
            // selected AES-128-CBC key fails strict padding validation.
            let empty_password_key = derive_key(EMPTY_PASSWORD);
            decrypt_cbc(&empty_password_key, ciphertext)
        }
        Err(error) => Err(error),
    }
}
