use std::fmt::{self, Debug, Display, Formatter};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::Sha256;
use thiserror::Error;

use crate::ProviderId;
use crate::privacy::PrivacyKey;

const MAX_PROVIDER_INSTANCE_ID_BYTES: usize = 128;
const MAX_ACCOUNT_KEY_BYTES: usize = 160;
const OPAQUE_RECORD_ID_HEX_BYTES: usize = 32;

macro_rules! scoped_id {
    ($name:ident, $maximum:ident, $description:literal, $redacted_debug:literal, $allow_at:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Box<str>);

        impl $name {
            /// Creates a validated routing identifier.
            ///
            /// # Errors
            ///
            /// Returns an error for empty, oversized, whitespace-padded, or
            /// unsupported-character input.
            pub fn new(value: impl AsRef<str>) -> Result<Self, ScopeIdError> {
                let value = value.as_ref();
                validate_scope_id(value, $maximum, $description, $allow_at)?;
                Ok(Self(value.into()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Debug for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                if $redacted_debug {
                    formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
                } else {
                    formatter
                        .debug_tuple(stringify!($name))
                        .field(&self.as_str())
                        .finish()
                }
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

scoped_id!(
    ProviderInstanceId,
    MAX_PROVIDER_INSTANCE_ID_BYTES,
    "provider instance ID",
    true,
    true
);

/// Domain-separated purpose for a stable installation-local record ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpaqueRecordKind {
    CreditEvent,
    ResetCredit,
}

impl OpaqueRecordKind {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::CreditEvent => b"credit-event",
            Self::ResetCredit => b"reset-credit",
        }
    }
}

/// A stable record identifier derived without retaining a provider's raw ID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct OpaqueRecordId(Box<str>);

impl OpaqueRecordId {
    /// Derives a scope- and installation-local record ID from bounded provider
    /// inputs. Length-prefixing prevents ambiguous component concatenation.
    #[must_use]
    pub(crate) fn derive(
        privacy_key: &PrivacyKey,
        scope: &AccountScope,
        kind: OpaqueRecordKind,
        components: &[&[u8]],
    ) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(privacy_key.as_bytes())
            .expect("a SHA-256 HMAC accepts the fixed privacy-key length");
        mac.update(b"omarchy-ai-bar/opaque-record/v1\0");
        mac.update(kind.domain());
        mac.update(b"\0");
        update_scope_mac(&mut mac, scope);
        for component in components {
            mac.update(&(component.len() as u64).to_be_bytes());
            mac.update(component);
        }
        let digest = format!("{:x}", mac.finalize().into_bytes());
        Self(digest[..OPAQUE_RECORD_ID_HEX_BYTES].into())
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn public_ordinal(kind: OpaqueRecordKind, ordinal: usize) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0_u8; 32])
            .expect("a SHA-256 HMAC accepts a fixed key");
        mac.update(b"omarchy-ai-bar/public-record-ordinal/v1\0");
        mac.update(kind.domain());
        mac.update(b"\0");
        mac.update(&ordinal.to_be_bytes());
        let digest = format!("{:x}", mac.finalize().into_bytes());
        Self(digest[..OPAQUE_RECORD_ID_HEX_BYTES].into())
    }

    fn from_wire(value: &str) -> Result<Self, OpaqueRecordIdError> {
        if value.len() != OPAQUE_RECORD_ID_HEX_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(OpaqueRecordIdError);
        }
        Ok(Self(value.into()))
    }
}

impl Debug for OpaqueRecordId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueRecordId(<redacted>)")
    }
}

impl Serialize for OpaqueRecordId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OpaqueRecordId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_wire(&value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("opaque record ID must use the canonical encoding")]
pub(crate) struct OpaqueRecordIdError;
scoped_id!(
    AccountKey,
    MAX_ACCOUNT_KEY_BYTES,
    "account key",
    true,
    false
);

/// Exact routing scope for provider data and last-known-good state.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountScope {
    provider: ProviderId,
    instance: ProviderInstanceId,
    account: AccountKey,
}

impl AccountScope {
    #[must_use]
    pub const fn new(
        provider: ProviderId,
        instance: ProviderInstanceId,
        account: AccountKey,
    ) -> Self {
        Self {
            provider,
            instance,
            account,
        }
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub const fn instance(&self) -> &ProviderInstanceId {
        &self.instance
    }

    #[must_use]
    pub const fn account(&self) -> &AccountKey {
        &self.account
    }

    /// Replaces provider-controlled routing labels with deterministic IDs for
    /// one serialized public envelope.
    pub(crate) fn public_projection(&self, privacy_key: &PrivacyKey) -> Self {
        let instance = public_scope_id(self, b"instance", privacy_key);
        let account = public_scope_id(self, b"account", privacy_key);
        Self::new(
            self.provider,
            ProviderInstanceId::new(format!("instance-{instance}"))
                .expect("generated public instance ID is valid"),
            AccountKey::new(format!("account-{account}"))
                .expect("generated public account key is valid"),
        )
    }
}

fn public_scope_id(scope: &AccountScope, field: &[u8], privacy_key: &PrivacyKey) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(privacy_key.as_bytes())
        .expect("a SHA-256 HMAC accepts the fixed privacy-key length");
    mac.update(b"omarchy-ai-bar/public-scope/v1\0");
    mac.update(field);
    mac.update(b"\0");
    update_scope_mac(&mut mac, scope);
    let digest = format!("{:x}", mac.finalize().into_bytes());
    digest[..24].to_owned()
}

fn update_scope_mac(mac: &mut Hmac<Sha256>, scope: &AccountScope) {
    mac.update(scope.provider.as_str().as_bytes());
    mac.update(b"\0");
    mac.update(scope.instance.as_str().as_bytes());
    mac.update(b"\0");
    mac.update(scope.account.as_str().as_bytes());
}

impl Debug for AccountScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountScope")
            .field("provider", &self.provider)
            .field("instance", &self.instance)
            .field("account", &"<redacted>")
            .finish()
    }
}

fn validate_scope_id(
    value: &str,
    maximum: usize,
    description: &'static str,
    allow_at: bool,
) -> Result<(), ScopeIdError> {
    if value.is_empty() {
        return Err(ScopeIdError::Empty { description });
    }
    if value != value.trim() {
        return Err(ScopeIdError::SurroundingWhitespace { description });
    }
    if value.len() > maximum {
        return Err(ScopeIdError::TooLong {
            description,
            maximum,
            actual: value.len(),
        });
    }
    if let Some(character) = value.chars().find(|character| {
        !(character.is_ascii_alphanumeric()
            || matches!(character, '-' | '_' | '.' | ':' | '+')
            || (allow_at && *character == '@'))
    }) {
        return Err(ScopeIdError::InvalidCharacter {
            description,
            character,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScopeIdError {
    #[error("{description} must not be empty")]
    Empty { description: &'static str },
    #[error("{description} must not contain surrounding whitespace")]
    SurroundingWhitespace { description: &'static str },
    #[error("{description} is {actual} bytes; maximum is {maximum} bytes")]
    TooLong {
        description: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("{description} contains unsupported character {character:?}")]
    InvalidCharacter {
        description: &'static str,
        character: char,
    },
}
