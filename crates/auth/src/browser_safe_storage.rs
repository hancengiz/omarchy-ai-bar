//! Opt-in, read-only Linux Chromium Safe Storage access.
//!
//! Browser keyring access is disabled by default. Enabling it performs only an
//! exact `application` search followed by an exact label match; this module
//! never creates, replaces, or deletes browser-owned secrets.

use std::fmt::{self, Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_store::SecretValue;

const MAX_CANDIDATE_LABEL_BYTES: usize = 256;

/// Maximum number of keyring candidates inspected for one browser product.
pub const MAX_BROWSER_SAFE_STORAGE_CANDIDATES: usize = 32;
/// Maximum accepted Safe Storage secret size.
pub const MAX_BROWSER_SAFE_STORAGE_SECRET_BYTES: usize = 4 * 1024;

/// Explicit browser-keyring access policy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKeyringAccess {
    /// Never connect to D-Bus, a portal, or a keyring.
    #[default]
    Disabled,
    /// Explicitly connect to the desktop keyring for read-only access.
    Enabled,
}

/// Chromium-family products with fixed Linux Safe Storage identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserSafeStorageProduct {
    /// Google Chrome stable.
    GoogleChrome,
    /// Open-source Chromium.
    Chromium,
    /// Brave Browser stable.
    Brave,
    /// Brave Origin, as shipped by Omarchy.
    BraveOrigin,
    /// Microsoft Edge stable.
    MicrosoftEdge,
}

impl BrowserSafeStorageProduct {
    /// Returns the product's exact Linux Secret Service mapping.
    #[must_use]
    pub const fn spec(self) -> BrowserSafeStorageSpec {
        match self {
            Self::GoogleChrome => BrowserSafeStorageSpec::new("chrome", "Chrome Safe Storage"),
            Self::Chromium => BrowserSafeStorageSpec::new("chromium", "Chromium Safe Storage"),
            Self::Brave | Self::BraveOrigin => {
                BrowserSafeStorageSpec::new("brave", "Brave Safe Storage")
            }
            // Edge's Linux integration uses this exact product mapping. Do
            // not broaden it into Chrome or Chromium fallback searches.
            Self::MicrosoftEdge => {
                BrowserSafeStorageSpec::new("microsoft-edge", "Microsoft Edge Safe Storage")
            }
        }
    }
}

impl Display for BrowserSafeStorageProduct {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GoogleChrome => "Google Chrome",
            Self::Chromium => "Chromium",
            Self::Brave => "Brave",
            Self::BraveOrigin => "Brave Origin",
            Self::MicrosoftEdge => "Microsoft Edge",
        })
    }
}

/// Exact Secret Service attributes for one supported browser product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserSafeStorageSpec {
    application: &'static str,
    label: &'static str,
}

impl BrowserSafeStorageSpec {
    const fn new(application: &'static str, label: &'static str) -> Self {
        Self { application, label }
    }

    /// Exact `application` attribute used for the keyring search.
    #[must_use]
    pub const fn application(self) -> &'static str {
        self.application
    }

    /// Exact item label required after the attribute search.
    #[must_use]
    pub const fn label(self) -> &'static str {
        self.label
    }
}

/// Stable, path- and secret-free browser keyring failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSafeStorageError {
    /// Access was not explicitly enabled.
    #[error("browser keyring access is disabled")]
    Disabled,
    /// No native desktop Secret Service or existing default collection was available.
    #[error("browser keyring is unavailable")]
    Unavailable,
    /// The selected collection or item could not be unlocked.
    #[error("browser keyring is locked")]
    Locked,
    /// More than one item had the exact application and label.
    #[error("browser keyring result is ambiguous")]
    Ambiguous,
    /// Candidate metadata or secret bytes violated a fixed bound.
    #[error("browser keyring returned invalid data")]
    InvalidData,
    /// A read-only backend operation failed.
    #[error("browser keyring operation failed")]
    Operation,
}

/// Boxed asynchronous operation used by the injectable keyring boundary.
#[doc(hidden)]
pub type BrowserSafeStorageFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One lazily accessed item returned by an exact application search.
///
/// This seam is public only to support non-probing adapters and deterministic
/// tests. Production callers normally use [`BrowserSafeStorageReader::connect`].
#[doc(hidden)]
pub trait BrowserSafeStorageItem: Send + Sync {
    /// Reads only the candidate label.
    fn label(&self) -> BrowserSafeStorageFuture<'_, Result<String, BrowserSafeStorageError>>;

    /// Unlocks this exact item after label selection.
    fn unlock(&self) -> BrowserSafeStorageFuture<'_, Result<(), BrowserSafeStorageError>>;

    /// Reads this exact item's secret after it is unlocked.
    fn secret(
        &self,
    ) -> BrowserSafeStorageFuture<'_, Result<Zeroizing<Vec<u8>>, BrowserSafeStorageError>>;
}

/// Read-only backend used by [`BrowserSafeStorageReader`].
#[doc(hidden)]
pub trait BrowserSafeStorageBackend: Send + Sync {
    /// Searches one exact `application` attribute.
    fn search(
        &self,
        application: &'static str,
    ) -> BrowserSafeStorageFuture<
        '_,
        Result<Vec<Box<dyn BrowserSafeStorageItem>>, BrowserSafeStorageError>,
    >;
}

/// Factory seam that proves disabled construction performs no backend I/O.
#[doc(hidden)]
pub trait BrowserSafeStorageConnector: Send + Sync {
    /// Opens a read-only backend.
    fn connect(
        &self,
    ) -> BrowserSafeStorageFuture<
        '_,
        Result<Box<dyn BrowserSafeStorageBackend>, BrowserSafeStorageError>,
    >;
}

enum ReaderState {
    Disabled,
    Enabled(Box<dyn BrowserSafeStorageBackend>),
}

/// Opt-in, read-only browser Safe Storage reader.
pub struct BrowserSafeStorageReader {
    state: ReaderState,
}

impl BrowserSafeStorageReader {
    /// Constructs a reader under an explicit access policy.
    ///
    /// [`BrowserKeyringAccess::Disabled`] succeeds without opening D-Bus, a
    /// portal, or a keyring. [`BrowserKeyringAccess::Enabled`] opens the
    /// native Secret Service and resolves its existing `default` collection
    /// alias without creating a collection.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserSafeStorageError::Unavailable`] when enabled access
    /// cannot open the native keyring collection.
    pub async fn connect(access: BrowserKeyringAccess) -> Result<Self, BrowserSafeStorageError> {
        Self::connect_with(access, &Oo7Connector).await
    }

    /// Constructs a reader with an injected connector.
    ///
    /// This is a deterministic adapter seam. The connector is never invoked
    /// while `access` is [`BrowserKeyringAccess::Disabled`].
    ///
    /// # Errors
    ///
    /// Returns [`BrowserSafeStorageError::Unavailable`] when an enabled
    /// connector cannot open its backend.
    #[doc(hidden)]
    pub async fn connect_with(
        access: BrowserKeyringAccess,
        connector: &dyn BrowserSafeStorageConnector,
    ) -> Result<Self, BrowserSafeStorageError> {
        match access {
            BrowserKeyringAccess::Disabled => Ok(Self {
                state: ReaderState::Disabled,
            }),
            BrowserKeyringAccess::Enabled => {
                let backend = connector
                    .connect()
                    .await
                    .map_err(|_| BrowserSafeStorageError::Unavailable)?;
                Ok(Self {
                    state: ReaderState::Enabled(backend),
                })
            }
        }
    }

    /// Reads the one exact Safe Storage secret for `product`.
    ///
    /// The method searches only the product's exact application attribute,
    /// reads bounded labels, establishes a unique exact-label match, and only
    /// then unlocks and reads that item.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserSafeStorageError::Disabled`] when access was not
    /// enabled, or another stable variant for backend, ambiguity, lock, and
    /// bounded-data failures.
    pub async fn read(
        &self,
        product: BrowserSafeStorageProduct,
    ) -> Result<Option<SecretValue>, BrowserSafeStorageError> {
        let ReaderState::Enabled(backend) = &self.state else {
            return Err(BrowserSafeStorageError::Disabled);
        };
        let spec = product.spec();
        let candidates = backend.search(spec.application()).await?;
        if candidates.len() > MAX_BROWSER_SAFE_STORAGE_CANDIDATES {
            return Err(BrowserSafeStorageError::InvalidData);
        }

        let mut selected = None;
        for candidate in candidates {
            let label = candidate.label().await?;
            if label.len() > MAX_CANDIDATE_LABEL_BYTES {
                return Err(BrowserSafeStorageError::InvalidData);
            }
            if label == spec.label() {
                if selected.is_some() {
                    return Err(BrowserSafeStorageError::Ambiguous);
                }
                selected = Some(candidate);
            }
        }

        let Some(selected) = selected else {
            return Ok(None);
        };
        selected.unlock().await?;
        let mut secret = selected.secret().await?;
        if secret.is_empty() || secret.len() > MAX_BROWSER_SAFE_STORAGE_SECRET_BYTES {
            return Err(BrowserSafeStorageError::InvalidData);
        }
        SecretValue::new(std::mem::take(&mut *secret))
            .map(Some)
            .map_err(|_| BrowserSafeStorageError::InvalidData)
    }
}

impl Debug for BrowserSafeStorageReader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserSafeStorageReader")
            .field(
                "access",
                &match self.state {
                    ReaderState::Disabled => BrowserKeyringAccess::Disabled,
                    ReaderState::Enabled(_) => BrowserKeyringAccess::Enabled,
                },
            )
            .finish_non_exhaustive()
    }
}

struct Oo7Connector;

impl BrowserSafeStorageConnector for Oo7Connector {
    fn connect(
        &self,
    ) -> BrowserSafeStorageFuture<
        '_,
        Result<Box<dyn BrowserSafeStorageBackend>, BrowserSafeStorageError>,
    > {
        Box::pin(async {
            let service = oo7::dbus::Service::new()
                .await
                .map_err(|_| BrowserSafeStorageError::Unavailable)?;
            let collection = service
                .with_alias(oo7::dbus::Service::DEFAULT_COLLECTION)
                .await
                .map_err(|_| BrowserSafeStorageError::Unavailable)?
                .ok_or(BrowserSafeStorageError::Unavailable)?;
            Ok(Box::new(Oo7Backend { collection }) as Box<dyn BrowserSafeStorageBackend>)
        })
    }
}

struct Oo7Backend {
    collection: oo7::dbus::Collection,
}

impl BrowserSafeStorageBackend for Oo7Backend {
    fn search(
        &self,
        application: &'static str,
    ) -> BrowserSafeStorageFuture<
        '_,
        Result<Vec<Box<dyn BrowserSafeStorageItem>>, BrowserSafeStorageError>,
    > {
        Box::pin(async move {
            if self
                .collection
                .is_locked()
                .await
                .map_err(|error| classify_oo7_dbus_error(&error))?
            {
                return Err(BrowserSafeStorageError::Locked);
            }
            let attributes = [("application", application)];
            self.collection
                .search_items(&attributes)
                .await
                .map_err(|error| classify_oo7_dbus_error(&error))
                .map(|items| {
                    items
                        .into_iter()
                        .map(|item| Box::new(Oo7Item { item }) as Box<dyn BrowserSafeStorageItem>)
                        .collect()
                })
        })
    }
}

struct Oo7Item {
    item: oo7::dbus::Item,
}

impl BrowserSafeStorageItem for Oo7Item {
    fn label(&self) -> BrowserSafeStorageFuture<'_, Result<String, BrowserSafeStorageError>> {
        Box::pin(async {
            self.item
                .label()
                .await
                .map_err(|error| classify_oo7_dbus_error(&error))
        })
    }

    fn unlock(&self) -> BrowserSafeStorageFuture<'_, Result<(), BrowserSafeStorageError>> {
        Box::pin(async {
            self.item
                .unlock(None)
                .await
                .map_err(|error| classify_oo7_dbus_error(&error))
        })
    }

    fn secret(
        &self,
    ) -> BrowserSafeStorageFuture<'_, Result<Zeroizing<Vec<u8>>, BrowserSafeStorageError>> {
        Box::pin(async {
            let secret = self
                .item
                .secret()
                .await
                .map_err(|error| classify_oo7_dbus_error(&error))?;
            Ok(Zeroizing::new(secret.as_bytes().to_vec()))
        })
    }
}

fn classify_oo7_dbus_error(error: &oo7::dbus::Error) -> BrowserSafeStorageError {
    match error {
        oo7::dbus::Error::Service(oo7::dbus::ServiceError::IsLocked(_))
        | oo7::dbus::Error::Dismissed => BrowserSafeStorageError::Locked,
        oo7::dbus::Error::ZBus(_)
        | oo7::dbus::Error::Service(_)
        | oo7::dbus::Error::Deleted
        | oo7::dbus::Error::NotFound(_)
        | oo7::dbus::Error::IO(_)
        | oo7::dbus::Error::Crypto(_) => BrowserSafeStorageError::Operation,
    }
}
