//! Account-scoped provider execution and fail-soft result contracts.

use std::future::Future;
use std::pin::Pin;

use oab_domain::{AccountScope, ClassifiedError, UsageSample};
use tokio_util::sync::CancellationToken;

use crate::descriptor::{ProviderDescriptor, ProviderSource};

/// Exact immutable inputs available to one provider fetch.
#[derive(Debug, Clone)]
pub struct ProviderContext {
    scope: AccountScope,
    source: ProviderSource,
    cancellation: CancellationToken,
    provider_cache_bypass: bool,
}

impl ProviderContext {
    /// Creates an account-isolated provider context.
    #[must_use]
    pub const fn new(
        scope: AccountScope,
        source: ProviderSource,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            scope,
            source,
            cancellation,
            provider_cache_bypass: false,
        }
    }

    /// Requests a fresh provider operation instead of a provider-local
    /// successful-result cache hit.
    ///
    /// Runtime bridges use this only for an explicit manual refresh. Network
    /// retry, coalescing, and last-known-good policy remain runtime-owned.
    #[must_use]
    pub const fn with_provider_cache_bypass(mut self) -> Self {
        self.provider_cache_bypass = true;
        self
    }

    /// Exact provider-instance/account routing scope.
    #[must_use]
    pub const fn scope(&self) -> &AccountScope {
        &self.scope
    }

    /// Explicit source selected for this account.
    #[must_use]
    pub const fn source(&self) -> ProviderSource {
        self.source
    }

    /// Cooperative cancellation owned by the refresh runtime.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Whether this call must bypass provider-local successful-result caches.
    #[must_use]
    pub const fn provider_cache_bypass(&self) -> bool {
        self.provider_cache_bypass
    }
}

/// Heap-independent future type used by provider trait objects.
pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UsageSample, ClassifiedError>> + Send + 'a>>;

/// UI-neutral native provider adapter contract.
pub trait ProviderAdapter: Send + Sync {
    /// Closed first-party descriptor.
    fn descriptor(&self) -> &'static ProviderDescriptor;
    /// Fetches one exact account scope using only the selected source.
    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a>;
}

/// Result of applying a required fetch to optional last-known-good data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome<T> {
    /// The fetch produced new authoritative data.
    Fresh(T),
    /// The fetch failed and the previous authoritative value is retained.
    Retained {
        /// Previous successful value.
        last_good: T,
        /// Safe classified failure overlaid on that value.
        error: ClassifiedError,
    },
    /// No safe value has ever been fetched.
    Unavailable {
        /// Safe classified failure.
        error: ClassifiedError,
    },
}

/// Applies fail-soft semantics without allowing an error to erase cached data.
#[must_use]
pub fn preserve_last_good<T>(
    previous: Option<T>,
    result: Result<T, ClassifiedError>,
) -> FetchOutcome<T> {
    match (previous, result) {
        (_, Ok(value)) => FetchOutcome::Fresh(value),
        (Some(last_good), Err(error)) => FetchOutcome::Retained { last_good, error },
        (None, Err(error)) => FetchOutcome::Unavailable { error },
    }
}
