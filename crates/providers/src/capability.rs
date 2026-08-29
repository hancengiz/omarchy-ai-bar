//! Closed capability vocabulary shared by first-party provider descriptors.

/// A normalized operation or enrichment a provider can supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProviderCapability {
    /// Required normalized quota or usage state.
    Usage = 1 << 0,
    /// Credits, balances, or reset-credit inventory.
    Credits = 1 << 1,
    /// Token, spend, or cost history.
    CostHistory = 1 << 2,
    /// Provider status and incidents.
    Status = 1 << 3,
    /// Local or remote agent sessions.
    Sessions = 1 << 4,
    /// Browser/manual-cookie acquisition.
    BrowserAuth = 1 << 5,
    /// Provider-owned storage reporting.
    StorageReport = 1 << 6,
    /// Login, account-switch, or provider actions.
    LoginAction = 1 << 7,
}

impl ProviderCapability {
    const ALL: [Self; 8] = [
        Self::Usage,
        Self::Credits,
        Self::CostHistory,
        Self::Status,
        Self::Sessions,
        Self::BrowserAuth,
        Self::StorageReport,
        Self::LoginAction,
    ];
}

/// Compact immutable set used by the static 69-provider registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet(u16);

impl CapabilitySet {
    /// Empty set used while constructing a descriptor.
    pub const EMPTY: Self = Self(0);
    /// The required capability every first-party provider supplies.
    pub const USAGE: Self = Self(ProviderCapability::Usage as u16);

    /// Adds one capability.
    #[must_use]
    pub const fn with(self, capability: ProviderCapability) -> Self {
        Self(self.0 | capability as u16)
    }

    /// Reports whether a capability is present.
    #[must_use]
    pub const fn contains(self, capability: ProviderCapability) -> bool {
        self.0 & capability as u16 != 0
    }

    /// Reports whether no capability is present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Iterates capabilities in stable declaration order.
    pub fn iter(self) -> impl Iterator<Item = ProviderCapability> {
        ProviderCapability::ALL
            .into_iter()
            .filter(move |capability| self.contains(*capability))
    }
}
