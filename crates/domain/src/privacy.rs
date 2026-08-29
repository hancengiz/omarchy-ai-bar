use std::fmt;

use serde::{Deserialize, Serialize, Serializer};

use crate::snapshot::{PrivateSnapshotEnvelope, SnapshotEnvelopeV1};

/// Installation-local key used to derive stable, non-reversible routing
/// aliases and normalized record IDs. Storage owns generation and persistence
/// of these bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivacyKey([u8; 32]);

impl PrivacyKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PrivacyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivacyKey(<redacted>)")
    }
}

/// A one-way, serializable policy projection of a snapshot envelope.
///
/// The field remains private so callers cannot manufacture a projection around
/// an unreviewed envelope or extract one after it has been sanitized.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedSnapshotEnvelope(SnapshotEnvelopeV1);

impl ProjectedSnapshotEnvelope {
    fn from_private(envelope: &SnapshotEnvelopeV1, privacy_key: &PrivacyKey) -> Self {
        Self(envelope.redacted(privacy_key))
    }
}

impl Serialize for ProjectedSnapshotEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.redacted_view().serialize(serializer)
    }
}

/// The only serializable surface decision for a snapshot aggregate.
///
/// Trusted local surfaces can receive the explicit private view when the user
/// selected `ShowPersonalInfo`. Public surfaces and all hidden-policy views own
/// a permanently sanitized [`ProjectedSnapshotEnvelope`].
#[derive(Debug, Clone, PartialEq)]
pub enum SurfaceSnapshotEnvelope<'a> {
    Trusted(PrivateSnapshotEnvelope<'a>),
    Public(ProjectedSnapshotEnvelope),
}

impl SurfaceSnapshotEnvelope<'_> {
    /// Applies a new policy/surface decision without ever restoring data that
    /// has already crossed into the public variant.
    #[must_use]
    pub fn project(
        &self,
        policy: PrivacyPolicy,
        surface: PrivacySurface,
        privacy_key: &PrivacyKey,
    ) -> SurfaceSnapshotEnvelope<'_> {
        match self {
            Self::Public(projected) => SurfaceSnapshotEnvelope::Public(projected.clone()),
            Self::Trusted(private) => {
                let envelope = private.envelope();
                envelope.project(policy, surface, privacy_key)
            }
        }
    }
}

impl Serialize for SurfaceSnapshotEnvelope<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Trusted(private) => private.serialize(serializer),
            Self::Public(projected) => projected.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyPolicy {
    ShowPersonalInfo,
    HidePersonalInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySurface {
    Ui,
    Notification,
    Hook,
    Cli,
    Server,
    Export,
    Diagnostics,
    FleetSync,
}

impl PrivacySurface {
    #[must_use]
    pub const fn is_always_public(self) -> bool {
        matches!(self, Self::Export | Self::Diagnostics | Self::FleetSync)
    }
}

impl SnapshotEnvelopeV1 {
    /// Produces the policy-aware serialization view for one output surface.
    ///
    /// Export, diagnostics, and fleet sync are always public. Other surfaces
    /// receive an explicitly private view only when the user selected
    /// [`PrivacyPolicy::ShowPersonalInfo`].
    #[must_use]
    pub fn project(
        &self,
        policy: PrivacyPolicy,
        surface: PrivacySurface,
        privacy_key: &PrivacyKey,
    ) -> SurfaceSnapshotEnvelope<'_> {
        if policy == PrivacyPolicy::HidePersonalInfo || surface.is_always_public() {
            SurfaceSnapshotEnvelope::Public(ProjectedSnapshotEnvelope::from_private(
                self,
                privacy_key,
            ))
        } else {
            SurfaceSnapshotEnvelope::Trusted(self.private_view())
        }
    }

    /// Produces a permanently sanitized wrapper independent of UI policy.
    #[must_use]
    pub fn public_projection(&self, privacy_key: &PrivacyKey) -> ProjectedSnapshotEnvelope {
        ProjectedSnapshotEnvelope::from_private(self, privacy_key)
    }
}
