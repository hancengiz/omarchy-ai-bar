use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{BoundedText, Timestamp};

pub const MAX_STATUS_DESCRIPTION_LENGTH: usize = 512;
pub const MAX_INCIDENT_ID_LENGTH: usize = 128;
pub const MAX_INCIDENT_TITLE_LENGTH: usize = 256;
pub const MAX_INCIDENTS_PER_PROVIDER: usize = 64;
pub const MAX_STATUS_COMPONENT_ID_LENGTH: usize = 128;
pub const MAX_STATUS_COMPONENT_NAME_LENGTH: usize = 256;
pub const MAX_STATUS_COMPONENT_RAW_STATUS_LENGTH: usize = 120;
pub const MAX_STATUS_COMPONENTS_PER_PROVIDER: usize = 64;
pub const MAX_STATUS_COMPONENT_DEPTH: usize = 4;

/// Normalized service-health severity for a provider or individual incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHealth {
    Operational,
    Degraded,
    PartialOutage,
    MajorOutage,
    Critical,
    Maintenance,
    Unknown,
}

/// A current or historical provider-service incident. The stable source ID,
/// not its title, is its identity and tie-breaker for ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIncident {
    id: BoundedText<MAX_INCIDENT_ID_LENGTH>,
    title: BoundedText<MAX_INCIDENT_TITLE_LENGTH>,
    health: ProviderHealth,
    started_at: Option<Timestamp>,
    updated_at: Option<Timestamp>,
    resolved_at: Option<Timestamp>,
    description: Option<BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>>,
}

impl ProviderIncident {
    /// Creates a status incident with a chronologically valid timeline.
    ///
    /// # Errors
    ///
    /// Returns an error when update/resolution times precede the start or when
    /// resolution precedes the last update.
    pub fn new(
        id: BoundedText<MAX_INCIDENT_ID_LENGTH>,
        title: BoundedText<MAX_INCIDENT_TITLE_LENGTH>,
        health: ProviderHealth,
        started_at: Option<Timestamp>,
        updated_at: Option<Timestamp>,
        resolved_at: Option<Timestamp>,
        description: Option<BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>>,
    ) -> Result<Self, ProviderStatusValidationError> {
        if updated_at.is_some_and(|updated| started_at.is_some_and(|started| updated < started))
            || resolved_at
                .is_some_and(|resolved| started_at.is_some_and(|started| resolved < started))
            || resolved_at
                .is_some_and(|resolved| updated_at.is_some_and(|updated| resolved < updated))
        {
            return Err(ProviderStatusValidationError::InvalidIncidentTimeline);
        }
        Ok(Self {
            id,
            title,
            health,
            started_at,
            updated_at,
            resolved_at,
            description,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &BoundedText<MAX_INCIDENT_ID_LENGTH> {
        &self.id
    }

    #[must_use]
    pub const fn title(&self) -> &BoundedText<MAX_INCIDENT_TITLE_LENGTH> {
        &self.title
    }

    #[must_use]
    pub const fn health(&self) -> ProviderHealth {
        self.health
    }

    #[must_use]
    pub const fn started_at(&self) -> Option<Timestamp> {
        self.started_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> Option<Timestamp> {
        self.updated_at
    }

    #[must_use]
    pub const fn resolved_at(&self) -> Option<Timestamp> {
        self.resolved_at
    }

    #[must_use]
    pub const fn description(&self) -> Option<&BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>> {
        self.description.as_ref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderIncidentWire {
    id: BoundedText<MAX_INCIDENT_ID_LENGTH>,
    title: BoundedText<MAX_INCIDENT_TITLE_LENGTH>,
    health: ProviderHealth,
    started_at: Option<Timestamp>,
    updated_at: Option<Timestamp>,
    resolved_at: Option<Timestamp>,
    description: Option<BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>>,
}

impl<'de> Deserialize<'de> for ProviderIncident {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProviderIncidentWire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.title,
            wire.health,
            wire.started_at,
            wire.updated_at,
            wire.resolved_at,
            wire.description,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl Ord for ProviderIncident {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .updated_at
            .cmp(&self.updated_at)
            .then_with(|| other.started_at.cmp(&self.started_at))
            .then_with(|| self.id.cmp(&other.id))
            .then_with(|| self.title.cmp(&other.title))
            .then_with(|| self.health.cmp(&other.health))
            .then_with(|| self.resolved_at.cmp(&other.resolved_at))
            .then_with(|| self.description.cmp(&other.description))
    }
}

impl PartialOrd for ProviderIncident {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A component exposed by a provider status feed. Nested components preserve
/// grouped feeds such as an API group containing CLI and model endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusComponent {
    id: BoundedText<MAX_STATUS_COMPONENT_ID_LENGTH>,
    name: BoundedText<MAX_STATUS_COMPONENT_NAME_LENGTH>,
    health: ProviderHealth,
    raw_status: BoundedText<MAX_STATUS_COMPONENT_RAW_STATUS_LENGTH>,
    children: Vec<Self>,
}

impl StatusComponent {
    /// Creates and validates one complete component subtree.
    ///
    /// # Errors
    ///
    /// Returns an error if the subtree exceeds the component depth/count
    /// limits or contains duplicate IDs.
    pub fn new(
        id: BoundedText<MAX_STATUS_COMPONENT_ID_LENGTH>,
        name: BoundedText<MAX_STATUS_COMPONENT_NAME_LENGTH>,
        health: ProviderHealth,
        raw_status: BoundedText<MAX_STATUS_COMPONENT_RAW_STATUS_LENGTH>,
        mut children: Vec<Self>,
    ) -> Result<Self, ProviderStatusValidationError> {
        normalize_components(&mut children)?;
        let component = Self {
            id,
            name,
            health,
            raw_status,
            children,
        };
        let mut singleton = [component];
        normalize_components(&mut singleton)?;
        let [component] = singleton;
        Ok(component)
    }

    #[must_use]
    pub const fn id(&self) -> &BoundedText<MAX_STATUS_COMPONENT_ID_LENGTH> {
        &self.id
    }

    #[must_use]
    pub const fn name(&self) -> &BoundedText<MAX_STATUS_COMPONENT_NAME_LENGTH> {
        &self.name
    }

    #[must_use]
    pub const fn health(&self) -> ProviderHealth {
        self.health
    }

    #[must_use]
    pub const fn raw_status(&self) -> &BoundedText<MAX_STATUS_COMPONENT_RAW_STATUS_LENGTH> {
        &self.raw_status
    }

    #[must_use]
    pub fn children(&self) -> &[Self] {
        &self.children
    }
}

impl Ord for StatusComponent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id
            .cmp(&other.id)
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| self.health.cmp(&other.health))
            .then_with(|| self.raw_status.cmp(&other.raw_status))
            .then_with(|| self.children.cmp(&other.children))
    }
}

impl PartialOrd for StatusComponent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusComponentWire {
    id: BoundedText<MAX_STATUS_COMPONENT_ID_LENGTH>,
    name: BoundedText<MAX_STATUS_COMPONENT_NAME_LENGTH>,
    health: ProviderHealth,
    raw_status: BoundedText<MAX_STATUS_COMPONENT_RAW_STATUS_LENGTH>,
    children: Vec<StatusComponent>,
}

impl<'de> Deserialize<'de> for StatusComponent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = StatusComponentWire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.name,
            wire.health,
            wire.raw_status,
            wire.children,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Provider-level status plus its incident feed. Incident ordering is always
/// normalized, giving CLI, hook, and UI payloads a deterministic shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStatus {
    health: ProviderHealth,
    description: Option<BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>>,
    checked_at: Option<Timestamp>,
    incidents: Vec<ProviderIncident>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    components: Vec<StatusComponent>,
}

impl ProviderStatus {
    /// Creates a provider status without a component feed.
    ///
    /// # Errors
    ///
    /// Returns an error when incidents exceed their bound or reuse an ID.
    pub fn new(
        health: ProviderHealth,
        description: Option<BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>>,
        checked_at: Option<Timestamp>,
        incidents: Vec<ProviderIncident>,
    ) -> Result<Self, ProviderStatusValidationError> {
        Self::with_components(health, description, checked_at, incidents, Vec::new())
    }

    /// Creates a provider status with a bounded, normalized component tree.
    ///
    /// # Errors
    ///
    /// Returns an error when incident or component IDs are duplicated, or
    /// when either collection exceeds its size/depth limits.
    pub fn with_components(
        health: ProviderHealth,
        description: Option<BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>>,
        checked_at: Option<Timestamp>,
        mut incidents: Vec<ProviderIncident>,
        mut components: Vec<StatusComponent>,
    ) -> Result<Self, ProviderStatusValidationError> {
        if incidents.len() > MAX_INCIDENTS_PER_PROVIDER {
            return Err(ProviderStatusValidationError::TooManyIncidents {
                actual: incidents.len(),
                maximum: MAX_INCIDENTS_PER_PROVIDER,
            });
        }
        let mut ids = BTreeSet::new();
        for incident in &incidents {
            if !ids.insert(incident.id.as_str()) {
                return Err(ProviderStatusValidationError::DuplicateIncidentId);
            }
        }
        incidents.sort();
        normalize_components(&mut components)?;

        Ok(Self {
            health,
            description,
            checked_at,
            incidents,
            components,
        })
    }

    #[must_use]
    pub const fn health(&self) -> ProviderHealth {
        self.health
    }

    #[must_use]
    pub const fn description(&self) -> Option<&BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>> {
        self.description.as_ref()
    }

    #[must_use]
    pub const fn checked_at(&self) -> Option<Timestamp> {
        self.checked_at
    }

    #[must_use]
    pub fn incidents(&self) -> &[ProviderIncident] {
        &self.incidents
    }

    #[must_use]
    pub fn components(&self) -> &[StatusComponent] {
        &self.components
    }

    /// Retains only non-personal health mechanics for public outputs. Provider
    /// descriptions, incidents, and component names/raw statuses are arbitrary
    /// source text and are intentionally excluded.
    #[must_use]
    pub fn without_personal_information(&self) -> Self {
        Self {
            health: self.health,
            description: None,
            checked_at: self.checked_at,
            incidents: Vec::new(),
            components: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderStatusWire {
    health: ProviderHealth,
    description: Option<BoundedText<MAX_STATUS_DESCRIPTION_LENGTH>>,
    checked_at: Option<Timestamp>,
    incidents: Vec<ProviderIncident>,
    #[serde(default)]
    components: Vec<StatusComponent>,
}

impl<'de> Deserialize<'de> for ProviderStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProviderStatusWire::deserialize(deserializer)?;
        Self::with_components(
            wire.health,
            wire.description,
            wire.checked_at,
            wire.incidents,
            wire.components,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatusValidationError {
    TooManyIncidents { actual: usize, maximum: usize },
    DuplicateIncidentId,
    TooManyComponents { actual: usize, maximum: usize },
    ComponentDepthExceeded { maximum: usize },
    DuplicateComponentId,
    InvalidIncidentTimeline,
}

impl Display for ProviderStatusValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyIncidents { actual, maximum } => {
                write!(
                    formatter,
                    "incident count {actual} exceeds maximum {maximum}"
                )
            }
            Self::DuplicateIncidentId => formatter.write_str("duplicate incident id"),
            Self::TooManyComponents { actual, maximum } => {
                write!(
                    formatter,
                    "component count {actual} exceeds maximum {maximum}"
                )
            }
            Self::ComponentDepthExceeded { maximum } => {
                write!(formatter, "component depth exceeds maximum {maximum}")
            }
            Self::DuplicateComponentId => formatter.write_str("duplicate component id"),
            Self::InvalidIncidentTimeline => {
                formatter.write_str("provider incident timestamps are chronologically inconsistent")
            }
        }
    }
}

impl std::error::Error for ProviderStatusValidationError {}

fn normalize_components(
    components: &mut [StatusComponent],
) -> Result<(), ProviderStatusValidationError> {
    let mut ids = BTreeSet::new();
    let mut count = 0;
    normalize_component_level(components, 1, &mut count, &mut ids)?;
    Ok(())
}

fn normalize_component_level(
    components: &mut [StatusComponent],
    depth: usize,
    count: &mut usize,
    ids: &mut BTreeSet<String>,
) -> Result<(), ProviderStatusValidationError> {
    if components.is_empty() {
        return Ok(());
    }
    if depth > MAX_STATUS_COMPONENT_DEPTH {
        return Err(ProviderStatusValidationError::ComponentDepthExceeded {
            maximum: MAX_STATUS_COMPONENT_DEPTH,
        });
    }
    for component in components.iter_mut() {
        *count += 1;
        if *count > MAX_STATUS_COMPONENTS_PER_PROVIDER {
            return Err(ProviderStatusValidationError::TooManyComponents {
                actual: *count,
                maximum: MAX_STATUS_COMPONENTS_PER_PROVIDER,
            });
        }
        if !ids.insert(component.id.as_str().to_owned()) {
            return Err(ProviderStatusValidationError::DuplicateComponentId);
        }
        normalize_component_level(&mut component.children, depth + 1, count, ids)?;
    }
    components.sort();
    Ok(())
}
