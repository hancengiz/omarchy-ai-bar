//! Versioned, credential-free messages for the long-lived UI connection.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug, Display, Formatter};

use oab_domain::{ProviderId, SurfaceSnapshotEnvelope};
use serde::de::{self, SeqAccess, Visitor};
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// The largest integer that JavaScript and QML can represent exactly.
pub const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;
pub const PROTOCOL_V1_MAJOR: u16 = 1;
pub const PROTOCOL_V1_MINOR: u16 = 0;
pub const V1_PROTOCOL: ProtocolVersion = ProtocolVersion::new(PROTOCOL_V1_MAJOR, PROTOCOL_V1_MINOR);
/// Maximum frontend sessions retained by one replay registry.
pub const MAX_REPLAY_SESSIONS: usize = 256;

const MAX_CAPABILITIES: usize = 32;
const MAX_CAPABILITY_NAME_BYTES: usize = 64;
const MAX_PUBLIC_ROUTE_ID_BYTES: usize = 96;
const FRONTEND_SESSION_ID_HEX_BYTES: usize = 32;

/// A wire protocol version. Major compatibility is checked by the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// The frontend bridge build version, kept separate from protocol compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl BridgeVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    #[must_use]
    pub const fn patch(self) -> u16 {
        self.patch
    }
}

/// Features independently negotiated within a compatible protocol major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    DisplaySnapshots,
    ProviderAccounts,
    Settings,
    RuntimeActions,
    WidgetGeometry,
    PanelState,
    Notifications,
    ActionProgress,
    CompatibilityErrors,
}

impl Capability {
    fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "display_snapshots" => Some(Self::DisplaySnapshots),
            "provider_accounts" => Some(Self::ProviderAccounts),
            "settings" => Some(Self::Settings),
            "runtime_actions" => Some(Self::RuntimeActions),
            "widget_geometry" => Some(Self::WidgetGeometry),
            "panel_state" => Some(Self::PanelState),
            "notifications" => Some(Self::Notifications),
            "action_progress" => Some(Self::ActionProgress),
            "compatibility_errors" => Some(Self::CompatibilityErrors),
            _ => None,
        }
    }
}

/// A bounded, sorted set whose serialization is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilitySet(Vec<Capability>);

impl CapabilitySet {
    /// Builds a canonical capability set.
    ///
    /// # Errors
    ///
    /// Duplicate or overlong inputs are rejected rather than silently changed.
    pub fn new(
        capabilities: impl IntoIterator<Item = Capability>,
    ) -> Result<Self, CapabilitySetError> {
        let mut capabilities = capabilities.into_iter().collect::<Vec<_>>();
        if capabilities.len() > MAX_CAPABILITIES {
            return Err(CapabilitySetError::TooMany);
        }
        capabilities.sort_unstable();
        if capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CapabilitySetError::Duplicate);
        }
        Ok(Self(capabilities))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Capability] {
        &self.0
    }

    #[must_use]
    pub fn contains(&self, capability: Capability) -> bool {
        self.0.binary_search(&capability).is_ok()
    }

    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self(
            self.0
                .iter()
                .copied()
                .filter(|capability| other.contains(*capability))
                .collect(),
        )
    }
}

impl Serialize for CapabilitySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapabilitySetVisitor;

        impl<'de> Visitor<'de> for CapabilitySetVisitor {
            type Value = CapabilitySet;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded list of canonical capability names")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut names = BTreeSet::new();
                let mut capabilities = Vec::new();
                while let Some(name) = sequence.next_element::<CapabilityName>()? {
                    if names.len() == MAX_CAPABILITIES {
                        return Err(de::Error::custom(CapabilitySetError::TooMany));
                    }
                    if !names.insert(name.0.clone()) {
                        return Err(de::Error::custom(CapabilitySetError::Duplicate));
                    }
                    if let Some(capability) = Capability::from_wire_name(&name.0) {
                        capabilities.push(capability);
                    }
                }
                Self::Value::new(capabilities).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_seq(CapabilitySetVisitor)
    }
}

struct CapabilityName(String);

impl<'de> Deserialize<'de> for CapabilityName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = value.as_bytes();
        let valid_character = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        let is_canonical = !bytes.is_empty()
            && bytes.len() <= MAX_CAPABILITY_NAME_BYTES
            && valid_character(bytes[0])
            && valid_character(bytes[bytes.len() - 1])
            && bytes
                .iter()
                .copied()
                .all(|byte| valid_character(byte) || byte == b'_')
            && !bytes.windows(2).any(|pair| pair == b"__");
        if !is_canonical {
            return Err(de::Error::custom(CapabilitySetError::InvalidName));
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CapabilitySetError {
    #[error("too many protocol capabilities")]
    TooMany,
    #[error("duplicate protocol capability")]
    Duplicate,
    #[error("invalid protocol capability name")]
    InvalidName,
}

/// A stable, non-secret identifier generated once by the frontend.
///
/// The canonical representation is exactly 128 bits written as 32 lowercase
/// hexadecimal characters. It remains stable across display-socket reconnects.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct FrontendSessionId(String);

impl FrontendSessionId {
    /// Parses one canonical frontend session identifier.
    ///
    /// # Errors
    ///
    /// Values that are not exactly 32 lowercase hexadecimal bytes are rejected.
    pub fn parse(value: impl Into<String>) -> Result<Self, FrontendSessionIdError> {
        let value = value.into();
        if value.len() != FRONTEND_SESSION_ID_HEX_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(FrontendSessionIdError);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for FrontendSessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrontendSessionId(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for FrontendSessionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A frontend session identifier failed canonical validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid frontend session ID")]
pub struct FrontendSessionIdError;

/// A validated frontend hello independent of the outer message tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    protocol: ProtocolVersion,
    bridge_version: BridgeVersion,
    session_id: FrontendSessionId,
    capabilities: CapabilitySet,
}

impl ClientHello {
    #[must_use]
    pub const fn new(
        protocol: ProtocolVersion,
        bridge_version: BridgeVersion,
        session_id: FrontendSessionId,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            protocol,
            bridge_version,
            session_id,
            capabilities,
        }
    }

    #[must_use]
    pub const fn protocol(&self) -> ProtocolVersion {
        self.protocol
    }

    #[must_use]
    pub const fn bridge_version(&self) -> BridgeVersion {
        self.bridge_version
    }

    #[must_use]
    pub const fn session_id(&self) -> &FrontendSessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }
}

/// The server's deterministic result for a compatible hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    protocol: ProtocolVersion,
    capabilities: CapabilitySet,
}

impl ServerHello {
    #[must_use]
    pub const fn protocol(&self) -> ProtocolVersion {
        self.protocol
    }

    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }
}

/// Negotiates protocol v1 and a stable capability intersection.
///
/// # Errors
///
/// A client using any other protocol major is rejected.
pub fn negotiate_v1(
    client: &ClientHello,
    server_capabilities: &CapabilitySet,
) -> Result<ServerHello, HandshakeError> {
    if client.protocol.major != PROTOCOL_V1_MAJOR {
        return Err(HandshakeError::UnsupportedMajor {
            received: client.protocol.major,
            supported: PROTOCOL_V1_MAJOR,
        });
    }

    Ok(ServerHello {
        protocol: V1_PROTOCOL,
        capabilities: client.capabilities.intersection(server_capabilities),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HandshakeError {
    #[error("unsupported protocol major {received}; supported major is {supported}")]
    UnsupportedMajor { received: u16, supported: u16 },
    #[error("the first client message must be a hello")]
    HelloRequired,
    #[error("the protocol handshake is already complete")]
    AlreadyComplete,
    #[error("the required protocol capability was not negotiated")]
    CapabilityNotNegotiated { required: Capability },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WireIntegerError {
    #[error("wire integer must be positive")]
    Zero,
    #[error("wire integer exceeds the exact JSON integer range")]
    ExceedsExactJsonRange,
}

macro_rules! exact_wire_integer {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Creates a positive ID that is exactly representable by QML.
            ///
            /// # Errors
            ///
            /// Zero and values above [`MAX_EXACT_JSON_INTEGER`] are rejected.
            pub const fn new(value: u64) -> Result<Self, WireIntegerError> {
                if value == 0 {
                    Err(WireIntegerError::Zero)
                } else if value > MAX_EXACT_JSON_INTEGER {
                    Err(WireIntegerError::ExceedsExactJsonRange)
                } else {
                    Ok(Self(value))
                }
            }

            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u64(self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

exact_wire_integer!(RequestId);
exact_wire_integer!(Sequence);

/// A public, non-secret routing alias used by enumerated actions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PublicRouteId(String);

impl PublicRouteId {
    /// Validates a canonical lowercase routing alias.
    ///
    /// # Errors
    ///
    /// Empty, overlong, non-ASCII, non-lowercase, or separator-ended IDs fail.
    pub fn parse(value: impl Into<String>) -> Result<Self, PublicRouteIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PUBLIC_ROUTE_ID_BYTES {
            return Err(PublicRouteIdError);
        }
        let bytes = value.as_bytes();
        let is_alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if !is_alphanumeric(bytes[0]) || !is_alphanumeric(bytes[bytes.len() - 1]) {
            return Err(PublicRouteIdError);
        }
        if bytes
            .iter()
            .copied()
            .any(|byte| !is_alphanumeric(byte) && !matches!(byte, b'-' | b'_' | b'.' | b':'))
        {
            return Err(PublicRouteIdError);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for PublicRouteId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicRouteId(<redacted>)")
    }
}

impl Display for PublicRouteId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PublicRouteId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid public route ID")]
pub struct PublicRouteIdError;

/// Settings destinations exposed by the panel; no arbitrary route is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigationDestination {
    General,
    Providers,
    Display,
    Notifications,
    UsageAndSpend,
    Sessions,
    Hooks,
    Plugins,
    FleetSync,
    Advanced,
    About,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Json,
    Csv,
    Png,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    ApproveOnce,
    ApproveAlways,
    Deny,
}

/// The complete executable action vocabulary accepted from the frontend.
///
/// There is deliberately no command, executable, argument-vector, URL, or
/// credential-bearing variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "id", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeAction {
    OpenPanel {},
    ClosePanel {},
    TogglePanel {},
    RefreshAll {},
    RefreshProvider {
        provider: ProviderId,
    },
    SwitchAccount {
        provider: ProviderId,
        instance: PublicRouteId,
        account: PublicRouteId,
    },
    Navigate {
        destination: NavigationDestination,
    },
    BeginLogin {
        provider: ProviderId,
    },
    LogOut {
        provider: ProviderId,
        account: PublicRouteId,
    },
    OpenProviderDashboard {
        provider: ProviderId,
    },
    Export {
        format: ExportFormat,
    },
    InstallPlugin {
        plugin: PublicRouteId,
    },
    ResolveApproval {
        approval_id: RequestId,
        decision: ApprovalDecision,
    },
    CancelRequest {
        target_request_id: RequestId,
    },
}

/// Messages accepted on the long-lived display socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    Hello {
        protocol: ProtocolVersion,
        bridge_version: BridgeVersion,
        session_id: FrontendSessionId,
        capabilities: CapabilitySet,
    },
    Action {
        request_id: RequestId,
        action: RuntimeAction,
    },
    SnapshotAck {
        sequence: Sequence,
    },
}

impl ClientMessage {
    #[must_use]
    pub fn hello(hello: ClientHello) -> Self {
        Self::Hello {
            protocol: hello.protocol,
            bridge_version: hello.bridge_version,
            session_id: hello.session_id,
            capabilities: hello.capabilities,
        }
    }

    #[must_use]
    pub fn as_hello(&self) -> Option<ClientHello> {
        match self {
            Self::Hello {
                protocol,
                bridge_version,
                session_id,
                capabilities,
            } => Some(ClientHello::new(
                *protocol,
                *bridge_version,
                session_id.clone(),
                capabilities.clone(),
            )),
            Self::Action { .. } | Self::SnapshotAck { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionProgressState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityErrorCode {
    UnsupportedProtocolMajor,
    HelloRequired,
    ProtocolViolation,
}

/// Serialize-only backend messages. Snapshot construction requires the
/// domain's policy-aware wrapper, so a raw JSON/string credential cannot be
/// smuggled into this long-lived channel.
///
/// ```compile_fail
/// use oab_ipc::credential::Credential;
/// use oab_ipc::protocol::{Sequence, ServerMessage};
///
/// let credential = Credential::new("secret").unwrap();
/// let message = ServerMessage::Snapshot {
///     sequence: Sequence::new(1).unwrap(),
///     snapshot: credential,
/// };
/// let _ = serde_json::to_vec(&message);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerMessage<'a> {
    Hello {
        protocol: ProtocolVersion,
        capabilities: CapabilitySet,
    },
    Snapshot {
        sequence: Sequence,
        #[serde(serialize_with = "serialize_snapshot_with_exact_u64")]
        snapshot: SurfaceSnapshotEnvelope<'a>,
    },
    ActionProgress {
        request_id: RequestId,
        state: ActionProgressState,
    },
    CompatibilityError {
        code: CompatibilityErrorCode,
        supported: ProtocolVersion,
    },
    Pong {
        request_id: RequestId,
    },
}

impl ServerMessage<'_> {
    #[must_use]
    pub fn hello(hello: ServerHello) -> Self {
        Self::Hello {
            protocol: hello.protocol,
            capabilities: hello.capabilities,
        }
    }
}

fn serialize_snapshot_with_exact_u64<S>(
    snapshot: &SurfaceSnapshotEnvelope<'_>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    SnapshotExactU64(snapshot).serialize(serializer)
}

/// A typed serializer adapter that changes only nested `u64` primitives.
///
/// Snapshot quantities remain exact when parsed by QML because they cross this
/// one field as decimal strings. Protocol IDs are outside this adapter and stay
/// JSON numbers guarded by [`MAX_EXACT_JSON_INTEGER`].
struct SnapshotExactU64<'a, T: ?Sized>(&'a T);

impl<T> Serialize for SnapshotExactU64<'_, T>
where
    T: Serialize + ?Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(SnapshotSerializer(serializer))
    }
}

struct SnapshotSerializer<S>(S);

impl<S> Serializer for SnapshotSerializer<S>
where
    S: Serializer,
{
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = SnapshotCompound<S::SerializeSeq>;
    type SerializeTuple = SnapshotCompound<S::SerializeTuple>;
    type SerializeTupleStruct = SnapshotCompound<S::SerializeTupleStruct>;
    type SerializeTupleVariant = SnapshotCompound<S::SerializeTupleVariant>;
    type SerializeMap = SnapshotCompound<S::SerializeMap>;
    type SerializeStruct = SnapshotCompound<S::SerializeStruct>;
    type SerializeStructVariant = SnapshotCompound<S::SerializeStructVariant>;

    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_bool(value)
    }

    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_i8(value)
    }

    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_i16(value)
    }

    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_i32(value)
    }

    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_i64(value)
    }

    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_i128(value)
    }

    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_u8(value)
    }

    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_u16(value)
    }

    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_u32(value)
    }

    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_str(&value.to_string())
    }

    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_u128(value)
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_f32(value)
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_f64(value)
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_char(value)
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_str(value)
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_bytes(value)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_none()
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_some(&SnapshotExactU64(value))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.0.serialize_unit_variant(name, variant_index, variant)
    }

    fn serialize_newtype_struct<T>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0
            .serialize_newtype_struct(name, &SnapshotExactU64(value))
    }

    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0
            .serialize_newtype_variant(name, variant_index, variant, &SnapshotExactU64(value))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.0.serialize_seq(len).map(SnapshotCompound)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.0.serialize_tuple(len).map(SnapshotCompound)
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.0
            .serialize_tuple_struct(name, len)
            .map(SnapshotCompound)
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.0
            .serialize_tuple_variant(name, variant_index, variant, len)
            .map(SnapshotCompound)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.0.serialize_map(len).map(SnapshotCompound)
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.0.serialize_struct(name, len).map(SnapshotCompound)
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.0
            .serialize_struct_variant(name, variant_index, variant, len)
            .map(SnapshotCompound)
    }

    fn collect_str<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Display + ?Sized,
    {
        self.0.collect_str(value)
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

struct SnapshotCompound<C>(C);

impl<C> SerializeSeq for SnapshotCompound<C>
where
    C: SerializeSeq,
{
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_element(&SnapshotExactU64(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C> SerializeTuple for SnapshotCompound<C>
where
    C: SerializeTuple,
{
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_element(&SnapshotExactU64(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C> SerializeTupleStruct for SnapshotCompound<C>
where
    C: SerializeTupleStruct,
{
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_field(&SnapshotExactU64(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C> SerializeTupleVariant for SnapshotCompound<C>
where
    C: SerializeTupleVariant,
{
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_field(&SnapshotExactU64(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C> SerializeMap for SnapshotCompound<C>
where
    C: SerializeMap,
{
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_key(&SnapshotExactU64(key))
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_value(&SnapshotExactU64(value))
    }

    fn serialize_entry<K, V>(&mut self, key: &K, value: &V) -> Result<(), Self::Error>
    where
        K: Serialize + ?Sized,
        V: Serialize + ?Sized,
    {
        self.0
            .serialize_entry(&SnapshotExactU64(key), &SnapshotExactU64(value))
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C> SerializeStruct for SnapshotCompound<C>
where
    C: SerializeStruct,
{
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_field(key, &SnapshotExactU64(value))
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.0.skip_field(key)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

impl<C> SerializeStructVariant for SnapshotCompound<C>
where
    C: SerializeStructVariant,
{
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.0.serialize_field(key, &SnapshotExactU64(value))
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.0.skip_field(key)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.0.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceDisposition {
    Accepted,
    Stale,
}

/// Classifies one request ID within a stable frontend session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestReplayDisposition {
    /// No equal or newer request has been observed for the session.
    New,
    /// The request repeats the most recently accepted ID.
    Replay,
    /// A strictly newer request has already been accepted for the session.
    Stale,
}

/// Configuration failures for a bounded request replay registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RequestReplayRegistryError {
    /// Capacity must be between one and [`MAX_REPLAY_SESSIONS`].
    #[error("invalid request replay registry capacity")]
    InvalidCapacity,
}

/// A bounded, reconnect-aware registry of the latest request per frontend.
///
/// Entries use least-recently-used eviction. A frontend repeats its stable
/// [`FrontendSessionId`] in each reconnect hello, allowing a registry owned by
/// the backend runtime to reject replays across display socket lifetimes.
#[derive(Debug, Clone)]
pub struct RequestReplayRegistry {
    capacity: usize,
    last_requests: BTreeMap<FrontendSessionId, RequestId>,
    recency: VecDeque<FrontendSessionId>,
}

impl RequestReplayRegistry {
    /// Creates a registry with an explicit bounded session capacity.
    ///
    /// # Errors
    ///
    /// Zero and capacities above [`MAX_REPLAY_SESSIONS`] are rejected.
    pub fn new(capacity: usize) -> Result<Self, RequestReplayRegistryError> {
        if !(1..=MAX_REPLAY_SESSIONS).contains(&capacity) {
            return Err(RequestReplayRegistryError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            last_requests: BTreeMap::new(),
            recency: VecDeque::new(),
        })
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.last_requests.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last_requests.is_empty()
    }

    #[must_use]
    pub fn last(&self, session_id: &FrontendSessionId) -> Option<RequestId> {
        self.last_requests.get(session_id).copied()
    }

    /// Classifies a request and advances the session only for a strictly newer
    /// ID. Replay and stale observations leave the latest ID unchanged.
    pub fn observe(
        &mut self,
        session_id: &FrontendSessionId,
        request_id: RequestId,
    ) -> RequestReplayDisposition {
        if let Some(last) = self.last_requests.get(session_id).copied() {
            self.mark_recent(session_id);
            return match request_id.cmp(&last) {
                std::cmp::Ordering::Greater => {
                    self.last_requests.insert(session_id.clone(), request_id);
                    RequestReplayDisposition::New
                }
                std::cmp::Ordering::Equal => RequestReplayDisposition::Replay,
                std::cmp::Ordering::Less => RequestReplayDisposition::Stale,
            };
        }

        if self.last_requests.len() == self.capacity
            && let Some(evicted) = self.recency.pop_front()
        {
            self.last_requests.remove(&evicted);
        }
        self.last_requests.insert(session_id.clone(), request_id);
        self.recency.push_back(session_id.clone());
        RequestReplayDisposition::New
    }

    fn mark_recent(&mut self, session_id: &FrontendSessionId) {
        if let Some(index) = self.recency.iter().position(|entry| entry == session_id) {
            self.recency.remove(index);
        }
        self.recency.push_back(session_id.clone());
    }
}

impl Default for RequestReplayRegistry {
    fn default() -> Self {
        Self::new(MAX_REPLAY_SESSIONS).expect("maximum replay capacity is valid")
    }
}

/// Tracks the last applied immutable snapshot sequence.
#[derive(Debug, Clone, Default)]
pub struct SequenceTracker {
    last: Option<Sequence>,
}

impl SequenceTracker {
    #[must_use]
    pub const fn last(&self) -> Option<Sequence> {
        self.last
    }

    /// Accepts only a strictly newer sequence. Equal and older snapshots are
    /// classified as stale without changing the current sequence.
    pub fn observe(&mut self, sequence: Sequence) -> SequenceDisposition {
        if self.last.is_some_and(|last| sequence <= last) {
            SequenceDisposition::Stale
        } else {
            self.last = Some(sequence);
            SequenceDisposition::Accepted
        }
    }

    /// Returns a value only when its sequence was accepted, naturally
    /// discarding stale snapshot payloads.
    pub fn retain_if_fresh<T>(&mut self, sequence: Sequence, value: T) -> Option<T> {
        match self.observe(sequence) {
            SequenceDisposition::Accepted => Some(value),
            SequenceDisposition::Stale => None,
        }
    }
}

/// A successfully accepted frame with all state and capability checks applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedClientFrame<'a> {
    /// The first hello completed negotiation and should be answered.
    Hello(ServerHello),
    /// A runtime action authorized by the negotiated capability set.
    Action {
        session_id: FrontendSessionId,
        request_id: RequestId,
        action: &'a RuntimeAction,
    },
    /// An acknowledgement authorized for a snapshot-capable frontend.
    SnapshotAck {
        session_id: FrontendSessionId,
        sequence: Sequence,
    },
}

/// Enforces hello-first and negotiated-capability state on every client frame.
#[derive(Debug, Clone)]
pub struct HandshakeGuard {
    server_capabilities: CapabilitySet,
    session: Option<NegotiatedSession>,
}

#[derive(Debug, Clone)]
struct NegotiatedSession {
    session_id: FrontendSessionId,
    hello: ServerHello,
}

impl HandshakeGuard {
    #[must_use]
    pub const fn new(server_capabilities: CapabilitySet) -> Self {
        Self {
            server_capabilities,
            session: None,
        }
    }

    /// Validates one frame against the complete connection state.
    ///
    /// # Errors
    ///
    /// Runtime messages before hello, repeated hellos, unsupported majors, and
    /// messages whose required capability was not negotiated are rejected.
    pub fn accept<'a>(
        &mut self,
        message: &'a ClientMessage,
    ) -> Result<AcceptedClientFrame<'a>, HandshakeError> {
        match message {
            ClientMessage::Hello { .. } => {
                if self.session.is_some() {
                    return Err(HandshakeError::AlreadyComplete);
                }
                let hello = message.as_hello().ok_or(HandshakeError::HelloRequired)?;
                let negotiated = negotiate_v1(&hello, &self.server_capabilities)?;
                self.session = Some(NegotiatedSession {
                    session_id: hello.session_id,
                    hello: negotiated.clone(),
                });
                Ok(AcceptedClientFrame::Hello(negotiated))
            }
            ClientMessage::Action { request_id, action } => {
                let session = self.ready_with(Capability::RuntimeActions)?;
                Ok(AcceptedClientFrame::Action {
                    session_id: session.session_id.clone(),
                    request_id: *request_id,
                    action,
                })
            }
            ClientMessage::SnapshotAck { sequence } => {
                let session = self.ready_with(Capability::DisplaySnapshots)?;
                Ok(AcceptedClientFrame::SnapshotAck {
                    session_id: session.session_id.clone(),
                    sequence: *sequence,
                })
            }
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.session.is_some()
    }

    #[must_use]
    pub fn negotiated(&self) -> Option<&ServerHello> {
        self.session.as_ref().map(|session| &session.hello)
    }

    #[must_use]
    pub fn session_id(&self) -> Option<&FrontendSessionId> {
        self.session.as_ref().map(|session| &session.session_id)
    }

    fn ready_with(&self, required: Capability) -> Result<&NegotiatedSession, HandshakeError> {
        let session = self.session.as_ref().ok_or(HandshakeError::HelloRequired)?;
        if !session.hello.capabilities.contains(required) {
            return Err(HandshakeError::CapabilityNotNegotiated { required });
        }
        Ok(session)
    }
}
