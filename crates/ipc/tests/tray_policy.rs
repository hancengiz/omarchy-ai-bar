use std::time::Duration;

use oab_ipc::frontend_presence::{
    FrontendCompatibility, FrontendPresence, FrontendPresenceError, SniStatus,
};
use oab_ipc::protocol::{
    AcceptedClientFrame, BridgeVersion, Capability, CapabilitySet, ClientHello, ClientMessage,
    FrontendSessionId, ProtocolVersion, ServerHandshakeContext, V1_PROTOCOL,
};

fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn handshake_context(capabilities: CapabilitySet) -> ServerHandshakeContext {
    ServerHandshakeContext::new(capabilities).expect("OS randomness for handshake stream ID")
}

fn client_hello(protocol: ProtocolVersion, capabilities: CapabilitySet) -> ClientMessage {
    ClientMessage::hello(ClientHello::new(
        protocol,
        BridgeVersion::new(1, 0, 0),
        FrontendSessionId::parse("00000000000000000000000000000001")
            .expect("canonical frontend session ID"),
        capabilities,
    ))
}

#[test]
fn only_a_negotiated_display_snapshot_frontend_is_compatible() {
    let display_capabilities =
        CapabilitySet::new([Capability::DisplaySnapshots]).expect("unique capability");
    let mut guard = handshake_context(display_capabilities.clone()).connection();
    assert_eq!(
        guard
            .negotiated()
            .map(FrontendCompatibility::from_server_hello),
        None
    );

    let hello = client_hello(V1_PROTOCOL, display_capabilities);
    let accepted = guard
        .accept(&hello)
        .expect("display-capable hello negotiates");
    let AcceptedClientFrame::Hello(server_hello) = accepted else {
        panic!("expected a negotiated server hello");
    };
    assert_eq!(
        FrontendCompatibility::from_server_hello(&server_hello),
        FrontendCompatibility::Compatible
    );

    let mut no_display_guard = handshake_context(CapabilitySet::default()).connection();
    let hello = client_hello(
        V1_PROTOCOL,
        CapabilitySet::new([Capability::DisplaySnapshots]).expect("unique capability"),
    );
    let accepted = no_display_guard
        .accept(&hello)
        .expect("same-major hello negotiates");
    let AcceptedClientFrame::Hello(server_hello) = accepted else {
        panic!("expected a negotiated server hello");
    };
    assert_eq!(
        FrontendCompatibility::from_server_hello(&server_hello),
        FrontendCompatibility::Incompatible
    );
}

#[test]
fn rejected_major_never_produces_compatible_negotiation() {
    let display_capabilities =
        CapabilitySet::new([Capability::DisplaySnapshots]).expect("unique capability");
    let mut guard = handshake_context(display_capabilities.clone()).connection();

    assert!(
        guard
            .accept(&client_hello(
                ProtocolVersion::new(V1_PROTOCOL.major() + 1, 0),
                display_capabilities,
            ))
            .is_err()
    );
    assert_eq!(
        guard
            .negotiated()
            .map(FrontendCompatibility::from_server_hello),
        None
    );
}

#[test]
fn startup_without_a_frontend_activates_only_when_grace_expires() {
    let mut presence = FrontendPresence::new(seconds(10), seconds(100));

    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), Some(seconds(110)));
    assert_eq!(
        presence
            .advance_to(seconds(109))
            .expect("monotonic timestamp"),
        SniStatus::Passive
    );
    assert_eq!(presence.next_deadline(), Some(seconds(110)));
    assert_eq!(
        presence
            .advance_to(seconds(110))
            .expect("deadline timestamp"),
        SniStatus::Active
    );
    assert_eq!(presence.next_deadline(), None);
}

#[test]
fn zero_grace_activates_immediately() {
    let presence = FrontendPresence::new(Duration::ZERO, seconds(7));

    assert_eq!(presence.status(), SniStatus::Active);
    assert_eq!(presence.next_deadline(), None);
}

#[test]
fn compatible_connection_suppresses_an_active_fallback_immediately() {
    let mut presence = FrontendPresence::new(Duration::ZERO, Duration::ZERO);
    assert_eq!(presence.status(), SniStatus::Active);

    let connection = presence
        .connect_at(seconds(1), FrontendCompatibility::Compatible)
        .expect("compatible connection");

    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);

    presence
        .disconnect_at(seconds(2), connection)
        .expect("compatible disconnection");
    assert_eq!(presence.status(), SniStatus::Active);
    assert_eq!(presence.next_deadline(), None);
}

#[test]
fn incompatible_connections_never_suppress_or_extend_fallback() {
    let mut active = FrontendPresence::new(Duration::ZERO, Duration::ZERO);
    let incompatible = active
        .connect_at(seconds(1), FrontendCompatibility::Incompatible)
        .expect("incompatible connection");
    assert_eq!(active.status(), SniStatus::Active);
    active
        .disconnect_at(seconds(2), incompatible)
        .expect("incompatible disconnection");
    assert_eq!(active.status(), SniStatus::Active);

    let mut waiting = FrontendPresence::new(seconds(10), Duration::ZERO);
    let original_deadline = waiting.next_deadline();
    let incompatible = waiting
        .connect_at(seconds(4), FrontendCompatibility::Incompatible)
        .expect("incompatible connection during grace");
    assert_eq!(waiting.status(), SniStatus::Passive);
    assert_eq!(waiting.next_deadline(), original_deadline);
    waiting
        .disconnect_at(seconds(9), incompatible)
        .expect("incompatible disconnection during grace");
    assert_eq!(waiting.next_deadline(), original_deadline);
    assert_eq!(
        waiting
            .advance_to(seconds(10))
            .expect("original grace deadline"),
        SniStatus::Active
    );
}

#[test]
fn rapid_reconnect_cancels_grace_without_active_flicker() {
    let mut presence = FrontendPresence::new(seconds(5), Duration::ZERO);
    let old_transport = presence
        .connect_at(seconds(1), FrontendCompatibility::Compatible)
        .expect("first compatible connection");
    presence
        .disconnect_at(seconds(2), old_transport)
        .expect("first compatible disconnection");
    assert_eq!(presence.next_deadline(), Some(seconds(7)));

    assert_eq!(
        presence
            .advance_to(seconds(6))
            .expect("time before deadline"),
        SniStatus::Passive
    );
    let new_transport = presence
        .connect_at(seconds(6), FrontendCompatibility::Compatible)
        .expect("replacement compatible connection");
    assert_ne!(old_transport, new_transport);
    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);

    presence
        .disconnect_at(seconds(7), old_transport)
        .expect("late duplicate disconnection");
    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);
}

#[test]
fn last_of_multiple_compatible_connections_arms_grace_once() {
    let mut presence = FrontendPresence::new(seconds(4), Duration::ZERO);
    let first = presence
        .connect_at(seconds(1), FrontendCompatibility::Compatible)
        .expect("first connection");
    let second = presence
        .connect_at(seconds(1), FrontendCompatibility::Compatible)
        .expect("second connection");
    assert_ne!(first, second);

    presence
        .disconnect_at(seconds(2), first)
        .expect("first disconnection");
    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);

    presence
        .disconnect_at(seconds(3), first)
        .expect("duplicate first disconnection");
    assert_eq!(presence.next_deadline(), None);

    presence
        .disconnect_at(seconds(5), second)
        .expect("last disconnection");
    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), Some(seconds(9)));

    presence
        .disconnect_at(seconds(6), second)
        .expect("duplicate last disconnection");
    assert_eq!(presence.next_deadline(), Some(seconds(9)));
    assert_eq!(
        presence
            .advance_to(seconds(9))
            .expect("last-client grace deadline"),
        SniStatus::Active
    );
}

#[test]
fn unknown_connection_id_does_not_disturb_a_compatible_connection() {
    let mut presence = FrontendPresence::new(seconds(4), Duration::ZERO);
    let connected = presence
        .connect_at(seconds(1), FrontendCompatibility::Compatible)
        .expect("target compatible connection");

    let mut other_policy = FrontendPresence::new(Duration::ZERO, Duration::ZERO);
    let _first_foreign_id = other_policy
        .connect_at(Duration::ZERO, FrontendCompatibility::Incompatible)
        .expect("first foreign transport");
    let unknown_id = other_policy
        .connect_at(Duration::ZERO, FrontendCompatibility::Incompatible)
        .expect("second foreign transport");
    assert_ne!(connected, unknown_id);

    presence
        .disconnect_at(seconds(2), unknown_id)
        .expect("unknown disconnection is harmless");
    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);

    presence
        .disconnect_at(seconds(3), connected)
        .expect("real disconnection");
    assert_eq!(presence.next_deadline(), Some(seconds(7)));
}

#[test]
fn stale_transport_disconnect_cannot_remove_an_overlapping_reconnect() {
    let mut presence = FrontendPresence::new(seconds(3), Duration::ZERO);
    let old_transport = presence
        .connect_at(seconds(1), FrontendCompatibility::Compatible)
        .expect("old transport");
    let replacement_transport = presence
        .connect_at(seconds(2), FrontendCompatibility::Compatible)
        .expect("overlapping replacement transport");

    presence
        .disconnect_at(seconds(3), old_transport)
        .expect("old transport disconnect");
    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);

    presence
        .disconnect_at(seconds(4), replacement_transport)
        .expect("replacement transport disconnect");
    assert_eq!(presence.next_deadline(), Some(seconds(7)));
}

#[test]
fn non_monotonic_transitions_are_rejected_without_changing_presence() {
    let mut presence = FrontendPresence::new(seconds(10), seconds(20));
    let connection = presence
        .connect_at(seconds(21), FrontendCompatibility::Compatible)
        .expect("compatible connection");

    let error = presence
        .disconnect_at(seconds(19), connection)
        .expect_err("backwards timestamp must fail");
    assert_eq!(
        error,
        FrontendPresenceError::NonMonotonicTime {
            last_observed: seconds(21),
            attempted: seconds(19),
        }
    );
    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);

    presence
        .disconnect_at(seconds(21), connection)
        .expect("same timestamp is monotonic");
    assert_eq!(presence.next_deadline(), Some(seconds(31)));
}

#[test]
fn an_unrepresentable_deadline_remains_safely_passive() {
    let mut presence = FrontendPresence::new(Duration::from_nanos(1), Duration::MAX);

    assert_eq!(presence.status(), SniStatus::Passive);
    assert_eq!(presence.next_deadline(), None);
    assert_eq!(
        presence
            .advance_to(Duration::MAX)
            .expect("maximum logical timestamp"),
        SniStatus::Passive
    );
}
