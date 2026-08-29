use std::cell::Cell;

use oab_domain::{SnapshotEnvelopeV1, SurfaceSnapshotEnvelope, Timestamp};
use oab_ipc::codec::{
    JsonLineDecoder, JsonLineError, MAX_JSON_LINE_BYTES, decode_json_line, encode_json_line,
};
use oab_ipc::protocol::{
    AcceptedClientFrame, BackendStreamId, BridgeVersion, Capability, CapabilitySet, ClientHello,
    ClientMessage, FrontendSessionId, HandshakeError, MAX_REPLAY_SESSIONS, ProtocolVersion,
    RequestId, RequestReplayDisposition, RequestReplayRegistry, RequestReplayRegistryError,
    RuntimeAction, Sequence, SequenceDisposition, SequenceTracker, ServerHandshakeContext,
    ServerMessage, V1_PROTOCOL, WireIntegerError,
};
use serde::Serialize;
use serde::ser::{Error as _, SerializeSeq};

fn session_id(suffix: u8) -> FrontendSessionId {
    FrontendSessionId::parse(format!("{suffix:032x}")).expect("canonical frontend session ID")
}

fn stream_id(suffix: u8) -> BackendStreamId {
    BackendStreamId::parse(format!("{suffix:032x}")).expect("canonical backend stream ID")
}

fn handshake_context(capabilities: CapabilitySet) -> ServerHandshakeContext {
    ServerHandshakeContext::new(capabilities).expect("OS randomness initializes handshake context")
}

fn client_hello(
    protocol: ProtocolVersion,
    session_id: FrontendSessionId,
    capabilities: CapabilitySet,
) -> ClientHello {
    ClientHello::new(
        protocol,
        BridgeVersion::new(1, 0, 0),
        session_id,
        capabilities,
    )
}

#[test]
fn v1_handshake_negotiates_a_canonical_capability_intersection() {
    let client = ClientHello::new(
        ProtocolVersion::new(1, 9),
        BridgeVersion::new(4, 2, 1),
        session_id(1),
        CapabilitySet::new([
            Capability::RuntimeActions,
            Capability::DisplaySnapshots,
            Capability::Notifications,
        ])
        .expect("unique capabilities"),
    );
    let server = CapabilitySet::new([
        Capability::ActionProgress,
        Capability::DisplaySnapshots,
        Capability::RuntimeActions,
    ])
    .expect("unique capabilities");

    let mut guard = handshake_context(server).connection();
    let AcceptedClientFrame::Hello(negotiated) = guard
        .accept(&ClientMessage::hello(client))
        .expect("compatible v1 handshake")
    else {
        panic!("expected negotiated hello");
    };

    assert_eq!(negotiated.protocol(), V1_PROTOCOL);
    assert_eq!(
        negotiated.capabilities().as_slice(),
        &[Capability::DisplaySnapshots, Capability::RuntimeActions,]
    );
}

#[test]
fn handshake_rejects_an_unsupported_major() {
    let client = client_hello(
        ProtocolVersion::new(2, 0),
        session_id(1),
        CapabilitySet::default(),
    );

    assert_eq!(
        handshake_context(CapabilitySet::default())
            .connection()
            .accept(&ClientMessage::hello(client)),
        Err(HandshakeError::UnsupportedMajor {
            received: 2,
            supported: 1,
        })
    );
}

#[test]
fn handshake_accepts_every_frame_and_enforces_state_and_capabilities() {
    let capabilities =
        CapabilitySet::new([Capability::DisplaySnapshots, Capability::RuntimeActions])
            .expect("unique capabilities");
    let frontend_session = session_id(1);
    let mut guard = handshake_context(capabilities.clone()).connection();
    let action: ClientMessage = decode_json_line(include_bytes!(
        "../../../fixtures/ipc/client-action-v1.jsonl"
    ))
    .expect("action fixture");
    assert_eq!(guard.accept(&action), Err(HandshakeError::HelloRequired));
    assert_eq!(
        guard.accept(&ClientMessage::SnapshotAck {
            sequence: Sequence::new(1).expect("positive sequence"),
        }),
        Err(HandshakeError::HelloRequired)
    );
    assert!(!guard.is_complete());

    let hello = ClientMessage::hello(ClientHello::new(
        V1_PROTOCOL,
        BridgeVersion::new(1, 0, 0),
        frontend_session.clone(),
        capabilities.clone(),
    ));
    let accepted = guard.accept(&hello).expect("hello accepted");
    assert!(matches!(&accepted, AcceptedClientFrame::Hello(_)));
    assert!(guard.is_complete());
    assert_eq!(guard.session_id(), Some(&frontend_session));
    assert_eq!(
        guard
            .negotiated()
            .expect("negotiated hello retained")
            .stream_id(),
        match &accepted {
            AcceptedClientFrame::Hello(hello) => hello.stream_id(),
            _ => unreachable!("accepted frame was already checked as hello"),
        }
    );
    assert_eq!(
        guard
            .negotiated()
            .expect("negotiated hello retained")
            .capabilities(),
        &capabilities
    );

    let accepted = guard.accept(&action).expect("runtime action accepted");
    assert!(matches!(
        accepted,
        AcceptedClientFrame::Action {
            session_id,
            request_id,
            action: RuntimeAction::RefreshProvider { .. },
        } if session_id == frontend_session && request_id.get() == 42
    ));

    let acknowledgement = ClientMessage::SnapshotAck {
        sequence: Sequence::new(7).expect("positive sequence"),
    };
    assert!(matches!(
        guard.accept(&acknowledgement),
        Ok(AcceptedClientFrame::SnapshotAck {
            session_id,
            sequence,
        }) if session_id == frontend_session && sequence.get() == 7
    ));
    assert_eq!(guard.accept(&hello), Err(HandshakeError::AlreadyComplete));
}

#[test]
fn handshake_rejects_runtime_frames_without_their_negotiated_capability() {
    let mut guard = handshake_context(
        CapabilitySet::new([Capability::DisplaySnapshots, Capability::RuntimeActions])
            .expect("unique capabilities"),
    )
    .connection();
    let hello = ClientMessage::hello(client_hello(
        V1_PROTOCOL,
        session_id(1),
        CapabilitySet::default(),
    ));
    guard.accept(&hello).expect("compatible hello");

    let action: ClientMessage = decode_json_line(include_bytes!(
        "../../../fixtures/ipc/client-action-v1.jsonl"
    ))
    .expect("action fixture");
    assert_eq!(
        guard.accept(&action),
        Err(HandshakeError::CapabilityNotNegotiated {
            required: Capability::RuntimeActions,
        })
    );
    assert_eq!(
        guard.accept(&ClientMessage::SnapshotAck {
            sequence: Sequence::new(1).expect("positive sequence"),
        }),
        Err(HandshakeError::CapabilityNotNegotiated {
            required: Capability::DisplaySnapshots,
        })
    );
}

#[test]
fn unsupported_major_does_not_create_a_negotiated_session() {
    let mut guard = handshake_context(CapabilitySet::default()).connection();
    let unsupported = ClientMessage::hello(client_hello(
        ProtocolVersion::new(2, 0),
        session_id(1),
        CapabilitySet::default(),
    ));
    assert_eq!(
        guard.accept(&unsupported),
        Err(HandshakeError::UnsupportedMajor {
            received: 2,
            supported: 1,
        })
    );
    assert!(!guard.is_complete());
    assert!(guard.negotiated().is_none());
    assert!(guard.session_id().is_none());

    let supported = ClientMessage::hello(client_hello(
        V1_PROTOCOL,
        session_id(1),
        CapabilitySet::default(),
    ));
    assert!(matches!(
        guard.accept(&supported),
        Ok(AcceptedClientFrame::Hello(_))
    ));
}

#[test]
fn stale_and_duplicate_sequences_are_discarded_without_advancing() {
    let mut tracker = SequenceTracker::default();
    let one = Sequence::new(1).expect("positive sequence");
    let two = Sequence::new(2).expect("positive sequence");

    assert_eq!(tracker.observe(one), SequenceDisposition::Accepted);
    assert_eq!(tracker.observe(one), SequenceDisposition::Stale);
    assert_eq!(tracker.observe(one), SequenceDisposition::Stale);
    assert_eq!(tracker.last(), Some(one));
    assert_eq!(tracker.observe(two), SequenceDisposition::Accepted);
    assert_eq!(tracker.last(), Some(two));
}

#[test]
fn request_ids_and_sequences_use_the_exact_json_integer_range() {
    assert_eq!(RequestId::new(0), Err(WireIntegerError::Zero));
    assert_eq!(Sequence::new(0), Err(WireIntegerError::Zero));
    assert!(RequestId::new(9_007_199_254_740_991).is_ok());
    assert_eq!(
        Sequence::new(9_007_199_254_740_992),
        Err(WireIntegerError::ExceedsExactJsonRange)
    );
    assert!(serde_json::from_str::<RequestId>("0").is_err());
    assert!(serde_json::from_str::<Sequence>("9007199254740992").is_err());
    assert!(serde_json::from_str::<Sequence>("1.0").is_err());
}

#[test]
fn frontend_session_ids_are_stable_canonical_and_error_safe() {
    let identifier = session_id(42);
    let encoded = serde_json::to_string(&identifier).expect("session ID serializes");
    assert_eq!(encoded, format!("\"{}\"", identifier.as_str()));
    assert_eq!(
        serde_json::from_str::<FrontendSessionId>(&encoded).expect("session ID round trip"),
        identifier
    );

    for invalid in [
        "short",
        "0123456789ABCDEF0123456789ABCDEF",
        "gggggggggggggggggggggggggggggggg",
        "0123456789abcdef0123456789abcdef00",
    ] {
        let payload = format!("\"{invalid}\"");
        let error = serde_json::from_str::<FrontendSessionId>(&payload)
            .expect_err("invalid session ID")
            .to_string();
        assert!(!error.contains(invalid));
    }
}

#[test]
fn backend_stream_ids_are_canonical_and_error_safe_on_reencode() {
    let identifier = stream_id(42);
    let encoded = serde_json::to_string(&identifier).expect("stream ID serializes");
    assert_eq!(encoded, r#""0000000000000000000000000000002a""#);
    let decoded = serde_json::from_str::<BackendStreamId>(&encoded).expect("stream ID round trip");
    assert_eq!(decoded, identifier);
    assert_eq!(
        serde_json::to_string(&decoded).expect("canonical stream ID reencode"),
        encoded
    );
    assert_eq!(format!("{identifier:?}"), "BackendStreamId(<redacted>)");

    for invalid in [
        "short",
        "0123456789ABCDEF0123456789ABCDEF",
        "gggggggggggggggggggggggggggggggg",
        "0123456789abcdef0123456789abcdef00",
    ] {
        let payload = format!("\"{invalid}\"");
        let error = serde_json::from_str::<BackendStreamId>(&payload)
            .expect_err("invalid stream ID")
            .to_string();
        assert!(!error.contains(invalid));
    }
}

#[test]
fn request_replay_registry_is_monotonic_across_reconnects() {
    let frontend_session = session_id(1);
    let action: ClientMessage = decode_json_line(include_bytes!(
        "../../../fixtures/ipc/client-action-v1.jsonl"
    ))
    .expect("action fixture");
    let capabilities = CapabilitySet::new([Capability::RuntimeActions]).expect("unique capability");
    let handshake = handshake_context(capabilities.clone());
    let mut registry = RequestReplayRegistry::new(2).expect("bounded registry");

    for expected in [
        RequestReplayDisposition::New,
        RequestReplayDisposition::Replay,
    ] {
        let mut connection = handshake.connection();
        connection
            .accept(&ClientMessage::hello(client_hello(
                V1_PROTOCOL,
                frontend_session.clone(),
                capabilities.clone(),
            )))
            .expect("reconnect hello");
        let accepted = connection.accept(&action).expect("authorized action");
        let AcceptedClientFrame::Action {
            session_id,
            request_id,
            ..
        } = accepted
        else {
            panic!("expected accepted action");
        };
        assert_eq!(registry.observe(&session_id, request_id), expected);
    }

    assert_eq!(
        registry.observe(
            &frontend_session,
            RequestId::new(41).expect("positive request")
        ),
        RequestReplayDisposition::Stale
    );
    assert_eq!(
        registry.observe(
            &frontend_session,
            RequestId::new(43).expect("positive request")
        ),
        RequestReplayDisposition::New
    );
    assert_eq!(
        registry.last(&frontend_session),
        Some(RequestId::new(43).expect("positive request"))
    );
}

#[test]
fn request_replay_registry_has_deterministic_lru_eviction() {
    assert_eq!(
        RequestReplayRegistry::new(0).expect_err("zero capacity"),
        RequestReplayRegistryError::InvalidCapacity
    );
    assert_eq!(
        RequestReplayRegistry::new(MAX_REPLAY_SESSIONS + 1).expect_err("oversized capacity"),
        RequestReplayRegistryError::InvalidCapacity
    );

    let first = session_id(1);
    let second = session_id(2);
    let third = session_id(3);
    let one = RequestId::new(1).expect("positive request");
    let mut registry = RequestReplayRegistry::new(2).expect("bounded registry");
    assert_eq!(registry.observe(&first, one), RequestReplayDisposition::New);
    assert_eq!(
        registry.observe(&second, one),
        RequestReplayDisposition::New
    );
    assert_eq!(
        registry.observe(&first, one),
        RequestReplayDisposition::Replay
    );
    assert_eq!(registry.observe(&third, one), RequestReplayDisposition::New);

    assert_eq!(registry.len(), 2);
    assert!(registry.last(&first).is_some());
    assert!(registry.last(&second).is_none());
    assert!(registry.last(&third).is_some());
}

#[test]
fn canonical_client_fixtures_decode_and_reencode_byte_for_byte() {
    for fixture in [
        include_bytes!("../../../fixtures/ipc/client-hello-v1.jsonl").as_slice(),
        include_bytes!("../../../fixtures/ipc/client-action-v1.jsonl").as_slice(),
    ] {
        let decoded: ClientMessage = decode_json_line(fixture).expect("canonical client fixture");
        assert_eq!(encode_json_line(&decoded).expect("encode fixture"), fixture);
    }
}

#[test]
fn quit_is_a_closed_payload_free_runtime_action() {
    let canonical = b"{\"type\":\"action\",\"request_id\":9,\"action\":{\"id\":\"quit\"}}\n";
    let decoded: ClientMessage = decode_json_line(canonical).expect("typed quit action");
    assert!(matches!(
        &decoded,
        ClientMessage::Action {
            request_id,
            action: RuntimeAction::Quit {},
        } if request_id.get() == 9
    ));
    assert_eq!(
        encode_json_line(&decoded).expect("canonical quit action"),
        canonical
    );

    assert!(
        decode_json_line::<ClientMessage>(
            b"{\"type\":\"action\",\"request_id\":9,\"action\":{\"id\":\"quit\",\"command\":\"shutdown\"}}\n"
        )
        .is_err(),
        "quit must never admit a command payload"
    );
}

#[test]
fn forward_minor_capabilities_are_ignored_without_authorizing_them() {
    let decoded: CapabilitySet = serde_json::from_str(
        r#"["future_widget","display_snapshots","another_future_capability"]"#,
    )
    .expect("bounded future capabilities are safe to ignore");
    assert_eq!(decoded.as_slice(), &[Capability::DisplaySnapshots]);
    assert_eq!(
        serde_json::to_string(&decoded).expect("known set serializes"),
        r#"["display_snapshots"]"#
    );
}

#[test]
fn forward_minor_hello_negotiates_only_known_capabilities() {
    let hello: ClientMessage = decode_json_line(
        b"{\"type\":\"hello\",\"protocol\":{\"major\":1,\"minor\":99},\"bridge_version\":{\"major\":1,\"minor\":0,\"patch\":0},\"session_id\":\"0123456789abcdef0123456789abcdef\",\"capabilities\":[\"display_snapshots\",\"future_widget\"]}\n",
    )
    .expect("future-minor hello");
    let mut guard = handshake_context(
        CapabilitySet::new([Capability::DisplaySnapshots]).expect("known capability"),
    )
    .connection();
    let AcceptedClientFrame::Hello(response) =
        guard.accept(&hello).expect("compatible major negotiates")
    else {
        panic!("expected negotiated hello");
    };
    assert_eq!(
        response.capabilities().as_slice(),
        &[Capability::DisplaySnapshots]
    );
}

#[test]
fn capability_names_are_bounded_canonical_and_unique_before_filtering() {
    for payload in [
        r#"["display_snapshots","display_snapshots"]"#.to_owned(),
        r#"["future_widget","future_widget"]"#.to_owned(),
        r#"["FutureWidget"]"#.to_owned(),
        r#"["future__widget"]"#.to_owned(),
        serde_json::to_string(&vec!["x".repeat(65)]).expect("test JSON"),
        serde_json::to_string(
            &(0..=32)
                .map(|index| format!("future_{index}"))
                .collect::<Vec<_>>(),
        )
        .expect("test JSON"),
    ] {
        assert!(
            serde_json::from_str::<CapabilitySet>(&payload).is_err(),
            "invalid capability set was accepted"
        );
    }

    let sensitive = r#"["secretvalue__must_not_leak"]"#;
    let error = serde_json::from_str::<CapabilitySet>(sensitive)
        .expect_err("malformed capability")
        .to_string();
    assert!(!error.contains("secretvalue"));
}

#[test]
fn canonical_server_fixtures_match_the_serialize_only_wire_types() {
    let hello = ServerMessage::Hello {
        protocol: V1_PROTOCOL,
        stream_id: stream_id(1),
        capabilities: CapabilitySet::new([
            Capability::DisplaySnapshots,
            Capability::RuntimeActions,
        ])
        .expect("unique capabilities"),
    };
    assert_eq!(
        encode_json_line(&hello).expect("encode server hello"),
        include_bytes!("../../../fixtures/ipc/server-hello-v1.jsonl")
    );

    let snapshot = SnapshotEnvelopeV1::new(
        Timestamp::parse("2026-08-29T00:00:00Z").expect("fixture timestamp"),
        Vec::new(),
    )
    .expect("empty fixture envelope");
    let message = ServerMessage::Snapshot {
        sequence: Sequence::new(7).expect("positive sequence"),
        snapshot: SurfaceSnapshotEnvelope::Trusted(snapshot.private_view()),
    };
    assert_eq!(
        encode_json_line(&message).expect("encode snapshot"),
        include_bytes!("../../../fixtures/ipc/server-snapshot-v1.jsonl")
    );
}

#[test]
fn snapshot_u64_values_are_nested_decimal_strings_but_protocol_ids_stay_numeric() {
    let fixture = include_str!("../../../fixtures/domain/snapshot-v1.json").replacen(
        "\"duration_seconds\": 18000",
        "\"duration_seconds\": 18446744073709551615",
        1,
    );
    let snapshot: SnapshotEnvelopeV1 =
        serde_json::from_str(&fixture).expect("maximum u64 duration remains valid domain data");
    let message = ServerMessage::Snapshot {
        sequence: Sequence::new(9_007_199_254_740_991).expect("maximum exact sequence"),
        snapshot: SurfaceSnapshotEnvelope::Trusted(snapshot.private_view()),
    };
    let encoded = encode_json_line(&message).expect("bounded nested snapshot");
    let value: serde_json::Value = serde_json::from_slice(
        encoded
            .strip_suffix(b"\n")
            .expect("encoded line has canonical terminator"),
    )
    .expect("encoded snapshot JSON");

    assert_eq!(
        value["sequence"],
        serde_json::json!(9_007_199_254_740_991_u64)
    );
    assert_eq!(value["snapshot"]["schema_version"], serde_json::json!(1));
    assert_eq!(
        value["snapshot"]["snapshots"][0]["last_known_good"]["primary"]["duration_seconds"],
        serde_json::json!("18446744073709551615")
    );
    assert_eq!(
        value["snapshot"]["snapshots"][0]["last_known_good"]["extra_windows"][0]["window"]["duration_seconds"],
        serde_json::json!("2592000")
    );
}

#[test]
fn unknown_messages_fields_and_actions_fail_closed() {
    for (case, invalid) in [
        br#"{"type":"execute","request_id":1}"#.as_slice(),
        br#"{"type":"hello","protocol":{"major":1,"minor":0},"bridge_version":{"major":1,"minor":0,"patch":0},"session_id":"0123456789abcdef0123456789abcdef","capabilities":[],"extra":true}"#.as_slice(),
        br#"{"type":"action","request_id":1,"action":{"id":"run_shell"}}"#.as_slice(),
        br#"{"type":"action","request_id":1,"action":{"id":"open_panel","command":"sh"}}"#.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut line = invalid.to_vec();
        line.push(b'\n');
        assert!(
            decode_json_line::<ClientMessage>(&line).is_err(),
            "invalid protocol case {case} was accepted"
        );
    }
}

#[test]
fn malformed_json_and_noncanonical_line_endings_fail_closed() {
    assert_eq!(
        decode_json_line::<ClientMessage>(b"{not-json}\n"),
        Err(JsonLineError::MalformedJson)
    );
    assert_eq!(
        decode_json_line::<ClientMessage>(b"{}\r\n"),
        Err(JsonLineError::NonCanonicalNewline)
    );
    assert_eq!(
        decode_json_line::<ClientMessage>(b"{}"),
        Err(JsonLineError::UnterminatedLine)
    );
}

#[derive(Serialize)]
struct Padding<'a> {
    padding: &'a str,
}

struct StreamingOversize<'a> {
    attempts: &'a Cell<usize>,
}

impl Serialize for StreamingOversize<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        const TOTAL_ELEMENTS: usize = 10_000;
        const PADDING: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let mut sequence = serializer.serialize_seq(None)?;
        for index in 0..TOTAL_ELEMENTS {
            self.attempts.set(index + 1);
            sequence.serialize_element(PADDING)?;
        }
        sequence.end()
    }
}

struct SerializationFailure;

impl Serialize for SerializationFailure {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(S::Error::custom("intentional test failure"))
    }
}

#[test]
fn exactly_64_kib_including_lf_is_accepted_and_one_more_byte_is_rejected() {
    let framing_overhead = b"{\"padding\":\"\"}\n".len();
    let exact_padding = "x".repeat(MAX_JSON_LINE_BYTES - framing_overhead);
    let exact = encode_json_line(&Padding {
        padding: &exact_padding,
    })
    .expect("exact-size line");
    assert_eq!(exact.len(), MAX_JSON_LINE_BYTES);
    let mut decoder = JsonLineDecoder::<serde_json::Value>::new();
    assert_eq!(
        decoder.feed(&exact).expect("decode exact-size line").len(),
        1
    );

    let oversized_padding = format!("{exact_padding}x");
    assert_eq!(
        encode_json_line(&Padding {
            padding: &oversized_padding,
        }),
        Err(JsonLineError::LineTooLong)
    );
}

#[test]
fn encoder_aborts_streaming_serialization_at_the_payload_ceiling() {
    let attempts = Cell::new(0);
    assert_eq!(
        encode_json_line(&StreamingOversize {
            attempts: &attempts,
        }),
        Err(JsonLineError::LineTooLong)
    );
    assert!(
        attempts.get() < 10_000,
        "the serializer must be stopped before producing its full value"
    );
    assert_eq!(
        encode_json_line(&SerializationFailure),
        Err(JsonLineError::Serialization)
    );
}

#[test]
fn streaming_decoder_defines_clean_and_truncated_eof_semantics() {
    let fixture = include_bytes!("../../../fixtures/ipc/client-action-v1.jsonl");
    let split = fixture.len() / 2;
    let mut decoder = JsonLineDecoder::<ClientMessage>::new();
    assert!(
        decoder
            .feed(&fixture[..split])
            .expect("partial frame")
            .is_empty()
    );
    assert_eq!(
        decoder
            .feed(&fixture[split..])
            .expect("complete frame")
            .len(),
        1
    );
    assert_eq!(decoder.finish(), Ok(()));

    let mut truncated = JsonLineDecoder::<ClientMessage>::new();
    assert!(truncated.feed(b"{}").expect("bounded prefix").is_empty());
    assert_eq!(truncated.finish(), Err(JsonLineError::UnterminatedLine));
    assert_eq!(truncated.feed(b"\n"), Err(JsonLineError::Poisoned));
}

#[test]
fn streaming_decoder_poisoning_prevents_recovery_after_oversize_input() {
    let mut decoder = JsonLineDecoder::<ClientMessage>::new();
    let oversized_unterminated = vec![b'x'; MAX_JSON_LINE_BYTES];

    assert_eq!(
        decoder.feed(&oversized_unterminated),
        Err(JsonLineError::LineTooLong)
    );
    assert_eq!(decoder.feed(b"\n"), Err(JsonLineError::Poisoned));
}
