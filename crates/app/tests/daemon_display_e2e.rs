mod support;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use oab_ipc::codec::encode_json_line;
use oab_ipc::protocol::{
    BridgeVersion, Capability, CapabilitySet, ClientHello, ClientMessage, FrontendSessionId,
    RequestId, RuntimeAction, V1_PROTOCOL,
};
use serde_json::Value;
use support::{DaemonFixture, terminate, wait_for_exit};

#[test]
fn daemon_publishes_four_provider_slice_and_completes_refresh_action() {
    let fixture = DaemonFixture::new("display-e2e");
    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);

    let mut stream = UnixStream::connect(fixture.display_socket_path()).expect("connect display");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set display timeout");
    let reader_stream = stream.try_clone().expect("clone display stream");
    let mut reader = BufReader::new(reader_stream);
    let capabilities = CapabilitySet::new([
        Capability::DisplaySnapshots,
        Capability::RuntimeActions,
        Capability::ActionProgress,
    ])
    .expect("capabilities");
    let hello = ClientMessage::hello(ClientHello::new(
        V1_PROTOCOL,
        BridgeVersion::new(0, 1, 0),
        FrontendSessionId::parse("0123456789abcdef0123456789abcdef").expect("session ID"),
        capabilities,
    ));
    stream
        .write_all(&encode_json_line(&hello).expect("encode hello"))
        .expect("write hello");

    let hello = read_json_line(&mut reader);
    assert_eq!(hello["type"], "hello");
    let snapshot = read_json_line(&mut reader);
    assert_eq!(snapshot["type"], "snapshot");
    assert_eq!(snapshot["snapshot"]["schema_version"], 1);
    let providers = snapshot["snapshot"]["snapshots"]
        .as_array()
        .expect("provider snapshots")
        .iter()
        .map(|entry| entry["scope"]["provider"].as_str().expect("provider ID"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        providers,
        std::collections::BTreeSet::from(["claude", "codex", "grok", "zai"])
    );

    let action = ClientMessage::Action {
        request_id: RequestId::new(1).expect("request ID"),
        action: RuntimeAction::RefreshAll {},
    };
    stream
        .write_all(&encode_json_line(&action).expect("encode action"))
        .expect("write action");

    let mut saw_running = false;
    let mut saw_completed = false;
    for _ in 0..8 {
        let frame = read_json_line(&mut reader);
        if frame["type"] == "action_progress" && frame["request_id"] == 1 {
            saw_running |= frame["state"] == "running";
            saw_completed |= frame["state"] == "completed";
        }
        if saw_completed {
            break;
        }
    }
    assert!(saw_running, "refresh action must report running");
    assert!(saw_completed, "refresh action must complete");

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
}

fn read_json_line(reader: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read display frame");
    assert!(!line.is_empty(), "display connection closed unexpectedly");
    serde_json::from_str(&line).expect("valid JSON display frame")
}
