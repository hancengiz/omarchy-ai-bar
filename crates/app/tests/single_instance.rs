mod support;

use std::os::unix::fs::MetadataExt;

use support::{DaemonFixture, EXPECTED_PROVIDER_IDS, assert_removed, terminate, wait_for_exit};

#[test]
fn second_invocation_forwards_activation_without_replacing_the_owner() {
    let fixture = DaemonFixture::new("single-instance");
    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);
    let identity = fixture.socket_identity();
    let display_identity =
        std::fs::symlink_metadata(fixture.display_socket_path()).expect("display socket metadata");

    let forwarded = fixture.activate();
    assert!(forwarded.status.success());
    assert!(forwarded.stdout.is_empty());
    assert!(forwarded.stderr.is_empty());
    assert!(daemon.try_wait().expect("poll daemon").is_none());
    assert_eq!(fixture.socket_identity(), identity);
    let display_after = std::fs::symlink_metadata(fixture.display_socket_path())
        .expect("display socket remains owned");
    assert_eq!(display_after.dev(), display_identity.dev());
    assert_eq!(display_after.ino(), display_identity.ino());

    terminate(&daemon);
    let status = wait_for_exit(&mut daemon);
    assert!(status.success());
    assert_removed(&fixture.socket_path());
    assert_removed(&fixture.display_socket_path());
}

#[test]
fn safe_command_uses_daemon_state_when_present() {
    let fixture = DaemonFixture::new("daemon-safe-command");
    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);
    assert!(fixture.activate().status.success(), "control loop is ready");

    let output = fixture
        .command()
        .args(["usage", "--format", "json"])
        .output()
        .expect("run daemon-backed safe command");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("daemon usage JSON");
    assert_eq!(payload["schema_version"], 1);
    assert_eq!(
        payload["snapshots"].as_array().map(Vec::len),
        Some(EXPECTED_PROVIDER_IDS.len())
    );
    assert!(daemon.try_wait().expect("poll daemon").is_none());

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
    assert_removed(&fixture.socket_path());
    assert_removed(&fixture.display_socket_path());
}
