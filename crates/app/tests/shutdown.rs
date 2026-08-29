mod support;

use std::time::{Duration, Instant};

use support::{DaemonFixture, assert_removed, read_child_output, terminate, wait_for_exit};

#[test]
fn sigterm_performs_bounded_clean_shutdown_without_output_noise() {
    let fixture = DaemonFixture::new("shutdown");
    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);

    let activation = fixture.activate();
    assert!(activation.status.success(), "daemon control loop is ready");
    let started = Instant::now();
    terminate(&daemon);
    let status = wait_for_exit(&mut daemon);
    let elapsed = started.elapsed();
    let output = read_child_output(&mut daemon, status);

    assert!(output.status.success());
    assert!(
        elapsed < Duration::from_secs(2),
        "shutdown took {elapsed:?}"
    );
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_removed(&fixture.socket_path());
    assert_removed(&fixture.display_socket_path());
}
