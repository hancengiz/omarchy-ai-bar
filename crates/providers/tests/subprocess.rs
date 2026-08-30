use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use oab_providers::subprocess::{StderrClassifier, SubprocessError, SubprocessRequest};
use tokio_util::sync::CancellationToken;

const STDOUT_LIMIT: usize = 16 * 1024;
const STDERR_LIMIT: usize = 16 * 1024;

fn request<I, S>(
    executable: impl Into<PathBuf>,
    arguments: I,
    timeout: Duration,
) -> SubprocessRequest
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    SubprocessRequest::new(executable, arguments, timeout, STDOUT_LIMIT, STDERR_LIMIT)
        .expect("valid subprocess request")
}

#[tokio::test]
async fn passes_exact_argv_without_interpolation_and_captures_stdout() {
    let invocation = request(
        "/usr/bin/printf",
        ["%s|%s", "alpha beta", "$HOME; echo interpolated"],
        Duration::from_secs(1),
    );

    let output = invocation
        .run(&CancellationToken::new())
        .await
        .expect("printf succeeds");

    let request_debug = format!("{invocation:?}");
    assert!(!request_debug.contains("alpha beta"));
    assert!(!request_debug.contains("$HOME; echo interpolated"));
    assert_eq!(output.stdout(), b"alpha beta|$HOME; echo interpolated");
    assert!(!format!("{output:?}").contains("alpha beta"));
    assert_eq!(output.into_stdout(), b"alpha beta|$HOME; echo interpolated");
}

#[tokio::test]
async fn closes_stdin_instead_of_inheriting_it() {
    let invocation = request(
        "/bin/sh",
        ["-c", "if read value; then exit 9; else printf closed; fi"],
        Duration::from_secs(1),
    );

    let output = invocation
        .run(&CancellationToken::new())
        .await
        .expect("closed stdin reaches EOF");

    assert_eq!(output.stdout(), b"closed");
}

#[tokio::test]
async fn nonzero_status_and_debug_output_do_not_expose_stderr_or_environment_values() {
    let secret = "fixture-secret-that-must-not-leak";
    let invocation = request(
        "/bin/sh",
        ["-c", "printf '%s' \"$OAB_SUBPROCESS_SECRET\" >&2; exit 17"],
        Duration::from_secs(1),
    )
    .with_cleared_environment()
    .with_environment("OAB_SUBPROCESS_SECRET", secret)
    .expect("valid environment change")
    .without_environment("OAB_UNUSED")
    .expect("valid environment removal");

    assert!(!format!("{invocation:?}").contains(secret));
    let error = invocation
        .run(&CancellationToken::new())
        .await
        .expect_err("nonzero status fails");

    assert_eq!(
        error,
        SubprocessError::NonZero {
            code: Some(17),
            stderr_tag: None,
        }
    );
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));
}

#[tokio::test]
async fn classifies_sso_login_and_expired_stderr_case_insensitively() {
    let sso_classifier =
        StderrClassifier::ascii_case_insensitive([(7, "run aws sso login"), (9, "expired")])
            .expect("valid stderr classifier");
    let sso = request(
        "/bin/sh",
        [
            "-c",
            "printf 'Credentials EXPIRED; RUN AWS SSO LOGIN now' >&2; exit 2",
        ],
        Duration::from_secs(1),
    )
    .with_stderr_classifier(sso_classifier);

    assert_eq!(
        sso.run(&CancellationToken::new()).await,
        Err(SubprocessError::NonZero {
            code: Some(2),
            stderr_tag: Some(7),
        })
    );

    let expired_classifier = StderrClassifier::ascii_case_insensitive([(11, "token has expired")])
        .expect("valid stderr classifier");
    let expired = request(
        "/bin/sh",
        ["-c", "printf 'TOKEN HAS EXPIRED' >&2; exit 4"],
        Duration::from_secs(1),
    )
    .with_stderr_classifier(expired_classifier);

    assert_eq!(
        expired.run(&CancellationToken::new()).await,
        Err(SubprocessError::NonZero {
            code: Some(4),
            stderr_tag: Some(11),
        })
    );
}

#[tokio::test]
async fn empty_stderr_has_no_classification_and_classifier_debug_is_redacted() {
    let secret_needle = "fixture classifier needle secret";
    let classifier = StderrClassifier::ascii_case_insensitive([(3, secret_needle)])
        .expect("valid stderr classifier");
    assert!(!format!("{classifier:?}").contains(secret_needle));
    let invocation = request("/bin/sh", ["-c", "exit 6"], Duration::from_secs(1))
        .with_stderr_classifier(classifier);
    assert!(!format!("{invocation:?}").contains(secret_needle));

    assert_eq!(
        invocation.run(&CancellationToken::new()).await,
        Err(SubprocessError::NonZero {
            code: Some(6),
            stderr_tag: None,
        })
    );
}

#[tokio::test]
async fn rejects_standard_output_above_the_configured_limit() {
    let invocation = SubprocessRequest::new(
        "/usr/bin/printf",
        ["%s", &"x".repeat(65)],
        Duration::from_secs(1),
        64,
        STDERR_LIMIT,
    )
    .expect("valid subprocess request");

    assert_eq!(
        invocation.run(&CancellationToken::new()).await,
        Err(SubprocessError::StdoutTooLarge)
    );
}

#[tokio::test]
async fn rejects_standard_error_above_the_configured_limit() {
    let oversized = "x".repeat(65);
    let invocation = SubprocessRequest::new(
        "/bin/sh",
        [
            "-c",
            "printf '%s' \"$1\" >&2",
            "subprocess-test",
            &oversized,
        ],
        Duration::from_secs(1),
        STDOUT_LIMIT,
        64,
    )
    .expect("valid subprocess request");

    assert_eq!(
        invocation.run(&CancellationToken::new()).await,
        Err(SubprocessError::StderrTooLarge)
    );
}

#[tokio::test]
async fn drains_large_standard_output_and_error_streams_concurrently() {
    let invocation = SubprocessRequest::new(
        "/bin/sh",
        [
            "-c",
            "/usr/bin/head -c 131072 /dev/zero >&2 & /usr/bin/head -c 131072 /dev/zero; wait",
        ],
        Duration::from_secs(2),
        256 * 1024,
        256 * 1024,
    )
    .expect("valid subprocess request");

    let output = invocation
        .run(&CancellationToken::new())
        .await
        .expect("both full pipes are drained");

    assert_eq!(output.stdout().len(), 131_072);
    assert!(output.stdout().iter().all(|byte| *byte == 0));
}

#[tokio::test]
async fn timeout_terminates_the_process_promptly() {
    let invocation = request("/usr/bin/sleep", ["30"], Duration::from_millis(40));
    let started = Instant::now();

    assert_eq!(
        invocation.run(&CancellationToken::new()).await,
        Err(SubprocessError::Timeout)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn cancellation_terminates_the_process_promptly() {
    let invocation = request("/usr/bin/sleep", ["30"], Duration::from_secs(10));
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        trigger.cancel();
    });
    let started = Instant::now();

    assert_eq!(
        invocation.run(&cancellation).await,
        Err(SubprocessError::Cancelled)
    );
    cancel_task.await.expect("cancellation task");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancellation_terminates_descendants_in_the_child_process_group() {
    let pid_file = unique_temp_path();
    let pid_file_argument = pid_file.as_os_str().to_os_string();
    let invocation = request(
        "/bin/sh",
        [
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(
                "sleep 30 & descendant=$!; printf '%s' \"$descendant\" > \"$1\"; wait",
            ),
            std::ffi::OsString::from("subprocess-test"),
            pid_file_argument,
        ],
        Duration::from_secs(10),
    );
    let cancellation = CancellationToken::new();
    let trigger = cancellation.clone();
    let path_for_trigger = pid_file.clone();
    let cancel_task = tokio::spawn(async move {
        wait_for_file(&path_for_trigger).await;
        trigger.cancel();
    });

    assert_eq!(
        invocation.run(&cancellation).await,
        Err(SubprocessError::Cancelled)
    );
    cancel_task.await.expect("cancellation task");

    let descendant = std::fs::read_to_string(&pid_file)
        .expect("descendant pid file")
        .trim()
        .parse::<u32>()
        .expect("numeric descendant pid");
    wait_for_process_to_stop(descendant).await;
    let _ = std::fs::remove_file(pid_file);
}

#[test]
fn invocation_and_environment_bounds_are_validated() {
    assert!(matches!(
        SubprocessRequest::new("", std::iter::empty::<&str>(), Duration::from_secs(1), 1, 1,),
        Err(SubprocessError::InvalidConfiguration)
    ));
    assert!(matches!(
        SubprocessRequest::new("printf", ["x"], Duration::from_secs(1), 1, 1,),
        Err(SubprocessError::InvalidConfiguration)
    ));
    assert!(matches!(
        SubprocessRequest::new("/usr/bin/printf", ["x"], Duration::ZERO, 1, 1,),
        Err(SubprocessError::InvalidConfiguration)
    ));
    assert!(matches!(
        request("/usr/bin/printf", ["x"], Duration::from_secs(1))
            .with_environment("INVALID=NAME", "value"),
        Err(SubprocessError::InvalidConfiguration)
    ));
    assert!(matches!(
        StderrClassifier::ascii_case_insensitive([(1, "")]),
        Err(SubprocessError::InvalidConfiguration)
    ));
    assert!(matches!(
        StderrClassifier::ascii_case_insensitive([(1, "not\nprintable")]),
        Err(SubprocessError::InvalidConfiguration)
    ));
    assert!(matches!(
        StderrClassifier::ascii_case_insensitive([(1, "é")]),
        Err(SubprocessError::InvalidConfiguration)
    ));
    assert!(matches!(
        StderrClassifier::ascii_case_insensitive((0_u8..17).map(|tag| (tag, "needle"))),
        Err(SubprocessError::InvalidConfiguration)
    ));
    let long_needle = "x".repeat(256);
    assert!(matches!(
        StderrClassifier::ascii_case_insensitive((0_u8..9).map(|tag| (tag, long_needle.as_str()))),
        Err(SubprocessError::InvalidConfiguration)
    ));
}

#[cfg(target_os = "linux")]
fn unique_temp_path() -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("oab-subprocess-{}-{id}.pid", std::process::id()))
}

#[cfg(target_os = "linux")]
async fn wait_for_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("descendant pid file appears");
}

#[cfg(target_os = "linux")]
async fn wait_for_process_to_stop(process_id: u32) {
    tokio::time::timeout(Duration::from_secs(2), async move {
        loop {
            match linux_process_state(process_id) {
                None | Some(b'Z' | b'X') => break,
                Some(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("descendant process is terminated");
}

#[cfg(target_os = "linux")]
fn linux_process_state(process_id: u32) -> Option<u8> {
    let stat = std::fs::read(format!("/proc/{process_id}/stat")).ok()?;
    let marker = stat.windows(2).rposition(|window| window == b") ")?;
    stat.get(marker + 2).copied()
}
