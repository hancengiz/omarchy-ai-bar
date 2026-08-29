use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_ipc::permissions::{
    PRIVATE_SOCKET_MODE, PermissionError, RUNTIME_DIRECTORY_MODE, RuntimeDirectory, effective_uid,
    validate_private_socket,
};
use oab_ipc::socket::{DisplaySocket, DisplaySocketError};

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[test]
fn runtime_directory_is_created_with_exact_private_permissions() {
    let temporary = TestDirectory::new();
    let runtime_path = temporary.path().join("runtime");

    let runtime = RuntimeDirectory::prepare(&runtime_path).expect("prepare runtime directory");
    let metadata = fs::symlink_metadata(runtime.path()).expect("inspect runtime directory");

    assert!(metadata.is_dir());
    assert_eq!(metadata.uid(), effective_uid());
    assert_eq!(metadata.mode() & 0o7777, RUNTIME_DIRECTORY_MODE);
}

#[test]
fn runtime_directory_symlinks_are_rejected() {
    let temporary = TestDirectory::new();
    let actual_path = temporary.path().join("actual");
    create_private_directory(&actual_path);
    let symlink_path = temporary.path().join("runtime");
    symlink(&actual_path, &symlink_path).expect("create runtime symlink");

    let error = RuntimeDirectory::prepare(&symlink_path).expect_err("reject runtime symlink");

    assert!(matches!(error, PermissionError::RuntimeDirectorySymlink));
}

#[test]
fn runtime_directory_with_wrong_mode_is_rejected() {
    let temporary = TestDirectory::new();
    let runtime_path = temporary.path().join("runtime");
    DirBuilder::new()
        .mode(0o755)
        .create(&runtime_path)
        .expect("create permissive runtime directory");
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o755))
        .expect("set permissive mode");

    let error = RuntimeDirectory::prepare(&runtime_path).expect_err("reject unsafe mode");

    assert!(matches!(error, PermissionError::RuntimeModeMismatch { .. }));
}

#[test]
fn runtime_directory_owner_is_checked_against_effective_context() {
    let temporary = TestDirectory::new();
    let runtime_path = temporary.path().join("runtime");
    create_private_directory(&runtime_path);
    let wrong_uid = distinct_uid(effective_uid());

    let error = RuntimeDirectory::prepare_for_uid(&runtime_path, wrong_uid)
        .expect_err("reject unexpected owner");

    assert!(matches!(
        error,
        PermissionError::RuntimeOwnerMismatch { .. }
    ));
}

#[test]
fn display_socket_has_exact_private_permissions_and_is_cleaned_up() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();

    let socket = DisplaySocket::bind(&socket_path).expect("bind display socket");
    let metadata = fs::symlink_metadata(&socket_path).expect("inspect display socket");

    assert_eq!(metadata.uid(), effective_uid());
    assert_eq!(metadata.mode() & 0o7777, PRIVATE_SOCKET_MODE);
    validate_private_socket(&socket_path, effective_uid()).expect("validate display socket");

    drop(socket);
    assert!(!socket_path.exists());
}

#[test]
fn binding_cannot_override_the_process_effective_uid() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();

    let error = DisplaySocket::bind_for_uid(&socket_path, distinct_uid(effective_uid()))
        .expect_err("reject non-effective owner UID");

    assert!(matches!(error, DisplaySocketError::EffectiveUidMismatch));
    assert!(!temporary.runtime_path().exists());
}

#[test]
fn socket_owner_and_mode_validation_is_exact() {
    let temporary = TestDirectory::new();
    create_private_directory(&temporary.runtime_path());
    let socket_path = temporary.socket_path();
    let listener = UnixListener::bind(&socket_path).expect("bind test socket");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .expect("set unsafe socket mode");

    let mode_error = validate_private_socket(&socket_path, effective_uid())
        .expect_err("reject unsafe socket mode");
    let owner_error = validate_private_socket(&socket_path, distinct_uid(effective_uid()))
        .expect_err("reject wrong socket owner");

    assert!(matches!(
        mode_error,
        PermissionError::SocketModeMismatch { .. }
    ));
    assert!(matches!(
        owner_error,
        PermissionError::SocketOwnerMismatch { .. }
    ));
    drop(listener);
}

#[test]
fn socket_path_symlinks_are_rejected_without_removal() {
    let temporary = TestDirectory::new();
    let runtime_path = temporary.runtime_path();
    create_private_directory(&runtime_path);
    let target_path = runtime_path.join("target");
    File::create(&target_path).expect("create target file");
    let socket_path = temporary.socket_path();
    symlink(&target_path, &socket_path).expect("create socket symlink");

    let error = DisplaySocket::bind(&socket_path).expect_err("reject socket symlink");

    assert!(matches!(
        error,
        DisplaySocketError::Permissions(PermissionError::SocketPathSymlink)
    ));
    assert!(
        fs::symlink_metadata(&socket_path)
            .expect("symlink remains")
            .file_type()
            .is_symlink()
    );
    assert!(target_path.exists());
}

#[test]
fn non_socket_stale_targets_are_rejected_without_removal() {
    let temporary = TestDirectory::new();
    create_private_directory(&temporary.runtime_path());
    let socket_path = temporary.socket_path();
    File::create(&socket_path).expect("create non-socket target");

    let error = DisplaySocket::bind(&socket_path).expect_err("reject non-socket target");

    assert!(matches!(
        error,
        DisplaySocketError::Permissions(PermissionError::SocketPathNotSocket)
    ));
    assert!(socket_path.is_file());
}

#[test]
fn errors_do_not_echo_sensitive_socket_paths() {
    let temporary = TestDirectory::new();
    create_private_directory(&temporary.runtime_path());
    let sensitive_name = "sk-proj-path-canary.sock";
    let socket_path = temporary.runtime_path().join(sensitive_name);
    File::create(&socket_path).expect("create non-socket target");

    let error = DisplaySocket::bind(&socket_path).expect_err("reject non-socket target");

    assert!(!error.to_string().contains(sensitive_name));
}

#[test]
fn an_owned_stale_unix_stream_socket_is_replaced() {
    let temporary = TestDirectory::new();
    create_private_directory(&temporary.runtime_path());
    let socket_path = temporary.socket_path();
    let stale = UnixListener::bind(&socket_path).expect("bind old listener");
    drop(stale);

    let replacement = DisplaySocket::bind(&socket_path).expect("replace stale socket");

    validate_private_socket(&socket_path, effective_uid()).expect("validate replacement");
    drop(replacement);
    assert!(!socket_path.exists());
}

#[test]
fn an_active_unix_stream_socket_is_never_replaced() {
    let temporary = TestDirectory::new();
    create_private_directory(&temporary.runtime_path());
    let socket_path = temporary.socket_path();
    let active = UnixListener::bind(&socket_path).expect("bind active listener");

    let error = DisplaySocket::bind(&socket_path).expect_err("reject active listener");

    assert!(matches!(error, DisplaySocketError::AlreadyActive));
    assert!(socket_path.exists());
    drop(active);
}

#[test]
fn cleanup_guard_does_not_unlink_a_replacement_inode() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let guarded = DisplaySocket::bind(&socket_path).expect("bind guarded listener");

    fs::remove_file(&socket_path).expect("unlink guarded pathname");
    let replacement = UnixListener::bind(&socket_path).expect("bind replacement listener");
    let replacement_inode = fs::symlink_metadata(&socket_path)
        .expect("inspect replacement")
        .ino();

    drop(guarded);

    assert_eq!(
        fs::symlink_metadata(&socket_path)
            .expect("replacement remains")
            .ino(),
        replacement_inode
    );
    drop(replacement);
}

#[test]
fn endpoint_lifecycle_lock_serializes_cooperating_binders() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let first = DisplaySocket::bind(&socket_path).expect("bind first listener");

    let error = DisplaySocket::bind(&socket_path).expect_err("reject lock contender");
    assert!(matches!(
        error,
        DisplaySocketError::Permissions(PermissionError::EndpointLockBusy)
    ));

    drop(first);
    let second = DisplaySocket::bind(&socket_path).expect("reuse persistent lock file");
    drop(second);
}

#[test]
fn endpoint_lock_symlinks_and_unsafe_modes_are_rejected() {
    let symlink_fixture = TestDirectory::new();
    let runtime_path = symlink_fixture.runtime_path();
    create_private_directory(&runtime_path);
    let target_path = runtime_path.join("lock-target");
    File::create(&target_path).expect("create lock target");
    let lock_path = runtime_path.join(".display.sock.lock");
    symlink(&target_path, &lock_path).expect("create lock symlink");

    let symlink_error = DisplaySocket::bind(symlink_fixture.socket_path())
        .expect_err("reject endpoint lock symlink");
    assert!(matches!(
        symlink_error,
        DisplaySocketError::Permissions(PermissionError::EndpointLockSymlink)
    ));
    assert!(target_path.exists());

    let mode_fixture = TestDirectory::new();
    let runtime_path = mode_fixture.runtime_path();
    create_private_directory(&runtime_path);
    let lock_path = runtime_path.join(".display.sock.lock");
    File::create(&lock_path).expect("create endpoint lock");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644))
        .expect("make endpoint lock unsafe");

    let mode_error =
        DisplaySocket::bind(mode_fixture.socket_path()).expect_err("reject unsafe endpoint lock");
    assert!(matches!(
        mode_error,
        DisplaySocketError::Permissions(PermissionError::EndpointLockModeMismatch)
    ));

    let type_fixture = TestDirectory::new();
    let runtime_path = type_fixture.runtime_path();
    create_private_directory(&runtime_path);
    fs::create_dir(runtime_path.join(".display.sock.lock"))
        .expect("create directory at endpoint lock path");

    let type_error =
        DisplaySocket::bind(type_fixture.socket_path()).expect_err("reject lock directory");
    assert!(matches!(
        type_error,
        DisplaySocketError::Permissions(PermissionError::EndpointLockNotRegular)
    ));

    let hardlink_fixture = TestDirectory::new();
    let runtime_path = hardlink_fixture.runtime_path();
    create_private_directory(&runtime_path);
    let lock_target = runtime_path.join("lock-hardlink-target");
    File::create(&lock_target).expect("create hard-link target");
    fs::set_permissions(&lock_target, fs::Permissions::from_mode(0o600))
        .expect("secure hard-link target");
    fs::hard_link(&lock_target, runtime_path.join(".display.sock.lock"))
        .expect("create hard-linked lock");

    let hardlink_error = DisplaySocket::bind(hardlink_fixture.socket_path())
        .expect_err("reject multiply-linked endpoint lock");
    assert!(matches!(
        hardlink_error,
        DisplaySocketError::Permissions(PermissionError::EndpointLockNotRegular)
    ));
}

#[test]
fn pinned_cleanup_ignores_a_replacement_at_the_original_parent_path() {
    let temporary = TestDirectory::new();
    let runtime_path = temporary.runtime_path();
    let socket_path = temporary.socket_path();
    let guarded = DisplaySocket::bind(&socket_path).expect("bind guarded listener");
    let moved_runtime = temporary.path().join("moved-runtime");
    fs::rename(&runtime_path, &moved_runtime).expect("move pinned runtime directory");
    create_private_directory(&runtime_path);
    let replacement = UnixListener::bind(&socket_path).expect("bind replacement listener");
    fs::set_permissions(
        &socket_path,
        fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
    )
    .expect("secure replacement listener");
    let replacement_inode = fs::symlink_metadata(&socket_path)
        .expect("inspect replacement")
        .ino();

    drop(guarded);

    assert_eq!(
        fs::symlink_metadata(&socket_path)
            .expect("replacement remains")
            .ino(),
        replacement_inode
    );
    assert!(!moved_runtime.join("display.sock").exists());
    drop(replacement);
}

#[test]
fn public_socket_path_must_fit_the_unix_address_limit() {
    let temporary = TestDirectory::new();
    let oversized_name = format!("{}.sock", "x".repeat(180));
    let oversized_path = temporary.path().join(oversized_name);

    let error = DisplaySocket::bind(&oversized_path).expect_err("reject oversized address");

    assert!(matches!(error, DisplaySocketError::InvalidPath));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn accepted_peer_must_match_the_expected_uid() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind display socket");
    let client = UnixStream::connect(&socket_path).expect("connect client");

    let accepted = listener.accept_verified().expect("authenticate peer");

    assert_eq!(accepted.peer_uid(), effective_uid());
    drop((accepted, client));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn peer_uid_mismatch_fails_closed() {
    let temporary = TestDirectory::new();
    let socket_path = temporary.socket_path();
    let listener = DisplaySocket::bind(&socket_path).expect("bind display socket");
    let client = UnixStream::connect(&socket_path).expect("connect client");
    let wrong_uid = distinct_uid(effective_uid());

    let error = listener
        .accept_verified_for_uid(wrong_uid)
        .expect_err("reject wrong UID");

    assert!(matches!(
        error,
        DisplaySocketError::PeerUidMismatch { expected, actual }
            if expected == wrong_uid && actual == effective_uid()
    ));
    drop(client);
}

fn distinct_uid(uid: u32) -> u32 {
    if uid == u32::MAX { uid - 1 } else { uid + 1 }
}

fn create_private_directory(path: &Path) {
    DirBuilder::new()
        .mode(RUNTIME_DIRECTORY_MODE)
        .create(path)
        .expect("create private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(RUNTIME_DIRECTORY_MODE))
        .expect("set private directory mode");
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let base = std::env::temp_dir();
        for _ in 0..128 {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = base.join(format!(
                "omarchy-ai-bar-ipc-test-{}-{sequence}",
                std::process::id()
            ));
            match DirBuilder::new()
                .mode(RUNTIME_DIRECTORY_MODE)
                .create(&candidate)
            {
                Ok(()) => {
                    fs::set_permissions(
                        &candidate,
                        fs::Permissions::from_mode(RUNTIME_DIRECTORY_MODE),
                    )
                    .expect("secure test directory");
                    return Self { path: candidate };
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create test directory: {error}"),
            }
        }
        panic!("could not allocate a unique test directory");
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn runtime_path(&self) -> PathBuf {
        self.path.join("runtime")
    }

    fn socket_path(&self) -> PathBuf {
        self.runtime_path().join("display.sock")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
