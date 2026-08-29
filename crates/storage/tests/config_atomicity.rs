//! Black-box durability and migration tests for configuration storage.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use oab_storage::atomic_file::{atomic_write, previous_path, stage_write};
use oab_storage::config::load_config_bytes;
use oab_storage::lock::ExclusiveLock;
use oab_storage::migrations::{
    CURRENT_SCHEMA_VERSION, MAX_CONFIG_BYTES, MigrationError, detect_schema_version, migrate,
    migrate_to_current,
};

static NEXT_TEST_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Debug)]
struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir();
        for _ in 0..128 {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let candidate = base.join(format!(
                "omarchy-ai-bar-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))
                        .expect("private test directory permissions");
                    return Self(candidate);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create test directory: {error}"),
            }
        }
        panic!("could not allocate a unique test directory");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assert_private_regular(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("managed file metadata");
    assert!(metadata.is_file(), "{} must be regular", path.display());
    assert_eq!(metadata.mode() & 0o777, 0o600, "{} mode", path.display());
    assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
}

fn assert_no_temporary_files(directory: &Path) {
    let residue = fs::read_dir(directory)
        .expect("read test directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| name.to_string_lossy().contains(".oab-"))
        .collect::<Vec<_>>();
    assert!(residue.is_empty(), "temporary residue: {residue:?}");
}

#[test]
fn atomic_replacement_is_private_and_preserves_one_predecessor() {
    let directory = TestDirectory::new("replace");
    let target = directory.path().join("config.json");

    fs::write(&target, b"old").expect("seed config");
    atomic_write(&target, b"new").expect("replace config");

    assert_eq!(fs::read(&target).expect("current config"), b"new");
    let previous = previous_path(&target).expect("previous path");
    assert_eq!(fs::read(&previous).expect("previous config"), b"old");
    assert_private_regular(&target);
    assert_private_regular(&previous);
    assert_private_regular(&directory.path().join("config.json.lock"));
    assert_no_temporary_files(directory.path());

    atomic_write(&target, b"newer").expect("second replacement");
    assert_eq!(fs::read(&target).expect("newest config"), b"newer");
    assert_eq!(fs::read(&previous).expect("new previous config"), b"new");
    assert_no_temporary_files(directory.path());
}

#[test]
fn a_stale_predecessor_is_made_private_even_when_current_is_absent() {
    let directory = TestDirectory::new("stale-previous");
    let target = directory.path().join("config.json");
    let previous = previous_path(&target).expect("previous path");
    fs::write(&previous, b"recoverable").expect("stale predecessor");
    fs::set_permissions(&previous, fs::Permissions::from_mode(0o644))
        .expect("seed permissive predecessor");

    atomic_write(&target, b"first-current").expect("first current write");

    assert_eq!(fs::read(&target).expect("new current"), b"first-current");
    assert_eq!(
        fs::read(&previous).expect("stale predecessor retained"),
        b"recoverable"
    );
    assert_private_regular(&target);
    assert_private_regular(&previous);
    assert_no_temporary_files(directory.path());
}

#[test]
fn prepared_write_is_a_real_precommit_interruption_seam() {
    let directory = TestDirectory::new("interruption");
    let target = directory.path().join("config.json");
    atomic_write(&target, b"committed").expect("initial commit");

    let prepared = stage_write(&target, b"interrupted")
        .expect("stage")
        .prepare()
        .expect("prepare predecessor");

    assert_eq!(
        fs::read(&target).expect("current during failpoint"),
        b"committed"
    );
    assert_eq!(
        fs::read(previous_path(&target).expect("previous path")).expect("recoverable predecessor"),
        b"committed"
    );
    let current_metadata = fs::metadata(&target).expect("current metadata");
    let previous_metadata =
        fs::metadata(previous_path(&target).expect("previous path")).expect("previous metadata");
    assert_eq!(current_metadata.dev(), previous_metadata.dev());
    assert_eq!(current_metadata.ino(), previous_metadata.ino());
    drop(prepared); // Models interruption after predecessor publication, before commit.

    assert_eq!(
        fs::read(&target).expect("current after interruption"),
        b"committed"
    );
    assert_eq!(
        fs::read(previous_path(&target).expect("previous path"))
            .expect("previous after interruption"),
        b"committed"
    );
    atomic_write(&target, b"recovered-write").expect("write after interrupted preparation");
    assert_eq!(
        fs::read(&target).expect("current after recovery"),
        b"recovered-write"
    );
    assert_eq!(
        fs::read(previous_path(&target).expect("previous path")).expect("previous after recovery"),
        b"committed"
    );
    assert_no_temporary_files(directory.path());
}

#[test]
fn staging_or_prepare_errors_leave_no_temporary_residue() {
    let directory = TestDirectory::new("cleanup");
    let target = directory.path().join("config.json");
    atomic_write(&target, b"old").expect("initial commit");

    let staged = stage_write(&target, b"new").expect("stage");
    let previous = previous_path(&target).expect("previous path");
    if previous.exists() {
        fs::remove_file(&previous).expect("remove old predecessor");
    }
    fs::create_dir(&previous).expect("hostile predecessor directory");
    assert!(staged.prepare().is_err());

    assert_eq!(fs::read(&target).expect("unchanged current"), b"old");
    assert_no_temporary_files(directory.path());
}

#[test]
fn exclusive_lock_and_atomic_writers_serialize_without_partial_documents() {
    let directory = TestDirectory::new("concurrency");
    let target = directory.path().join("config.json");
    atomic_write(&target, b"seed").expect("seed config");

    let staged = stage_write(&target, b"held").expect("stage while holding the lock");
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let blocked_target = target.clone();
    let blocked_writer = thread::spawn(move || {
        started_tx.send(()).expect("announce writer");
        let result = atomic_write(&blocked_target, b"after-lock");
        done_tx.send(result).expect("return writer result");
    });
    started_rx.recv().expect("writer started");
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    drop(staged);
    done_rx
        .recv()
        .expect("writer completed")
        .expect("writer succeeded");
    blocked_writer.join().expect("writer did not panic");

    let payloads = (0..12)
        .map(|index| {
            format!(
                "{{\"writer\":{index},\"padding\":\"{}\"}}",
                "x".repeat(4096)
            )
        })
        .collect::<Vec<_>>();
    thread::scope(|scope| {
        for payload in &payloads {
            let path = &target;
            scope.spawn(move || {
                for _ in 0..8 {
                    atomic_write(path, payload.as_bytes()).expect("concurrent atomic write");
                }
            });
        }
    });

    let current = fs::read(&target).expect("current payload");
    let previous =
        fs::read(previous_path(&target).expect("previous path")).expect("previous payload");
    assert!(payloads.iter().any(|payload| payload.as_bytes() == current));
    assert!(
        payloads
            .iter()
            .any(|payload| payload.as_bytes() == previous)
    );
    assert_no_temporary_files(directory.path());
}

#[test]
fn direct_raii_lock_blocks_a_second_holder_until_drop() {
    let directory = TestDirectory::new("lock");
    let path = directory.path().join("manual.lock");
    let first = ExclusiveLock::acquire(&path).expect("first lock");
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let second_path = path.clone();
    let second = thread::spawn(move || {
        started_tx.send(()).expect("announce second holder");
        let result = ExclusiveLock::acquire(&second_path).map(drop);
        acquired_tx.send(result).expect("return lock result");
    });
    started_rx.recv().expect("second holder started");
    assert!(matches!(
        acquired_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    drop(first);
    acquired_rx
        .recv()
        .expect("second holder completed")
        .expect("second holder acquired lock");
    second.join().expect("second holder did not panic");
}

#[test]
fn unsafe_paths_symlinks_and_nonregular_files_are_rejected() {
    let directory = TestDirectory::new("unsafe");
    let target = directory.path().join("config.json");

    assert!(stage_write(Path::new("relative/config.json"), b"x").is_err());
    assert!(stage_write(directory.path().join("../escape.json"), b"x").is_err());

    let unsafe_parent = directory.path().join("writable");
    fs::create_dir(&unsafe_parent).expect("unsafe parent");
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).expect("unsafe mode");
    assert!(stage_write(unsafe_parent.join("config.json"), b"x").is_err());

    let actual_parent = directory.path().join("actual");
    fs::create_dir(&actual_parent).expect("actual parent");
    fs::set_permissions(&actual_parent, fs::Permissions::from_mode(0o700)).expect("actual mode");
    let linked_parent = directory.path().join("linked");
    symlink(&actual_parent, &linked_parent).expect("parent symlink");
    assert!(stage_write(linked_parent.join("config.json"), b"x").is_err());

    fs::create_dir(&target).expect("directory target");
    assert!(stage_write(&target, b"x").is_err());
    fs::remove_dir(&target).expect("remove directory target");

    let link_destination = directory.path().join("destination");
    fs::write(&link_destination, b"do not touch").expect("link destination");
    symlink(&link_destination, &target).expect("target symlink");
    assert!(stage_write(&target, b"x").is_err());
    assert_eq!(
        fs::read(&link_destination).expect("destination unchanged"),
        b"do not touch"
    );
}

#[test]
fn hostile_lock_and_predecessor_entries_are_rejected() {
    let directory = TestDirectory::new("hostile-auxiliary");
    let target = directory.path().join("config.json");
    let destination = directory.path().join("destination");
    fs::write(&destination, b"untouched").expect("destination");
    symlink(&destination, directory.path().join("config.json.lock")).expect("lock symlink");
    assert!(stage_write(&target, b"new").is_err());
    assert_eq!(
        fs::read(&destination).expect("lock destination"),
        b"untouched"
    );

    fs::remove_file(directory.path().join("config.json.lock")).expect("remove lock symlink");
    fs::write(&target, b"current").expect("current");
    symlink(&destination, previous_path(&target).expect("previous path"))
        .expect("previous symlink");
    assert!(stage_write(&target, b"new").is_err());
    assert_eq!(fs::read(&target).expect("current unchanged"), b"current");
    assert_eq!(
        fs::read(&destination).expect("previous destination"),
        b"untouched"
    );
    assert_no_temporary_files(directory.path());
}

#[test]
fn current_schema_is_detected_and_passed_through_byte_for_byte() {
    let bytes = br#"{
  "schema_version": 1,
  "providers": [{"id":"codex","instance_id":"default","enabled":true,"accounts":[{"id":"account-one","enabled":true}]}],
  "provider_order": ["codex"]
}"#;
    assert_eq!(
        detect_schema_version(bytes).expect("detect v1"),
        CURRENT_SCHEMA_VERSION
    );
    let migration = migrate(bytes).expect("pass through current schema");
    assert!(!migration.was_migrated());
    assert_eq!(migration.original_bytes(), bytes);
    assert_eq!(migration.current_bytes(), bytes);
    load_config_bytes(migration.current_bytes()).expect("current config accepted by typed loader");
}

#[test]
fn current_schema_pass_through_still_enforces_typed_and_secret_validation() {
    let secret_canary = "do-not-echo-secret-canary";
    let with_secret = format!(
        "{{\"schema_version\":1,\"providers\":[],\"provider_order\":[],\"api_key\":\"{secret_canary}\"}}"
    );
    let error = migrate(with_secret.as_bytes()).expect_err("secret field must be rejected");
    assert!(matches!(error, MigrationError::InvalidCurrent));
    assert!(!error.to_string().contains(secret_canary));

    let invalid_current = br#"{"schema_version":1,"providers":[]}"#;
    assert!(matches!(
        migrate(invalid_current),
        Err(MigrationError::InvalidCurrent)
    ));
}

#[test]
fn migration_debug_output_is_redacted_to_safe_metadata() {
    let canary = "debug-private-canary";
    let legacy =
        format!("{{\"schema_version\":0,\"provider\":\"codex\",\"account\":\"{canary}\"}}");
    let migration = migrate(legacy.as_bytes()).expect("migrate canary document");
    let debug = format!("{migration:?}");

    assert!(!debug.contains(canary));
    assert!(!debug.contains("codex"));
    assert!(!debug.contains("schema_version"));
    assert!(debug.contains("from_version: 0"));
    assert!(debug.contains("original_len:"));
    assert!(debug.contains("current_len:"));
    assert!(debug.contains("was_migrated: true"));
}

#[test]
fn legacy_v0_migrates_to_valid_canonical_v1_and_preserves_rollback_bytes() {
    let legacy = br#"{ "schema_version": 0, "provider": "codex", "account": "account-one" }"#;
    assert_eq!(detect_schema_version(legacy).expect("detect v0"), 0);

    let migration = migrate(legacy).expect("migrate v0");
    assert!(migration.was_migrated());
    assert_eq!(migration.original_bytes(), legacy);
    assert_eq!(
        migration.current_bytes(),
        br#"{"schema_version":1,"providers":[{"id":"codex","instance_id":"default","enabled":true,"accounts":[{"id":"account-one","enabled":true}]}],"provider_order":["codex"]}"#
    );
    load_config_bytes(migration.current_bytes()).expect("migrated config accepted by typed loader");
    assert_eq!(
        migrate_to_current(legacy).expect("convenience migration"),
        migration.current_bytes()
    );

    let versionless = br#"{"provider":"codex","account":"account-two"}"#;
    assert_eq!(
        detect_schema_version(versionless).expect("detect versionless v0"),
        0
    );
    load_config_bytes(&migrate_to_current(versionless).expect("migrate versionless v0"))
        .expect("versionless migration accepted");

    assert_eq!(
        CURRENT_SCHEMA_VERSION,
        oab_storage::config::CURRENT_SCHEMA_VERSION
    );
    assert_eq!(MAX_CONFIG_BYTES, oab_storage::config::MAX_CONFIG_BYTES);

    let boundary_account = "1".repeat(160);
    let boundary_legacy = format!(
        "{{\"schema_version\":0,\"provider\":\"codex\",\"account\":\"{boundary_account}\"}}"
    );
    let boundary_current =
        migrate_to_current(boundary_legacy.as_bytes()).expect("160-byte digit-first account");
    load_config_bytes(&boundary_current).expect("boundary account accepted by typed loader");

    let oversized_account = "1".repeat(161);
    let oversized_legacy = format!(
        "{{\"schema_version\":0,\"provider\":\"codex\",\"account\":\"{oversized_account}\"}}"
    );
    assert!(migrate(oversized_legacy.as_bytes()).is_err());
}

#[test]
fn migration_rejects_future_unknown_malformed_and_unbounded_documents() {
    assert!(matches!(
        detect_schema_version(br#"{"schema_version":2}"#),
        Err(MigrationError::FutureVersion {
            found: 2,
            current: CURRENT_SCHEMA_VERSION
        })
    ));
    assert!(matches!(
        detect_schema_version(br#"{"schema_version":null}"#),
        Err(MigrationError::MalformedVersion)
    ));

    for malformed in [
        br#"{"schema_version":2}"#.as_slice(),
        br#"{"schema_version":-1}"#,
        br#"{"schema_version":1.5}"#,
        br#"{"schema_version":"1"}"#,
        br#"{"schema_version":null}"#,
        br#"{"schema_version":1,"schema_version":0,"provider":"codex","account":"x"}"#,
        br"[]",
        br"not-json",
    ] {
        assert!(
            migrate(malformed).is_err(),
            "accepted {}",
            String::from_utf8_lossy(malformed)
        );
    }

    assert!(migrate(br#"{"schema_version":0,"provider":"claude","account":"x"}"#).is_err());
    assert!(migrate(br#"{"schema_version":0,"provider":"codex","account":""}"#).is_err());
    assert!(
        migrate(br#"{"schema_version":0,"provider":"codex","account":"Account-One"}"#).is_err()
    );
    assert!(migrate(br#"{"schema_version":0,"provider":"codex","account":"a..b"}"#).is_err());
    assert!(
        migrate(br#"{"schema_version":0,"provider":"codex","account":"x","secret":"no"}"#).is_err()
    );

    let oversized = vec![b' '; MAX_CONFIG_BYTES + 1];
    assert!(migrate(&oversized).is_err());
}

#[test]
fn previous_path_requires_the_same_safe_absolute_shape_as_a_target() {
    assert!(previous_path(Path::new("relative.json")).is_err());
    assert!(previous_path(Path::new("/tmp/../escape.json")).is_err());
    assert!(previous_path(Path::new("/tmp/./config.json")).is_err());
    assert!(previous_path(Path::new("//tmp/config.json")).is_err());
    assert!(previous_path(Path::new("/tmp/config.json/")).is_err());
    assert!(previous_path(Path::new("/tmp/config\n.json")).is_err());
    assert_eq!(
        previous_path(Path::new("/tmp/config.json")).expect("valid previous path"),
        Path::new("/tmp/config.json.previous")
    );
}
