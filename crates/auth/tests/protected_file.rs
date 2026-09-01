use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use oab_auth::credential_slot::CredentialSlotId;
use oab_auth::protected_file::{
    PROTECTED_FILE_NAME, ProtectedFileAcknowledgement, ProtectedFileError, ProtectedFileStore,
};
use oab_auth::secret_store::{SecretKey, SecretStore, SecretStoreError, SecretValue};
use oab_domain::{AccountKey, AccountScope, ProviderId, ProviderInstanceId};
use oab_storage::atomic_file::previous_path;

static NEXT_TEST_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Debug)]
struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        for _ in 0..128 {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let candidate = std::env::temp_dir().join(format!(
                "omarchy-ai-bar-auth-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))
                        .expect("private directory mode");
                    return Self(candidate);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create test directory: {error}"),
            }
        }
        panic!("could not allocate test directory");
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

fn acknowledged_store(path: PathBuf) -> ProtectedFileStore {
    ProtectedFileStore::open(
        path,
        ProtectedFileAcknowledgement::acknowledge_unencrypted_storage_warning(),
    )
    .expect("open acknowledged protected store")
}

#[tokio::test]
async fn persistence_is_dedicated_private_and_has_no_plaintext_predecessor() {
    let directory = TestDirectory::new("private");
    let path = directory.path().join(PROTECTED_FILE_NAME);
    let store = acknowledged_store(path.clone());
    let key = SecretKey::new("codex", "personal", "token").expect("key");

    store
        .put(
            &key,
            SecretValue::new(b"old-canary".to_vec()).expect("secret"),
        )
        .await
        .expect("initial put");
    store
        .put(
            &key,
            SecretValue::new(b"new-canary".to_vec()).expect("secret"),
        )
        .await
        .expect("replacement put");

    let metadata = fs::symlink_metadata(&path).expect("credential metadata");
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(
        fs::symlink_metadata(directory.path().join(format!("{PROTECTED_FILE_NAME}.lock")))
            .expect("lock metadata")
            .mode()
            & 0o777,
        0o600
    );
    assert!(!previous_path(&path).expect("previous path").exists());
    assert_eq!(
        store
            .get(&key)
            .await
            .expect("get")
            .expect("present")
            .expose_secret(),
        b"new-canary"
    );
}

#[test]
fn ordinary_settings_filename_is_rejected_even_with_acknowledgement() {
    let error = ProtectedFileStore::open(
        PathBuf::from("/tmp/omarchy-ai-bar/config.json"),
        ProtectedFileAcknowledgement::acknowledge_unencrypted_storage_warning(),
    )
    .expect_err("ordinary settings file must be rejected");
    assert!(matches!(error, ProtectedFileError::DedicatedNameRequired));
}

#[tokio::test]
async fn symlinks_and_extra_hard_links_are_rejected() {
    let directory = TestDirectory::new("links");
    let destination = directory.path().join("destination");
    fs::write(&destination, b"untouched").expect("destination");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).expect("destination mode");
    let path = directory.path().join(PROTECTED_FILE_NAME);
    symlink(&destination, &path).expect("credential symlink");
    let store = acknowledged_store(path.clone());
    let key = SecretKey::new("codex", "personal", "token").expect("key");
    assert!(
        store
            .put(&key, SecretValue::new(b"secret".to_vec()).expect("secret"))
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(&destination).expect("destination remains"),
        b"untouched"
    );

    fs::remove_file(&path).expect("remove symlink");
    let store = acknowledged_store(path.clone());
    store
        .put(&key, SecretValue::new(b"secret".to_vec()).expect("secret"))
        .await
        .expect("seed protected file");
    fs::hard_link(&path, directory.path().join("second-name")).expect("hard link");
    assert!(store.get(&key).await.is_err());
}

#[tokio::test]
async fn permissive_existing_file_is_not_read() {
    let directory = TestDirectory::new("mode");
    let path = directory.path().join(PROTECTED_FILE_NAME);
    fs::write(&path, br#"{"version":1,"entries":[]}"#).expect("seed file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissive mode");
    let store = acknowledged_store(path);
    let key = SecretKey::new("codex", "personal", "token").expect("key");
    assert!(store.get(&key).await.is_err());
}

#[tokio::test]
async fn stale_plaintext_predecessor_blocks_writes_instead_of_being_retained() {
    let directory = TestDirectory::new("predecessor");
    let path = directory.path().join(PROTECTED_FILE_NAME);
    let predecessor = previous_path(&path).expect("previous path");
    fs::write(&predecessor, b"stale-secret-canary").expect("seed predecessor");
    fs::set_permissions(&predecessor, fs::Permissions::from_mode(0o600)).expect("predecessor mode");
    let store = acknowledged_store(path.clone());
    let key = SecretKey::new("codex", "personal", "token").expect("key");

    assert!(
        store
            .put(
                &key,
                SecretValue::new(b"new-secret".to_vec()).expect("secret")
            )
            .await
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(
        fs::read(predecessor).expect("predecessor left for explicit recovery or removal"),
        b"stale-secret-canary"
    );
}

#[tokio::test]
async fn named_slots_and_legacy_keys_coexist_without_schema_changes() {
    let directory = TestDirectory::new("named-slots");
    let path = directory.path().join(PROTECTED_FILE_NAME);
    let store = acknowledged_store(path);
    let legacy = SecretKey::new("zai", "ambient", "manual-session").expect("legacy key");
    let named = CredentialSlotId::new(
        AccountScope::new(
            ProviderId::Zai,
            ProviderInstanceId::new("default").expect("instance"),
            AccountKey::new("ambient").expect("account"),
        ),
        "api-key",
    )
    .expect("named slot");

    store
        .put(
            &legacy,
            SecretValue::new(b"legacy-secret".to_vec()).expect("legacy secret"),
        )
        .await
        .expect("store legacy secret");
    store
        .put(
            named.secret_key(),
            SecretValue::new(b"named-secret".to_vec()).expect("named secret"),
        )
        .await
        .expect("store named secret");

    assert_eq!(
        store
            .get(&legacy)
            .await
            .expect("get legacy")
            .expect("legacy present")
            .expose_secret(),
        b"legacy-secret"
    );
    assert_eq!(
        store
            .get(named.secret_key())
            .await
            .expect("get named")
            .expect("named present")
            .expose_secret(),
        b"named-secret"
    );
}

#[tokio::test]
async fn duplicate_named_slot_records_fail_closed() {
    let directory = TestDirectory::new("duplicate-named-slot");
    let path = directory.path().join(PROTECTED_FILE_NAME);
    let named = CredentialSlotId::new(
        AccountScope::new(
            ProviderId::Codex,
            ProviderInstanceId::new("default").expect("instance"),
            AccountKey::new("ambient").expect("account"),
        ),
        "api-key",
    )
    .expect("named slot");
    let key = named.secret_key();
    let document = serde_json::json!({
        "version": 1,
        "entries": [
            {
                "provider": key.provider(),
                "account": key.account(),
                "purpose": key.purpose(),
                "secret": [102, 105, 114, 115, 116]
            },
            {
                "provider": key.provider(),
                "account": key.account(),
                "purpose": key.purpose(),
                "secret": [115, 101, 99, 111, 110, 100]
            }
        ]
    });
    fs::write(
        &path,
        serde_json::to_vec(&document).expect("encode duplicate document"),
    )
    .expect("seed duplicate document");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    let store = acknowledged_store(path);

    assert_eq!(
        store
            .get(key)
            .await
            .expect_err("duplicates must fail closed"),
        SecretStoreError::InvalidData
    );
}
