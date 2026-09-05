use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use oab_storage::privacy::load_or_create;

#[test]
fn installation_record_key_is_private_stable_and_rejects_unsafe_replacement() {
    let root = tempfile::tempdir().unwrap();
    let first = load_or_create(root.path()).unwrap();
    assert_eq!(first, load_or_create(root.path()).unwrap());
    let path = root.path().join("privacy-key");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!root.path().join("privacy-key.previous").exists());
    fs::remove_file(&path).unwrap();
    symlink("/nonexistent/privacy-key-test", &path).unwrap();
    assert!(load_or_create(root.path()).is_err());
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"invalid").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_or_create(root.path()).is_err());
}
