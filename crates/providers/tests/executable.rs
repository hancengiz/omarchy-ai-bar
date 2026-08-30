use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_providers::executable::{ExecutableLookupError, resolve_executable};

#[test]
fn configured_override_is_authoritative_trimmed_unquoted_and_redacted() {
    let tree = TempTree::new();
    let override_path = tree.executable("custom tool");
    let path_tool = tree.directory("path").join("fixture-tool");
    make_executable(&path_tool);
    let configured = format!("  \"{}\"  ", override_path.display());

    let resolved = resolve_executable(
        "fixture-tool",
        Some(&configured),
        Some(tree.directory("path").as_os_str()),
        &[],
    )
    .expect("valid lookup")
    .expect("configured executable");

    assert_eq!(resolved.as_path(), override_path);
    assert!(!format!("{resolved:?}").contains("custom tool"));
}

#[test]
fn missing_configured_override_does_not_fall_through_to_path() {
    let tree = TempTree::new();
    let path_directory = tree.directory("path");
    make_executable(&path_directory.join("fixture-tool"));
    let missing = tree.root().join("missing");

    let resolved = resolve_executable(
        "fixture-tool",
        Some(missing.to_str().expect("utf-8 path")),
        Some(path_directory.as_os_str()),
        &[],
    )
    .expect("valid lookup");

    assert!(resolved.is_none());
}

#[test]
fn path_order_wins_and_relative_entries_are_ignored() {
    let tree = TempTree::new();
    let first = tree.directory("first");
    let second = tree.directory("second");
    make_executable(&first.join("fixture-tool"));
    make_executable(&second.join("fixture-tool"));
    let joined =
        std::env::join_paths([Path::new("relative"), &first, &second]).expect("valid PATH fixture");

    let resolved = resolve_executable("fixture-tool", None, Some(&joined), &[])
        .expect("valid lookup")
        .expect("PATH executable");

    assert_eq!(resolved.as_path(), first.join("fixture-tool"));
}

#[test]
fn ordered_fallbacks_follow_path_and_require_the_expected_filename() {
    let tree = TempTree::new();
    let missing = tree.root().join("missing").join("fixture-tool");
    let found = tree.directory("fallback").join("fixture-tool");
    make_executable(&found);

    let resolved = resolve_executable(
        "fixture-tool",
        None,
        Some(OsStr::new("")),
        &[missing, found.clone()],
    )
    .expect("valid lookup")
    .expect("fallback executable");
    assert_eq!(resolved.as_path(), found);

    assert_eq!(
        resolve_executable(
            "fixture-tool",
            None,
            None,
            &[tree.root().join("wrong-name")],
        ),
        Err(ExecutableLookupError::InvalidConfiguration)
    );
}

#[test]
fn only_regular_executable_files_are_selected() {
    let tree = TempTree::new();
    let directory = tree.directory("path");
    let candidate = directory.join("fixture-tool");
    fs::write(&candidate, b"not executable").expect("write fixture");

    assert!(
        resolve_executable("fixture-tool", None, Some(directory.as_os_str()), &[])
            .expect("valid lookup")
            .is_none()
    );

    fs::remove_file(&candidate).expect("remove fixture file");
    fs::create_dir(&candidate).expect("create fixture directory");
    assert!(
        resolve_executable("fixture-tool", None, Some(directory.as_os_str()), &[])
            .expect("valid lookup")
            .is_none()
    );
}

#[test]
fn unsafe_names_paths_and_unbounded_searches_fail_closed() {
    assert_eq!(
        resolve_executable("../tool", None, None, &[]),
        Err(ExecutableLookupError::InvalidConfiguration)
    );
    assert_eq!(
        resolve_executable("tool", Some("relative/tool"), None, &[]),
        Err(ExecutableLookupError::InvalidConfiguration)
    );
    assert_eq!(
        resolve_executable("tool", None, Some(OsStr::new(&"x".repeat(65 * 1024))), &[]),
        Err(ExecutableLookupError::InvalidConfiguration)
    );
    let fallbacks = (0..33)
        .map(|index| PathBuf::from(format!("/tmp/{index}/tool")))
        .collect::<Vec<_>>();
    assert_eq!(
        resolve_executable("tool", None, None, &fallbacks),
        Err(ExecutableLookupError::InvalidConfiguration)
    );
}

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("oab-executable-test-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create temp fixture root");
        Self(path)
    }

    fn root(&self) -> &Path {
        &self.0
    }

    fn directory(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(&path).expect("create fixture directory");
        path
    }

    fn executable(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        make_executable(&path);
        path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove temp fixture tree");
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, b"#!/bin/sh\nexit 0\n").expect("write fixture executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("make fixture executable");
}

#[cfg(not(unix))]
fn make_executable(path: &Path) {
    fs::write(path, b"fixture").expect("write fixture executable");
}
