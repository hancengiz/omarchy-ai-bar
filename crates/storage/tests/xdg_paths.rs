use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_storage::paths::{APP_NAMESPACE, AppPaths, PathError};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-storage-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test root");
        Self(path)
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.0.join(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn environment(entries: &[(&str, PathBuf)]) -> BTreeMap<String, OsString> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.as_os_str().to_owned()))
        .collect()
}

#[test]
fn explicit_xdg_roots_are_normalized_and_namespaced() {
    let temp = TempRoot::new("explicit");
    let config = temp.join("config/./nested/..");
    let data = temp.join("data");
    let cache = temp.join("cache");
    let runtime = temp.join("runtime");
    let env = environment(&[
        ("XDG_CONFIG_HOME", config),
        ("XDG_DATA_HOME", data.clone()),
        ("XDG_CACHE_HOME", cache.clone()),
        ("XDG_RUNTIME_DIR", runtime.clone()),
    ]);
    let mut env = env;
    env.insert("HOME".to_owned(), OsString::from("unused-relative-home"));

    let paths = AppPaths::from_env_map(&env).expect("resolve explicit XDG roots");

    assert_eq!(APP_NAMESPACE, "omarchy-ai-bar");
    assert_eq!(paths.config_dir(), temp.join("config/omarchy-ai-bar"));
    assert_eq!(
        paths.config_file(),
        temp.join("config/omarchy-ai-bar/config.json")
    );
    assert_eq!(paths.data_dir(), data.join(APP_NAMESPACE));
    assert_eq!(
        paths.history_database(),
        data.join("omarchy-ai-bar/history.sqlite3")
    );
    assert_eq!(paths.cache_dir(), cache.join(APP_NAMESPACE));
    assert_eq!(paths.runtime_dir(), runtime.join(APP_NAMESPACE));
    assert_eq!(
        paths.socket_path(),
        runtime.join("omarchy-ai-bar/daemon.sock")
    );

    for path in paths.private_directories() {
        assert!(path.is_absolute());
        assert!(!path.components().any(|component| matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )));
    }
}

#[test]
fn home_supplies_only_standard_non_runtime_fallbacks() {
    let temp = TempRoot::new("fallback");
    let home = temp.join("home");
    let runtime = temp.join("run");
    let env = environment(&[("HOME", home.clone()), ("XDG_RUNTIME_DIR", runtime)]);

    let paths = AppPaths::from_env_map(&env).expect("resolve HOME fallbacks");

    assert_eq!(paths.config_dir(), home.join(".config/omarchy-ai-bar"));
    assert_eq!(paths.data_dir(), home.join(".local/share/omarchy-ai-bar"));
    assert_eq!(paths.cache_dir(), home.join(".cache/omarchy-ai-bar"));

    let without_runtime = environment(&[("HOME", home)]);
    assert!(matches!(
        AppPaths::from_env_map(&without_runtime),
        Err(PathError::MissingRuntimeDirectory)
    ));
}

#[test]
fn relative_or_missing_environment_roots_are_rejected() {
    let temp = TempRoot::new("invalid");
    let mut env = environment(&[
        ("HOME", temp.join("home")),
        ("XDG_RUNTIME_DIR", temp.join("run")),
    ]);
    env.insert("XDG_CONFIG_HOME".to_owned(), OsString::from("relative"));

    assert!(matches!(
        AppPaths::from_env_map(&env),
        Err(PathError::RootNotAbsolute { .. })
    ));

    let env = environment(&[("XDG_RUNTIME_DIR", temp.join("run"))]);
    assert!(matches!(
        AppPaths::from_env_map(&env),
        Err(PathError::MissingHomeDirectory)
    ));
}

#[test]
fn private_application_directories_are_mode_0700() {
    let temp = TempRoot::new("permissions");
    let env = environment(&[
        ("XDG_CONFIG_HOME", temp.join("config")),
        ("XDG_DATA_HOME", temp.join("data")),
        ("XDG_CACHE_HOME", temp.join("cache")),
        ("XDG_RUNTIME_DIR", temp.join("run")),
    ]);
    let paths = AppPaths::from_env_map(&env).expect("resolve paths");

    paths
        .create_private_directories()
        .expect("create private application roots");

    for path in paths.private_directories() {
        let metadata = fs::symlink_metadata(path).expect("stat private root");
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), nix::unistd::Uid::effective().as_raw());
    }
}

#[test]
fn symlink_and_wrong_type_application_roots_are_rejected() {
    let temp = TempRoot::new("hostile");
    let env = environment(&[
        ("XDG_CONFIG_HOME", temp.join("config")),
        ("XDG_DATA_HOME", temp.join("data")),
        ("XDG_CACHE_HOME", temp.join("cache")),
        ("XDG_RUNTIME_DIR", temp.join("run")),
    ]);
    let paths = AppPaths::from_env_map(&env).expect("resolve paths");
    fs::create_dir_all(temp.join("config")).expect("create config base");
    fs::create_dir_all(temp.join("target")).expect("create symlink target");
    symlink(temp.join("target"), paths.config_dir()).expect("create hostile symlink");

    assert!(matches!(
        paths.create_private_directories(),
        Err(PathError::RootIsSymlink { .. })
    ));

    fs::remove_file(paths.config_dir()).expect("remove test symlink");
    fs::write(paths.config_dir(), b"not a directory").expect("create wrong-type root");
    assert!(matches!(
        paths.create_private_directories(),
        Err(PathError::RootWrongType { .. })
    ));
}
