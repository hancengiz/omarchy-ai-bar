use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_domain::ProviderId;
use oab_storage::config::{
    CURRENT_SCHEMA_VERSION, DiagnosticCode, MAX_CONFIG_BYTES, load_config_bytes,
};
use oab_storage::watcher::{ConfigReloader, ReloadOutcome};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-config-reload-{}-{unique}",
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

fn config(provider: &str, account: &str) -> String {
    format!(
        r#"{{
            "schema_version": 1,
            "providers": [{{
                "id": "{provider}",
                "instance_id": "default",
                "enabled": true,
                "endpoint": "https://api.example.test/v1",
                "config_path": "/var/lib/provider/config.json",
                "accounts": [{{ "id": "{account}", "enabled": true }}]
            }}],
            "provider_order": ["{provider}"]
        }}"#
    )
}

fn write_private(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).expect("write private config");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("set private config permissions");
}

#[test]
fn valid_v1_config_is_typed_and_bounded() {
    let parsed = load_config_bytes(config("codex", "account-one").as_bytes())
        .expect("valid schema v1 config");

    assert_eq!(parsed.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(parsed.providers[0].id, ProviderId::Codex);
    assert_eq!(parsed.providers[0].instance_id.as_str(), "default");
    assert_eq!(parsed.providers[0].accounts[0].id.as_str(), "account-one");

    let oversized = vec![b' '; MAX_CONFIG_BYTES + 1];
    let error = load_config_bytes(&oversized).expect_err("oversized config must fail");
    assert_eq!(error.code(), DiagnosticCode::ConfigTooLarge);
}

#[test]
fn unknown_and_secret_like_fields_are_rejected_without_echoing_input() {
    let unknown = br#"{
        "schema_version": 1,
        "providers": [],
        "provider_order": [],
        "future_toggle": true
    }"#;
    let error = load_config_bytes(unknown).expect_err("unknown field must fail");
    assert_eq!(error.code(), DiagnosticCode::SchemaInvalid);
    assert_eq!(error.to_string(), "configuration does not match schema v1");

    let secret = br#"{
        "schema_version": 1,
        "providers": [{
            "id": "codex",
            "instance_id": "default",
            "enabled": true,
            "accounts": [],
            "api_key": "must-not-appear-in-diagnostics"
        }],
        "provider_order": ["codex"]
    }"#;
    let error = load_config_bytes(secret).expect_err("ordinary config must reject secrets");
    assert_eq!(error.code(), DiagnosticCode::SecretField);
    assert!(!error.to_string().contains("must-not-appear"));
    assert!(!format!("{error:?}").contains("must-not-appear"));

    let duplicate = br#"{
        "schema_version": 1,
        "schema_version": 1,
        "providers": [],
        "provider_order": []
    }"#;
    assert_eq!(
        load_config_bytes(duplicate)
            .expect_err("duplicate schema fields are ambiguous")
            .code(),
        DiagnosticCode::SchemaInvalid
    );
}

#[test]
fn semantic_conflicts_and_unsafe_values_are_rejected() {
    let multiple_instances = br#"{
        "schema_version": 1,
        "providers": [
            {"id":"codex","instance_id":"one","enabled":true,"accounts":[]},
            {"id":"codex","instance_id":"two","enabled":true,"accounts":[]}
        ],
        "provider_order": ["codex"]
    }"#;
    load_config_bytes(multiple_instances).expect("distinct provider instances are valid");

    let duplicate_provider = br#"{
        "schema_version": 1,
        "providers": [
            {"id":"codex","instance_id":"one","enabled":true,"accounts":[]},
            {"id":"codex","instance_id":"one","enabled":true,"accounts":[]}
        ],
        "provider_order": ["codex"]
    }"#;
    assert_eq!(
        load_config_bytes(duplicate_provider)
            .expect_err("duplicate provider")
            .code(),
        DiagnosticCode::DuplicateProvider
    );

    let duplicate_order = br#"{
        "schema_version":1,
        "providers":[{"id":"codex","instance_id":"default","enabled":true,"accounts":[]}],
        "provider_order":["codex","codex"]
    }"#;
    assert_eq!(
        load_config_bytes(duplicate_order)
            .expect_err("duplicate order entry")
            .code(),
        DiagnosticCode::DuplicateProviderOrder
    );

    let wrong_order_set = br#"{
        "schema_version":1,
        "providers":[{"id":"codex","instance_id":"default","enabled":true,"accounts":[]}],
        "provider_order":["claude"]
    }"#;
    assert_eq!(
        load_config_bytes(wrong_order_set)
            .expect_err("order must name exactly configured providers")
            .code(),
        DiagnosticCode::ProviderOrderMismatch
    );

    let scoped_account_ids = br#"{
        "schema_version":1,
        "providers":[
            {"id":"codex","instance_id":"default","enabled":true,"accounts":[{"id":"same-account","enabled":true}]},
            {"id":"claude","instance_id":"default","enabled":true,"accounts":[{"id":"same-account","enabled":true}]}
        ],
        "provider_order":["codex","claude"]
    }"#;
    load_config_bytes(scoped_account_ids)
        .expect("account IDs are scoped to a provider instance route");

    let conflict = br#"{
        "schema_version":1,
        "providers":[
            {"id":"codex","instance_id":"default","enabled":true,"accounts":[
                {"id":"same-account","enabled":true},
                {"id":"same-account","enabled":false}
            ]}
        ],
        "provider_order":["codex"]
    }"#;
    assert_eq!(
        load_config_bytes(conflict)
            .expect_err("account IDs are unique within a provider instance")
            .code(),
        DiagnosticCode::ConflictingAccountId
    );

    for invalid in [
        config("codex", ".."),
        config("codex", "UPPERCASE"),
        config("not-a-provider", "account-one"),
    ] {
        let error = load_config_bytes(invalid.as_bytes()).expect_err("invalid identifier");
        assert!(matches!(
            error.code(),
            DiagnosticCode::InvalidIdentifier | DiagnosticCode::SchemaInvalid
        ));
    }
}

#[test]
fn endpoints_and_provider_paths_fail_closed() {
    for (provider, endpoint) in [
        ("ollama", "http://localhost:11434/v1"),
        ("ollama", "http://127.42.0.9:4000/v1"),
        ("ollama", "http://[::1]:8080/v1"),
        ("sub2api", "http://127.0.0.1:8080/v1"),
        ("wayfinder", "http://localhost:8088"),
        ("litellm", "http://127.0.0.1:4000/v1"),
        ("litellm", "http://192.168.1.5:4000/v1"),
        ("llmproxy", "http://proxy.local:4000/v1"),
        ("llmproxy", "http://[fd00::1]:4000/v1"),
    ] {
        let input =
            config(provider, "account-one").replace("https://api.example.test/v1", endpoint);
        load_config_bytes(input.as_bytes()).expect("HTTP loopback endpoint is allowed");
    }

    for endpoint in [
        "http://api.example.test",
        "http://localhost:11434",
        "http://192.168.1.5:11434",
        "http://localhost.example.test:11434",
        "http://localhost.:11434",
        "https://user:pass@api.example.test",
        "https://api.example.test/path?token=value",
        "https://api.example.test/path#fragment",
        "https:///missing-host",
    ] {
        let input = config("codex", "account-one").replace("https://api.example.test/v1", endpoint);
        assert_eq!(
            load_config_bytes(input.as_bytes())
                .expect_err("unsafe endpoint")
                .code(),
            DiagnosticCode::InvalidEndpoint
        );
    }

    for (provider, endpoint) in [
        ("sub2api", "http://192.168.1.5:8080"),
        ("wayfinder", "http://router.local:8088"),
        ("litellm", "http://api.example.test:4000"),
        ("llmproxy", "http://8.8.8.8:4000"),
    ] {
        let input =
            config(provider, "account-one").replace("https://api.example.test/v1", endpoint);
        assert_eq!(
            load_config_bytes(input.as_bytes())
                .expect_err("provider HTTP policy must fail closed")
                .code(),
            DiagnosticCode::InvalidEndpoint
        );
    }

    for provider_path in ["relative/config.json", "/safe/../escape", "/safe/./config"] {
        let input =
            config("codex", "account-one").replace("/var/lib/provider/config.json", provider_path);
        assert_eq!(
            load_config_bytes(input.as_bytes())
                .expect_err("unsafe provider path")
                .code(),
            DiagnosticCode::UnsafeProviderPath
        );
    }
}

#[test]
fn polling_retains_last_valid_config_after_an_invalid_edit() {
    let temp = TempRoot::new();
    let path = temp.join("config.json");
    write_private(&path, config("codex", "account-one"));
    let mut reloader = ConfigReloader::load(&path).expect("load initial valid config");

    assert_eq!(reloader.poll(), ReloadOutcome::Unchanged);
    assert_eq!(reloader.current().providers[0].id, ProviderId::Codex);

    fs::write(&path, b"{ invalid and sensitive looking bytes }").expect("write invalid edit");
    assert_eq!(
        reloader.poll(),
        ReloadOutcome::Rejected(DiagnosticCode::JsonInvalid)
    );
    assert_eq!(reloader.current().providers[0].id, ProviderId::Codex);
    assert_eq!(reloader.poll(), ReloadOutcome::Unchanged);

    fs::write(&path, config("claude", "account-two")).expect("write valid edit");
    assert_eq!(reloader.poll(), ReloadOutcome::Reloaded);
    assert_eq!(reloader.current().providers[0].id, ProviderId::Claude);
}

#[test]
fn poll_diagnostics_are_stable_codes_and_do_not_echo_paths() {
    let temp = TempRoot::new();
    let path = temp.join("sensitive-path-name.json");
    write_private(&path, config("codex", "account-one"));
    let mut reloader = ConfigReloader::load(&path).expect("load initial valid config");
    fs::remove_file(&path).expect("remove live config");

    let outcome = reloader.poll();
    assert_eq!(
        outcome,
        ReloadOutcome::Rejected(DiagnosticCode::ConfigReadFailed)
    );
    assert!(!format!("{outcome:?}").contains("sensitive-path-name"));
    assert_eq!(reloader.current().providers[0].id, ProviderId::Codex);
}

#[test]
fn polling_rejects_a_permissive_config_file_and_retains_last_valid() {
    let temp = TempRoot::new();
    let path = temp.join("config.json");
    write_private(&path, config("codex", "account-one"));
    let mut reloader = ConfigReloader::load(&path).expect("load private initial config");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("make config permissions unsafe");
    assert_eq!(
        reloader.poll(),
        ReloadOutcome::Rejected(DiagnosticCode::ConfigReadFailed)
    );
    assert_eq!(reloader.current().providers[0].id, ProviderId::Codex);
}
