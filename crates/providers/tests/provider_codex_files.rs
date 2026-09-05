use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use oab_domain::{ErrorKind, Timestamp};
use oab_providers::providers::codex::{
    CodexAttemptFailure, CodexBearerKind, CodexCredentialError, CodexCredentialSource,
    CodexPatHomeScope, CodexPatRoot,
};
use oab_providers::providers::codex_files::{
    CodexCredentialLoadError, CodexCredentialPaths, load_bearer_bundle_for_usage,
    load_bearer_for_usage, load_bearer_selection_for_usage, load_native_auth_file,
    load_pat_bundle_for_scope, load_pat_for_scope,
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

struct Fixture {
    temporary: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            temporary: tempfile::tempdir().expect("temporary home"),
        }
    }

    fn home(&self) -> &Path {
        self.temporary.path()
    }

    fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.home().join(relative)
    }

    fn write_auth(&self, relative_root: impl AsRef<Path>, contents: &str) {
        let root = self.path(relative_root);
        fs::create_dir_all(&root).expect("credential root");
        fs::write(root.join("auth.json"), contents).expect("auth fixture");
    }

    fn write_config(&self, relative_root: impl AsRef<Path>, contents: &str) {
        self.write_config_bytes(relative_root, contents.as_bytes());
    }

    fn write_config_bytes(&self, relative_root: impl AsRef<Path>, contents: &[u8]) {
        let root = self.path(relative_root);
        fs::create_dir_all(&root).expect("config root");
        fs::write(root.join("config.toml"), contents).expect("config fixture");
    }

    fn paths(
        &self,
        codex_home: Option<&OsStr>,
        xdg_data_home: Option<&OsStr>,
    ) -> CodexCredentialPaths {
        CodexCredentialPaths::resolve(self.home(), codex_home, xdg_data_home)
            .expect("credential paths")
    }
}

fn native_auth(pat: &str, access: &str) -> String {
    format!(
        r#"{{"personal_access_token":"{pat}","tokens":{{"access_token":"{access}","refresh_token":"refresh"}}}}"#
    )
}

fn opencode_auth(access: &str) -> String {
    format!(
        r#"{{"openai":{{"type":"oauth","access":"{access}","refresh":"refresh","expires":4102444800000}}}}"#
    )
}

#[test]
fn credential_load_errors_project_to_planner_and_public_error_classes() {
    let cases = [
        (CodexCredentialError::NotFound, ErrorKind::MissingCredential),
        (
            CodexCredentialError::Unreadable,
            ErrorKind::MissingCredential,
        ),
        (CodexCredentialError::Invalid, ErrorKind::Parse),
        (
            CodexCredentialError::MissingTokens,
            ErrorKind::MissingCredential,
        ),
        (
            CodexCredentialError::NativeRefreshRequired,
            ErrorKind::AuthenticationExpired,
        ),
        (
            CodexCredentialError::ReadOnlySource,
            ErrorKind::AuthenticationExpired,
        ),
    ];

    for (credential, expected_kind) in cases {
        let error = CodexCredentialLoadError::Credential(credential);
        assert_eq!(
            error.attempt_failure(),
            Some(CodexAttemptFailure::Credential(credential))
        );
        assert_eq!(
            error.classified().map(|classified| classified.kind()),
            Some(expected_kind)
        );
    }
}

#[test]
fn cancelled_credential_load_remains_a_distinct_control_flow_outcome() {
    let error = CodexCredentialLoadError::Cancelled;

    assert!(matches!(error, CodexCredentialLoadError::Cancelled));
    assert_eq!(error.attempt_failure(), None);
    assert_eq!(error.classified(), None);
}

#[test]
fn native_file_is_read_once_and_lanes_remain_independent() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();
    let auth = load_native_auth_file(&paths, &cancellation).expect("native auth file");

    assert_eq!(auth.pat().expect("PAT").token(), "ambient-pat");
    let bearer = auth.bearer().expect("bearer");
    assert_eq!(bearer.access_token(), "ambient-oauth");
    assert_eq!(bearer.source(), CodexCredentialSource::Native);

    let diagnostics = format!("{paths:?} {auth:?} {bearer:?}");
    assert!(!diagnostics.contains(fixture.home().to_string_lossy().as_ref()));
    assert!(!diagnostics.contains("ambient-oauth"));
}

#[test]
fn explicit_blank_and_tilde_codex_homes_are_resolved_without_source_leakage() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    fixture.write_auth(
        "profiles/work",
        &native_auth("profile-pat", "profile-oauth"),
    );
    fixture.write_auth(".profiles/tilde", &native_auth("tilde-pat", "tilde-oauth"));
    let cancellation = CancellationToken::new();

    let profile_root = fixture.path("profiles/work");
    let explicit = fixture.paths(Some(profile_root.as_os_str()), None);
    assert!(explicit.has_explicit_codex_home());
    assert_eq!(
        load_bearer_for_usage(&explicit, true, &cancellation)
            .expect("explicit bearer")
            .access_token(),
        "profile-oauth"
    );

    let blank = fixture.paths(Some(OsStr::new("  \t ")), None);
    assert!(!blank.has_explicit_codex_home());
    assert_eq!(
        load_bearer_for_usage(&blank, false, &cancellation)
            .expect("ambient bearer")
            .access_token(),
        "ambient-oauth"
    );

    let tilde = fixture.paths(Some(OsStr::new("~/.profiles/tilde")), None);
    assert_eq!(
        load_bearer_for_usage(&tilde, false, &cancellation)
            .expect("tilde bearer")
            .access_token(),
        "tilde-oauth"
    );

    for invalid in [
        "relative/home",
        "~another-user",
        "/tmp/../escape",
        "/tmp//double",
    ] {
        let error = CodexCredentialPaths::resolve(fixture.home(), Some(OsStr::new(invalid)), None)
            .expect_err("invalid explicit Codex home");
        assert_eq!(
            error,
            CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
        );
        assert!(!format!("{error:?}").contains(invalid));
    }

    let escaped = tempfile::tempdir().expect("escaped root");
    let tilde_absolute_escape = format!("~/{}", escaped.path().display());
    assert_eq!(
        CodexCredentialPaths::resolve(
            fixture.home(),
            Some(OsStr::new(&tilde_absolute_escape)),
            None,
        )
        .expect_err("tilde expansion may not discard trusted home"),
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );
}

#[test]
fn external_oauth_is_missing_only_opt_in_and_legacy_precedes_opencode() {
    let fixture = Fixture::new();
    fixture.write_auth(
        ".config/codex",
        r#"{"tokens":{"access_token":"legacy-oauth","refresh_token":"legacy-refresh"},"last_refresh":"2000-01-01T00:00:00Z"}"#,
    );
    fixture.write_auth(".local/share/opencode", &opencode_auth("opencode-oauth"));
    let cancellation = CancellationToken::new();
    let paths = fixture.paths(None, None);

    let legacy = load_bearer_for_usage(&paths, true, &cancellation).expect("legacy wins");
    assert_eq!(legacy.source(), CodexCredentialSource::Legacy);
    assert!(
        legacy
            .needs_refresh_at(Timestamp::parse("2026-08-30T00:00:00Z").expect("fixture timestamp"))
    );
    assert_eq!(
        load_bearer_for_usage(&paths, false, &cancellation).expect_err("external disabled"),
        CodexCredentialLoadError::Credential(CodexCredentialError::NotFound)
    );

    fixture.write_auth(
        ".config/codex",
        r#"{"OPENAI_API_KEY":"legacy-key-must-not-win","personal_access_token":"legacy-pat"}"#,
    );
    let bearer = load_bearer_for_usage(&paths, true, &cancellation).expect("OpenCode fallback");
    assert_eq!(bearer.source(), CodexCredentialSource::OpenCode);
    assert_eq!(bearer.access_token(), "opencode-oauth");

    fixture.write_auth(".codex", "{malformed");
    assert_eq!(
        load_bearer_for_usage(&paths, true, &cancellation)
            .expect_err("present malformed native authority"),
        CodexCredentialLoadError::Credential(CodexCredentialError::Invalid)
    );

    fs::remove_dir_all(fixture.path(".codex")).expect("remove native fixture");
    let missing_profile = fixture.path("missing-profile");
    let explicit = fixture.paths(Some(missing_profile.as_os_str()), None);
    assert_eq!(
        load_bearer_for_usage(&explicit, true, &cancellation)
            .expect_err("explicit Codex home blocks external fallback"),
        CodexCredentialLoadError::Credential(CodexCredentialError::NotFound)
    );
}

#[test]
fn xdg_data_home_is_exact_and_invalid_values_use_the_default_opencode_root() {
    let fixture = Fixture::new();
    let xdg = fixture.path("xdg-data");
    fixture.write_auth("xdg-data/opencode", &opencode_auth("xdg-opencode"));
    fixture.write_auth(".local/share/opencode", &opencode_auth("default-opencode"));
    fixture.write_auth(".xdg-tilde/opencode", &opencode_auth("tilde-opencode"));
    let cancellation = CancellationToken::new();

    let explicit_xdg = fixture.paths(None, Some(xdg.as_os_str()));
    assert_eq!(
        load_bearer_for_usage(&explicit_xdg, true, &cancellation)
            .expect("XDG OpenCode")
            .access_token(),
        "xdg-opencode"
    );

    let tilde_xdg = fixture.paths(None, Some(OsStr::new("~/.xdg-tilde")));
    assert_eq!(
        load_bearer_for_usage(&tilde_xdg, true, &cancellation)
            .expect("tilde XDG OpenCode")
            .access_token(),
        "tilde-opencode"
    );

    for invalid in ["relative-xdg", "~another-user"] {
        let paths = fixture.paths(None, Some(OsStr::new(invalid)));
        assert_eq!(
            load_bearer_for_usage(&paths, true, &cancellation)
                .expect("default OpenCode")
                .access_token(),
            "default-opencode"
        );
    }

    let escaped = tempfile::tempdir().expect("escaped XDG root");
    fs::create_dir_all(escaped.path().join("opencode")).expect("escaped OpenCode root");
    fs::write(
        escaped.path().join("opencode/auth.json"),
        opencode_auth("escaped-opencode-must-not-win"),
    )
    .expect("escaped OpenCode auth");
    let tilde_absolute_escape = format!("~/{}", escaped.path().display());
    let paths = fixture.paths(None, Some(OsStr::new(&tilde_absolute_escape)));
    assert_eq!(
        load_bearer_for_usage(&paths, true, &cancellation)
            .expect("invalid XDG escape falls back")
            .access_token(),
        "default-opencode"
    );
}

#[test]
fn pat_scope_never_substitutes_ambient_for_a_profile() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    fixture.write_auth(
        "profiles/work",
        &native_auth("profile-pat", "profile-oauth"),
    );
    let profile_root = fixture.path("profiles/work");
    let paths = fixture.paths(Some(profile_root.as_os_str()), None);
    let cancellation = CancellationToken::new();

    assert_eq!(
        load_pat_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation)
            .expect("profile PAT")
            .token(),
        "profile-pat"
    );
    for scope in [
        CodexPatHomeScope::Ambient,
        CodexPatHomeScope::Managed,
        CodexPatHomeScope::FailClosed,
    ] {
        assert_eq!(
            load_pat_for_scope(&paths, scope, &cancellation)
                .expect("ambient PAT")
                .token(),
            "ambient-pat"
        );
    }

    fixture.write_auth(
        "profiles/work",
        r#"{"tokens":{"access_token":"oauth","refresh_token":"refresh"}}"#,
    );
    assert!(load_pat_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation).is_err());
    fixture.write_auth("profiles/work", "{invalid");
    assert!(load_pat_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation).is_err());
    fs::remove_file(fixture.path("profiles/work/auth.json")).expect("remove profile auth");
    assert!(load_pat_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation).is_err());
}

#[test]
fn pat_bundle_binds_config_to_the_winning_pat_authority() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    fixture.write_config(".codex", "authority = \"ambient-config-canary\"\n");
    fixture.write_auth(
        "profiles/work",
        &native_auth("profile-pat", "profile-oauth"),
    );
    fixture.write_config("profiles/work", "authority = \"profile-config-canary\"\n");
    let profile_root = fixture.path("profiles/work");
    let paths = fixture.paths(Some(profile_root.as_os_str()), None);
    let cancellation = CancellationToken::new();

    let profile = load_pat_bundle_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation)
        .expect("profile PAT bundle");
    assert_eq!(profile.credentials().token(), "profile-pat");
    assert_eq!(profile.root(), CodexPatRoot::Profile);
    assert_eq!(
        profile.config_toml(),
        Some("authority = \"profile-config-canary\"\n")
    );

    let managed = load_pat_bundle_for_scope(&paths, CodexPatHomeScope::Managed, &cancellation)
        .expect("managed PAT bundle");
    assert_eq!(managed.credentials().token(), "ambient-pat");
    assert_eq!(managed.root(), CodexPatRoot::Ambient);
    assert_eq!(
        managed.config_toml(),
        Some("authority = \"ambient-config-canary\"\n")
    );

    fixture.write_auth(
        "profiles/work",
        r#"{"tokens":{"access_token":"oauth","refresh_token":"refresh"}}"#,
    );
    assert!(load_pat_bundle_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation).is_err());
}

#[test]
fn bearer_bundle_uses_native_config_and_external_sources_never_supply_it() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    fixture.write_config(".codex", "authority = \"ambient-config-canary\"\n");
    fixture.write_auth(
        "profiles/work",
        &native_auth("profile-pat", "profile-oauth"),
    );
    fixture.write_config("profiles/work", "authority = \"profile-config-canary\"\n");
    let profile_root = fixture.path("profiles/work");
    let explicit = fixture.paths(Some(profile_root.as_os_str()), None);
    let cancellation = CancellationToken::new();

    let native = load_bearer_bundle_for_usage(&explicit, true, &cancellation)
        .expect("profile bearer bundle");
    assert_eq!(native.credentials().access_token(), "profile-oauth");
    assert_eq!(
        native.config_toml(),
        Some("authority = \"profile-config-canary\"\n")
    );

    fs::remove_file(fixture.path(".codex/auth.json")).expect("remove ambient auth");
    fixture.write_auth(
        ".config/codex",
        r#"{"tokens":{"access_token":"legacy-oauth","refresh_token":"legacy-refresh"},"last_refresh":"2000-01-01T00:00:00Z"}"#,
    );
    fixture.write_config(
        ".config/codex",
        "authority = \"external-config-must-not-win\"\n",
    );
    let ambient = fixture.paths(None, None);
    let external = load_bearer_bundle_for_usage(&ambient, true, &cancellation)
        .expect("external bearer with ambient config");
    assert_eq!(external.credentials().access_token(), "legacy-oauth");
    assert_eq!(
        external.credentials().source(),
        CodexCredentialSource::Legacy
    );
    assert_eq!(
        external.config_toml(),
        Some("authority = \"ambient-config-canary\"\n")
    );
}

#[test]
fn missing_config_is_an_empty_optional_default_for_each_bundle() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();

    let pat = load_pat_bundle_for_scope(&paths, CodexPatHomeScope::Ambient, &cancellation)
        .expect("PAT without config");
    assert_eq!(pat.config_toml(), None);
    let bearer =
        load_bearer_bundle_for_usage(&paths, false, &cancellation).expect("bearer without config");
    assert_eq!(bearer.config_toml(), None);

    fs::remove_dir_all(fixture.path(".codex")).expect("remove native root");
    fixture.write_auth(
        ".config/codex",
        r#"{"tokens":{"access_token":"legacy-oauth","refresh_token":"legacy-refresh"},"last_refresh":"2000-01-01T00:00:00Z"}"#,
    );
    let external = load_bearer_bundle_for_usage(&paths, true, &cancellation)
        .expect("external bearer without native root");
    assert_eq!(external.config_toml(), None);
}

#[test]
fn selected_config_fails_closed_when_non_utf8_unsafe_or_oversized() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();

    fixture.write_config_bytes(".codex", &[0xff, 0xfe]);
    let invalid_utf8 = load_pat_bundle_for_scope(&paths, CodexPatHomeScope::Ambient, &cancellation)
        .expect_err("non-UTF-8 config");
    assert_eq!(
        invalid_utf8,
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );
    let diagnostics = format!("{paths:?} {invalid_utf8:?}");
    assert!(!diagnostics.contains(fixture.home().to_string_lossy().as_ref()));
    assert!(!diagnostics.contains("config.toml"));

    fs::remove_file(fixture.path(".codex/config.toml")).expect("remove invalid config");
    fixture.write_config("outside", "secret = \"outside-config-canary\"\n");
    symlink(
        fixture.path("outside/config.toml"),
        fixture.path(".codex/config.toml"),
    )
    .expect("config symlink");
    assert_eq!(
        load_bearer_bundle_for_usage(&paths, false, &cancellation)
            .expect_err("unsafe config symlink"),
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );

    fs::remove_file(fixture.path(".codex/config.toml")).expect("remove config symlink");
    let oversized = vec![b'x'; 256 * 1024 + 1];
    fixture.write_config_bytes(".codex", &oversized);
    assert_eq!(
        load_bearer_bundle_for_usage(&paths, false, &cancellation).expect_err("oversized config"),
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );
}

#[test]
fn bearer_freshness_selection_defers_config_without_changing_authority() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    fixture.write_config_bytes(".codex", &[0xff, 0xfe]);
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();

    let credentials = load_bearer_for_usage(&paths, false, &cancellation)
        .expect("auth-only selection ignores HTTP config");
    assert_eq!(credentials.source(), CodexCredentialSource::Native);

    let selection =
        load_bearer_selection_for_usage(&paths, false, &cancellation).expect("freshness selection");
    assert_eq!(
        selection.credentials().source(),
        CodexCredentialSource::Native
    );
    assert_eq!(
        selection
            .bind_config(&cancellation)
            .expect_err("the pinned unsafe config still fails closed"),
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );
}

#[test]
fn bundle_cancellation_is_never_suppressed_by_fallback() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", &native_auth("ambient-pat", "ambient-oauth"));
    fixture.write_config(".codex", "authority = \"ambient\"\n");
    fixture.write_auth(".config/codex", &native_auth("legacy-pat", "legacy-oauth"));
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    assert_eq!(
        load_pat_bundle_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation)
            .expect_err("cancelled PAT bundle"),
        CodexCredentialLoadError::Cancelled
    );
    assert_eq!(
        load_bearer_bundle_for_usage(&paths, true, &cancellation)
            .expect_err("cancelled bearer bundle"),
        CodexCredentialLoadError::Cancelled
    );
}

#[test]
fn unsafe_layout_and_cancellation_never_trigger_external_substitution() {
    let fixture = Fixture::new();
    fixture.write_auth("outside", &native_auth("outside-pat", "outside-oauth"));
    fixture.write_auth(".config/codex", &native_auth("legacy-pat", "legacy-oauth"));
    symlink(fixture.path("outside"), fixture.path(".codex")).expect("native root symlink");
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();
    assert_eq!(
        load_bearer_for_usage(&paths, true, &cancellation)
            .expect_err("unsafe native root is authoritative"),
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        load_bearer_for_usage(&paths, true, &cancelled).expect_err("cancelled acquisition"),
        CodexCredentialLoadError::Cancelled
    );
}

#[test]
fn successful_source_kind_and_all_diagnostics_are_bounded_and_redacted() {
    let fixture = Fixture::new();
    fixture.write_auth(".codex", r#"{"OPENAI_API_KEY":"api-key-canary"}"#);
    fixture.write_config(".codex", "marker = \"config-canary\"\n");
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();
    let bundle =
        load_bearer_bundle_for_usage(&paths, false, &cancellation).expect("native API-key bundle");
    assert_eq!(bundle.credentials().kind(), CodexBearerKind::ApiKey);

    let diagnostics = format!(
        "{paths:?} {bundle:?} {:?}",
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );
    assert!(!diagnostics.contains("api-key-canary"));
    assert!(!diagnostics.contains("config-canary"));
    assert!(!diagnostics.contains(fixture.home().to_string_lossy().as_ref()));
}
