use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use oab_domain::Timestamp;
use oab_providers::providers::codex::{
    CodexBearerKind, CodexCredentialError, CodexCredentialSource, CodexPatHomeScope,
};
use oab_providers::providers::codex_files::{
    CodexCredentialLoadError, CodexCredentialPaths, load_bearer_for_usage, load_native_auth_file,
    load_pat_for_scope,
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
fn pat_scope_uses_profile_only_when_usable_and_managed_scopes_stay_ambient() {
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
    assert_eq!(
        load_pat_for_scope(&paths, CodexPatHomeScope::Profile, &cancellation)
            .expect("profile without PAT falls back")
            .token(),
        "ambient-pat"
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
    let paths = fixture.paths(None, None);
    let cancellation = CancellationToken::new();
    let bearer = load_bearer_for_usage(&paths, false, &cancellation).expect("native API key");
    assert_eq!(bearer.kind(), CodexBearerKind::ApiKey);

    let diagnostics = format!(
        "{paths:?} {bearer:?} {:?}",
        CodexCredentialLoadError::Credential(CodexCredentialError::Unreadable)
    );
    assert!(!diagnostics.contains("api-key-canary"));
    assert!(!diagnostics.contains(fixture.home().to_string_lossy().as_ref()));
}
