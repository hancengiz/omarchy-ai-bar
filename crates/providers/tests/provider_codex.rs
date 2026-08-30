use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oab_domain::Timestamp;
use oab_providers::providers::codex::{
    CodexAttemptFailure, CodexBearerKind, CodexCredentialError, CodexCredentialSource,
    CodexNativeCredentialOutcome, CodexPatHomeScope, CodexPatRoot, CodexSourceAttempt,
    CodexSourceMode, CodexSourcePlan, external_oauth_sources, may_attempt_codex_cli_owner_recovery,
    may_try_external_credentials, native_oauth_error_outcome, parse_codex_bearer,
    parse_native_codex_pat, parse_opencode_oauth, select_codex_pat_root,
    should_continue_codex_plan,
};
use serde_json::json;

const NATIVE: &[u8] = include_bytes!("../../../fixtures/providers/codex/auth_native.json");
const OPENCODE: &[u8] = include_bytes!("../../../fixtures/providers/codex/auth_opencode.json");

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("fixture timestamp")
}

fn jwt(payload: &serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("JWT payload"));
    format!("{header}.{payload}.signature")
}

#[test]
fn native_document_keeps_pat_and_bearer_independent_and_redacted() {
    let pat = parse_native_codex_pat(NATIVE).expect("PAT");
    let bearer = parse_codex_bearer(NATIVE, CodexCredentialSource::Native).expect("native bearer");

    assert_eq!(pat.token(), "fixture-codex-pat-canary");
    assert_eq!(pat.source(), CodexCredentialSource::Native);
    assert_eq!(bearer.kind(), CodexBearerKind::OAuth);
    assert_eq!(bearer.access_token(), "fixture-codex-access-canary");
    assert_eq!(bearer.refresh_token(), "fixture-codex-refresh-canary");
    assert_eq!(bearer.id_token(), Some("fixture-codex-id-canary"));
    assert_eq!(bearer.account_id(), Some("fixture-account"));
    assert_eq!(
        bearer.last_refresh(),
        Some(timestamp("2026-08-29T12:00:00Z"))
    );

    let diagnostics = format!("{pat:?} {bearer:?}");
    for canary in [
        "fixture-codex-pat-canary",
        "fixture-codex-access-canary",
        "fixture-codex-refresh-canary",
        "fixture-codex-id-canary",
        "fixture-account",
    ] {
        assert!(!diagnostics.contains(canary));
    }
}

#[test]
fn native_alias_precedence_api_key_and_jwt_account_recovery_match_baseline() {
    let access = jwt(&json!({
        "chatgpt_account_id": "direct-account",
        "https://api.openai.com/auth": {"chatgpt_account_id": "namespaced-account"},
        "organizations": [{"id": "organization-account"}]
    }));
    let id = jwt(&json!({"organizations": [{"id": "id-token-organization"}]}));
    let oauth = serde_json::to_vec(&json!({
        "tokens": {
            "access_token": access,
            "accessToken": "camel-must-not-win",
            "refresh_token": "snake-refresh",
            "refreshToken": "camel-refresh",
            "id_token": id,
            "account_id": "  "
        }
    }))
    .expect("OAuth JSON");
    let bearer = parse_codex_bearer(&oauth, CodexCredentialSource::Native).expect("OAuth aliases");
    assert_eq!(bearer.refresh_token(), "snake-refresh");
    assert_eq!(bearer.account_id(), Some("id-token-organization"));

    let api_key = br#"{
        "OPENAI_API_KEY":"  fixture-api-key-canary  ",
        "tokens":{"access_token":"oauth","refresh_token":"refresh"}
    }"#;
    let bearer =
        parse_codex_bearer(api_key, CodexCredentialSource::Native).expect("API key precedence");
    assert_eq!(bearer.kind(), CodexBearerKind::ApiKey);
    assert_eq!(bearer.access_token(), "  fixture-api-key-canary  ");
    assert!(!bearer.needs_refresh_at(timestamp("2099-01-01T00:00:00Z")));
}

#[test]
fn jwt_account_claim_precedence_skips_blank_candidates() {
    let cases = [
        (
            json!({
                "chatgpt_account_id": "direct-account",
                "https://api.openai.com/auth": {"chatgpt_account_id": "namespaced-account"},
                "organizations": [{"id": "organization-account"}]
            }),
            "direct-account",
        ),
        (
            json!({
                "chatgpt_account_id": "  ",
                "https://api.openai.com/auth": {"chatgpt_account_id": "namespaced-account"},
                "organizations": [{"id": "organization-account"}]
            }),
            "namespaced-account",
        ),
        (
            json!({
                "https://api.openai.com/auth": {"chatgpt_account_id": ""},
                "organizations": [{"id": "  "}, {"id": "organization-account"}]
            }),
            "organization-account",
        ),
    ];

    for (claims, expected) in cases {
        let encoded = serde_json::to_vec(&json!({
            "tokens": {
                "access_token": jwt(&claims),
                "refresh_token": "refresh"
            }
        }))
        .expect("OAuth fixture");
        let bearer = parse_codex_bearer(&encoded, CodexCredentialSource::Native)
            .expect("JWT-backed OAuth bearer");
        assert_eq!(bearer.account_id(), Some(expected));
    }
}

#[test]
fn native_expiry_and_age_hints_are_deterministic_and_source_owned() {
    let native_token = jwt(&json!({"exp": 1_800_000_000}));
    let bearer = parse_codex_bearer(
        serde_json::to_string(&json!({
            "tokens": {"access_token": native_token, "refresh_token": "refresh"},
            "last_refresh": "2000-01-01T00:00:00Z"
        }))
        .expect("native JSON")
        .as_bytes(),
        CodexCredentialSource::Native,
    )
    .expect("native expiry");
    assert_eq!(
        bearer.expires_at(),
        Some(Timestamp::from_unix_timestamp(1_800_000_000).expect("expiry"))
    );
    assert!(!bearer.needs_refresh_at(
        Timestamp::from_unix_timestamp(1_800_000_000 - 301).expect("before skew")
    ));
    assert!(
        bearer.needs_refresh_at(
            Timestamp::from_unix_timestamp(1_800_000_000 - 300).expect("at skew")
        )
    );

    let fractional = jwt(&json!({"exp": 1_800_000_000.0}));
    let bearer = parse_codex_bearer(
        serde_json::to_string(&json!({
            "tokens": {"access_token": fractional, "refresh_token": "refresh"},
            "last_refresh": "2026-08-29T00:00:00Z"
        }))
        .expect("fractional JSON")
        .as_bytes(),
        CodexCredentialSource::Native,
    )
    .expect("fractional expiry falls back");
    assert!(bearer.expires_at().is_none());
    assert!(!bearer.needs_refresh_at(timestamp("2026-09-05T23:59:59Z")));
    assert!(bearer.needs_refresh_at(timestamp("2026-09-06T00:00:01Z")));

    let duplicate_payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1800000000,"exp":1800000001}"#);
    let duplicate = format!("header.{duplicate_payload}.signature");
    let bearer = parse_codex_bearer(
        serde_json::to_string(&json!({
            "tokens": {"access_token": duplicate, "refresh_token": "refresh"}
        }))
        .expect("duplicate JSON")
        .as_bytes(),
        CodexCredentialSource::Native,
    )
    .expect("duplicate expiry is only an unavailable scheduling hint");
    assert!(bearer.expires_at().is_none());
}

#[test]
fn opencode_credentials_are_trimmed_read_only_and_use_short_refresh_skew() {
    let bearer = parse_opencode_oauth(OPENCODE).expect("OpenCode fixture");
    assert_eq!(bearer.source(), CodexCredentialSource::OpenCode);
    assert_eq!(bearer.kind(), CodexBearerKind::OAuth);
    assert_eq!(bearer.account_id(), Some("fixture-opencode-account"));
    assert_eq!(bearer.expires_at(), Some(timestamp("2100-01-01T00:00:00Z")));
    assert!(!bearer.needs_refresh_at(timestamp("2099-12-31T23:58:59Z")));
    assert!(bearer.needs_refresh_at(timestamp("2099-12-31T23:59:00Z")));

    let diagnostics = format!("{bearer:?}");
    assert!(!diagnostics.contains("fixture-opencode-access-canary"));
    assert!(!diagnostics.contains("fixture-opencode-refresh-canary"));
    assert!(!diagnostics.contains("fixture-opencode-account"));
}

#[test]
fn credential_lanes_are_independent_and_source_authority_is_closed() {
    let pat_only = br#"{"personalAccessToken":"  at-profile  "}"#;
    let pat = parse_native_codex_pat(pat_only).expect("native PAT lane");
    assert_eq!(pat.token(), "at-profile");
    let bearer_error = parse_codex_bearer(pat_only, CodexCredentialSource::Native)
        .expect_err("PAT must not satisfy bearer lane");
    assert_eq!(bearer_error, CodexCredentialError::MissingTokens);
    let outcome = native_oauth_error_outcome(bearer_error);
    assert_eq!(outcome, CodexNativeCredentialOutcome::Invalid);
    assert!(external_oauth_sources(outcome, true, None).is_empty());

    let oauth_only = br#"{
        "tokens":{"access_token":"access","refresh_token":"refresh"}
    }"#;
    assert_eq!(
        parse_native_codex_pat(oauth_only).expect_err("OAuth must not satisfy PAT lane"),
        CodexCredentialError::MissingTokens
    );
    assert_eq!(
        parse_codex_bearer(oauth_only, CodexCredentialSource::Native)
            .expect("native OAuth")
            .kind(),
        CodexBearerKind::OAuth
    );

    let legacy_mixed = br#"{
        "personal_access_token":"legacy-pat-must-not-win",
        "OPENAI_API_KEY":"legacy-key-must-not-win",
        "tokens":{"access_token":"legacy-oauth","refresh_token":"legacy-refresh"}
    }"#;
    let legacy =
        parse_codex_bearer(legacy_mixed, CodexCredentialSource::Legacy).expect("legacy OAuth only");
    assert_eq!(legacy.kind(), CodexBearerKind::OAuth);
    assert_eq!(legacy.access_token(), "legacy-oauth");

    for unsupported in [
        &br#"{"OPENAI_API_KEY":"legacy-api-key"}"#[..],
        &br#"{"personal_access_token":"legacy-pat"}"#[..],
    ] {
        assert_eq!(
            parse_codex_bearer(unsupported, CodexCredentialSource::Legacy)
                .expect_err("legacy non-OAuth authority rejected"),
            CodexCredentialError::MissingTokens
        );
    }

    let opencode = parse_codex_bearer(OPENCODE, CodexCredentialSource::OpenCode)
        .expect("source-routed OpenCode bearer");
    assert_eq!(opencode.source(), CodexCredentialSource::OpenCode);

    let native_api_key_with_invalid_oauth = br#"{
        "OPENAI_API_KEY":"native-key",
        "tokens":{"access_token":"oauth-without-refresh"}
    }"#;
    let bearer = parse_codex_bearer(
        native_api_key_with_invalid_oauth,
        CodexCredentialSource::Native,
    )
    .expect("native API key wins without evaluating OAuth");
    assert_eq!(bearer.kind(), CodexBearerKind::ApiKey);
    assert_eq!(bearer.access_token(), "native-key");

    let valid_pat_invalid_bearer = br#"{
        "personal_access_token":"valid-pat",
        "tokens":{"access_token":"oauth","refresh_token":"invalid\nrefresh"}
    }"#;
    assert_eq!(
        parse_native_codex_pat(valid_pat_invalid_bearer)
            .expect("invalid bearer lane must not suppress PAT")
            .token(),
        "valid-pat"
    );
    assert_eq!(
        parse_codex_bearer(valid_pat_invalid_bearer, CodexCredentialSource::Native)
            .expect_err("selected bearer lane retains hardening"),
        CodexCredentialError::Invalid
    );

    let oversized_irrelevant_pat = "x".repeat(64 * 1024 + 1);
    let invalid_pat_valid_bearer = serde_json::to_vec(&json!({
        "personal_access_token": oversized_irrelevant_pat,
        "tokens": {"access_token": "valid-oauth", "refresh_token": "valid-refresh"}
    }))
    .expect("cross-lane fixture");
    assert_eq!(
        parse_native_codex_pat(&invalid_pat_valid_bearer)
            .expect_err("selected PAT lane retains hardening"),
        CodexCredentialError::Invalid
    );
    assert_eq!(
        parse_codex_bearer(&invalid_pat_valid_bearer, CodexCredentialSource::Native)
            .expect("invalid PAT lane must not suppress bearer")
            .access_token(),
        "valid-oauth"
    );
}

#[test]
fn malformed_missing_and_bounded_documents_fail_closed() {
    for invalid in [
        &b""[..],
        &b"not-json"[..],
        &b"[]"[..],
        &br#"{"tokens":{"access_token":"only-access"}}"#[..],
        &br#"{"OPENAI_API_KEY":"   "}"#[..],
    ] {
        assert!(matches!(
            parse_codex_bearer(invalid, CodexCredentialSource::Native),
            Err(CodexCredentialError::Invalid | CodexCredentialError::MissingTokens)
        ));
    }

    let oversized = vec![b'x'; 1024 * 1024 + 1];
    assert_eq!(
        parse_codex_bearer(&oversized, CodexCredentialSource::Native).expect_err("document cap"),
        CodexCredentialError::Invalid
    );

    let mut nested = json!({"tokens":{"access_token":"access","refresh_token":"refresh"}});
    for _ in 0..18 {
        nested = json!({"nested": nested});
    }
    assert_eq!(
        parse_codex_bearer(
            &serde_json::to_vec(&nested).expect("nested fixture"),
            CodexCredentialSource::Native,
        )
        .expect_err("depth cap"),
        CodexCredentialError::Invalid
    );

    assert_eq!(
        parse_opencode_oauth(br#"{"openai":{"type":"api","access":"secret"}}"#)
            .expect_err("wrong OpenCode type"),
        CodexCredentialError::MissingTokens
    );
}

#[test]
fn external_fallback_and_source_plans_preserve_authority_boundaries() {
    for outcome in [
        CodexNativeCredentialOutcome::Unreadable,
        CodexNativeCredentialOutcome::Invalid,
        CodexNativeCredentialOutcome::Available,
    ] {
        assert!(!may_try_external_credentials(outcome, true, false));
    }
    assert!(!may_try_external_credentials(
        CodexNativeCredentialOutcome::Missing,
        false,
        false
    ));
    assert!(!may_try_external_credentials(
        CodexNativeCredentialOutcome::Missing,
        true,
        true
    ));
    assert!(may_try_external_credentials(
        CodexNativeCredentialOutcome::Missing,
        true,
        false
    ));

    assert_eq!(
        CodexSourcePlan::new(CodexSourceMode::Auto, true).attempts(),
        [
            CodexSourceAttempt::Pat,
            CodexSourceAttempt::OAuth,
            CodexSourceAttempt::Cli,
        ]
    );
    assert_eq!(
        CodexSourcePlan::new(CodexSourceMode::Auto, false).attempts(),
        [CodexSourceAttempt::Pat, CodexSourceAttempt::OAuth]
    );
    assert_eq!(
        CodexSourcePlan::new(CodexSourceMode::OAuth, true).attempts(),
        [
            CodexSourceAttempt::OAuth,
            CodexSourceAttempt::CliOwnerRecovery,
        ]
    );
    assert_eq!(
        CodexSourcePlan::new(CodexSourceMode::OAuth, false).attempts(),
        [
            CodexSourceAttempt::OAuth,
            CodexSourceAttempt::CliOwnerRecovery,
        ]
    );
    assert_eq!(
        CodexSourcePlan::new(CodexSourceMode::Pat, true).attempts(),
        [CodexSourceAttempt::Pat]
    );
    assert_eq!(
        CodexSourcePlan::new(CodexSourceMode::Cli, false).attempts(),
        [CodexSourceAttempt::Cli]
    );
}

#[test]
fn external_oauth_plan_is_missing_only_opt_in_ordered_and_codex_home_scoped() {
    let expected = [
        CodexCredentialSource::Legacy,
        CodexCredentialSource::OpenCode,
    ];
    for codex_home in [None, Some(""), Some("   ")] {
        assert_eq!(
            external_oauth_sources(CodexNativeCredentialOutcome::Missing, true, codex_home,),
            expected
        );
    }
    for outcome in [
        CodexNativeCredentialOutcome::Unreadable,
        CodexNativeCredentialOutcome::Invalid,
        CodexNativeCredentialOutcome::Available,
    ] {
        assert!(external_oauth_sources(outcome, true, None).is_empty());
    }
    assert!(external_oauth_sources(CodexNativeCredentialOutcome::Missing, false, None).is_empty());
    assert!(
        external_oauth_sources(
            CodexNativeCredentialOutcome::Missing,
            true,
            Some("/explicit/codex-home"),
        )
        .is_empty()
    );

    assert_eq!(
        native_oauth_error_outcome(CodexCredentialError::NotFound),
        CodexNativeCredentialOutcome::Missing
    );
    assert_eq!(
        native_oauth_error_outcome(CodexCredentialError::Unreadable),
        CodexNativeCredentialOutcome::Unreadable
    );
    for error in [
        CodexCredentialError::Invalid,
        CodexCredentialError::MissingTokens,
        CodexCredentialError::NativeRefreshRequired,
        CodexCredentialError::ReadOnlySource,
    ] {
        assert_eq!(
            native_oauth_error_outcome(error),
            CodexNativeCredentialOutcome::Invalid
        );
    }
}

#[test]
fn pat_authority_keeps_managed_homes_isolated_and_profiles_fall_back() {
    let cases = [
        (CodexPatHomeScope::Ambient, false, CodexPatRoot::Ambient),
        (CodexPatHomeScope::Ambient, true, CodexPatRoot::Ambient),
        (CodexPatHomeScope::Profile, false, CodexPatRoot::Ambient),
        (CodexPatHomeScope::Profile, true, CodexPatRoot::Profile),
        (CodexPatHomeScope::Managed, false, CodexPatRoot::Ambient),
        (CodexPatHomeScope::Managed, true, CodexPatRoot::Ambient),
        (CodexPatHomeScope::FailClosed, false, CodexPatRoot::Ambient),
        (CodexPatHomeScope::FailClosed, true, CodexPatRoot::Ambient),
    ];
    for (scope, profile_has_usable_pat, expected) in cases {
        assert_eq!(
            select_codex_pat_root(scope, profile_has_usable_pat),
            expected,
            "scope={scope:?}, profile_has_usable_pat={profile_has_usable_pat}"
        );
    }
}

#[test]
fn cli_owner_recovery_requires_stale_native_unmanaged_explicit_oauth() {
    assert!(may_attempt_codex_cli_owner_recovery(
        CodexSourceMode::OAuth,
        false,
        true,
        Some(CodexCredentialSource::Native),
        true,
    ));

    let rejected = [
        (
            CodexSourceMode::Auto,
            false,
            true,
            Some(CodexCredentialSource::Native),
            true,
        ),
        (
            CodexSourceMode::OAuth,
            true,
            true,
            Some(CodexCredentialSource::Native),
            true,
        ),
        (
            CodexSourceMode::OAuth,
            false,
            false,
            Some(CodexCredentialSource::Native),
            true,
        ),
        (CodexSourceMode::OAuth, false, true, None, true),
        (
            CodexSourceMode::OAuth,
            false,
            true,
            Some(CodexCredentialSource::Legacy),
            true,
        ),
        (
            CodexSourceMode::OAuth,
            false,
            true,
            Some(CodexCredentialSource::OpenCode),
            true,
        ),
        (
            CodexSourceMode::OAuth,
            false,
            true,
            Some(CodexCredentialSource::Native),
            false,
        ),
    ];
    for (mode, managed, executable, source, stale) in rejected {
        assert!(!may_attempt_codex_cli_owner_recovery(
            mode, managed, executable, source, stale,
        ));
    }
}

#[test]
fn fallback_matrix_matches_pinned_pat_oauth_and_cli_contracts() {
    use CodexAttemptFailure as Failure;
    use CodexCredentialError as Credential;

    let failures = [
        Failure::Unavailable,
        Failure::Unauthorized,
        Failure::Credential(Credential::NotFound),
        Failure::Credential(Credential::Unreadable),
        Failure::Credential(Credential::MissingTokens),
        Failure::Credential(Credential::Invalid),
        Failure::Credential(Credential::NativeRefreshRequired),
        Failure::Credential(Credential::ReadOnlySource),
        Failure::TerminalRefresh,
        Failure::InvalidResponse,
        Failure::Server,
        Failure::Network,
        Failure::Other,
    ];
    let pat_auto_fallbacks = [
        Failure::Unavailable,
        Failure::Unauthorized,
        Failure::Credential(Credential::NotFound),
        Failure::Credential(Credential::Unreadable),
        Failure::Credential(Credential::MissingTokens),
    ];
    let oauth_auto_fallbacks = [
        Failure::Unavailable,
        Failure::Unauthorized,
        Failure::Credential(Credential::NotFound),
        Failure::Credential(Credential::Unreadable),
        Failure::Credential(Credential::MissingTokens),
        Failure::Credential(Credential::NativeRefreshRequired),
        Failure::TerminalRefresh,
    ];
    let oauth_explicit_fallbacks = [
        Failure::Unavailable,
        Failure::Credential(Credential::NativeRefreshRequired),
    ];

    for failure in failures {
        assert_eq!(
            should_continue_codex_plan(CodexSourceMode::Auto, CodexSourceAttempt::Pat, failure,),
            pat_auto_fallbacks.contains(&failure),
            "PAT auto failure {failure:?}"
        );
        assert_eq!(
            should_continue_codex_plan(CodexSourceMode::Auto, CodexSourceAttempt::OAuth, failure,),
            oauth_auto_fallbacks.contains(&failure),
            "OAuth auto failure {failure:?}"
        );
        assert_eq!(
            should_continue_codex_plan(CodexSourceMode::OAuth, CodexSourceAttempt::OAuth, failure,),
            oauth_explicit_fallbacks.contains(&failure),
            "OAuth explicit failure {failure:?}"
        );
        assert!(!should_continue_codex_plan(
            CodexSourceMode::Pat,
            CodexSourceAttempt::Pat,
            failure,
        ));
        assert!(!should_continue_codex_plan(
            CodexSourceMode::Cli,
            CodexSourceAttempt::Cli,
            failure,
        ));
        assert!(!should_continue_codex_plan(
            CodexSourceMode::OAuth,
            CodexSourceAttempt::CliOwnerRecovery,
            failure,
        ));
    }
}
