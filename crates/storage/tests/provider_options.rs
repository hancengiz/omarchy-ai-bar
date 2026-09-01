use oab_storage::config::{
    DiagnosticCode, MAX_PROVIDER_OPTION_DEPTH, MAX_PROVIDER_OPTION_ENTRIES,
    MAX_PROVIDER_OPTION_KEY_BYTES, MAX_PROVIDER_OPTION_TEXT_BYTES,
    MAX_PROVIDER_OPTION_TOTAL_TEXT_BYTES, MAX_PROVIDER_OPTION_VALUE_BYTES, ProviderCookieSource,
    ProviderOptionValue, ProviderSourceMode, load_config_bytes, validate_config,
};
use oab_storage::migrations::{migrate, migrate_to_current};
use serde_json::{Map, Value, json};

fn document(options: Value) -> Vec<u8> {
    let mut provider = json!({
        "id": "codex",
        "instance_id": "default",
        "enabled": true,
        "accounts": [{"id": "account-one", "enabled": true}]
    });
    provider
        .as_object_mut()
        .expect("provider fixture is an object")
        .insert("options".to_owned(), options);
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "providers": [provider],
        "provider_order": ["codex"]
    }))
    .expect("serialize provider option test document")
}

fn rejection(options: Value) -> DiagnosticCode {
    load_config_bytes(&document(options))
        .expect_err("provider options must be rejected")
        .code()
}

#[test]
fn all_common_and_provider_specific_options_round_trip() {
    let bytes = document(json!({
        "source": "oauth",
        "cookie_source": "manual",
        "extras_enabled": true,
        "region": "eu-west-1",
        "workspace": "workspace-42",
        "project": "observability",
        "organization": "example-org",
        "team": "platform",
        "enterprise_host": "https://github.example.test",
        "deployment": "production-blue",
        "provider_options": {
            "api_version": "2026-08-31",
            "history_days": 30,
            "include_preview": false,
            "lanes": ["session", "weekly"],
            "labels": {"primary": "Usage", "secondary": "Cost"}
        }
    }));

    let parsed = load_config_bytes(&bytes).expect("typed provider options");
    let options = &parsed.providers[0].options;
    assert_eq!(options.source, Some(ProviderSourceMode::Oauth));
    assert_eq!(options.cookie_source, Some(ProviderCookieSource::Manual));
    assert_eq!(options.extras_enabled, Some(true));
    assert_eq!(options.region.as_deref(), Some("eu-west-1"));
    assert_eq!(options.workspace.as_deref(), Some("workspace-42"));
    assert_eq!(options.project.as_deref(), Some("observability"));
    assert_eq!(options.organization.as_deref(), Some("example-org"));
    assert_eq!(options.team.as_deref(), Some("platform"));
    assert_eq!(
        options.enterprise_host.as_deref(),
        Some("https://github.example.test")
    );
    assert_eq!(options.deployment.as_deref(), Some("production-blue"));
    assert!(matches!(
        options.extensions.get("include_preview"),
        Some(ProviderOptionValue::Boolean(false))
    ));
    assert!(matches!(
        options.extensions.get("history_days"),
        Some(ProviderOptionValue::Number(number)) if number.as_u64() == Some(30)
    ));

    let encoded = serde_json::to_vec(&parsed).expect("serialize typed provider options");
    let reparsed = load_config_bytes(&encoded).expect("reload typed provider options");
    assert_eq!(reparsed, parsed);

    let migration = migrate(&bytes).expect("current v1 options pass migration validation");
    assert!(!migration.was_migrated());
    assert_eq!(migration.current_bytes(), bytes.as_slice());
}

#[test]
fn every_common_and_concrete_source_lane_has_a_stable_wire_spelling() {
    for (source, spelling) in [
        (ProviderSourceMode::Auto, "auto"),
        (ProviderSourceMode::Web, "web"),
        (ProviderSourceMode::Cli, "cli"),
        (ProviderSourceMode::Oauth, "oauth"),
        (ProviderSourceMode::Api, "api"),
        (ProviderSourceMode::Pat, "pat"),
        (ProviderSourceMode::ApiKey, "api_key"),
        (
            ProviderSourceMode::ConfigurableEndpoint,
            "configurable_endpoint",
        ),
        (ProviderSourceMode::ManualCookie, "manual_cookie"),
        (ProviderSourceMode::BrowserSession, "browser_session"),
        (ProviderSourceMode::Local, "local"),
        (ProviderSourceMode::CloudCredentials, "cloud_credentials"),
    ] {
        assert_eq!(
            serde_json::to_value(source).expect("serialize source mode"),
            Value::String(spelling.to_owned())
        );
        assert_eq!(
            serde_json::from_value::<ProviderSourceMode>(Value::String(spelling.to_owned()))
                .expect("deserialize source mode"),
            source
        );
    }
}

#[test]
fn every_cookie_source_has_a_stable_wire_spelling() {
    for (source, spelling) in [
        (ProviderCookieSource::Auto, "auto"),
        (ProviderCookieSource::Manual, "manual"),
        (ProviderCookieSource::Off, "off"),
    ] {
        assert_eq!(
            serde_json::to_value(source).expect("serialize cookie source"),
            Value::String(spelling.to_owned())
        );
        assert_eq!(
            serde_json::from_value::<ProviderCookieSource>(Value::String(spelling.to_owned()))
                .expect("deserialize cookie source"),
            source
        );
    }
}

#[test]
fn existing_v1_and_legacy_v0_documents_keep_empty_options_implicit() {
    let existing = br#"{
        "schema_version": 1,
        "providers": [{
            "id": "codex",
            "instance_id": "default",
            "enabled": true,
            "accounts": []
        }],
        "provider_order": ["codex"]
    }"#;
    let parsed = load_config_bytes(existing).expect("existing schema v1 remains valid");
    assert!(parsed.providers[0].options.is_empty());
    let encoded = serde_json::to_value(&parsed).expect("serialize existing config");
    assert!(encoded["providers"][0].get("options").is_none());

    let migrated = migrate_to_current(br#"{"provider":"codex","account":"account-one"}"#)
        .expect("legacy v0 migration");
    let parsed = load_config_bytes(&migrated).expect("migrated v1 remains valid");
    assert!(parsed.providers[0].options.is_empty());
    let encoded = serde_json::to_value(parsed).expect("serialize migrated config");
    assert!(encoded["providers"][0].get("options").is_none());
}

#[test]
fn source_cookie_source_and_unknown_common_fields_fail_closed() {
    assert_eq!(
        rejection(json!({"source": "native"})),
        DiagnosticCode::SchemaInvalid
    );
    assert_eq!(
        rejection(json!({"cookie_source": "browser"})),
        DiagnosticCode::SchemaInvalid
    );
    assert_eq!(
        rejection(json!({"future_option": true})),
        DiagnosticCode::SchemaInvalid
    );
}

#[test]
fn common_option_text_is_bounded_and_canonical() {
    for options in [
        json!({"region": ""}),
        json!({"workspace": " leading-space"}),
        json!({"project": "trailing-space "}),
        json!({"organization": "line\nbreak"}),
    ] {
        assert_eq!(rejection(options), DiagnosticCode::InvalidProviderOption);
    }

    assert_eq!(
        rejection(json!({"deployment": "x".repeat(MAX_PROVIDER_OPTION_TEXT_BYTES + 1)})),
        DiagnosticCode::TextTooLong
    );
}

#[test]
fn provider_specific_maps_enforce_entry_key_value_depth_and_total_bounds() {
    let mut too_many = Map::new();
    for index in 0..=MAX_PROVIDER_OPTION_ENTRIES {
        too_many.insert(format!("option_{index}"), Value::Bool(true));
    }
    assert_eq!(
        rejection(json!({"provider_options": too_many})),
        DiagnosticCode::CollectionTooLarge
    );

    let long_key = "k".repeat(MAX_PROVIDER_OPTION_KEY_BYTES + 1);
    assert_eq!(
        rejection(json!({"provider_options": {(long_key): true}})),
        DiagnosticCode::TextTooLong
    );
    assert_eq!(
        rejection(json!({
            "provider_options": {
                "label": "x".repeat(MAX_PROVIDER_OPTION_VALUE_BYTES + 1)
            }
        })),
        DiagnosticCode::TextTooLong
    );

    let mut too_deep = Value::Bool(true);
    for _ in 0..=MAX_PROVIDER_OPTION_DEPTH {
        too_deep = Value::Array(vec![too_deep]);
    }
    assert_eq!(
        rejection(json!({"provider_options": {"nested": too_deep}})),
        DiagnosticCode::CollectionTooLarge
    );

    let node_heavy = Value::Array(
        (0..9)
            .map(|_| Value::Array(vec![Value::Bool(true); 64]))
            .collect(),
    );
    assert_eq!(
        rejection(json!({"provider_options": {"matrix": node_heavy}})),
        DiagnosticCode::CollectionTooLarge
    );

    let value = "x".repeat(MAX_PROVIDER_OPTION_VALUE_BYTES);
    let aggregate_heavy = Value::Array(vec![Value::String(value); 17]);
    const {
        assert!(17 * MAX_PROVIDER_OPTION_VALUE_BYTES > MAX_PROVIDER_OPTION_TOTAL_TEXT_BYTES);
    }
    assert_eq!(
        rejection(json!({"provider_options": {"labels": aggregate_heavy}})),
        DiagnosticCode::TextTooLong
    );
}

#[test]
fn provider_specific_keys_are_canonical_and_cannot_name_secrets() {
    for key in ["", ".leading", "trailing-", "two..dots", "has space"] {
        assert_eq!(
            rejection(json!({"provider_options": {(key): true}})),
            DiagnosticCode::InvalidProviderOption
        );
    }

    for key in ["api_key", "access_token", "cookie", "cookie_source"] {
        assert_eq!(
            rejection(json!({"provider_options": {(key): "canary"}})),
            DiagnosticCode::SecretField
        );
    }
}

#[test]
fn programmatically_constructed_options_receive_the_same_secret_validation() {
    let mut parsed = load_config_bytes(&document(json!({}))).expect("base config");
    parsed.providers[0].options.extensions.insert(
        "refresh_token".to_owned(),
        ProviderOptionValue::Text("must-not-be-stored".to_owned()),
    );
    let error = validate_config(&parsed).expect_err("typed values must fail closed too");
    assert_eq!(error.code(), DiagnosticCode::SecretField);
    assert!(!error.to_string().contains("must-not-be-stored"));
    assert!(!format!("{error:?}").contains("must-not-be-stored"));
}
