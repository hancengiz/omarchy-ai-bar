use oab_domain::{AccountKey, AccountScope, PrivacyKey, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::providers::codex_http::{CodexHttpError, CodexHttpRoutes};
use oab_providers::providers::codex_resets::parse_codex_reset_credits;
use serde_json::{Value, json};

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("default").unwrap(),
        AccountKey::new(account).unwrap(),
    )
}
fn inventory() -> Value {
    json!({"available_count": 2, "credits": [
        {"id": "private-reset-a", "reset_type": "codex_rate_limits", "status": "available", "granted_at": "2026-06-01T00:00:00Z", "expires_at": "2026-09-01T00:00:00Z"},
        {"id": "private-reset-b", "reset_type": "codex_rate_limits", "status": "available", "granted_at": "2026-08-01T00:00:00.731630Z", "expires_at": "2026-10-01T00:00:00Z"},
        {"id": "private-reset-c", "reset_type": "codex_rate_limits", "status": "available", "granted_at": "2026-08-01T00:00:00Z", "expires_at": null}
    ]})
}
#[test]
fn reset_inventory_filters_expired_entries_and_keeps_private_ids_scoped() {
    let now = Timestamp::parse("2026-09-05T00:00:00Z").unwrap();
    let key = PrivacyKey::from_bytes([7; 32]);
    let raw = serde_json::to_vec(&inventory()).unwrap();
    let first = parse_codex_reset_credits(&raw, &key, scope("alpha"), now).unwrap();
    let second = parse_codex_reset_credits(&raw, &key, scope("beta"), now).unwrap();
    assert_eq!(first.reported_available_count(), 2);
    assert_eq!(first.available_credits_at(now).len(), 2);
    assert!(first.reported_count_matches_inventory_at(now));
    assert_ne!(first.credits()[0].id(), second.credits()[0].id());
    assert!(!format!("{first:?}").contains("private-reset"));
    assert_eq!(
        first,
        parse_codex_reset_credits(&raw, &key, scope("alpha"), now).unwrap()
    );
}
#[test]
fn reset_inventory_rejects_malformed_bounds_duplicates_and_invalid_lifecycles() {
    let now = Timestamp::parse("2026-09-05T00:00:00Z").unwrap();
    let key = PrivacyKey::from_bytes([7; 32]);
    let mut cases = vec![
        json!({}),
        json!({"available_count": -1, "credits": []}),
        json!({"available_count": 4097, "credits": []}),
    ];
    let mut duplicate = inventory();
    duplicate["credits"][1]["id"] = duplicate["credits"][0]["id"].clone();
    cases.push(duplicate);
    let mut invalid = inventory();
    invalid["credits"][0]["granted_at"] = json!("invalid-timestamp");
    cases.push(invalid);
    let mut too_many = inventory();
    too_many["credits"] = json!(vec![inventory()["credits"][0].clone(); 65]);
    cases.push(too_many);
    for case in cases {
        assert_eq!(
            parse_codex_reset_credits(
                &serde_json::to_vec(&case).unwrap(),
                &key,
                scope("alpha"),
                now
            )
            .unwrap_err(),
            CodexHttpError::InvalidResponse
        );
    }
    let zero = parse_codex_reset_credits(
        br#"{"available_count":0,"credits":[]}"#,
        &key,
        scope("alpha"),
        now,
    )
    .unwrap();
    assert_eq!(zero.reported_available_count(), 0);
}
#[test]
fn reset_endpoint_preserves_configured_usage_origin_and_base_path() {
    for (config, expected) in [
        (
            None,
            "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits",
        ),
        (
            Some("chatgpt_base_url = 'https://chat.openai.com/'"),
            "https://chat.openai.com/backend-api/wham/rate-limit-reset-credits",
        ),
        (
            Some("chatgpt_base_url = 'https://example.test/custom'"),
            "https://example.test/custom/wham/rate-limit-reset-credits",
        ),
    ] {
        let routes = CodexHttpRoutes::from_config_text(config).unwrap();
        assert_eq!(routes.reset_credits_url().as_str(), expected);
        assert_eq!(
            routes.reset_credits_url().origin(),
            routes.usage_url().origin()
        );
    }
}
