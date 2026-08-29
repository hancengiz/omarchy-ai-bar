use oab_domain::{
    AccountKey, AccountScope, PrivacyKey, PrivacyPolicy, PrivacySurface, ProviderId,
    ProviderInstanceId, ProviderSnapshot, SnapshotEnvelopeV1, Timestamp,
};

fn fixture() -> SnapshotEnvelopeV1 {
    serde_json::from_str(include_str!(
        "../../../fixtures/domain/privacy-unredacted-v1.json"
    ))
    .expect("privacy fixture should decode")
}

fn privacy_key() -> PrivacyKey {
    PrivacyKey::from_bytes([0x11; 32])
}

#[test]
fn hide_personal_information_is_a_pure_idempotent_domain_projection() {
    let original = fixture();
    let privacy_key = privacy_key();
    let original_json = serde_json::to_string_pretty(&original.private_view())
        .expect("private snapshot view should encode");

    for surface in [
        PrivacySurface::Ui,
        PrivacySurface::Notification,
        PrivacySurface::Hook,
        PrivacySurface::Cli,
        PrivacySurface::Server,
        PrivacySurface::Export,
        PrivacySurface::Diagnostics,
        PrivacySurface::FleetSync,
    ] {
        let projected = original.project(PrivacyPolicy::HidePersonalInfo, surface, &privacy_key);
        let projected_again =
            projected.project(PrivacyPolicy::HidePersonalInfo, surface, &privacy_key);
        assert!(
            projected == projected_again,
            "projection must be idempotent for {surface:?}"
        );
        let encoded =
            serde_json::to_string_pretty(&projected).expect("projected snapshot should encode");
        assert_eq!(
            format!("{encoded}\n"),
            include_str!("../../../fixtures/domain/privacy-redacted-v1.json"),
            "surface {surface:?} must use the shared redaction contract"
        );
    }

    assert_eq!(
        serde_json::to_string_pretty(&original.private_view())
            .expect("private snapshot view should still encode"),
        original_json,
        "projection must not mutate the private snapshot"
    );
}

#[test]
fn public_exports_diagnostics_and_fleet_sync_are_always_redacted() {
    let original = fixture();
    let privacy_key = privacy_key();
    for surface in [
        PrivacySurface::Export,
        PrivacySurface::Diagnostics,
        PrivacySurface::FleetSync,
    ] {
        let projected = original.project(PrivacyPolicy::ShowPersonalInfo, surface, &privacy_key);
        let encoded = serde_json::to_string_pretty(&projected).expect("projection should encode");
        assert_eq!(
            format!("{encoded}\n"),
            include_str!("../../../fixtures/domain/privacy-redacted-v1.json")
        );
    }

    for surface in [
        PrivacySurface::Ui,
        PrivacySurface::Notification,
        PrivacySurface::Hook,
        PrivacySurface::Cli,
        PrivacySurface::Server,
    ] {
        let trusted = original.project(PrivacyPolicy::ShowPersonalInfo, surface, &privacy_key);
        let encoded = serde_json::to_string_pretty(&trusted).expect("projection should encode");
        assert_eq!(
            format!("{encoded}\n"),
            include_str!("../../../fixtures/domain/privacy-unredacted-v1.json"),
            "trusted surface {surface:?} follows the unredacted policy"
        );
    }
}

#[test]
fn redacted_json_contains_no_identity_or_free_text_canaries() {
    let original = fixture();
    let redacted = original.project(
        PrivacyPolicy::HidePersonalInfo,
        PrivacySurface::Server,
        &privacy_key(),
    );
    let json = serde_json::to_string(&redacted).expect("projection should encode");
    for canary in [
        "ada@example.com",
        "Analytical Engines",
        "usr_ada_private",
        "Ada personal",
        "\"instance\":\"personal\"",
        "acct_fixture_7m3j",
        "/home/ada/secret-project",
        "Monthly reset",
        "September 1",
        "reset-august",
        "Private API spend",
        "Monthly credit limit",
        "rate_limit",
        "Bonus reset",
        "One additional quota reset",
        "Requests by model",
        "Cached tokens",
        "gpt-5",
        "Codex CLI",
        "local account",
        "All systems operational",
        "OAuth",
        "Pro",
    ] {
        assert!(!json.contains(canary), "redacted output leaked {canary}");
    }
    assert!(
        json.contains("account-2d7d6886316a124fa54d3ccf"),
        "stable public routing ID remains usable"
    );
    assert!(
        json.contains("window-1"),
        "safe deterministic labels remain"
    );
}

#[test]
fn projected_envelopes_cannot_be_unredacted_by_reprojection() {
    let original = fixture();
    let privacy_key = privacy_key();
    let projected = original.project(
        PrivacyPolicy::HidePersonalInfo,
        PrivacySurface::Hook,
        &privacy_key,
    );
    let reprojected = projected.project(
        PrivacyPolicy::ShowPersonalInfo,
        PrivacySurface::Ui,
        &privacy_key,
    );

    assert_eq!(projected, reprojected);
    let encoded = serde_json::to_string(&reprojected).expect("projection should encode");
    for canary in [
        "ada@example.com",
        "Analytical Engines",
        "usr_ada_private",
        "Ada personal",
        "\"instance\":\"personal\"",
        "acct_fixture_7m3j",
        "/home/ada/secret-project",
        "Monthly reset",
        "reset-august",
        "Bonus reset",
        "Cached tokens",
        "Codex CLI",
        "All systems operational",
    ] {
        assert!(!encoded.contains(canary), "reprojection leaked {canary}");
    }
}

#[test]
fn public_scope_aliases_are_stable_under_insertion_and_key_scoped() {
    fn ready_account(envelope: &SnapshotEnvelopeV1, key: &PrivacyKey) -> String {
        let value = serde_json::to_value(envelope.public_projection(key))
            .expect("public projection serializes");
        value["snapshots"]
            .as_array()
            .expect("snapshot array")
            .iter()
            .find(|snapshot| snapshot["state"] == "ready")
            .and_then(|snapshot| snapshot["last_known_good"]["scope"]["account"].as_str())
            .expect("ready public account alias")
            .to_owned()
    }

    let original = fixture();
    let key = privacy_key();
    let original_alias = ready_account(&original, &key);
    assert_eq!(original_alias, ready_account(&original, &key));

    let inserted = ProviderSnapshot::loading(AccountScope::new(
        ProviderId::Claude,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("acct_inserted_4k2m").expect("account"),
    ));
    let expanded = SnapshotEnvelopeV1::new(
        Timestamp::parse("2026-08-29T10:00:00Z").expect("timestamp"),
        vec![inserted, original.snapshots()[0].clone()],
    )
    .expect("expanded envelope");
    assert_eq!(original_alias, ready_account(&expanded, &key));

    let other_key = PrivacyKey::from_bytes([0x22; 32]);
    assert_ne!(original_alias, ready_account(&original, &other_key));
    assert!(!format!("{key:?}").contains("11"));
}

#[test]
fn redacted_wire_is_marked_and_cannot_decode_as_a_private_snapshot() {
    let projected = fixture().public_projection(&privacy_key());
    let encoded = serde_json::to_string(&projected).expect("public projection serializes");
    assert!(encoded.contains(r#""privacy":"redacted""#));
    assert!(serde_json::from_str::<SnapshotEnvelopeV1>(&encoded).is_err());
}

#[test]
fn adversarial_provider_text_is_removed_before_public_serialization() {
    let envelope = fixture();
    let mut value =
        serde_json::to_value(envelope.private_view()).expect("private fixture serializes");
    let sample = &mut value["snapshots"][0]["last_known_good"];
    sample["scope"]["instance"] = serde_json::json!("ada@example.com");
    sample["scope"]["account"] = serde_json::json!("sk_live_scope_canary");
    sample["identity"]["scope"]["instance"] = serde_json::json!("ada@example.com");
    sample["identity"]["scope"]["account"] = serde_json::json!("sk_live_scope_canary");
    sample["credits"]["scope"]["instance"] = serde_json::json!("ada@example.com");
    sample["credits"]["scope"]["account"] = serde_json::json!("sk_live_scope_canary");
    sample["credits"]["events"][0]["scope"]["instance"] = serde_json::json!("ada@example.com");
    sample["credits"]["events"][0]["scope"]["account"] = serde_json::json!("sk_live_scope_canary");
    sample["reset_credits"]["scope"]["instance"] = serde_json::json!("ada@example.com");
    sample["reset_credits"]["scope"]["account"] = serde_json::json!("sk_live_scope_canary");
    sample["reset_credits"]["credits"][0]["scope"]["instance"] =
        serde_json::json!("ada@example.com");
    sample["reset_credits"]["credits"][0]["scope"]["account"] =
        serde_json::json!("sk_live_scope_canary");
    sample["credits"]["events"][0]["service"] = serde_json::json!("private-credit-service");
    sample["credits"]["limit"]["title"] = serde_json::json!("private-credit-limit-title");
    sample["reset_credits"]["credits"][0]["status"] = serde_json::json!("private-reset-status");
    sample["status"]["description"] = serde_json::json!("private-status-description");
    sample["extensions"][0]["facts"][0]["label"] = serde_json::json!("private-extension-label");
    sample["extensions"][0]["facts"][0]["value"] = serde_json::json!({
        "type": "text",
        "value": "private-extension-value"
    });

    let seeded: SnapshotEnvelopeV1 =
        serde_json::from_value(value).expect("adversarial but valid private snapshot");
    let public = serde_json::to_string(&seeded.public_projection(&privacy_key()))
        .expect("public projection serializes");
    for canary in [
        "ada@example.com",
        "sk_live_scope_canary",
        "private-credit-service",
        "private-credit-limit-title",
        "private-reset-status",
        "private-status-description",
        "private-extension-label",
        "private-extension-value",
    ] {
        assert!(!public.contains(canary), "public output leaked {canary}");
    }
}
