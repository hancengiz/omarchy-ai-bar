use std::collections::HashSet;

use oab_auth::credential_slot::{
    CredentialSlotId, CredentialSlotIdError, MAX_CREDENTIAL_SLOT_NAME_BYTES,
};
use oab_auth::secret_store::SecretKey;
use oab_domain::{AccountKey, AccountScope, ProviderId, ProviderInstanceId};

fn scope(provider: ProviderId, instance: &str, account: &str) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new(instance).expect("instance"),
        AccountKey::new(account).expect("account"),
    )
}

#[test]
fn storage_identity_includes_provider_instance_account_and_slot() {
    let slots = [
        CredentialSlotId::new(scope(ProviderId::Codex, "default", "ambient"), "api-key")
            .expect("base slot"),
        CredentialSlotId::new(scope(ProviderId::Claude, "default", "ambient"), "api-key")
            .expect("provider slot"),
        CredentialSlotId::new(scope(ProviderId::Codex, "work", "ambient"), "api-key")
            .expect("instance slot"),
        CredentialSlotId::new(scope(ProviderId::Codex, "default", "team"), "api-key")
            .expect("account slot"),
        CredentialSlotId::new(
            scope(ProviderId::Codex, "default", "ambient"),
            "session-cookie",
        )
        .expect("named slot"),
    ];
    let keys = slots
        .iter()
        .map(|slot| slot.secret_key().clone())
        .collect::<HashSet<_>>();

    assert_eq!(keys.len(), slots.len());
    let base = &slots[0];
    assert_eq!(base.scope().provider(), ProviderId::Codex);
    assert_eq!(base.slot(), "api-key");
    assert_eq!(base.secret_key().provider(), "codex");
    assert_eq!(base.secret_key().account(), "ambient");
    assert_eq!(
        base.secret_key().purpose(),
        "credential-slot/v1/default/api-key"
    );
}

#[test]
fn slot_names_have_one_canonical_bounded_spelling() {
    let scope = scope(ProviderId::Codex, "default", "ambient");
    let maximum = "a".repeat(MAX_CREDENTIAL_SLOT_NAME_BYTES);
    assert!(CredentialSlotId::new(scope.clone(), &maximum).is_ok());
    assert_eq!(
        CredentialSlotId::new(scope.clone(), ""),
        Err(CredentialSlotIdError::Empty)
    );
    assert_eq!(
        CredentialSlotId::new(
            scope.clone(),
            "a".repeat(MAX_CREDENTIAL_SLOT_NAME_BYTES + 1),
        ),
        Err(CredentialSlotIdError::TooLarge)
    );
    for invalid in [
        "API-key", "api_key", "-api-key", "api-key-", "api--key", "api/key", " api-key",
    ] {
        assert_eq!(
            CredentialSlotId::new(scope.clone(), invalid),
            Err(CredentialSlotIdError::NonCanonical),
            "accepted noncanonical slot"
        );
    }
}

#[test]
fn slot_debug_and_errors_never_expose_identity_values() {
    let slot = CredentialSlotId::new(
        scope(ProviderId::Codex, "instance-canary", "account-canary"),
        "slot-canary",
    )
    .expect("slot");
    let error = CredentialSlotId::new(
        scope(ProviderId::Codex, "default", "ambient"),
        "Sensitive-Slot-Canary",
    )
    .expect_err("uppercase slot is noncanonical");
    let output = format!("{slot:?} {error:?} {error}");

    for canary in [
        "instance-canary",
        "account-canary",
        "slot-canary",
        "Sensitive-Slot-Canary",
    ] {
        assert!(
            !output.contains(canary),
            "identity leaked through diagnostics"
        );
    }
}

#[test]
fn legacy_manual_session_and_copilot_keys_remain_exact_and_disjoint() {
    let manual = SecretKey::new("zai", "ambient", "manual-session").expect("legacy manual key");
    assert_eq!(manual.provider(), "zai");
    assert_eq!(manual.account(), "ambient");
    assert_eq!(manual.purpose(), "manual-session");

    let copilot = SecretKey::new("copilot", "ambient", "oauth-token").expect("Copilot key");
    assert_eq!(copilot.provider(), "copilot");
    assert_eq!(copilot.account(), "ambient");
    assert_eq!(copilot.purpose(), "oauth-token");

    let named = CredentialSlotId::new(
        scope(ProviderId::Copilot, "default", "ambient"),
        "oauth-token",
    )
    .expect("named Copilot slot");
    assert_ne!(named.secret_key(), &copilot);
    assert_ne!(named.secret_key().purpose(), manual.purpose());
}
