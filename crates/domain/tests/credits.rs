#![allow(clippy::float_cmp)]

use oab_domain::{
    AccountKey, AccountScope, CreditEvent, CreditLimitSnapshot, CreditsSnapshot, DisplayPercent,
    ExactDecimal, MAX_CREDIT_EVENTS, MAX_REPORTED_AVAILABLE_RESET_CREDITS, PrivacyKey, ProviderId,
    ProviderInstanceId, ResetCredit, ResetCreditStatus, ResetCreditsSnapshot, Timestamp,
};

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("test decimal")
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("test timestamp")
}

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("personal").expect("instance"),
        AccountKey::new("account-one").expect("account"),
    )
}

fn event(
    key: &PrivacyKey,
    scope: &AccountScope,
    source: &str,
    occurrence: u32,
    at: &str,
    amount: &str,
) -> CreditEvent {
    CreditEvent::from_provider(
        key,
        scope,
        Some(source),
        occurrence,
        timestamp(at),
        "API",
        decimal(amount),
    )
    .expect("credit event")
}

#[test]
fn credit_events_are_exact_bounded_deterministic_and_newest_first() {
    let key = PrivacyKey::from_bytes([0x31; 32]);
    let scope = scope();
    let older = event(&key, &scope, "older", 0, "2026-08-28T10:00:00Z", "1.25");
    let newer = event(&key, &scope, "newer", 0, "2026-08-29T10:00:00Z", "2.5");
    let snapshot = CreditsSnapshot::new(
        scope.clone(),
        decimal("96.25"),
        vec![older, newer.clone()],
        timestamp("2026-08-29T10:01:00Z"),
        None,
    )
    .expect("credit snapshot");

    assert_eq!(snapshot.events()[0], newer);
    assert_eq!(snapshot.remaining(), decimal("96.25"));
    assert!(
        CreditEvent::from_provider(
            &key,
            &scope,
            Some("negative"),
            0,
            timestamp("2026-08-29T10:00:00Z"),
            "API",
            decimal("-0.01"),
        )
        .is_err()
    );

    let duplicate_id = snapshot.events()[0].id();
    let duplicate_wire = serde_json::json!({
        "scope": {
            "provider": "codex",
            "instance": "personal",
            "account": "account-one"
        },
        "remaining": "1",
        "events": [
            {
                "scope": {
                    "provider": "codex",
                    "instance": "personal",
                    "account": "account-one"
                },
                "id": duplicate_id,
                "occurred_at": "2026-08-27T10:00:00Z",
                "service": "API",
                "used": "1"
            },
            {
                "scope": {
                    "provider": "codex",
                    "instance": "personal",
                    "account": "account-one"
                },
                "id": "11111111111111111111111111111111",
                "occurred_at": "2026-08-28T10:00:00Z",
                "service": "API",
                "used": "1"
            },
            {
                "scope": {
                    "provider": "codex",
                    "instance": "personal",
                    "account": "account-one"
                },
                "id": duplicate_id,
                "occurred_at": "2026-08-30T10:00:00Z",
                "service": "API",
                "used": "2"
            }
        ],
        "updated_at": "2026-08-30T10:01:00Z",
        "limit": null
    });
    assert!(serde_json::from_value::<CreditsSnapshot>(duplicate_wire).is_err());
}

#[test]
fn monthly_limit_preserves_provider_percent_and_derives_consistent_amounts() {
    let limit = CreditLimitSnapshot::new(
        "Monthly credit limit",
        decimal("36.797"),
        decimal("1000"),
        DisplayPercent::new(96.0).expect("display percent"),
        Some(timestamp("2026-09-01T00:00:00Z")),
        timestamp("2026-08-29T09:55:00Z"),
    )
    .expect("credit limit");

    assert_eq!(limit.remaining(), decimal("963.203"));
    assert_eq!(limit.remaining_percent().get(), 96.0);
    assert_eq!(limit.used_percent().get(), 4.0);
    assert!(
        CreditLimitSnapshot::new(
            "Monthly",
            decimal("0"),
            decimal("0"),
            DisplayPercent::new(100.0).expect("display percent"),
            None,
            timestamp("2026-08-29T09:55:00Z"),
        )
        .is_err()
    );

    let inconsistent_wire = serde_json::json!({
        "title": "Monthly credit limit",
        "used": "36.797",
        "limit": "1000",
        "remaining": "999",
        "remaining_percent": 96.0,
        "resets_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-08-29T09:55:00Z"
    });
    assert!(serde_json::from_value::<CreditLimitSnapshot>(inconsistent_wire).is_err());

    let fallback = CreditLimitSnapshot::new(
        "   ",
        decimal("0"),
        decimal("1"),
        DisplayPercent::new(100.0).expect("display percent"),
        None,
        timestamp("2026-08-29T09:55:00Z"),
    )
    .expect("blank title falls back");
    assert_eq!(fallback.title(), "Monthly credit limit");
}

#[test]
fn provider_record_ids_are_stable_and_key_scope_purpose_and_occurrence_separated() {
    let key = PrivacyKey::from_bytes([0x42; 32]);
    let scope = scope();
    let first = event(&key, &scope, "provider-id", 0, "2026-08-29T10:00:00Z", "1");
    let same = event(&key, &scope, "provider-id", 0, "2026-08-29T10:00:00Z", "1");
    assert_eq!(first.id(), same.id());

    let different_occurrence = event(&key, &scope, "provider-id", 1, "2026-08-29T10:00:00Z", "1");
    assert_ne!(first.id(), different_occurrence.id());

    let other_scope = AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("work").expect("instance"),
        AccountKey::new("account-two").expect("account"),
    );
    let scoped = event(
        &key,
        &other_scope,
        "provider-id",
        0,
        "2026-08-29T10:00:00Z",
        "1",
    );
    assert_ne!(first.id(), scoped.id());

    let other_keyed = event(
        &PrivacyKey::from_bytes([0x43; 32]),
        &scope,
        "provider-id",
        0,
        "2026-08-29T10:00:00Z",
        "1",
    );
    assert_ne!(first.id(), other_keyed.id());

    let reset = ResetCredit::from_provider(
        &key,
        &scope,
        "provider-id",
        "rate_limit",
        ResetCreditStatus::Available,
        timestamp("2026-08-01T00:00:00Z"),
        None,
        None,
        None,
        None,
        None,
    )
    .expect("reset record");
    assert_ne!(first.id(), reset.id());
    assert!(!format!("{first:?}").contains(first.id()));
    assert!(!format!("{reset:?}").contains("provider-id"));
}

#[test]
fn reset_inventory_preserves_reported_evidence_without_conflating_local_availability() {
    let key = PrivacyKey::from_bytes([0x52; 32]);
    let scope = scope();
    let expiring = ResetCredit::from_provider(
        &key,
        &scope,
        "raw-reset-expiring",
        "rate_limit",
        ResetCreditStatus::Available,
        timestamp("2026-08-01T00:00:00Z"),
        Some(timestamp("2026-08-31T00:00:00Z")),
        None,
        None,
        Some("Private bonus".to_owned()),
        None,
    )
    .expect("expiring reset");
    let no_expiry = ResetCredit::from_provider(
        &key,
        &scope,
        "raw-reset-no-expiry",
        "rate_limit",
        ResetCreditStatus::Available,
        timestamp("2026-08-01T00:00:00Z"),
        None,
        None,
        None,
        None,
        None,
    )
    .expect("non-expiring reset");
    let inventory = ResetCreditsSnapshot::new(
        scope.clone(),
        vec![no_expiry, expiring.clone()],
        99,
        timestamp("2026-08-29T10:00:00Z"),
    )
    .expect("inventory");

    assert_eq!(inventory.credits()[0], expiring);
    assert_eq!(
        inventory.available_credits_at(inventory.updated_at()).len(),
        2
    );
    assert_eq!(inventory.reported_available_count(), 99);
    assert!(!inventory.reported_count_matches_inventory_at(inventory.updated_at()));
    assert!(
        ResetCreditsSnapshot::new(
            scope,
            Vec::new(),
            MAX_REPORTED_AVAILABLE_RESET_CREDITS + 1,
            timestamp("2026-08-29T10:00:00Z"),
        )
        .is_err()
    );
}

#[test]
fn credit_event_collection_is_bounded_at_the_domain_boundary() {
    let key = PrivacyKey::from_bytes([0x61; 32]);
    let scope = scope();
    let events = (0..MAX_CREDIT_EVENTS)
        .map(|index| {
            event(
                &key,
                &scope,
                "same-source",
                u32::try_from(index).expect("test index fits"),
                "2026-08-29T10:00:00Z",
                "1",
            )
        })
        .collect::<Vec<_>>();
    assert!(
        CreditsSnapshot::new(
            scope.clone(),
            decimal("1"),
            events.clone(),
            timestamp("2026-08-29T10:01:00Z"),
            None,
        )
        .is_ok()
    );
    let mut too_many = events;
    too_many.push(event(
        &key,
        &scope,
        "same-source",
        u32::try_from(MAX_CREDIT_EVENTS).expect("test bound fits"),
        "2026-08-29T10:00:00Z",
        "1",
    ));
    assert!(
        CreditsSnapshot::new(
            scope,
            decimal("1"),
            too_many,
            timestamp("2026-08-29T10:01:00Z"),
            None,
        )
        .is_err()
    );
}
