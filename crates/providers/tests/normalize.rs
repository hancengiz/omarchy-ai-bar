use oab_domain::{
    AccountKey, AccountScope, CreditsSnapshot, ErrorKind, ExactDecimal, ProviderId,
    ProviderInstanceId, Timestamp,
};
use oab_providers::normalize::UsageSampleBuilder;

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("codex-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn timestamp() -> Timestamp {
    Timestamp::parse("2026-08-30T12:00:00Z").expect("test timestamp")
}

fn credits(scope: AccountScope, remaining: &str) -> CreditsSnapshot {
    CreditsSnapshot::new(
        scope,
        ExactDecimal::parse(remaining).expect("credit balance"),
        Vec::new(),
        timestamp(),
        None,
    )
    .expect("credit snapshot")
}

#[test]
fn builder_attaches_same_scope_credits() {
    let scope = scope("account-one");
    let sample = UsageSampleBuilder::new(scope.clone(), timestamp())
        .credits(credits(scope, "42.5"))
        .build()
        .expect("same-scope credits");

    assert_eq!(
        sample.credits().expect("attached credits").remaining(),
        ExactDecimal::parse("42.5").expect("expected balance")
    );
}

#[test]
fn credits_only_identity_sample_builds_without_quota_windows() {
    let scope = scope("account-one");
    let sample = UsageSampleBuilder::new(scope.clone(), timestamp())
        .email(Some("person@example.com".to_owned()))
        .expect("identity")
        .credits(credits(scope, "7"))
        .build()
        .expect("credits-only identity sample");

    assert!(sample.primary().is_none());
    assert!(sample.secondary().is_none());
    assert!(sample.tertiary().is_none());
    assert_eq!(
        sample.identity().email().expect("email").as_str(),
        "person@example.com"
    );
    assert_eq!(
        sample.credits().expect("credits").remaining(),
        ExactDecimal::parse("7").expect("expected balance")
    );
}

#[test]
fn credits_scope_mismatch_is_a_stable_parse_error() {
    let sample_scope = scope("account-one");
    let foreign_credits = credits(scope("account-two"), "3");
    let error = UsageSampleBuilder::new(sample_scope, timestamp())
        .credits(foreign_credits)
        .build()
        .expect_err("scope mismatch must fail");

    assert_eq!(error.kind(), ErrorKind::Parse);
}
