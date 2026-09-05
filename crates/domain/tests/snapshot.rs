#![allow(clippy::float_cmp)]

use oab_domain::{
    AccountKey, AccountScope, ClassifiedError, DetailChart, DetailChartKind, DetailChartPoint,
    DetailRow, DetailSection, DetailSensitivity, DisplayPercent, ErrorKind, ExtensionFact,
    ExtensionValue, FiniteNumber, ProviderExtension, ProviderExtensionKind, ProviderId,
    ProviderInstanceId, ResetCreditStatus, SnapshotEnvelopeV1, Timestamp, UnknownResetCreditStatus,
    UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use serde_json::json;

fn fixture() -> SnapshotEnvelopeV1 {
    serde_json::from_str(include_str!("../../../fixtures/domain/snapshot-v1.json"))
        .expect("snapshot fixture should decode")
}

fn sample() -> UsageSample {
    fixture().snapshots()[0]
        .last_known_good()
        .expect("snapshot fixture should contain a ready sample")
        .clone()
}

fn sample_value() -> serde_json::Value {
    let envelope = fixture();
    let value = serde_json::to_value(envelope.private_view())
        .expect("private snapshot view should serialize");
    value["snapshots"][0]["last_known_good"].clone()
}

#[test]
fn percentages_preserve_raw_values_and_clamp_only_for_display() {
    assert!(UsagePercent::new(f64::NAN).is_err());
    assert!(UsagePercent::new(f64::INFINITY).is_err());
    assert!(UsagePercent::new(f64::NEG_INFINITY).is_err());

    let over_quota = UsagePercent::new(135.25).expect("finite percentage");
    let diagnostic_negative = UsagePercent::new(-1.0).expect("finite negative diagnostic");
    assert_eq!(over_quota.get(), 135.25);
    assert_eq!(over_quota.remaining().get(), 0.0);
    assert_eq!(diagnostic_negative.remaining().get(), 101.0);
    assert_eq!(DisplayPercent::clamped(over_quota).get(), 100.0);
    assert_eq!(DisplayPercent::clamped(diagnostic_negative).get(), 0.0);

    let encoded = serde_json::to_string(&over_quota).expect("percentage should encode");
    assert_eq!(encoded, "135.25");
    assert_eq!(
        serde_json::from_str::<UsagePercent>(&encoded)
            .expect("percentage should decode")
            .get(),
        135.25
    );
}

#[test]
fn window_usage_reset_and_duration_states_do_not_collapse() {
    assert!(WindowDuration::from_seconds(0).is_err());
    assert_eq!(
        WindowDuration::from_seconds(300)
            .expect("positive duration")
            .seconds(),
        300
    );

    let snapshot = fixture();
    let sample = snapshot.snapshots()[0]
        .last_known_good()
        .expect("fixture should have last-good data");
    let primary = sample.primary().expect("primary window");
    assert!(matches!(primary.usage(), WindowUsage::Known { .. }));
    assert_eq!(primary.used_percent().expect("known usage").get(), 42.5);
    assert_eq!(
        primary.remaining_percent().expect("known usage").get(),
        57.5
    );
    assert_eq!(primary.duration().expect("duration").seconds(), 18_000);
    assert_eq!(
        primary.resets_at().expect("reset").to_string(),
        "2026-08-29T12:00:00Z"
    );

    let unknown = &sample.extra_windows()[0];
    assert!(matches!(unknown.window().usage(), WindowUsage::Unknown));
    assert!(unknown.window().used_percent().is_none());
    assert!(!unknown.window().is_synthetic_placeholder());

    let synthetic = &sample.extra_windows()[1];
    assert!(synthetic.window().is_synthetic_placeholder());
    assert_eq!(
        synthetic
            .window()
            .used_percent()
            .expect("placeholder raw value")
            .get(),
        0.0
    );
}

#[test]
fn identity_and_last_good_overlays_require_the_exact_account_scope() {
    let snapshot = fixture().snapshots()[0].clone();
    let sample = snapshot
        .last_known_good()
        .expect("fixture should have last-good data");
    let scope = sample.scope().clone();
    assert_eq!(sample.identity().scope(), &scope);
    let preserved = sample.clone();
    let error = ClassifiedError::new(ErrorKind::Network);
    let stale_since = Timestamp::parse("2026-08-29T10:01:00Z").expect("timestamp");
    let overlaid = snapshot
        .with_error_overlay(&scope, error.clone(), stale_since)
        .expect("same scope may retain last-good data");
    assert!(
        overlaid
            .last_known_good()
            .is_some_and(|sample| sample == &preserved)
    );
    assert_eq!(overlaid.error(), Some(&error));

    let mismatches = [
        AccountScope::new(
            ProviderId::Claude,
            ProviderInstanceId::new("personal").expect("instance"),
            AccountKey::new("acct_fixture_7m3j").expect("account"),
        ),
        AccountScope::new(
            ProviderId::Codex,
            ProviderInstanceId::new("work").expect("instance"),
            AccountKey::new("acct_fixture_7m3j").expect("account"),
        ),
        AccountScope::new(
            ProviderId::Codex,
            ProviderInstanceId::new("personal").expect("instance"),
            AccountKey::new("acct_other_91kq").expect("account"),
        ),
    ];
    for mismatch in mismatches {
        assert!(
            snapshot
                .with_error_overlay(&mismatch, error.clone(), stale_since)
                .is_err(),
            "cross-boundary last-good reuse must fail"
        );
    }
}

#[test]
fn snapshot_v1_round_trips_to_the_canonical_fixture() {
    let decoded = fixture();
    assert_eq!(decoded.schema_version(), 1);
    let encoded = serde_json::to_string_pretty(&decoded.private_view())
        .expect("private snapshot view should encode");
    assert_eq!(
        format!("{encoded}\n"),
        include_str!("../../../fixtures/domain/snapshot-v1.json")
    );
    assert!(
        serde_json::from_str::<SnapshotEnvelopeV1>(
            &include_str!("../../../fixtures/domain/snapshot-v1.json").replacen(
                "\"schema_version\": 1",
                "\"schema_version\": 2",
                1,
            ),
        )
        .is_err()
    );
}

#[test]
fn expanded_provider_payload_remains_typed_and_queryable() {
    let sample = sample();
    let credits = sample.credits().expect("fixture credits");
    assert_eq!(credits.remaining().to_string(), "123.45");
    assert_eq!(credits.events().len(), 1);
    assert_eq!(credits.events()[0].service(), "Private API spend");
    let credit_limit = credits.limit().expect("fixture monthly credit limit");
    assert_eq!(credit_limit.remaining().to_string(), "963.203");
    assert_eq!(credit_limit.remaining_percent().get(), 96.0);
    let cost = sample.cost().expect("fixture cost summary");
    assert_eq!(cost.used().amount().to_string(), "12.34");
    assert_eq!(cost.limit().to_string(), "100");
    assert_eq!(cost.period(), Some("Monthly"));
    assert_eq!(
        cost.personal_used().expect("personal cost").to_string(),
        "7.25"
    );
    assert_eq!(cost.balance().expect("cost balance").to_string(), "19.99");
    let reset_inventory = sample.reset_credits().expect("reset-credit inventory");
    assert_eq!(reset_inventory.credits().len(), 1);
    assert_eq!(reset_inventory.reported_available_count(), 1);
    assert_eq!(
        reset_inventory.updated_at().to_string(),
        "2026-08-29T09:58:00Z"
    );
    assert!(reset_inventory.reported_count_matches_inventory_at(sample.fetched_at()));
    let reset = &reset_inventory.credits()[0];
    assert_eq!(reset.id(), "0123456789abcdef0123456789abcdef");
    assert_eq!(reset.reset_type(), "rate_limit");
    assert_eq!(reset.status(), &ResetCreditStatus::Available);
    assert!(
        reset.is_available_at(Timestamp::parse("2026-08-29T10:00:00Z").expect("valid timestamp"))
    );
    assert_eq!(sample.available_reset_credits(sample.fetched_at()).len(), 1);

    assert_eq!(sample.detail_sections().len(), 1);
    let chart = sample.detail_sections()[0]
        .chart()
        .expect("provider detail chart");
    assert_eq!(chart.title(), Some("Requests by model"));
    assert_eq!(chart.unit(), Some("requests"));
    assert_eq!(chart.points()[0].label(), "gpt-5");
    assert_eq!(chart.points()[0].value().get(), 14.0);

    assert_eq!(sample.extensions().len(), 1);
    assert_eq!(
        sample.extensions()[0].kind(),
        ProviderExtensionKind::OpenAiApiUsage
    );
    assert_eq!(sample.extensions()[0].facts()[0].key(), "cached_tokens");
    assert_eq!(sample.status().components().len(), 1);
    assert!(sample.subscription_expires_at().is_some());
}

#[test]
fn ready_snapshot_wire_rejects_impossible_freshness_error_states() {
    let safe_error = ClassifiedError::new(ErrorKind::Network);
    let fixture_envelope = fixture();
    let mut value = serde_json::to_value(fixture_envelope.private_view())
        .expect("private fixture view serializes");
    value["snapshots"][0]["error"] = serde_json::to_value(&safe_error).expect("error serializes");
    assert!(
        serde_json::from_value::<SnapshotEnvelopeV1>(value.clone()).is_err(),
        "fresh data cannot carry an error overlay"
    );

    value["snapshots"][0]["freshness"] = json!({
        "state": "stale",
        "since": "2026-08-29T09:59:59Z"
    });
    assert!(
        serde_json::from_value::<SnapshotEnvelopeV1>(value).is_err(),
        "stale time cannot predate the retained sample"
    );

    let snapshot = fixture().snapshots()[0].clone();
    assert!(
        snapshot
            .with_error_overlay(
                sample().scope(),
                safe_error,
                Timestamp::parse("2026-08-29T09:59:59Z").expect("valid timestamp"),
            )
            .is_err()
    );
}

#[test]
fn reset_backfill_is_scoped_to_the_exact_provider_instance_and_account() {
    let cached = sample();
    let mut fresh_value = sample_value();
    fresh_value["primary"]["usage"]["used_percent"] = json!(88.0);
    fresh_value["primary"]["duration_seconds"] = serde_json::Value::Null;
    fresh_value["primary"]["resets_at"] = serde_json::Value::Null;
    fresh_value["primary"]["reset_description"] = serde_json::Value::Null;
    fresh_value["primary"]["next_regen_percent"] = json!(3.0);
    let fresh: UsageSample = serde_json::from_value(fresh_value).expect("fresh sample decodes");
    let now = Timestamp::parse("2026-08-29T10:00:00Z").expect("valid timestamp");
    let merged = fresh
        .backfilling_reset_times(&cached, now)
        .expect("same account can reuse reset metadata");
    let primary = merged.primary().expect("primary window");
    assert_eq!(primary.used_percent().expect("usage").get(), 88.0);
    assert_eq!(primary.next_regen_percent().expect("regen").get(), 3.0);
    assert_eq!(
        primary.duration().expect("cached duration").seconds(),
        18_000
    );
    assert_eq!(
        primary.resets_at().expect("cached reset").to_string(),
        "2026-08-29T12:00:00Z"
    );

    let mut other_value = sample_value();
    other_value["scope"]["account"] = json!("acct_other_91kq");
    other_value["identity"]["scope"]["account"] = json!("acct_other_91kq");
    other_value["credits"]["scope"]["account"] = json!("acct_other_91kq");
    other_value["credits"]["events"][0]["scope"]["account"] = json!("acct_other_91kq");
    other_value["reset_credits"]["scope"]["account"] = json!("acct_other_91kq");
    other_value["reset_credits"]["credits"][0]["scope"]["account"] = json!("acct_other_91kq");
    let other: UsageSample = serde_json::from_value(other_value).expect("other sample decodes");
    assert!(fresh.backfilling_reset_times(&other, now).is_err());
}

#[test]
fn nested_wire_invariants_cannot_be_bypassed_by_deserialization() {
    let fixture_envelope = fixture();
    let original = serde_json::to_value(fixture_envelope.private_view())
        .expect("private fixture view serializes");

    let mut incomplete_cost = original.clone();
    incomplete_cost["snapshots"][0]["last_known_good"]["cost"]["period_end"] =
        serde_json::Value::Null;
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(incomplete_cost).is_err());

    let mut bad_reset_state = original.clone();
    bad_reset_state["snapshots"][0]["last_known_good"]["reset_credits"]["credits"][0]["status"] =
        json!("redeemed");
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(bad_reset_state).is_err());

    let mut bad_reset_timeline = original.clone();
    bad_reset_timeline["snapshots"][0]["last_known_good"]["reset_credits"]["credits"][0]["expires_at"] =
        json!("2026-08-01T00:00:00Z");
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(bad_reset_timeline).is_err());

    let mut bad_credit_scope = original.clone();
    bad_credit_scope["snapshots"][0]["last_known_good"]["credits"]["scope"]["account"] =
        json!("other-account");
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(bad_credit_scope).is_err());

    let mut bad_inventory_scope = original.clone();
    bad_inventory_scope["snapshots"][0]["last_known_good"]["reset_credits"]["scope"]["instance"] =
        json!("other-instance");
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(bad_inventory_scope).is_err());

    let mut transplanted_credit_event = original.clone();
    transplanted_credit_event["snapshots"][0]["last_known_good"]["credits"]["events"][0]["scope"]
        ["account"] = json!("other-account");
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(transplanted_credit_event).is_err());

    let mut transplanted_reset_credit = original.clone();
    transplanted_reset_credit["snapshots"][0]["last_known_good"]["reset_credits"]["credits"][0]["scope"]
        ["account"] = json!("other-account");
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(transplanted_reset_credit).is_err());

    let extension = original["snapshots"][0]["last_known_good"]["extensions"][0].clone();
    let mut duplicate_extension = original;
    duplicate_extension["snapshots"][0]["last_known_good"]["extensions"] =
        json!([extension.clone(), extension]);
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(duplicate_extension).is_err());
}

#[test]
fn unknown_reset_statuses_are_canonical_and_cannot_shadow_reserved_values() {
    assert!(UnknownResetCreditStatus::new("available").is_err());
    assert!(UnknownResetCreditStatus::new(" private-status ").is_err());
    assert!(serde_json::from_str::<ResetCreditStatus>(r#"" available ""#).is_err());

    let unknown = ResetCreditStatus::Unknown(
        UnknownResetCreditStatus::new("provider-specific").expect("valid unknown status"),
    );
    let encoded = serde_json::to_string(&unknown).expect("unknown status serializes");
    assert_eq!(encoded, r#""provider-specific""#);
    assert_eq!(
        serde_json::from_str::<ResetCreditStatus>(&encoded).expect("status round trips"),
        unknown
    );
}

#[test]
fn absent_and_authoritatively_empty_credit_inventories_remain_distinct() {
    let mut absent = sample_value();
    absent["reset_credits"] = serde_json::Value::Null;
    let absent: UsageSample = serde_json::from_value(absent).expect("absent inventory decodes");
    assert!(absent.reset_credits().is_none());

    let mut empty = sample_value();
    empty["reset_credits"]["credits"] = json!([]);
    empty["reset_credits"]["reported_available_count"] = json!(0);
    let empty: UsageSample = serde_json::from_value(empty).expect("empty inventory decodes");
    let inventory = empty
        .reset_credits()
        .expect("authoritative empty inventory remains present");
    assert!(inventory.credits().is_empty());
    assert!(inventory.reported_count_matches_inventory_at(empty.fetched_at()));
}

#[test]
fn bounded_collections_accept_the_documented_maximum_and_reject_the_next_item() {
    let row =
        DetailRow::new("Metric", "Value", None, DetailSensitivity::Public).expect("detail row");
    assert!(DetailSection::new(None, vec![row.clone(); 24], None).is_ok());
    assert!(DetailSection::new(None, vec![row; 25], None).is_err());

    let point = DetailChartPoint::new(
        "Bucket",
        FiniteNumber::new(1.0).expect("finite chart value"),
    )
    .expect("chart point");
    assert!(DetailChart::new(DetailChartKind::Bars, None, None, vec![point.clone(); 120]).is_ok());
    assert!(DetailChart::new(DetailChartKind::Bars, None, None, vec![point; 121]).is_err());

    let facts = (0..64)
        .map(|index| {
            ExtensionFact::new(
                format!("fact-{index}"),
                "Fact",
                ExtensionValue::Boolean { value: true },
                DetailSensitivity::Public,
            )
            .expect("extension fact")
        })
        .collect::<Vec<_>>();
    assert!(
        ProviderExtension::new(
            ProviderExtensionKind::MistralUsage,
            facts.clone(),
            Vec::new()
        )
        .is_ok()
    );
    let mut too_many_facts = facts;
    too_many_facts.push(
        ExtensionFact::new(
            "fact-64",
            "Fact",
            ExtensionValue::Boolean { value: true },
            DetailSensitivity::Public,
        )
        .expect("extension fact"),
    );
    assert!(
        ProviderExtension::new(
            ProviderExtensionKind::MistralUsage,
            too_many_facts,
            Vec::new(),
        )
        .is_err()
    );

    let original = sample_value();
    let credit = original["reset_credits"]["credits"][0].clone();
    let mut at_limit = original.clone();
    at_limit["reset_credits"]["credits"] = serde_json::Value::Array(
        (0..64)
            .map(|index| {
                let mut item = credit.clone();
                item["id"] = json!(format!("{index:032x}"));
                item
            })
            .collect(),
    );
    assert!(serde_json::from_value::<UsageSample>(at_limit.clone()).is_ok());
    at_limit["reset_credits"]["credits"]
        .as_array_mut()
        .expect("reset array")
        .push({
            let mut item = credit;
            item["id"] = json!(format!("{:032x}", 64));
            item
        });
    assert!(serde_json::from_value::<UsageSample>(at_limit).is_err());
}

#[test]
fn reset_inventory_attachment_rejects_another_account() {
    let sample = sample();
    let other_scope = AccountScope::new(
        ProviderId::Codex,
        ProviderInstanceId::new("default").unwrap(),
        AccountKey::new("another-account").unwrap(),
    );
    let other =
        oab_domain::ResetCreditsSnapshot::new(other_scope, vec![], 2, sample.fetched_at()).unwrap();
    assert!(sample.clone().with_reset_credits(other).is_err());
    let own = oab_domain::ResetCreditsSnapshot::new(
        sample.scope().clone(),
        vec![],
        0,
        sample.fetched_at(),
    )
    .unwrap();
    assert_eq!(
        sample
            .with_reset_credits(own)
            .unwrap()
            .reset_credits()
            .unwrap()
            .reported_available_count(),
        0
    );
}
