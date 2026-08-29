use oab_domain::{
    CostProvenance, CostUnit, CostUsageCoverage, CostUsageDailyBucket, CostUsageHourlyBucket,
    CostUsageInterval, CostUsageLineItem, CostUsageMetrics, CostUsageModelBreakdown,
    CostUsageProjectBreakdown, CostUsageProjectSourceBreakdown, CostUsageSessionBreakdown,
    CostUsageSnapshot, CostUsageTokenMix, CurrencyCode, ExactDecimal, Freshness,
    MAX_COST_DAILY_BUCKETS, MAX_COST_HISTORY_DAYS, MAX_COST_MODELS, PrivacyKey, PrivacyPolicy,
    PrivacySurface, ProviderSnapshot, RefreshPhase, SnapshotEnvelopeV1, Timestamp,
};
use serde_json::{Value, json};

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::parse(value).expect("test decimal should be exact")
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("test timestamp should be valid")
}

fn coverage() -> CostUsageCoverage {
    CostUsageCoverage::new(2, 1, 1, 1).expect("bounded coverage")
}

fn metrics(amount: &str) -> CostUsageMetrics {
    CostUsageMetrics::new(
        CostUsageTokenMix::new(Some(100), Some(20), Some(30), Some(4), Some(5)),
        Some(159),
        Some(5),
        Some(decimal(amount)),
        coverage(),
    )
    .expect("valid test metrics")
}

fn model(name: &str, amount: &str) -> CostUsageModelBreakdown {
    CostUsageModelBreakdown::new(
        name,
        metrics(amount),
        Some(decimal("0.5")),
        Some(decimal("0.25")),
        Some(80),
        Some(79),
    )
    .expect("valid model breakdown")
}

fn bucket(day: &str, first_model: &str, second_model: &str) -> CostUsageDailyBucket {
    CostUsageDailyBucket::new(
        day,
        Some(
            CostUsageInterval::new(
                timestamp(&format!("{day}T00:00:00Z")),
                timestamp(&format!("{day}T23:59:59Z")),
            )
            .expect("valid daily interval"),
        ),
        metrics("1.75"),
        vec![first_model.to_owned(), second_model.to_owned()],
        vec![model(first_model, "1"), model(second_model, "0.75")],
        vec![
            CostUsageLineItem::new("z-private-line-item", decimal("0.75")).expect("line item"),
            CostUsageLineItem::new("a-private-line-item", decimal("1")).expect("line item"),
        ],
    )
    .expect("valid daily bucket")
}

fn source(name: &str, path: &str) -> CostUsageProjectSourceBreakdown {
    CostUsageProjectSourceBreakdown::new(
        name,
        Some(path.to_owned()),
        metrics("1.75"),
        vec![bucket("2026-08-28", "z-private-model", "a-private-model")],
        vec![model("z-private-model", "1.75")],
    )
    .expect("valid project source")
}

fn project(name: &str, path: &str) -> CostUsageProjectBreakdown {
    CostUsageProjectBreakdown::new(
        name,
        Some(path.to_owned()),
        metrics("3.5"),
        vec![bucket("2026-08-29", "z-private-model", "a-private-model")],
        vec![
            model("z-private-model", "1.75"),
            model("a-private-model", "1.75"),
        ],
        vec![
            source("z-private-source", "/home/ada/z-private-source"),
            source("a-private-source", "/home/ada/a-private-source"),
        ],
    )
    .expect("valid project")
}

fn full_snapshot(unit: CostUnit) -> CostUsageSnapshot {
    CostUsageSnapshot::new(
        unit,
        metrics("1.75"),
        metrics("7.5"),
        Some(decimal("6.25")),
        30,
        true,
        Some("Private billing history".to_owned()),
        Some("credential-fingerprint-private".to_owned()),
        vec![
            bucket("2026-08-29", "z-private-model", "a-private-model"),
            bucket("2026-08-28", "z-private-model", "a-private-model"),
        ],
        vec![
            project("z-private-project", "/home/ada/z-private-project"),
            project("a-private-project", "/home/ada/a-private-project"),
        ],
        vec![
            CostUsageSessionBreakdown::new(
                "z-private-session",
                timestamp("2026-08-29T09:00:00Z"),
                metrics("1"),
                vec![model("z-private-model", "1")],
            )
            .expect("valid session"),
            CostUsageSessionBreakdown::new(
                "a-private-session",
                timestamp("2026-08-29T08:00:00Z"),
                metrics("0.75"),
                vec![model("a-private-model", "0.75")],
            )
            .expect("valid session"),
        ],
        vec![
            CostUsageHourlyBucket::new(timestamp("2026-08-29T09:00:00Z"), metrics("1")),
            CostUsageHourlyBucket::new(timestamp("2026-08-29T08:00:00Z"), metrics("0.75")),
        ],
        timestamp("2026-08-29T10:00:00Z"),
        CostProvenance::Mixed,
    )
    .expect("valid full cost snapshot")
}

fn envelope_with_cost(cost_usage: CostUsageSnapshot) -> SnapshotEnvelopeV1 {
    let fixture: SnapshotEnvelopeV1 =
        serde_json::from_str(include_str!("../../../fixtures/domain/snapshot-v1.json"))
            .expect("domain fixture should decode");
    let sample = fixture.snapshots()[0]
        .last_known_good()
        .expect("fixture ready sample")
        .clone()
        .with_cost_usage(cost_usage);
    let provider = ProviderSnapshot::ready(sample, Freshness::Fresh, RefreshPhase::Idle, None)
        .expect("fresh snapshot without error");
    SnapshotEnvelopeV1::new(fixture.generated_at(), vec![provider]).expect("single-scope envelope")
}

fn private_value(cost_usage: CostUsageSnapshot) -> Value {
    let envelope = envelope_with_cost(cost_usage);
    serde_json::to_value(envelope.private_view()).expect("trusted envelope should serialize")
}

fn cost_value(value: &mut Value) -> &mut Value {
    &mut value["snapshots"][0]["last_known_good"]["cost_usage"]
}

#[test]
fn typed_snapshot_carries_baseline_mechanics_and_sorts_every_key() {
    let snapshot = full_snapshot(CostUnit::currency(
        CurrencyCode::new("usd").expect("currency"),
    ));

    assert_eq!(snapshot.unit().as_str(), "USD");
    assert_eq!(snapshot.history_days(), 30);
    assert!(snapshot.history_coverage_is_established());
    assert_eq!(snapshot.history_label(), Some("Private billing history"));
    assert_eq!(snapshot.metered_amount(), Some(decimal("6.25")));
    assert_eq!(snapshot.provenance(), CostProvenance::Mixed);

    let mix = snapshot.history().token_mix();
    assert_eq!(mix.input_tokens(), Some(100));
    assert_eq!(mix.output_tokens(), Some(20));
    assert_eq!(mix.cache_read_tokens(), Some(30));
    assert_eq!(mix.cache_creation_tokens(), Some(4));
    assert_eq!(mix.reasoning_tokens(), Some(5));
    assert_eq!(snapshot.history().request_count(), Some(5));
    assert_eq!(snapshot.history().coverage().priced(), 2);
    assert_eq!(snapshot.history().coverage().unpriced(), 1);
    assert_eq!(snapshot.history().coverage().unmetered(), 1);
    assert_eq!(snapshot.history().coverage().estimated(), 1);

    assert_eq!(snapshot.daily()[0].day(), "2026-08-28");
    let open_ai_bucket = &snapshot.daily()[0];
    assert!(open_ai_bucket.interval().is_some());
    assert_eq!(open_ai_bucket.models()[0].name(), "a-private-model");
    assert_eq!(
        open_ai_bucket.models()[0].metrics().request_count(),
        Some(5)
    );
    assert_eq!(open_ai_bucket.line_items()[0].name(), "a-private-line-item");
    assert_eq!(
        open_ai_bucket.models_used().collect::<Vec<_>>(),
        vec!["a-private-model", "z-private-model"]
    );

    assert_eq!(snapshot.projects()[0].name(), "a-private-project");
    assert_eq!(
        snapshot.projects()[0].path(),
        Some("/home/ada/a-private-project")
    );
    assert_eq!(
        snapshot.projects()[0].sources()[0].name(),
        "a-private-source"
    );
    assert_eq!(snapshot.sessions()[0].session_id(), "a-private-session");
    assert_eq!(
        snapshot.hourly()[0].hour(),
        timestamp("2026-08-29T08:00:00Z")
    );
}

#[test]
fn trusted_wire_round_trips_and_revalidates_nested_invariants() {
    let original = private_value(full_snapshot(CostUnit::currency(
        CurrencyCode::new("USD").expect("currency"),
    )));
    let decoded: SnapshotEnvelopeV1 =
        serde_json::from_value(original.clone()).expect("trusted wire should decode");
    assert_eq!(
        serde_json::to_value(decoded.private_view()).expect("decoded trusted wire serializes"),
        original,
        "validated decoding must retain the canonical private wire"
    );
    let decoded_cost = decoded.snapshots()[0]
        .last_known_good()
        .and_then(|sample| sample.cost_usage())
        .expect("typed cost usage survives decoding");
    assert_eq!(decoded_cost.history_days(), 30);
    assert_eq!(decoded_cost.daily().len(), 2);

    let mut invalid_days = original.clone();
    cost_value(&mut invalid_days)["history_days"] = json!(0);
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(invalid_days).is_err());

    let mut invalid_interval = original.clone();
    let start = cost_value(&mut invalid_interval)["daily"][0]["interval"]["start"].clone();
    cost_value(&mut invalid_interval)["daily"][0]["interval"]["end"] = start;
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(invalid_interval).is_err());

    let mut duplicate_model = original.clone();
    let first_model = cost_value(&mut duplicate_model)["daily"][0]["models"][0].clone();
    cost_value(&mut duplicate_model)["daily"][0]["models"] =
        json!([first_model.clone(), first_model]);
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(duplicate_model).is_err());

    let mut negative_amount = original.clone();
    cost_value(&mut negative_amount)["metered_amount"] = json!("-0.01");
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(negative_amount).is_err());

    let mut unknown = original;
    cost_value(&mut unknown)["unexpected"] = json!(true);
    assert!(serde_json::from_value::<SnapshotEnvelopeV1>(unknown).is_err());
}

#[test]
fn public_projection_removes_private_names_but_keeps_numeric_mechanics() {
    let private =
        full_snapshot(CostUnit::provider("private-provider-unit").expect("provider unit"));
    let envelope = envelope_with_cost(private);
    let projected = envelope.project(
        PrivacyPolicy::HidePersonalInfo,
        PrivacySurface::Ui,
        &PrivacyKey::from_bytes([0x77; 32]),
    );
    let value = serde_json::to_value(projected).expect("public projection serializes");
    let encoded = serde_json::to_string(&value).expect("public JSON");

    for private_canary in [
        "credential-fingerprint-private",
        "Private billing history",
        "private-provider-unit",
        "a-private-project",
        "/home/ada/a-private-project",
        "a-private-source",
        "a-private-session",
        "a-private-model",
        "a-private-line-item",
    ] {
        assert!(
            !encoded.contains(private_canary),
            "public projection leaked {private_canary}"
        );
    }

    let cost = &value["snapshots"][0]["last_known_good"]["cost_usage"];
    assert_eq!(cost["unit"], json!({"kind": "provider", "unit": "credits"}));
    assert_eq!(cost["history_label"], Value::Null);
    assert_eq!(cost["credential_scope_fingerprint"], Value::Null);
    assert_eq!(cost["metered_amount"], json!("6.25"));
    assert_eq!(cost["history"]["token_mix"]["cache_read_tokens"], 30);
    assert_eq!(cost["history"]["coverage"]["unmetered"], 1);
    assert_eq!(cost["daily"].as_array().expect("daily").len(), 2);
    assert_eq!(cost["daily"][0]["models"][0]["name"], "model-1");
    assert_eq!(cost["daily"][0]["line_items"][0]["name"], "line-item-1");
    assert_eq!(cost["projects"][0]["name"], "project-1");
    assert_eq!(cost["projects"][0]["path"], Value::Null);
    assert_eq!(cost["projects"][0]["sources"][0]["name"], "source-1");
    assert_eq!(cost["sessions"][0]["session_id"], "session-1");
    assert_eq!(cost["hourly"][0]["metrics"]["total_tokens"], 159);
}

#[test]
#[allow(clippy::too_many_lines)]
fn bounds_dates_amounts_and_coverage_fail_closed() {
    assert!(CostUsageCoverage::new(u64::MAX, 1, 0, 0).is_err());
    assert!(
        CostUsageMetrics::new(
            CostUsageTokenMix::default(),
            None,
            Some(1),
            None,
            CostUsageCoverage::new(2, 0, 0, 0).expect("representable coverage"),
        )
        .is_err()
    );
    assert!(
        CostUsageMetrics::new(
            CostUsageTokenMix::default(),
            None,
            None,
            Some(decimal("-1")),
            CostUsageCoverage::default(),
        )
        .is_err()
    );
    assert!(
        CostUsageInterval::new(
            timestamp("2026-08-29T10:00:00Z"),
            timestamp("2026-08-29T10:00:00Z")
        )
        .is_err()
    );
    for invalid_day in ["2026-02-29", "2026-13-01", "2026-01-32", "20260829"] {
        assert!(
            CostUsageDailyBucket::new(
                invalid_day,
                None,
                metrics("0"),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .is_err()
        );
    }
    assert!(
        CostUsageDailyBucket::new(
            "2024-02-29",
            None,
            metrics("0"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .is_ok()
    );

    let too_many_models = (0..=MAX_COST_MODELS)
        .map(|index| model(&format!("model-{index:03}"), "0"))
        .collect();
    assert!(
        CostUsageDailyBucket::new(
            "2026-08-29",
            None,
            metrics("0"),
            Vec::new(),
            too_many_models,
            Vec::new(),
        )
        .is_err()
    );

    let daily = (1..=MAX_COST_DAILY_BUCKETS)
        .map(|ordinal| {
            let ordinal = u16::try_from(ordinal).expect("daily bound fits u16");
            let day = time::Date::from_ordinal_date(2025, ordinal)
                .expect("2025 ordinal")
                .to_string();
            CostUsageDailyBucket::new(day, None, metrics("0"), Vec::new(), Vec::new(), Vec::new())
                .expect("bounded daily bucket")
        })
        .collect::<Vec<_>>();
    let make = |history_days, daily| {
        CostUsageSnapshot::new(
            CostUnit::currency(CurrencyCode::new("USD").expect("currency")),
            metrics("0"),
            metrics("0"),
            None,
            history_days,
            true,
            None,
            None,
            daily,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            timestamp("2026-08-29T10:00:00Z"),
            CostProvenance::Unknown,
        )
    };
    assert!(make(MAX_COST_HISTORY_DAYS, daily.clone()).is_ok());
    let mut too_many_days = daily;
    too_many_days.push(
        CostUsageDailyBucket::new(
            "2026-01-01",
            None,
            metrics("0"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("extra daily bucket"),
    );
    assert!(make(MAX_COST_HISTORY_DAYS, too_many_days).is_err());
    assert!(make(0, Vec::new()).is_err());
    assert!(make(MAX_COST_HISTORY_DAYS + 1, Vec::new()).is_err());
}
