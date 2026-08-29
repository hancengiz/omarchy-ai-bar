#![allow(clippy::float_cmp, clippy::needless_pass_by_value)]

use oab_domain::{
    BoundedText, NamedRateWindow, ProviderHealth, ProviderId, ProviderStatus, RateWindow,
    Timestamp, UsagePercent, WindowDuration, WindowUsage,
};
use serde_json::{Value, json};

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("valid timestamp")
}

fn percent(value: f64) -> UsagePercent {
    UsagePercent::new(value).expect("finite percentage")
}

fn window(
    used_percent: f64,
    duration: Option<u64>,
    resets_at: Option<Timestamp>,
    reset_description: Option<&str>,
    next_regen_percent: Option<f64>,
    synthetic_placeholder: bool,
) -> RateWindow {
    RateWindow::new(
        WindowUsage::known(percent(used_percent)),
        duration.map(|seconds| WindowDuration::from_seconds(seconds).expect("positive duration")),
        resets_at,
        reset_description
            .map(|description| BoundedText::<120>::new(description).expect("bounded description")),
        next_regen_percent.map(percent),
        synthetic_placeholder,
    )
    .expect("valid rate window")
}

#[test]
fn rate_window_public_projection_keeps_mechanics_and_removes_text() {
    let placeholder = window(
        0.0,
        Some(300),
        Some(timestamp("2026-08-29T11:00:00Z")),
        Some("private reset"),
        None,
        true,
    );
    assert!(placeholder.is_synthetic_placeholder());
    assert_eq!(placeholder.used_percent().expect("known zero").get(), 0.0);

    let projected = placeholder.without_personal_information();
    assert_eq!(projected.resets_at(), placeholder.resets_at());
    assert!(projected.reset_description().is_none());
    assert!(projected.is_synthetic_placeholder());

    let named = NamedRateWindow::new(
        BoundedText::<128>::new("workspace-ada").expect("bounded ID"),
        BoundedText::<120>::new("Ada private workspace").expect("bounded title"),
        placeholder,
    );
    let projected_named = NamedRateWindow::public_projection(&[named]);
    assert_eq!(projected_named[0].id().as_str(), "window-1");
    assert_eq!(projected_named[0].title().as_str(), "Window 1");
    assert!(projected_named[0].window().reset_description().is_none());
}

fn component(id: &str, children: Vec<Value>) -> Value {
    json!({
        "id": id,
        "name": format!("{id} component"),
        "health": "degraded",
        "raw_status": "degraded_performance",
        "children": children,
    })
}

fn status_json(components: Vec<Value>) -> Value {
    json!({
        "health": "operational",
        "description": "private provider message",
        "checked_at": "2026-08-29T10:00:00Z",
        "incidents": [],
        "components": components,
    })
}

#[test]
fn status_components_sort_deterministically_and_public_projection_drops_source_text() {
    let status: ProviderStatus = serde_json::from_value(status_json(vec![
        component("zeta", vec![]),
        component("alpha", vec![]),
    ]))
    .expect("valid status component feed");
    let wire = serde_json::to_value(&status).expect("status serializes");
    assert_eq!(wire["components"][0]["id"], "alpha");
    assert_eq!(wire["components"][1]["id"], "zeta");

    let public = status.without_personal_information();
    assert_eq!(public.health(), ProviderHealth::Operational);
    assert_eq!(public.checked_at(), Some(timestamp("2026-08-29T10:00:00Z")));
    let public_wire = serde_json::to_value(public).expect("public status serializes");
    assert!(public_wire.get("description").is_some_and(Value::is_null));
    assert_eq!(public_wire["incidents"], json!([]));
    assert!(public_wire.get("components").is_none());
}

#[test]
fn status_component_deserialization_rejects_unknown_duplicate_excessive_and_too_deep_trees() {
    let mut unknown = status_json(vec![component("alpha", vec![])]);
    unknown["components"][0]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<ProviderStatus>(unknown).is_err());

    assert!(
        serde_json::from_value::<ProviderStatus>(status_json(vec![
            component("same", vec![]),
            component("same", vec![]),
        ]))
        .is_err()
    );

    let excessive = (0..65)
        .map(|index| component(&format!("component-{index}"), vec![]))
        .collect();
    assert!(serde_json::from_value::<ProviderStatus>(status_json(excessive)).is_err());

    let depth_five = component(
        "one",
        vec![component(
            "two",
            vec![component(
                "three",
                vec![component("four", vec![component("five", vec![])])],
            )],
        )],
    );
    assert!(serde_json::from_value::<ProviderStatus>(status_json(vec![depth_five])).is_err());

    let depth_four = component(
        "one",
        vec![component(
            "two",
            vec![component("three", vec![component("four", vec![])])],
        )],
    );
    assert!(serde_json::from_value::<ProviderStatus>(status_json(vec![depth_four])).is_ok());
}

#[test]
fn status_incident_deserialization_rejects_contradictory_timestamps() {
    let mut value = status_json(Vec::new());
    value["incidents"] = json!([{
        "id": "incident-1",
        "title": "Incident",
        "health": "degraded",
        "started_at": "2026-08-29T10:00:00Z",
        "updated_at": "2026-08-29T09:59:59Z",
        "resolved_at": null,
        "description": null
    }]);
    assert!(serde_json::from_value::<ProviderStatus>(value).is_err());
}

#[test]
fn validation_errors_never_echo_provider_controlled_identifiers() {
    let canary = "sk-proj-validation-canary";
    let duplicate_window = NamedRateWindow::new(
        BoundedText::<128>::new(canary).expect("bounded ID"),
        BoundedText::<120>::new("Window").expect("bounded title"),
        window(1.0, None, None, None, None, false),
    );
    let window_error =
        NamedRateWindow::validate_unique_ids(&[duplicate_window.clone(), duplicate_window])
            .expect_err("duplicate named windows fail");
    assert!(!window_error.to_string().contains(canary));

    let status: ProviderStatus =
        serde_json::from_value(status_json(vec![component(canary, vec![])]))
            .expect("one component is valid");
    let component = status.components()[0].clone();
    let status_error = ProviderStatus::with_components(
        ProviderHealth::Operational,
        None,
        None,
        Vec::new(),
        vec![component.clone(), component],
    )
    .expect_err("duplicate components fail");
    assert!(!status_error.to_string().contains(canary));

    let provider_error = canary
        .parse::<ProviderId>()
        .expect_err("unknown provider fails");
    assert!(!provider_error.to_string().contains(canary));
}
