use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use oab_domain::ProviderId;
use oab_providers::registry::PROVIDERS;
use serde_json::Value;

const REQUIRED_PROVIDER_CELLS: [&str; 9] = [
    "authentication",
    "usage_resets",
    "costs_history",
    "sessions",
    "browser",
    "status_errors",
    "refresh",
    "cli_server",
    "qml_ui",
];

const REQUIRED_FEATURE_CELLS: [&str; 3] = ["implementation", "integration", "verification"];

const REQUIRED_FEATURES: [&str; 37] = [
    "privacy-redaction",
    "per-account-bar-items",
    "claude-swap",
    "preferred-currency",
    "cost-controls",
    "models-dev-pricing",
    "advanced-display",
    "config-cli",
    "cards-dashboard",
    "provider-storage",
    "share-export",
    "diagnostics",
    "multi-account",
    "bar-popup",
    "settings",
    "refresh-status-notifications",
    "sessions-hooks",
    "user-plugins",
    "browser-auth",
    "local-server",
    "fleet-sync",
    "localization-rtl",
    "aur-packaging",
    "sni-fallback",
    "secret-service",
    "widget-forms",
    "cost-history",
    "private-ipc",
    "daemon-lifecycle",
    "bridge-lifecycle",
    "hyprland-integration",
    "provider-login-actions",
    "accessibility-keyboard",
    "reduced-motion",
    "multi-monitor-scaling",
    "apple-secret-sync",
    "apple-widget-host-semantics",
];

const PROVIDER_RECORD_STATUSES: [&str; 3] = ["planned", "in-progress", "passing"];
const REQUIRED_FEATURE_STATUSES: [&str; 3] = ["planned", "in-progress", "passing"];
const CELL_STATUSES: [&str; 4] = ["planned", "in-progress", "passing", "not-applicable"];
const APPROVED_OMISSIONS: [&str; 2] = ["apple-secret-sync", "apple-widget-host-semantics"];

fn parity_file(name: &str) -> Value {
    let bytes =
        fs::read(workspace_root().join("parity").join(name)).expect("parity file should exist");
    serde_json::from_slice(&bytes).expect("parity file should be valid JSON")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("providers crate should be under workspace root")
        .to_owned()
}

fn non_empty_strings<'a>(value: &'a Value, context: &str) -> Result<Vec<&'a str>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|text| !text.is_empty())
                .ok_or_else(|| format!("{context} entries must be non-empty strings"))
        })
        .collect()
}

fn validate_required_cells(ledger: &Value, expected: &[&str]) -> Result<BTreeSet<String>, String> {
    let declared = non_empty_strings(&ledger["required_cells"], "required_cells")?;
    let declared_set: BTreeSet<String> = declared.iter().map(|cell| (*cell).to_owned()).collect();
    let expected_set: BTreeSet<String> = expected.iter().map(|cell| (*cell).to_owned()).collect();

    if declared.len() != declared_set.len() {
        return Err("required_cells contains a duplicate".to_owned());
    }
    if declared_set != expected_set {
        return Err("required_cells does not match the closed schema".to_owned());
    }
    Ok(declared_set)
}

fn validate_portable_paths(paths: &[&str], context: &str) -> Result<(), String> {
    for path in paths {
        let path = Path::new(path);
        if path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
            return Err(format!(
                "{context} contains a non-portable path: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_test_references(tests: &[&str], context: &str) -> Result<(), String> {
    validate_portable_paths(tests, context)?;
    let workspace = workspace_root();
    for test in tests {
        let path = Path::new(test);
        let is_test_artifact = path
            .components()
            .any(|component| component.as_os_str() == "tests")
            && matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("rs" | "sh" | "qml")
            );
        if !is_test_artifact {
            return Err(format!(
                "{context} must reference a Rust, shell, or QML file under a tests directory: {test}"
            ));
        }
        if !workspace.join(path).is_file() {
            return Err(format!("{context} references a missing test file: {test}"));
        }
    }
    Ok(())
}

fn validate_tracking(
    entry: &Value,
    context: &str,
    required_cells: &BTreeSet<String>,
    allowed_record_statuses: &[&str],
    allow_not_applicable: bool,
) -> Result<(String, Vec<String>), String> {
    let sources = non_empty_strings(
        &entry["baseline_sources"],
        &format!("{context}.baseline_sources"),
    )?;
    validate_portable_paths(&sources, &format!("{context}.baseline_sources"))?;

    if let Some(platform_sources) = entry.get("platform_sources") {
        non_empty_strings(platform_sources, &format!("{context}.platform_sources"))?;
    }

    let tests = non_empty_strings(&entry["tests"], &format!("{context}.tests"))?;
    validate_test_references(&tests, &format!("{context}.tests"))?;
    let record_status = entry["status"]
        .as_str()
        .ok_or_else(|| format!("{context}.status must be a string"))?;
    if !allowed_record_statuses.contains(&record_status) {
        return Err(format!(
            "{context} has unknown record status: {record_status}"
        ));
    }

    let cells = entry["cells"]
        .as_object()
        .ok_or_else(|| format!("{context}.cells must be an object"))?;
    let actual_cells: BTreeSet<String> = cells.keys().cloned().collect();
    if &actual_cells != required_cells {
        return Err(format!("{context}.cells does not match required_cells"));
    }

    let cell_statuses: Vec<String> = cells
        .iter()
        .map(|(cell, status)| {
            let status = status
                .as_str()
                .ok_or_else(|| format!("{context}.cells.{cell} must be a string"))?;
            if !CELL_STATUSES.contains(&status) {
                return Err(format!(
                    "{context}.cells.{cell} has unknown status: {status}"
                ));
            }
            Ok(status.to_owned())
        })
        .collect::<Result<_, String>>()?;

    let all_planned = cell_statuses.iter().all(|status| status == "planned");
    let all_complete = cell_statuses
        .iter()
        .all(|status| matches!(status.as_str(), "passing" | "not-applicable"));
    let passing_cells = cell_statuses
        .iter()
        .filter(|status| *status == "passing")
        .count();
    let not_applicable_cells: BTreeSet<&str> = cells
        .iter()
        .filter(|(_, status)| *status == "not-applicable")
        .map(|(cell, _)| cell.as_str())
        .collect();
    if !allow_not_applicable && !not_applicable_cells.is_empty() {
        return Err(format!("{context} cannot have not-applicable cells"));
    }
    validate_not_applicable_reasons(entry, context, &not_applicable_cells)?;

    match record_status {
        "planned" if !all_planned => {
            return Err(format!("{context} is planned but has non-planned cells"));
        }
        "in-progress" if all_planned || all_complete => {
            return Err(format!("{context} has an inconsistent in-progress status"));
        }
        "passing" if !all_complete => {
            return Err(format!("{context} is passing but has incomplete cells"));
        }
        "passing" if passing_cells == 0 => {
            return Err(format!("{context} is passing without a passing cell"));
        }
        _ => {}
    }
    if passing_cells != 0 && tests.is_empty() {
        return Err(format!(
            "{context} has passing cells without test references"
        ));
    }

    Ok((record_status.to_owned(), cell_statuses))
}

fn validate_not_applicable_reasons(
    entry: &Value,
    context: &str,
    not_applicable_cells: &BTreeSet<&str>,
) -> Result<(), String> {
    let reasons = entry.get("not_applicable_reasons");
    if not_applicable_cells.is_empty() {
        if reasons.is_some_and(|reasons| {
            reasons
                .as_object()
                .is_none_or(|reasons| !reasons.is_empty())
        }) {
            return Err(format!(
                "{context} has reasons without not-applicable cells"
            ));
        }
        return Ok(());
    }

    let reasons = reasons
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{context}.not_applicable_reasons must be an object"))?;
    let reason_cells: BTreeSet<&str> = reasons.keys().map(String::as_str).collect();
    if &reason_cells != not_applicable_cells {
        return Err(format!(
            "{context} must explain every not-applicable cell exactly once"
        ));
    }
    if !reasons
        .values()
        .all(|reason| reason.as_str().is_some_and(|reason| !reason.is_empty()))
    {
        return Err(format!("{context} has an empty not-applicable reason"));
    }
    Ok(())
}

fn validate_provider_ledger(ledger: &Value) -> Result<(), String> {
    if ledger["schema_version"] != 1 {
        return Err("provider ledger schema_version must be 1".to_owned());
    }
    let required_cells = validate_required_cells(ledger, &REQUIRED_PROVIDER_CELLS)?;
    let providers = ledger["providers"]
        .as_array()
        .ok_or_else(|| "providers must be an array".to_owned())?;
    if providers.len() != ProviderId::ALL.len() {
        return Err("provider ledger has the wrong record count".to_owned());
    }

    let mut actual = BTreeSet::new();
    for (index, entry) in providers.iter().enumerate() {
        let id = entry["id"]
            .as_str()
            .ok_or_else(|| format!("providers[{index}].id must be a string"))?;
        let provider: ProviderId = id
            .parse()
            .map_err(|error| format!("providers[{index}]: {error}"))?;
        if !actual.insert(provider) {
            return Err(format!("duplicate provider record: {id}"));
        }
        validate_tracking(
            entry,
            &format!("providers[{index}]"),
            &required_cells,
            &PROVIDER_RECORD_STATUSES,
            true,
        )?;
    }

    let expected: BTreeSet<ProviderId> = ProviderId::ALL.into_iter().collect();
    if actual != expected {
        return Err("provider ledger does not match the closed registry".to_owned());
    }
    Ok(())
}

fn validate_feature_ledger(ledger: &Value) -> Result<(), String> {
    if ledger["schema_version"] != 1 {
        return Err("feature ledger schema_version must be 1".to_owned());
    }
    let required_cells = validate_required_cells(ledger, &REQUIRED_FEATURE_CELLS)?;
    let features = ledger["features"]
        .as_array()
        .ok_or_else(|| "features must be an array".to_owned())?;
    if features.len() != REQUIRED_FEATURES.len() {
        return Err("feature ledger has the wrong record count".to_owned());
    }

    let expected: BTreeSet<&str> = REQUIRED_FEATURES.into_iter().collect();
    let approved_omissions: BTreeSet<&str> = APPROVED_OMISSIONS.into_iter().collect();
    let mut actual = BTreeSet::new();
    for (index, entry) in features.iter().enumerate() {
        let context = format!("features[{index}]");
        let id = entry["id"]
            .as_str()
            .ok_or_else(|| format!("{context}.id must be a string"))?;
        if !expected.contains(id) {
            return Err(format!("unrecognized feature record: {id}"));
        }
        if !actual.insert(id) {
            return Err(format!("duplicate feature record: {id}"));
        }
        let mapping = entry["omarchy_mapping"]
            .as_str()
            .filter(|mapping| !mapping.is_empty())
            .ok_or_else(|| format!("{context}.omarchy_mapping must be non-empty"))?;
        let _ = mapping;

        match entry["disposition"].as_str() {
            Some("required") if !approved_omissions.contains(id) => {
                validate_tracking(
                    entry,
                    &context,
                    &required_cells,
                    &REQUIRED_FEATURE_STATUSES,
                    false,
                )?;
            }
            Some("unsupported-approved") if approved_omissions.contains(id) => {
                validate_approved_omission(entry, &context, &required_cells)?;
            }
            Some(disposition) => {
                return Err(format!("{context} has invalid disposition: {disposition}"));
            }
            None => return Err(format!("{context}.disposition must be a string")),
        }
    }

    if actual != expected {
        return Err("feature ledger does not match the closed feature set".to_owned());
    }
    Ok(())
}

fn validate_approved_omission(
    entry: &Value,
    context: &str,
    required_cells: &BTreeSet<String>,
) -> Result<(), String> {
    let sources = non_empty_strings(
        &entry["baseline_sources"],
        &format!("{context}.baseline_sources"),
    )?;
    validate_portable_paths(&sources, &format!("{context}.baseline_sources"))?;
    let tests = non_empty_strings(&entry["tests"], &format!("{context}.tests"))?;
    if tests.is_empty() {
        return Err(format!("{context} must cite approval-test evidence"));
    }
    validate_test_references(&tests, &format!("{context}.tests"))?;
    entry["unsupported_reason"]
        .as_str()
        .filter(|reason| !reason.is_empty())
        .ok_or_else(|| format!("{context}.unsupported_reason must be non-empty"))?;
    if entry["status"] != "unsupported-approved" {
        return Err(format!("{context}.status must be unsupported-approved"));
    }
    let cells = entry["cells"]
        .as_object()
        .ok_or_else(|| format!("{context}.cells must be an object"))?;
    let actual_cells: BTreeSet<String> = cells.keys().cloned().collect();
    if &actual_cells != required_cells
        || !cells
            .values()
            .all(|status| status == "unsupported-approved")
    {
        return Err(format!("{context} has invalid unsupported cells"));
    }
    Ok(())
}

fn validate_baseline_sources(ledger: &Value, baseline_dir: &Path) -> Result<(), String> {
    let collection = ledger
        .get("providers")
        .or_else(|| ledger.get("features"))
        .and_then(Value::as_array)
        .ok_or_else(|| "ledger must contain providers or features".to_owned())?;
    for entry in collection {
        for source in non_empty_strings(&entry["baseline_sources"], "baseline_sources")? {
            if !baseline_dir.join(source).exists() {
                return Err(format!("baseline source does not exist: {source}"));
            }
        }
    }
    Ok(())
}

fn validate_baseline_revision(baseline_dir: &Path) -> Result<(), String> {
    let expected = parity_file("baseline.json")["source"]["commit_full"]
        .as_str()
        .ok_or_else(|| "baseline commit_full must be a string".to_owned())?
        .to_owned();
    let output = Command::new("git")
        .arg("-C")
        .arg(baseline_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("could not inspect baseline checkout: {error}"))?;
    if !output.status.success() {
        return Err("could not resolve baseline checkout HEAD".to_owned());
    }
    let actual = String::from_utf8(output.stdout)
        .map_err(|error| format!("baseline revision is not UTF-8: {error}"))?;
    if actual.trim() != expected {
        return Err(format!(
            "baseline checkout is at {}, expected {expected}",
            actual.trim()
        ));
    }
    Ok(())
}

fn provider_records_are_complete(ledger: &Value) -> bool {
    ledger["providers"].as_array().is_some_and(|providers| {
        providers
            .iter()
            .all(|provider| record_is_complete(provider, true))
    })
}

fn feature_records_are_complete(ledger: &Value) -> bool {
    ledger["features"].as_array().is_some_and(|features| {
        features.iter().all(|feature| {
            feature["status"] == "unsupported-approved" || record_is_complete(feature, false)
        })
    })
}

fn record_is_complete(record: &Value, allow_not_applicable: bool) -> bool {
    if record["status"] != "passing" || record["tests"].as_array().is_none_or(Vec::is_empty) {
        return false;
    }
    record["cells"].as_object().is_some_and(|cells| {
        let has_passing = cells.values().any(|status| status == "passing");
        let all_complete = cells.values().all(|status| {
            status == "passing" || (allow_not_applicable && status == "not-applicable")
        });
        has_passing && all_complete
    })
}

#[test]
fn baseline_is_pinned_to_the_approved_revision() {
    let baseline = parity_file("baseline.json");

    assert_eq!(baseline["schema_version"], 1);
    assert_eq!(
        baseline["source"]["repository"],
        "https://github.com/steipete/CodexBar.git"
    );
    assert_eq!(baseline["source"]["commit"], "1680b4ed5");
    assert_eq!(
        baseline["source"]["commit_full"],
        "1680b4ed5bca69f167d388ed17a5b2c36dd05d1f"
    );
    assert_eq!(baseline["provider_count"], 69);
}

#[test]
fn metadata_registry_covers_every_provider_once() {
    let actual_ids: BTreeSet<ProviderId> = PROVIDERS.iter().map(|metadata| metadata.id).collect();
    let expected_ids: BTreeSet<ProviderId> = ProviderId::ALL.into_iter().collect();

    assert_eq!(PROVIDERS.len(), 69);
    assert_eq!(actual_ids, expected_ids);
    assert!(
        PROVIDERS
            .iter()
            .all(|metadata| !metadata.display_name.is_empty())
    );
}

#[test]
fn current_ledgers_match_the_closed_schemas() {
    validate_provider_ledger(&parity_file("providers.json"))
        .expect("provider ledger should validate");
    validate_feature_ledger(&parity_file("features.json")).expect("feature ledger should validate");
}

#[test]
fn validators_reject_missing_duplicate_unrecognized_and_statusless_records() {
    let provider_ledger = parity_file("providers.json");

    let mut missing = provider_ledger.clone();
    missing["providers"]
        .as_array_mut()
        .expect("providers")
        .pop();
    assert!(validate_provider_ledger(&missing).is_err());

    let mut duplicate = provider_ledger.clone();
    let first = duplicate["providers"][0].clone();
    duplicate["providers"].as_array_mut().expect("providers")[1] = first;
    assert!(validate_provider_ledger(&duplicate).is_err());

    let mut unknown = provider_ledger.clone();
    unknown["providers"][0]["id"] = Value::String("not-a-provider".to_owned());
    assert!(validate_provider_ledger(&unknown).is_err());

    let feature_ledger = parity_file("features.json");
    let mut duplicate_feature = feature_ledger.clone();
    let first_feature = duplicate_feature["features"][0].clone();
    duplicate_feature["features"]
        .as_array_mut()
        .expect("features")[1] = first_feature;
    assert!(validate_feature_ledger(&duplicate_feature).is_err());

    let mut statusless = feature_ledger;
    statusless["features"][0]
        .as_object_mut()
        .expect("feature record")
        .remove("status");
    assert!(validate_feature_ledger(&statusless).is_err());
}

#[test]
fn completion_requires_passing_cells_and_real_test_evidence() {
    let mut vacuous = parity_file("providers.json");
    let record = &mut vacuous["providers"][0];
    record["status"] = Value::String("passing".to_owned());
    record["tests"] = serde_json::json!(["crates/providers/tests/ledger.rs"]);
    let cells = record["cells"].as_object_mut().expect("provider cells");
    let cell_names: Vec<String> = cells.keys().cloned().collect();
    for status in cells.values_mut() {
        *status = Value::String("not-applicable".to_owned());
    }
    record["not_applicable_reasons"] = Value::Object(
        cell_names
            .into_iter()
            .map(|cell| {
                (
                    cell,
                    Value::String("Provider does not expose this capability".to_owned()),
                )
            })
            .collect(),
    );
    assert!(validate_provider_ledger(&vacuous).is_err());
    assert!(!record_is_complete(&vacuous["providers"][0], true));

    let mut missing_test = parity_file("features.json");
    missing_test["features"][0]["tests"] = serde_json::json!(["tests/does-not-exist.rs"]);
    assert!(validate_feature_ledger(&missing_test).is_err());

    let mut unrelated_evidence = parity_file("features.json");
    unrelated_evidence["features"][0]["tests"] = serde_json::json!(["README.md"]);
    assert!(validate_feature_ledger(&unrelated_evidence).is_err());
}

#[test]
fn baseline_provenance_exists_when_a_checkout_is_supplied() {
    let Ok(baseline_dir) = env::var("OAB_BASELINE_DIR") else {
        return;
    };
    let baseline_dir = Path::new(&baseline_dir);
    assert!(
        baseline_dir.is_dir(),
        "OAB_BASELINE_DIR must be a directory"
    );
    validate_baseline_revision(baseline_dir)
        .expect("baseline checkout should be at the pinned revision");
    validate_baseline_sources(&parity_file("providers.json"), baseline_dir)
        .expect("provider provenance should exist");
    validate_baseline_sources(&parity_file("features.json"), baseline_dir)
        .expect("feature provenance should exist");
}

#[test]
fn requested_completion_gate_is_satisfied() {
    let gate = env::var("OAB_PARITY_GATE").unwrap_or_default();
    if gate.is_empty() {
        return;
    }

    let providers = parity_file("providers.json");
    validate_provider_ledger(&providers)
        .expect("provider ledger should validate before completion checks");
    assert!(
        provider_records_are_complete(&providers),
        "not every provider parity record is complete"
    );

    match gate.as_str() {
        "providers-complete" => {}
        "all-complete" => {
            let features = parity_file("features.json");
            validate_feature_ledger(&features)
                .expect("feature ledger should validate before completion checks");
            assert!(
                feature_records_are_complete(&features),
                "not every feature parity record is complete"
            );
        }
        _ => panic!("unknown OAB_PARITY_GATE: {gate}"),
    }
}
