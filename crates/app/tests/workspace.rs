use std::path::Path;
use std::process::Command;

use serde_json::Value;

#[test]
fn workspace_has_exactly_one_binary_target() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("app crate should be nested under the workspace root");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .expect("cargo metadata should run");

    assert!(output.status.success());

    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata should emit JSON");
    let mut binary_targets: Vec<&str> = metadata["packages"]
        .as_array()
        .expect("packages should be an array")
        .iter()
        .flat_map(|package| {
            package["targets"]
                .as_array()
                .expect("targets should be an array")
        })
        .filter(|target| {
            target["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
        })
        .filter_map(|target| target["name"].as_str())
        .collect();
    binary_targets.sort_unstable();

    assert_eq!(binary_targets, ["omarchy-ai-bar"]);
}
