use std::process::Command;

use serde_json::Value;

#[test]
fn version_json_is_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .args(["version", "--json"])
        .output()
        .expect("version command should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "stderr should be empty");

    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should contain JSON");
    assert_eq!(value["name"], "omarchy-ai-bar");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}
