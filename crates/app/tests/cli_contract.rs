mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use serde_json::Value;

use support::{DaemonFixture, EXPECTED_PROVIDER_IDS, terminate, wait_for_exit};

const UNAVAILABLE: i32 = 69;

#[test]
fn help_registers_the_complete_command_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .arg("--help")
        .output()
        .expect("run help");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    for command in [
        "daemon",
        "usage",
        "cards",
        "dashboard",
        "cost",
        "serve",
        "config",
        "hooks",
        "guard",
        "credential",
        "cookie",
        "copilot",
        "codex",
        "cache",
        "plugins",
        "sessions",
        "diagnose",
        "bridge",
        "completion",
        "version",
    ] {
        assert!(help.contains(command), "help omitted {command}");
    }
}

#[test]
fn codex_account_cli_exposes_native_account_and_rejects_unknown_activation() {
    let fixture = DaemonFixture::new("codex-accounts");
    let listed = fixture
        .command()
        .args(["codex", "list", "--format", "json"])
        .output()
        .expect("list Codex accounts");
    assert!(listed.status.success());
    assert!(listed.stderr.is_empty());
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("Codex account JSON");
    assert_eq!(listed["schema_version"], 1);
    assert_eq!(listed["accounts"][0]["id"], "ambient");
    assert_eq!(listed["accounts"][0]["active"], true);
    assert_eq!(listed["accounts"][0]["ambient"], true);

    let rejected = fixture
        .command()
        .args(["codex", "activate", "acct-unknown"])
        .output()
        .expect("reject unknown Codex account");
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert!(!rejected.stderr.is_empty());
}

#[test]
fn unavailable_handlers_and_daemon_commands_without_a_daemon_are_stable() {
    let fixture = DaemonFixture::new("placeholders");
    let cases: &[&[&str]] = &[
        &["usage"],
        &["cards"],
        &["cost"],
        &["guard"],
        &["sessions"],
        &["diagnose"],
    ];

    for arguments in cases {
        let output = fixture
            .command()
            .args(*arguments)
            .output()
            .expect("run placeholder");
        assert_eq!(output.status.code(), Some(UNAVAILABLE), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(!output.stderr.is_empty(), "{arguments:?}");
    }
}

#[test]
fn local_server_is_loopback_only_and_projects_daemon_json() {
    let fixture = DaemonFixture::new("local-server");
    let rejected = fixture
        .command()
        .args(["serve", "--listen", "0.0.0.0:43129"])
        .output()
        .expect("reject non-loopback listener");
    assert_eq!(rejected.status.code(), Some(2));

    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let address = reservation.local_addr().expect("reserved address");
    drop(reservation);
    let mut server = fixture
        .command()
        .args([
            "serve",
            "--listen",
            &address.to_string(),
            "--max-requests",
            "2",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn local server");
    let mut announcement = String::new();
    BufReader::new(server.stdout.take().expect("server stdout"))
        .read_line(&mut announcement)
        .expect("read server announcement");
    assert!(announcement.contains(&address.to_string()));

    let health = http_get(address, "/health");
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(health.contains("\r\nCache-Control: no-store\r\n"));
    assert!(health.ends_with("{\"daemon\":\"running\",\"status\":\"ok\"}"));
    let usage = http_get(address, "/v1/usage");
    assert!(usage.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(usage.contains("\"snapshots\":"));
    assert!(server.wait().expect("wait for local server").success());

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
}

fn http_get(address: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("connect to local server");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("write HTTP request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read HTTP response");
    response
}

#[test]
fn config_init_show_and_validate_use_the_private_xdg_file() {
    let fixture = DaemonFixture::new("config-cli");
    let initial = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show missing config");
    assert!(initial.status.success());
    let initial: Value = serde_json::from_slice(&initial.stdout).expect("initial JSON");
    assert_eq!(initial["initialized"], false);

    let initialized = fixture
        .command()
        .args(["config", "init"])
        .output()
        .expect("initialize config");
    assert!(initialized.status.success());

    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show config");
    assert!(shown.status.success());
    assert!(shown.stderr.is_empty());
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("shown JSON");
    assert_eq!(shown["initialized"], true);
    assert_eq!(shown["config"]["schema_version"], 1);
    assert_eq!(shown["config"]["providers"], serde_json::json!([]));

    let validated = fixture
        .command()
        .args(["config", "validate"])
        .output()
        .expect("validate config");
    assert!(validated.status.success());
    assert_eq!(validated.stdout, b"Configuration is valid.\n");

    let disabled = fixture
        .command()
        .args(["config", "disable", "claude"])
        .output()
        .expect("disable provider");
    assert!(disabled.status.success());
    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show disabled provider");
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("disabled provider JSON");
    assert_eq!(shown["config"]["providers"][0]["id"], "claude");
    assert_eq!(shown["config"]["providers"][0]["instance_id"], "default");
    assert_eq!(shown["config"]["providers"][0]["enabled"], false);

    let enabled = fixture
        .command()
        .args(["config", "enable", "claude"])
        .output()
        .expect("enable provider");
    assert!(enabled.status.success());

    let reordered = fixture
        .command()
        .args(["config", "reorder", "zai", "claude"])
        .output()
        .expect("reorder providers");
    assert!(reordered.status.success());
    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show reordered providers");
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("reordered provider JSON");
    assert_eq!(
        shown["config"]["provider_order"],
        serde_json::json!(["zai", "claude"])
    );
    assert_eq!(shown["config"]["providers"][1]["id"], "zai");
    assert_eq!(shown["config"]["providers"][1]["enabled"], true);

    let duplicate = fixture
        .command()
        .args(["config", "reorder", "zai", "zai"])
        .output()
        .expect("reject duplicate provider order");
    assert_eq!(duplicate.status.code(), Some(2));
    let invalid = fixture
        .command()
        .args(["config", "disable", "not-a-provider"])
        .output()
        .expect("reject unknown provider");
    assert_eq!(invalid.status.code(), Some(2));
}

#[test]
fn disabled_provider_is_omitted_from_daemon_runtime() {
    let fixture = DaemonFixture::new("disabled-provider");
    fixture.configure_all_providers_enabled();
    let configured = fixture
        .command()
        .args(["config", "disable", "claude"])
        .output()
        .expect("disable provider before daemon startup");
    assert!(configured.status.success());

    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);
    let usage = fixture
        .command()
        .args(["usage", "--format", "json"])
        .output()
        .expect("read filtered usage");
    assert!(usage.status.success());
    let usage: Value = serde_json::from_slice(&usage.stdout).expect("filtered usage JSON");
    let providers = usage["snapshots"]
        .as_array()
        .expect("provider snapshots")
        .iter()
        .filter_map(|snapshot| snapshot["scope"]["provider"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        providers.len(),
        EXPECTED_PROVIDER_IDS.len() - 1,
        "unexpected detected providers: {providers:?}"
    );
    assert!(!providers.contains("claude"));

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
}

#[test]
fn provider_endpoint_configuration_is_validated_atomic_and_clearable() {
    let fixture = DaemonFixture::new("provider-endpoint-cli");
    let unsupported = fixture
        .command()
        .args([
            "config",
            "set-endpoint",
            "zai",
            "https://ambiguous.example.test",
        ])
        .output()
        .expect("reject provider without one endpoint role");
    assert_eq!(unsupported.status.code(), Some(2));

    let configured = fixture
        .command()
        .args([
            "config",
            "set-endpoint",
            "litellm",
            "https://llm.example.test",
        ])
        .output()
        .expect("configure provider endpoint");
    assert!(configured.status.success());

    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show configured endpoint");
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("endpoint config JSON");
    assert_eq!(
        shown["config"]["providers"][0]["endpoint"],
        "https://llm.example.test"
    );
    assert_eq!(shown["config"]["providers"][0]["enabled"], false);

    let rejected = fixture
        .command()
        .args([
            "config",
            "set-endpoint",
            "litellm",
            "https://user:secret@llm.example.test",
        ])
        .output()
        .expect("reject endpoint credentials");
    assert_eq!(rejected.status.code(), Some(2));
    let after_rejection = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show endpoint after rejected change");
    let after_rejection: Value =
        serde_json::from_slice(&after_rejection.stdout).expect("preserved endpoint config JSON");
    assert_eq!(
        after_rejection["config"]["providers"][0]["endpoint"],
        "https://llm.example.test"
    );

    let cleared = fixture
        .command()
        .args(["config", "set-endpoint", "litellm", "--clear"])
        .output()
        .expect("clear provider endpoint");
    assert!(cleared.status.success());
    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show cleared endpoint");
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("cleared endpoint config JSON");
    assert!(shown["config"]["providers"][0].get("endpoint").is_none());
}

fn assert_typed_provider_descriptors(fixture: &DaemonFixture) {
    let described = fixture
        .command()
        .args(["config", "describe", "--format", "json"])
        .output()
        .expect("describe typed provider settings");
    assert!(described.status.success());
    assert!(described.stderr.is_empty());
    let described: Value = serde_json::from_slice(&described.stdout).expect("descriptor JSON");
    let providers = described["providers"]
        .as_array()
        .expect("typed provider descriptors");
    assert_eq!(providers.len(), 5);
    let codex = providers
        .iter()
        .find(|provider| provider["provider"] == "codex")
        .expect("Codex descriptor");
    assert!(codex["controls"].as_array().is_some_and(|controls| {
        controls.iter().any(|control| {
            control["descriptor"]["id"] == "codex-usage-source"
                && control["descriptor"]["availability"]["state"] == "implemented"
        })
    }));
    let copilot = providers
        .iter()
        .find(|provider| provider["provider"] == "copilot")
        .expect("Copilot descriptor");
    assert!(copilot["controls"].as_array().is_some_and(|controls| {
        controls.iter().any(|control| {
            control["descriptor"]["id"] == "copilot-budget-extras"
                && control["descriptor"]["availability"]["state"] == "implemented"
        }) && controls.iter().any(|control| {
            control["descriptor"]["id"] == "copilot-budget-cookie-source"
                && control["descriptor"]["options"]
                    .as_array()
                    .is_some_and(|options| {
                        options.iter().any(|option| {
                            option["choice"] == "auto"
                                && option["availability"]["state"] == "unavailable"
                        })
                    })
        })
    }));
    let encoded = serde_json::to_string(&described).expect("encode descriptor JSON");
    for forbidden in ["Z_AI_API_KEY", "COPILOT_API_TOKEN", "manual-session"] {
        assert!(
            !encoded.contains(forbidden),
            "descriptor leaked {forbidden}"
        );
    }
}

fn configure_runtime_backed_typed_provider_settings(fixture: &DaemonFixture) {
    for arguments in [
        ["config", "set-option", "codex", "codex-usage-source", "pat"],
        [
            "config",
            "set-option",
            "codex",
            "codex-spark-usage-visible",
            "false",
        ],
        [
            "config",
            "set-option",
            "claude",
            "claude-usage-source",
            "auto",
        ],
        [
            "config",
            "set-option",
            "codex",
            "codex-external-oauth-sources",
            "true",
        ],
        [
            "config",
            "set-option",
            "zai",
            "zai-api-region",
            "bigmodel-cn",
        ],
        [
            "config",
            "set-option",
            "copilot",
            "copilot-budget-extras",
            "true",
        ],
        [
            "config",
            "set-option",
            "copilot",
            "copilot-budget-cookie-source",
            "manual",
        ],
        [
            "config",
            "set-option",
            "copilot",
            "copilot-enterprise-host",
            "OctoCorp.GHE.com",
        ],
    ] {
        let configured = fixture
            .command()
            .args(arguments)
            .output()
            .expect("configure typed provider option");
        assert!(
            configured.status.success(),
            "{}",
            String::from_utf8_lossy(&configured.stderr)
        );
    }
}

fn assert_unavailable_or_unsafe_typed_provider_settings_are_rejected(fixture: &DaemonFixture) {
    let rejected = fixture
        .command()
        .args([
            "config",
            "set-option",
            "codex",
            "codex-openai-web-extras",
            "true",
        ])
        .output()
        .expect("reject unavailable typed setting");
    assert_eq!(rejected.status.code(), Some(2));
    let rejected_copilot_auto = fixture
        .command()
        .args([
            "config",
            "set-option",
            "copilot",
            "copilot-budget-cookie-source",
            "auto",
        ])
        .output()
        .expect("reject unsupported Copilot browser-cookie source");
    assert_eq!(rejected_copilot_auto.status.code(), Some(2));
    let rejected_enterprise_host = fixture
        .command()
        .args([
            "config",
            "set-option",
            "copilot",
            "copilot-enterprise-host",
            "https://user:secret@github.example.test",
        ])
        .output()
        .expect("reject credential-bearing Copilot enterprise host");
    assert_eq!(rejected_enterprise_host.status.code(), Some(2));
    let rejected_loopback_host = fixture
        .command()
        .args([
            "config",
            "set-option",
            "copilot",
            "copilot-enterprise-host",
            "127.0.0.1",
        ])
        .output()
        .expect("reject loopback Copilot enterprise host");
    assert_eq!(rejected_loopback_host.status.code(), Some(2));
}

fn assert_typed_provider_settings_round_trip_and_clear(fixture: &DaemonFixture) {
    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show typed provider options");
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("typed config JSON");
    let routes = shown["config"]["providers"]
        .as_array()
        .expect("configured provider routes");
    let codex = routes
        .iter()
        .find(|route| route["id"] == "codex")
        .expect("Codex route");
    assert_eq!(codex["options"]["source"], "pat");
    assert_eq!(
        codex["options"]["provider_options"]["spark_usage_visible"],
        false
    );
    assert_eq!(
        codex["options"]["provider_options"]["external_oauth_sources"],
        true
    );
    let claude = routes
        .iter()
        .find(|route| route["id"] == "claude")
        .expect("Claude route");
    assert_eq!(claude["options"]["source"], "auto");
    let zai = routes
        .iter()
        .find(|route| route["id"] == "zai")
        .expect("z.ai route");
    assert_eq!(zai["options"]["region"], "bigmodel-cn");
    let copilot = routes
        .iter()
        .find(|route| route["id"] == "copilot")
        .expect("Copilot route");
    assert_eq!(copilot["options"]["extras_enabled"], true);
    assert_eq!(copilot["options"]["cookie_source"], "manual");
    assert_eq!(copilot["options"]["enterprise_host"], "octocorp.ghe.com");

    let cleared = fixture
        .command()
        .args([
            "config",
            "set-option",
            "codex",
            "codex-usage-source",
            "--clear",
        ])
        .output()
        .expect("clear typed provider option");
    assert!(cleared.status.success());
    let shown = fixture
        .command()
        .args(["config", "show", "--format", "json"])
        .output()
        .expect("show cleared typed option");
    let shown: Value = serde_json::from_slice(&shown.stdout).expect("cleared config JSON");
    let codex = shown["config"]["providers"]
        .as_array()
        .and_then(|routes| routes.iter().find(|route| route["id"] == "codex"))
        .expect("Codex route after clear");
    assert!(codex["options"].get("source").is_none());
}

#[test]
fn typed_provider_settings_are_described_and_only_runtime_backed_values_persist() {
    let fixture = DaemonFixture::new("typed-provider-settings-cli");
    assert_typed_provider_descriptors(&fixture);
    configure_runtime_backed_typed_provider_settings(&fixture);
    assert_unavailable_or_unsafe_typed_provider_settings_are_rejected(&fixture);
    assert_typed_provider_settings_round_trip_and_clear(&fixture);
}

#[test]
fn grok_typed_source_and_cookie_choices_round_trip_through_the_cli() {
    let fixture = DaemonFixture::new("grok-typed-source-cli");

    for (setting, choices, config_field) in [
        (
            "grok-usage-source",
            ["auto", "cli", "oauth", "web"].as_slice(),
            "source",
        ),
        (
            "grok-cookie-source",
            ["auto", "manual", "off"].as_slice(),
            "cookie_source",
        ),
    ] {
        for choice in choices {
            let configured = fixture
                .command()
                .args(["config", "set-option", "grok", setting, choice])
                .output()
                .expect("configure Grok typed option");
            assert!(
                configured.status.success(),
                "{}",
                String::from_utf8_lossy(&configured.stderr)
            );

            let shown = fixture
                .command()
                .args(["config", "show", "--format", "json"])
                .output()
                .expect("show Grok typed option");
            let shown: Value =
                serde_json::from_slice(&shown.stdout).expect("typed Grok config JSON");
            let grok = shown["config"]["providers"]
                .as_array()
                .and_then(|routes| routes.iter().find(|route| route["id"] == "grok"))
                .expect("Grok route");
            assert_eq!(grok["options"][config_field], *choice);
        }
    }
}

#[test]
fn cache_status_and_clear_are_scoped_to_the_application_cache() {
    let fixture = DaemonFixture::new("cache-cli");
    let empty = fixture
        .command()
        .args(["cache", "status", "--format", "json"])
        .output()
        .expect("inspect empty cache");
    assert!(empty.status.success());
    let empty: Value = serde_json::from_slice(&empty.stdout).expect("empty cache JSON");
    assert_eq!(empty["entries"], 0);
    let cache_path = std::path::PathBuf::from(empty["path"].as_str().expect("cache path"));
    std::fs::create_dir_all(cache_path.join("pricing")).expect("create cache fixture");
    std::fs::write(cache_path.join("pricing/models.json"), b"model-data")
        .expect("write cache fixture");

    let populated = fixture
        .command()
        .args(["cache", "status", "--format", "json"])
        .output()
        .expect("inspect populated cache");
    let populated: Value = serde_json::from_slice(&populated.stdout).expect("populated JSON");
    assert_eq!(populated["entries"], 2);
    assert_eq!(populated["bytes"], 10);

    let cleared = fixture
        .command()
        .args(["cache", "clear"])
        .output()
        .expect("clear cache");
    assert!(cleared.status.success());
    assert!(cache_path.is_dir());
    assert_eq!(
        std::fs::read_dir(cache_path).expect("read cache").count(),
        0
    );
}

#[test]
fn cookie_registry_is_machine_readable_and_never_echoes_credentials() {
    let fixture = DaemonFixture::new("cookie-cli");
    let listed = fixture
        .command()
        .args(["cookie", "list", "--format", "json"])
        .output()
        .expect("list manual credentials");
    assert!(listed.status.success());
    assert!(listed.stderr.is_empty());
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("credential registry JSON");
    let entries = listed.as_array().expect("credential entries");
    assert_eq!(entries.len(), 54);
    assert!(entries.iter().all(|entry| {
        entry["provider"].is_string()
            && entry["environment_override"].is_string()
            && entry.get("value").is_none()
    }));
    assert!(entries.iter().any(|entry| {
        entry["provider"] == "zai" && entry["environment_override"] == "Z_AI_API_KEY"
    }));
    assert!(entries.iter().any(|entry| {
        entry["provider"] == "openai" && entry["environment_override"] == "OPENAI_API_KEY"
    }));
    assert!(entries.iter().any(|entry| {
        entry["provider"] == "cursor"
            && entry["environment_override"] == "OMARCHY_AI_BAR_CURSOR_COOKIE"
    }));

    let unsupported = fixture
        .command()
        .args(["cookie", "status", "unknown-provider"])
        .output()
        .expect("reject unsupported credential provider");
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(unsupported.stdout.is_empty());
}

#[test]
fn hooks_are_shell_free_bounded_and_owned_by_the_user() {
    let fixture = DaemonFixture::new("hooks-cli");
    let path = fixture
        .command()
        .args(["hooks", "path"])
        .output()
        .expect("resolve hooks path");
    assert!(path.status.success());
    let path = std::path::PathBuf::from(
        String::from_utf8(path.stdout)
            .expect("UTF-8 hook path")
            .trim(),
    );
    std::fs::create_dir_all(&path).expect("create hook directory");
    let executable = path.join("warning");
    std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("write hook");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("secure hook");

    let listed = fixture
        .command()
        .args(["hooks", "list", "--format", "json"])
        .output()
        .expect("list hooks");
    assert!(listed.status.success());
    let listed: Value = serde_json::from_slice(&listed.stdout).expect("hooks JSON");
    assert!(listed.as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row["event"] == "warning" && row["installed"] == true)
    }));

    let run = fixture
        .command()
        .args(["hooks", "run", "warning"])
        .output()
        .expect("run hook");
    assert!(run.status.success());
    assert_eq!(run.stdout, b"Hook warning completed.\n");
}

#[test]
fn plugins_run_inside_the_embedded_bounded_javascript_contract() {
    let fixture = DaemonFixture::new("plugins-cli");
    let path = fixture
        .command()
        .args(["plugins", "path"])
        .output()
        .expect("resolve plugins path");
    let directory = std::path::PathBuf::from(
        String::from_utf8(path.stdout)
            .expect("UTF-8 plugin path")
            .trim(),
    );
    std::fs::create_dir_all(&directory).expect("create plugin directory");
    let source = directory.join("fixture.js");
    std::fs::write(
        &source,
        br#"
            globalThis.omarchyAiBarPlugin = {
                id: "fixture-provider",
                name: "Fixture Provider",
                version: 1,
                collect() { return { used_percent: 17, node: typeof process }; }
            };
        "#,
    )
    .expect("write plugin source");

    let validated = fixture
        .command()
        .args(["plugins", "validate", source.to_str().expect("plugin path")])
        .output()
        .expect("validate plugin");
    assert!(validated.status.success());

    let run = fixture
        .command()
        .args([
            "plugins",
            "run",
            source.to_str().expect("plugin path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run plugin");
    assert!(run.status.success());
    assert!(run.stderr.is_empty());
    let run: Value = serde_json::from_slice(&run.stdout).expect("plugin JSON");
    assert_eq!(run["manifest"]["id"], "fixture-provider");
    assert_eq!(run["sample"]["used_percent"], 17);
    assert_eq!(run["sample"]["node"], "undefined");
}

#[test]
fn packaged_shell_completions_are_generated_from_the_cli_tree() {
    for shell in ["bash", "zsh", "fish"] {
        let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
            .args(["completion", shell])
            .output()
            .expect("generate completion");
        assert!(output.status.success(), "{shell}");
        assert!(output.stderr.is_empty(), "{shell}");
        let completion = String::from_utf8(output.stdout).expect("UTF-8 completion");
        assert!(completion.contains("omarchy-ai-bar"), "{shell}");
    }
}

#[test]
fn json_and_toon_stdout_are_data_only_and_diagnostics_stay_on_stderr() {
    let fixture = DaemonFixture::new("machine-output");
    for format in ["json", "toon"] {
        let output = fixture
            .command()
            .args(["usage", "--format", format])
            .output()
            .expect("run usage placeholder");
        assert_eq!(output.status.code(), Some(UNAVAILABLE));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).starts_with("omarchy-ai-bar: "),
            "diagnostic must remain on stderr"
        );
    }

    let version = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .args(["version", "--json"])
        .output()
        .expect("run JSON version");
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    let value: Value = serde_json::from_slice(&version.stdout).expect("data-only JSON stdout");
    assert_eq!(value["name"], "omarchy-ai-bar");
}

#[test]
fn invalid_command_uses_clap_usage_status_without_stdout_noise() {
    let output = Command::new(env!("CARGO_BIN_EXE_omarchy-ai-bar"))
        .arg("not-a-command")
        .output()
        .expect("run invalid command");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn bridge_status_is_an_implemented_read_only_command() {
    let fixture = DaemonFixture::new("bridge-status");
    let output = fixture
        .command()
        .args(["bridge", "status"])
        .output()
        .expect("run bridge status");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 bridge status"),
        "Omarchy bridge: not installed\n"
    );
}

#[test]
fn running_daemon_serves_usage_cards_and_redacted_diagnostics() {
    let fixture = DaemonFixture::new("live-cli-output");
    fixture.configure_all_providers_enabled();
    let mut daemon = fixture.spawn_daemon();
    fixture.wait_until_listening(&mut daemon);

    let usage = fixture
        .command()
        .args(["usage", "--format", "json"])
        .output()
        .expect("run JSON usage");
    assert!(
        usage.status.success(),
        "{}",
        String::from_utf8_lossy(&usage.stderr)
    );
    assert!(usage.stderr.is_empty());
    let usage: Value = serde_json::from_slice(&usage.stdout).expect("usage JSON");
    assert_eq!(usage["schema_version"], 1);
    assert_eq!(
        usage["snapshots"].as_array().map(Vec::len),
        Some(EXPECTED_PROVIDER_IDS.len())
    );

    let cards = fixture
        .command()
        .args(["cards", "--format", "json"])
        .output()
        .expect("run JSON cards");
    assert!(cards.status.success());
    assert!(cards.stderr.is_empty());
    let cards: Value = serde_json::from_slice(&cards.stdout).expect("cards JSON");
    assert_eq!(
        cards.as_array().map(Vec::len),
        Some(EXPECTED_PROVIDER_IDS.len())
    );
    assert!(cards.as_array().is_some_and(|items| {
        items
            .iter()
            .all(|item| item.get("provider").is_some() && item.get("state").is_some())
    }));

    let diagnose = fixture
        .command()
        .args(["diagnose", "--format", "json"])
        .output()
        .expect("run JSON diagnostics");
    assert!(diagnose.status.success());
    assert!(diagnose.stderr.is_empty());
    let diagnose: Value = serde_json::from_slice(&diagnose.stdout).expect("diagnostics JSON");
    assert_eq!(diagnose["daemon"], "running");
    assert_eq!(
        diagnose["providers"].as_array().map(Vec::len),
        Some(EXPECTED_PROVIDER_IDS.len())
    );
    let diagnosed = diagnose["providers"]
        .as_array()
        .expect("diagnosed providers")
        .iter()
        .filter_map(|provider| provider["provider"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(diagnosed, EXPECTED_PROVIDER_IDS.into_iter().collect());
    let encoded = serde_json::to_string(&diagnose).expect("encode diagnostics");
    for private_field in [
        "email",
        "account_label",
        "provider_account_id",
        "organization",
    ] {
        assert!(!encoded.contains(private_field));
    }

    let toon = fixture
        .command()
        .args(["cards", "--format", "toon"])
        .output()
        .expect("run TOON cards");
    assert!(toon.status.success());
    assert!(toon.stderr.is_empty());
    let toon = String::from_utf8(toon.stdout).expect("UTF-8 TOON");
    assert!(toon.contains("provider:"));
    assert!(!toon.contains('{'));

    assert_extended_daemon_commands(&fixture);

    terminate(&daemon);
    assert!(wait_for_exit(&mut daemon).success());
}

fn assert_extended_daemon_commands(fixture: &DaemonFixture) {
    let cost = fixture
        .command()
        .args(["cost", "--format", "json"])
        .output()
        .expect("run JSON cost");
    assert!(cost.status.success());
    let cost: Value = serde_json::from_slice(&cost.stdout).expect("cost JSON");
    assert_eq!(cost["schema_version"], 1);
    assert!(cost["providers"].is_array());

    let sessions = fixture
        .command()
        .args(["sessions", "--format", "json"])
        .output()
        .expect("run JSON sessions");
    assert!(sessions.status.success());
    let sessions: Value = serde_json::from_slice(&sessions.stdout).expect("sessions JSON");
    assert_eq!(sessions["schema_version"], 1);
    assert!(sessions["sessions"].is_array());

    let guard = fixture
        .command()
        .args(["guard", "--max-used", "100"])
        .output()
        .expect("run guard");
    assert!(guard.status.success());
    assert!(String::from_utf8_lossy(&guard.stdout).starts_with("ALLOW:"));
}
