//! Process-mode selection, dependency wiring, and stdout/stderr separation.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use oab_cli::args::{BridgeTransport, Cli, Command, CompletionShell, OutputArgs};
use oab_cli::commands::bridge::{
    BridgeError, BridgeManager, BridgeStatus, PACKAGED_PLUGIN_PATH, SystemOmarchyCommands,
};
use oab_cli::exit_code::AppExitCode;
use oab_cli::output::{OutputFormat, write_json_line, write_toon};
use oab_storage::paths::AppPaths;
use serde_json::{Value, json};

use crate::daemon;
use crate::single_instance::{
    ControlAction, ControlStatus, ForwardOutcome, InstanceRole, acquire_or_forward, forward,
};

const INTERNAL_MESSAGE: &str = "omarchy-ai-bar: internal operation failed";
const UNAVAILABLE_MESSAGE: &str = "omarchy-ai-bar: requested feature is not available yet";
const DAEMON_UNAVAILABLE_MESSAGE: &str =
    "omarchy-ai-bar: requested feature is not available from the running daemon";
const ONESHOT_UNAVAILABLE_MESSAGE: &str =
    "omarchy-ai-bar: requested feature is not available in isolated one-shot mode";

/// Runs one parsed process mode and returns its stable exit class.
pub(crate) fn run(cli: Cli) -> AppExitCode {
    match cli.command {
        None | Some(Command::Daemon) => run_daemon_or_forward(),
        Some(Command::Usage(arguments)) => run_safe(ControlAction::Usage, arguments),
        Some(Command::Cards(arguments)) => run_safe(ControlAction::Cards, arguments),
        Some(Command::Dashboard(arguments)) => run_dashboard(arguments),
        Some(Command::Cost(arguments)) => run_safe(ControlAction::Cost, arguments),
        Some(Command::Sessions(arguments)) => run_safe(ControlAction::Sessions, arguments),
        Some(Command::Diagnose(arguments)) => run_safe(ControlAction::Diagnose, arguments),
        Some(Command::Bridge {
            transport: BridgeTransport::Stdio { socket },
        }) => match crate::run_stdio_bridge(socket) {
            Ok(()) => AppExitCode::Success,
            Err(_error) => {
                eprintln!("{}", crate::BRIDGE_FAILURE_MESSAGE);
                AppExitCode::Internal
            }
        },
        Some(Command::Bridge {
            transport:
                BridgeTransport::HyprlandEvents {
                    socket,
                    monitor_name_base64,
                    parent_pid,
                    ready_fd,
                    authorization_fd,
                },
        }) => match crate::hyprland_events::run(
            socket,
            &monitor_name_base64,
            parent_pid,
            ready_fd,
            authorization_fd,
        ) {
            Ok(()) => AppExitCode::Success,
            Err(_error) => {
                eprintln!("{}", crate::hyprland_events::FAILURE_MESSAGE);
                AppExitCode::Internal
            }
        },
        Some(Command::Bridge {
            transport: BridgeTransport::Install,
        }) => run_bridge(BridgeLifecycleAction::Install),
        Some(Command::Bridge {
            transport: BridgeTransport::Update,
        }) => run_bridge(BridgeLifecycleAction::Update),
        Some(Command::Bridge {
            transport: BridgeTransport::Status,
        }) => run_bridge(BridgeLifecycleAction::Status),
        Some(Command::Bridge {
            transport: BridgeTransport::Uninstall,
        }) => run_bridge(BridgeLifecycleAction::Uninstall),
        Some(Command::Version { json }) => write_version(json),
        Some(Command::Completion { shell }) => run_completion(shell),
        Some(
            Command::Serve
            | Command::Config
            | Command::Hooks
            | Command::Guard
            | Command::Cookie
            | Command::Cache
            | Command::Plugins,
        ) => unavailable(),
    }
}

fn run_completion(requested: Option<CompletionShell>) -> AppExitCode {
    let shell = requested.or_else(|| {
        env::var_os("SHELL")
            .as_deref()
            .and_then(oab_cli::completion::detect)
    });
    let Some(shell) = shell else {
        eprintln!("omarchy-ai-bar: specify bash, zsh, or fish");
        return AppExitCode::Usage;
    };
    let mut completion = Vec::new();
    oab_cli::completion::write(shell, &mut completion);
    if io::stdout().lock().write_all(&completion).is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    AppExitCode::Success
}

fn run_dashboard(arguments: OutputArgs) -> AppExitCode {
    let installed = std::path::Path::new("/usr/share/omarchy/bin/omarchy");
    let executable = if installed.is_file() {
        installed.as_os_str()
    } else {
        OsStr::new("omarchy")
    };
    let status = ProcessCommand::new(executable)
        .args(["shell", "-q", "omarchy-ai-bar", "open"])
        .status();
    if !status.is_ok_and(|status| status.success()) {
        eprintln!("{UNAVAILABLE_MESSAGE}");
        return AppExitCode::Unavailable;
    }
    if arguments.format.is_machine_readable() {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        let result = match arguments.format {
            OutputFormat::Json => write_json_line(&mut output, &json!({"opened": true})),
            OutputFormat::Toon => write_toon(&mut output, &json!({"opened": true})),
            OutputFormat::Human => unreachable!("human output was excluded"),
        };
        if result.is_err() {
            eprintln!("{INTERNAL_MESSAGE}");
            return AppExitCode::Internal;
        }
    }
    AppExitCode::Success
}

#[derive(Clone, Copy)]
enum BridgeLifecycleAction {
    Install,
    Update,
    Status,
    Uninstall,
}

fn run_bridge(action: BridgeLifecycleAction) -> AppExitCode {
    let Some(config_home) = bridge_config_home() else {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    };
    let source = env::var_os("OMARCHY_AI_BAR_BRIDGE_SOURCE")
        .map_or_else(|| PathBuf::from(PACKAGED_PLUGIN_PATH), PathBuf::from);
    let manager = BridgeManager::new(source, config_home, SystemOmarchyCommands);
    let result = match action {
        BridgeLifecycleAction::Install => manager.install().map(|()| {
            println!("Installed and enabled the Omarchy AI Bar bridge.");
        }),
        BridgeLifecycleAction::Update => manager.update().map(|()| {
            println!("Updated the Omarchy AI Bar bridge; placement and settings were preserved.");
        }),
        BridgeLifecycleAction::Status => manager.status().map(print_bridge_status),
        BridgeLifecycleAction::Uninstall => manager.uninstall().map(|()| {
            println!("Disabled and removed the Omarchy AI Bar bridge.");
        }),
    };
    match result {
        Ok(()) => AppExitCode::Success,
        Err(error) => {
            eprintln!("omarchy-ai-bar: {error}");
            bridge_error_exit_code(&error)
        }
    }
}

fn print_bridge_status(status: BridgeStatus) {
    match status {
        BridgeStatus::NotInstalled => println!("Omarchy bridge: not installed"),
        BridgeStatus::Installed {
            payload_version,
            protocol_major,
            update_available,
        } => {
            let package_state = match update_available {
                Some(true) => "package update available",
                Some(false) => "matches package",
                None => "packaged payload unavailable",
            };
            println!(
                "Omarchy bridge: installed (payload {payload_version}, protocol {protocol_major}, {package_state})"
            );
        }
        BridgeStatus::Modified => {
            println!("Omarchy bridge: locally modified; automatic update refused");
        }
        BridgeStatus::Unrecognized => {
            println!("Omarchy bridge: destination exists but is not application-managed");
        }
        BridgeStatus::Incompatible { protocol_major } => println!(
            "Omarchy bridge: protocol {protocol_major} is outside the supported rolling-update window"
        ),
    }
}

const fn bridge_error_exit_code(error: &BridgeError) -> AppExitCode {
    match error {
        BridgeError::MissingPayload | BridgeError::NotInstalled | BridgeError::OmarchyCommand => {
            AppExitCode::Unavailable
        }
        BridgeError::UnsafePayload
        | BridgeError::UnrecognizedTree
        | BridgeError::AlreadyInstalled
        | BridgeError::ModifiedTree
        | BridgeError::IncompatibleProtocol => AppExitCode::Usage,
        BridgeError::Filesystem(_) => AppExitCode::Internal,
    }
}

fn bridge_config_home() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
}

fn run_daemon_or_forward() -> AppExitCode {
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    if paths.create_private_directories().is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }

    match acquire_or_forward(&paths.socket_path()) {
        Ok(InstanceRole::Primary(socket)) => {
            let display_socket = paths.runtime_dir().join("display.sock");
            let providers = match crate::provider_bootstrap::discover() {
                Ok(providers) => providers,
                Err(_error) => {
                    eprintln!("{INTERNAL_MESSAGE}");
                    return AppExitCode::Internal;
                }
            };
            match daemon::run(socket, &display_socket, providers) {
                Ok(()) => AppExitCode::Success,
                Err(_error) => {
                    eprintln!("{INTERNAL_MESSAGE}");
                    AppExitCode::Internal
                }
            }
        }
        Ok(InstanceRole::Forwarded(response)) => match response.status() {
            ControlStatus::Accepted => AppExitCode::Success,
            ControlStatus::Unavailable => unavailable(),
        },
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            AppExitCode::Internal
        }
    }
}

fn run_safe(action: ControlAction, arguments: OutputArgs) -> AppExitCode {
    let _machine_output_is_data_only = arguments.format.is_machine_readable();
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    match forward(&paths.socket_path(), action) {
        Ok(ForwardOutcome::Response(response)) => match response.status() {
            ControlStatus::Accepted => response.payload().map_or(AppExitCode::Success, |payload| {
                write_control_output(action, arguments.format, payload)
            }),
            ControlStatus::Unavailable => {
                eprintln!("{DAEMON_UNAVAILABLE_MESSAGE}");
                AppExitCode::Unavailable
            }
        },
        Ok(ForwardOutcome::NoDaemon) => {
            eprintln!("{ONESHOT_UNAVAILABLE_MESSAGE}");
            AppExitCode::Unavailable
        }
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            AppExitCode::Internal
        }
    }
}

fn write_control_output(
    action: ControlAction,
    format: OutputFormat,
    payload: &Value,
) -> AppExitCode {
    let rendered = if action == ControlAction::Cards {
        cards_payload(payload)
    } else {
        payload.clone()
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let result = match format {
        OutputFormat::Json => write_json_line(&mut output, &rendered),
        OutputFormat::Toon => write_toon(&mut output, &rendered),
        OutputFormat::Human => write_human_output(&mut output, action, &rendered),
    };
    match result {
        Ok(()) => AppExitCode::Success,
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            AppExitCode::Internal
        }
    }
}

fn write_human_output(
    output: &mut impl Write,
    action: ControlAction,
    payload: &Value,
) -> io::Result<()> {
    match action {
        ControlAction::Usage => write_usage_human(output, payload),
        ControlAction::Cards => write_cards_human(output, payload),
        ControlAction::Diagnose => write_diagnostics_human(output, payload),
        ControlAction::Activate
        | ControlAction::Dashboard
        | ControlAction::Cost
        | ControlAction::Sessions => Ok(()),
    }
}

fn write_usage_human(output: &mut impl Write, payload: &Value) -> io::Result<()> {
    let generated_at = payload
        .get("generated_at")
        .and_then(Value::as_str)
        .unwrap_or("unknown time");
    writeln!(output, "Provider usage ({generated_at})")?;
    let snapshots = payload
        .get("snapshots")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for snapshot in snapshots {
        let provider = provider_label(provider_id(snapshot));
        match snapshot.get("state").and_then(Value::as_str) {
            Some("ready") => {
                let sample = snapshot.get("last_known_good").unwrap_or(&Value::Null);
                let usage = sample
                    .pointer("/primary/usage/used_percent")
                    .and_then(Value::as_f64);
                let reset = sample
                    .pointer("/primary/reset_description")
                    .and_then(Value::as_str);
                let account = sample
                    .pointer("/identity/account_label")
                    .and_then(Value::as_str);
                write!(output, "{provider}: ")?;
                match usage {
                    Some(percent) => write!(output, "{}% used", format_percent(percent))?,
                    None => write!(output, "usage available")?,
                }
                if let Some(reset) = reset {
                    write!(output, " · resets {reset}")?;
                }
                if let Some(account) = account {
                    write!(output, " · {account}")?;
                }
                if let Some(error) = error_kind(snapshot) {
                    write!(output, " · stale ({error})")?;
                }
                writeln!(output)?;
            }
            Some("loading") => writeln!(output, "{provider}: loading")?,
            _ => writeln!(
                output,
                "{provider}: unavailable ({})",
                error_kind(snapshot).unwrap_or("unknown")
            )?,
        }
    }
    Ok(())
}

fn cards_payload(payload: &Value) -> Value {
    let cards = payload
        .get("snapshots")
        .and_then(Value::as_array)
        .map(|snapshots| {
            snapshots
                .iter()
                .map(|snapshot| {
                    let sample = snapshot.get("last_known_good");
                    json!({
                        "provider": provider_id(snapshot),
                        "state": snapshot.get("state").and_then(Value::as_str).unwrap_or("unknown"),
                        "used_percent": sample.and_then(|value| value.pointer("/primary/usage/used_percent")).and_then(Value::as_f64),
                        "reset_description": sample.and_then(|value| value.pointer("/primary/reset_description")).and_then(Value::as_str),
                        "error_kind": error_kind(snapshot),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Value::Array(cards)
}

fn write_cards_human(output: &mut impl Write, payload: &Value) -> io::Result<()> {
    let cards = payload.as_array().map_or(&[][..], Vec::as_slice);
    for card in cards {
        let provider = card
            .get("provider")
            .and_then(Value::as_str)
            .map_or("Unknown", provider_label);
        if let Some(percent) = card.get("used_percent").and_then(Value::as_f64) {
            writeln!(output, "{provider} {}%", format_percent(percent))?;
        } else {
            let state = card
                .get("error_kind")
                .and_then(Value::as_str)
                .or_else(|| card.get("state").and_then(Value::as_str))
                .unwrap_or("unavailable");
            writeln!(output, "{provider} {state}")?;
        }
    }
    Ok(())
}

fn write_diagnostics_human(output: &mut impl Write, payload: &Value) -> io::Result<()> {
    writeln!(
        output,
        "Daemon: {}",
        payload
            .get("daemon")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    )?;
    let providers = payload
        .get("providers")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for provider in providers {
        let label = provider
            .get("provider")
            .and_then(Value::as_str)
            .map_or("Unknown", provider_label);
        let state = provider
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let error = provider.get("error_kind").and_then(Value::as_str);
        match error {
            Some(error) => writeln!(output, "{label}: {state} ({error})")?,
            None => writeln!(output, "{label}: {state}")?,
        }
    }
    Ok(())
}

fn provider_id(snapshot: &Value) -> &str {
    snapshot
        .pointer("/last_known_good/scope/provider")
        .or_else(|| snapshot.pointer("/scope/provider"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

fn error_kind(snapshot: &Value) -> Option<&str> {
    snapshot.pointer("/error/kind").and_then(Value::as_str)
}

fn provider_label(provider: &str) -> &str {
    match provider {
        "codex" => "Codex",
        "claude" => "Claude",
        "grok" => "Grok",
        "zai" => "z.ai Coding Plan",
        _ => provider,
    }
}

fn format_percent(percent: f64) -> String {
    if percent.fract().abs() < f64::EPSILON {
        format!("{percent:.0}")
    } else {
        format!("{percent:.1}")
    }
}

fn write_version(as_json: bool) -> AppExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let result = if as_json {
        write_json_line(
            &mut output,
            &json!({
                "name": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
            }),
        )
    } else {
        writeln!(
            output,
            "{} {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
    };
    match result {
        Ok(()) => AppExitCode::Success,
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            AppExitCode::Internal
        }
    }
}

fn unavailable() -> AppExitCode {
    eprintln!("{UNAVAILABLE_MESSAGE}");
    AppExitCode::Unavailable
}

fn resolved_paths() -> Option<AppPaths> {
    let mut environment = BTreeMap::<String, OsString>::new();
    for name in [
        "HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        if let Some(value) = env::var_os(name) {
            environment.insert(name.into(), value);
        }
    }
    match AppPaths::from_env_map(&environment) {
        Ok(paths) => Some(paths),
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            None
        }
    }
}
