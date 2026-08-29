//! Process-mode selection, dependency wiring, and stdout/stderr separation.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

use oab_cli::args::{BridgeTransport, Cli, Command, OutputArgs};
use oab_cli::commands::bridge::{
    BridgeError, BridgeManager, BridgeStatus, PACKAGED_PLUGIN_PATH, SystemOmarchyCommands,
};
use oab_cli::exit_code::AppExitCode;
use oab_cli::output::write_json_line;
use oab_storage::paths::AppPaths;
use serde_json::json;

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
        Some(Command::Dashboard(arguments)) => run_safe(ControlAction::Dashboard, arguments),
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
        Some(
            Command::Serve
            | Command::Config
            | Command::Hooks
            | Command::Guard
            | Command::Cookie
            | Command::Cache
            | Command::Plugins
            | Command::Completion { .. },
        ) => unavailable(),
    }
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
            match daemon::run(socket, &display_socket) {
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
            ControlStatus::Accepted => AppExitCode::Success,
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
