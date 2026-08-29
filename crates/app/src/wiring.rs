//! Process-mode selection, dependency wiring, and stdout/stderr separation.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::io::{self, Write};

use oab_cli::args::{BridgeTransport, Cli, Command, OutputArgs};
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
        Some(Command::Version { json }) => write_version(json),
        Some(
            Command::Serve
            | Command::Config
            | Command::Hooks
            | Command::Guard
            | Command::Cookie
            | Command::Cache
            | Command::Plugins
            | Command::Completion { .. }
            | Command::Bridge {
                transport: BridgeTransport::Manage,
            },
        ) => unavailable(),
    }
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
