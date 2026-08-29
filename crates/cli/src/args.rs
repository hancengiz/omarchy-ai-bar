//! Complete top-level command registry and typed argument models.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::output::OutputFormat;

/// Omarchy AI Bar command line.
#[derive(Debug, Parser)]
#[command(name = "omarchy-ai-bar")]
#[command(about = "Omarchy-native AI provider usage monitoring")]
pub struct Cli {
    /// Selected process mode. No subcommand starts the desktop daemon.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Every stable top-level process mode.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the foreground desktop backend.
    Daemon,
    /// Print provider usage.
    Usage(OutputArgs),
    /// Print compact provider cards.
    Cards(OutputArgs),
    /// Open or emit the dashboard.
    Dashboard(OutputArgs),
    /// Print cost and token history.
    Cost(OutputArgs),
    /// Run the local HTTP server.
    Serve,
    /// Inspect or modify configuration.
    Config,
    /// Inspect or modify external hooks.
    Hooks,
    /// Evaluate a noninteractive quota guard.
    Guard,
    /// Manage explicit cookie input.
    Cookie,
    /// Inspect or clear application caches.
    Cache,
    /// Manage user-provider plugins.
    Plugins,
    /// Inspect and focus agent sessions.
    Sessions(OutputArgs),
    /// Print redacted diagnostics.
    Diagnose(OutputArgs),
    /// Integrate with the Omarchy frontend.
    Bridge {
        /// Bridge transport or lifecycle action.
        #[command(subcommand)]
        transport: BridgeTransport,
    },
    /// Generate shell completion output.
    Completion {
        /// Target shell. Detection will be added with packaging support.
        #[arg(value_enum)]
        shell: Option<CompletionShell>,
    },
    /// Print application version information.
    Version {
        /// Emit a machine-readable JSON object.
        #[arg(long)]
        json: bool,
    },
}

/// Common format selection for read-only commands.
#[derive(Debug, Clone, Copy, Args)]
pub struct OutputArgs {
    /// Select human, JSON, or TOON output.
    #[arg(long, value_enum, default_value_t)]
    pub format: OutputFormat,
}

/// Packaged shell-completion targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    /// Bourne Again Shell.
    Bash,
    /// Z shell.
    Zsh,
    /// Friendly Interactive Shell.
    Fish,
}

/// Internal and user-facing Omarchy integration transports.
#[derive(Debug, Subcommand)]
pub enum BridgeTransport {
    /// Forward bounded protocol records between standard I/O and the display socket.
    Stdio {
        /// Override the display socket pathname (used by integration tests).
        #[arg(long, value_name = "PATH", hide = true)]
        socket: Option<PathBuf>,
    },
    /// Observe only the exact monitor lifecycle events used by the live gate.
    #[command(name = "hyprland-events", hide = true)]
    HyprlandEvents {
        /// Hyprland event socket pathname.
        #[arg(long, value_name = "PATH", hide = true)]
        socket: PathBuf,
        /// Exact monitor name encoded as canonical RFC 4648 base64.
        #[arg(long, value_name = "BASE64", hide = true)]
        monitor_name_base64: String,
        /// PID of the lifecycle-owning launcher process.
        #[arg(long, value_name = "PID", hide = true)]
        parent_pid: u32,
        /// Inherited descriptor used to acknowledge readiness and privacy arming.
        #[arg(long, value_name = "FD", hide = true)]
        ready_fd: i32,
        /// Inherited descriptor used by the launcher to authorize event reads.
        #[arg(long, value_name = "FD", hide = true)]
        authorization_fd: i32,
    },
    /// Install, inspect, update, or remove the per-user Omarchy bridge.
    Manage,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn every_stable_top_level_command_is_registered() {
        let command = Cli::command();
        let names = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect::<Vec<_>>();
        for expected in [
            "daemon",
            "usage",
            "cards",
            "dashboard",
            "cost",
            "serve",
            "config",
            "hooks",
            "guard",
            "cookie",
            "cache",
            "plugins",
            "sessions",
            "diagnose",
            "bridge",
            "completion",
            "version",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn data_commands_accept_json_and_toon_without_implicit_logs() {
        let json = Cli::try_parse_from(["omarchy-ai-bar", "usage", "--format", "json"])
            .expect("parse JSON usage");
        assert!(matches!(
            json.command,
            Some(Command::Usage(OutputArgs {
                format: OutputFormat::Json
            }))
        ));

        let toon = Cli::try_parse_from(["omarchy-ai-bar", "cards", "--format", "toon"])
            .expect("parse TOON cards");
        assert!(matches!(
            toon.command,
            Some(Command::Cards(OutputArgs {
                format: OutputFormat::Toon
            }))
        ));
    }
}
