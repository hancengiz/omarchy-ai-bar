//! Complete top-level command registry and typed argument models.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::output::OutputFormat;

/// Omarchy AI Bar command line.
#[derive(Debug, Parser)]
#[command(name = "omarchy-ai-bar")]
#[command(about = "Omarchy-native AI provider usage monitoring")]
#[command(version)]
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
    Serve(ServeArgs),
    /// Inspect or modify configuration.
    Config(ConfigArgs),
    /// Inspect or modify external hooks.
    Hooks(HooksArgs),
    /// Evaluate a noninteractive quota guard.
    Guard(GuardArgs),
    /// Manage app-owned provider credentials.
    Credential(CookieArgs),
    /// Manage app-owned provider credentials (legacy command name).
    Cookie(CookieArgs),
    /// Manage the app-owned GitHub Copilot OAuth session.
    Copilot(CopilotArgs),
    /// Manage isolated Codex OAuth accounts owned by Omarchy AI Bar.
    Codex(CodexArgs),
    /// Inspect or clear application caches.
    Cache(CacheArgs),
    /// Manage user-provider plugins.
    Plugins(PluginsArgs),
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

/// Loopback-only JSON API server options.
#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// Loopback address to listen on.
    #[arg(long, value_name = "ADDRESS", default_value = "127.0.0.1:43129")]
    pub listen: SocketAddr,
    /// Exit after serving this many connections; zero runs until signalled.
    #[arg(long, default_value_t = 0, hide = true)]
    pub max_requests: u64,
}

/// Noninteractive quota-policy evaluation.
#[derive(Debug, Clone, Args)]
pub struct GuardArgs {
    /// Deny when used quota is at or above this percentage.
    #[arg(long, value_name = "PERCENT", default_value_t = 90, value_parser = clap::value_parser!(u8).range(1..=100))]
    pub max_used: u8,
    /// Evaluate only this canonical provider ID.
    #[arg(long, value_name = "PROVIDER")]
    pub provider: Option<String>,
    /// Suppress the human-readable decision.
    #[arg(long)]
    pub quiet: bool,
}

/// Typed non-secret configuration operations.
#[derive(Debug, Clone, Args)]
pub struct ConfigArgs {
    /// Configuration operation. Omitting it shows the current state.
    #[command(subcommand)]
    pub action: Option<ConfigAction>,
}

/// Configuration operation.
#[derive(Debug, Clone, Subcommand)]
pub enum ConfigAction {
    /// Print the resolved configuration path.
    Path,
    /// Print the validated configuration, or its missing state.
    Show(OutputArgs),
    /// Validate a file without changing application state.
    Validate {
        /// File to validate. Defaults to the active XDG configuration.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Create a minimal valid configuration document.
    Init {
        /// Replace an existing application configuration.
        #[arg(long)]
        force: bool,
    },
    /// Describe supported provider settings without exposing secret values.
    Describe {
        /// Canonical provider ID. Omitting it describes every provider.
        #[arg(value_name = "PROVIDER")]
        provider: Option<String>,
        /// Output format.
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Enable a provider in the desktop daemon and bar.
    Enable {
        /// Canonical provider ID.
        provider: String,
    },
    /// Disable a provider in the desktop daemon and bar.
    Disable {
        /// Canonical provider ID.
        provider: String,
    },
    /// Persist the display order for one or more providers.
    Reorder {
        /// Canonical provider IDs from first to last. Providers omitted from
        /// this list retain their existing relative order afterward.
        #[arg(value_name = "PROVIDER", num_args = 1.., required = true)]
        providers: Vec<String>,
    },
    /// Set or clear a provider's non-secret API endpoint.
    SetEndpoint {
        /// Canonical provider ID.
        provider: String,
        /// Validated HTTPS URL, or a supported loopback HTTP URL.
        #[arg(value_name = "URL", required_unless_present = "clear")]
        endpoint: Option<String>,
        /// Remove the configured endpoint and return to provider defaults.
        #[arg(long, conflicts_with = "endpoint")]
        clear: bool,
    },
    /// Set or clear one typed, non-secret provider option.
    SetOption {
        /// Canonical provider ID.
        provider: String,
        /// Canonical provider option key.
        key: String,
        /// Typed option value accepted by the provider descriptor.
        #[arg(value_name = "VALUE", required_unless_present = "clear")]
        value: Option<String>,
        /// Remove the configured value and return to the provider default.
        #[arg(long, conflicts_with = "value")]
        clear: bool,
    },
}

/// Application-owned cache operations.
#[derive(Debug, Clone, Args)]
pub struct CacheArgs {
    /// Cache operation. Omitting it prints status.
    #[command(subcommand)]
    pub action: Option<CacheAction>,
}

/// Cache operation.
#[derive(Debug, Clone, Subcommand)]
pub enum CacheAction {
    /// Print the cache path, entry count, and byte count.
    Status(OutputArgs),
    /// Remove only the contents of the application-owned cache directory.
    Clear,
}

/// Secure app-owned provider credential operations.
#[derive(Debug, Clone, Args)]
pub struct CookieArgs {
    /// Credential operation. Omitting it lists supported providers.
    #[command(subcommand)]
    pub action: Option<CookieAction>,
}

/// App-owned provider credential operation.
#[derive(Debug, Clone, Subcommand)]
pub enum CookieAction {
    /// List providers that accept a managed credential.
    List(OutputArgs),
    /// Read a credential from standard input and store it in Secret Service.
    Set {
        /// Canonical provider ID.
        provider: String,
        /// Account routing ID.
        #[arg(long, default_value = "ambient")]
        account: String,
        /// Named credential slot. Omitting it preserves legacy primary-credential behavior.
        #[arg(long, value_name = "SLOT")]
        slot: Option<String>,
    },
    /// Report whether an exact managed credential exists without revealing it.
    Status {
        /// Canonical provider ID.
        provider: String,
        /// Account routing ID.
        #[arg(long, default_value = "ambient")]
        account: String,
        /// Named credential slot. Omitting it preserves legacy primary-credential behavior.
        #[arg(long, value_name = "SLOT")]
        slot: Option<String>,
    },
    /// Delete an exact managed credential from Secret Service.
    Delete {
        /// Canonical provider ID.
        provider: String,
        /// Account routing ID.
        #[arg(long, default_value = "ambient")]
        account: String,
        /// Named credential slot. Omitting it preserves legacy primary-credential behavior.
        #[arg(long, value_name = "SLOT")]
        slot: Option<String>,
    },
}

/// App-owned GitHub Copilot OAuth operations.
#[derive(Debug, Clone, Args)]
pub struct CopilotArgs {
    /// OAuth operation. Omitting it reports the app-owned session status.
    #[command(subcommand)]
    pub action: Option<CopilotAction>,
}

/// GitHub Copilot OAuth operation.
#[derive(Debug, Clone, Subcommand)]
pub enum CopilotAction {
    /// Sign in through GitHub's OAuth device flow without touching Copilot CLI credentials.
    Login {
        /// Print the verification URL without opening the default browser.
        #[arg(long)]
        no_open_browser: bool,
    },
    /// Report whether Omarchy AI Bar owns a Copilot OAuth session.
    Status,
    /// Delete only Omarchy AI Bar's Copilot OAuth session.
    Logout,
}

/// App-owned Codex managed-account operations.
#[derive(Debug, Clone, Args)]
pub struct CodexArgs {
    /// Account operation. Omitting it lists configured accounts.
    #[command(subcommand)]
    pub action: Option<CodexAction>,
}

/// Codex managed-account operation.
#[derive(Debug, Clone, Subcommand)]
pub enum CodexAction {
    /// Sign in to a new isolated Codex home and add it to Omarchy AI Bar.
    Login,
    /// List the ambient and app-managed Codex accounts.
    List(OutputArgs),
    /// Select the account displayed as the active Codex account.
    Activate {
        /// Managed account ID, or `ambient` for the native Codex account.
        account: String,
    },
    /// Remove an app-managed account without changing native Codex credentials.
    Remove {
        /// Managed account ID.
        account: String,
    },
}

/// Shell-free external hook operations.
#[derive(Debug, Clone, Args)]
pub struct HooksArgs {
    /// Hook operation. Omitting it lists hook status.
    #[command(subcommand)]
    pub action: Option<HooksAction>,
}

/// Hook operation.
#[derive(Debug, Clone, Subcommand)]
pub enum HooksAction {
    /// List supported events and installed executables.
    List(OutputArgs),
    /// Print the private hook executable directory.
    Path,
    /// Run the exact installed executable for one supported event.
    Run {
        /// Event name such as warning or refresh-completed.
        event: String,
    },
}

/// Sandboxed user-provider plugin operations.
#[derive(Debug, Clone, Args)]
pub struct PluginsArgs {
    /// Plugin operation. Omitting it lists installed source files.
    #[command(subcommand)]
    pub action: Option<PluginsAction>,
}

/// Plugin operation.
#[derive(Debug, Clone, Subcommand)]
pub enum PluginsAction {
    /// List installed local JavaScript source files without executing them.
    List(OutputArgs),
    /// Print the private plugin source directory.
    Path,
    /// Validate one source file in the `QuickJS` sandbox.
    Validate {
        /// JavaScript source file.
        path: PathBuf,
    },
    /// Evaluate one source file and print its JSON-compatible sample.
    Run {
        /// JavaScript source file.
        path: PathBuf,
        /// Output format.
        #[command(flatten)]
        output: OutputArgs,
    },
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
    /// Install and enable the packaged per-user Omarchy bridge.
    Install,
    /// Atomically replace an intact managed bridge with the packaged payload.
    Update,
    /// Inspect bridge ownership, integrity, protocol compatibility, and package drift.
    Status,
    /// Disable and remove an intact application-managed bridge.
    Uninstall,
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

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

    #[test]
    fn bridge_lifecycle_actions_are_direct_and_explicit() {
        for action in ["install", "update", "status", "uninstall"] {
            let cli = Cli::try_parse_from(["omarchy-ai-bar", "bridge", action])
                .expect("parse bridge lifecycle action");
            assert!(matches!(cli.command, Some(Command::Bridge { .. })));
        }
        assert!(Cli::try_parse_from(["omarchy-ai-bar", "bridge", "manage"]).is_err());
    }

    #[test]
    fn copilot_auth_commands_are_explicit_and_app_scoped() {
        let login =
            Cli::try_parse_from(["omarchy-ai-bar", "copilot", "login", "--no-open-browser"])
                .expect("parse Copilot login");
        assert!(matches!(
            login.command,
            Some(Command::Copilot(CopilotArgs {
                action: Some(CopilotAction::Login {
                    no_open_browser: true
                })
            }))
        ));

        let logout = Cli::try_parse_from(["omarchy-ai-bar", "copilot", "logout"])
            .expect("parse Copilot logout");
        assert!(matches!(
            logout.command,
            Some(Command::Copilot(CopilotArgs {
                action: Some(CopilotAction::Logout)
            }))
        ));
    }

    #[test]
    fn codex_managed_account_commands_are_typed() {
        let login = Cli::try_parse_from(["omarchy-ai-bar", "codex", "login"])
            .expect("parse managed Codex login");
        assert!(matches!(
            login.command,
            Some(Command::Codex(CodexArgs {
                action: Some(CodexAction::Login)
            }))
        ));

        let activate = Cli::try_parse_from([
            "omarchy-ai-bar",
            "codex",
            "activate",
            "acct-0123456789abcdef01234567",
        ])
        .expect("parse Codex activation");
        assert!(matches!(
            activate.command,
            Some(Command::Codex(CodexArgs {
                action: Some(CodexAction::Activate { account })
            })) if account == "acct-0123456789abcdef01234567"
        ));
    }

    #[test]
    fn provider_endpoint_configuration_is_explicit_and_clearable() {
        let set = Cli::try_parse_from([
            "omarchy-ai-bar",
            "config",
            "set-endpoint",
            "litellm",
            "https://llm.example.test",
        ])
        .expect("parse endpoint configuration");
        assert!(matches!(
            set.command,
            Some(Command::Config(ConfigArgs {
                action: Some(ConfigAction::SetEndpoint {
                    provider,
                    endpoint: Some(endpoint),
                    clear: false,
                })
            })) if provider == "litellm" && endpoint == "https://llm.example.test"
        ));

        let clear = Cli::try_parse_from([
            "omarchy-ai-bar",
            "config",
            "set-endpoint",
            "litellm",
            "--clear",
        ])
        .expect("parse endpoint removal");
        assert!(matches!(
            clear.command,
            Some(Command::Config(ConfigArgs {
                action: Some(ConfigAction::SetEndpoint {
                    provider,
                    endpoint: None,
                    clear: true,
                })
            })) if provider == "litellm"
        ));
    }

    #[test]
    fn provider_reordering_requires_one_or_more_provider_ids() {
        let reordered = Cli::try_parse_from([
            "omarchy-ai-bar",
            "config",
            "reorder",
            "zai",
            "codex",
            "claude",
        ])
        .expect("parse provider order");
        assert!(matches!(
            reordered.command,
            Some(Command::Config(ConfigArgs {
                action: Some(ConfigAction::Reorder { providers })
            })) if providers == ["zai", "codex", "claude"]
        ));

        assert!(Cli::try_parse_from(["omarchy-ai-bar", "config", "reorder"]).is_err());
    }

    #[test]
    fn credential_and_legacy_cookie_commands_share_typed_operations() {
        let credential = Cli::try_parse_from([
            "omarchy-ai-bar",
            "credential",
            "set",
            "claude",
            "--account",
            "work",
            "--slot",
            "oauth-token",
        ])
        .expect("parse named credential slot");
        assert!(matches!(
            credential.command,
            Some(Command::Credential(CookieArgs {
                action: Some(CookieAction::Set {
                    provider,
                    account,
                    slot: Some(slot),
                })
            })) if provider == "claude" && account == "work" && slot == "oauth-token"
        ));

        let legacy = Cli::try_parse_from(["omarchy-ai-bar", "cookie", "status", "claude"])
            .expect("parse legacy credential status");
        assert!(matches!(
            legacy.command,
            Some(Command::Cookie(CookieArgs {
                action: Some(CookieAction::Status {
                    provider,
                    account,
                    slot: None,
                })
            })) if provider == "claude" && account == "ambient"
        ));

        let delete = Cli::try_parse_from([
            "omarchy-ai-bar",
            "credential",
            "delete",
            "claude",
            "--slot",
            "admin-key",
        ])
        .expect("parse named credential deletion");
        assert!(matches!(
            delete.command,
            Some(Command::Credential(CookieArgs {
                action: Some(CookieAction::Delete {
                    provider,
                    account,
                    slot: Some(slot),
                })
            })) if provider == "claude" && account == "ambient" && slot == "admin-key"
        ));
    }

    #[test]
    fn provider_setting_descriptions_have_scoped_machine_formats() {
        let all = Cli::try_parse_from(["omarchy-ai-bar", "config", "describe", "--format", "json"])
            .expect("parse all-provider description");
        assert!(matches!(
            all.command,
            Some(Command::Config(ConfigArgs {
                action: Some(ConfigAction::Describe {
                    provider: None,
                    output: OutputArgs {
                        format: OutputFormat::Json,
                    },
                })
            }))
        ));

        let provider = Cli::try_parse_from([
            "omarchy-ai-bar",
            "config",
            "describe",
            "codex",
            "--format",
            "toon",
        ])
        .expect("parse provider description");
        assert!(matches!(
            provider.command,
            Some(Command::Config(ConfigArgs {
                action: Some(ConfigAction::Describe {
                    provider: Some(provider),
                    output: OutputArgs {
                        format: OutputFormat::Toon,
                    },
                })
            })) if provider == "codex"
        ));
    }

    #[test]
    fn provider_options_require_exactly_value_or_clear() {
        let set = Cli::try_parse_from([
            "omarchy-ai-bar",
            "config",
            "set-option",
            "codex",
            "source",
            "oauth",
        ])
        .expect("parse typed provider option");
        assert!(matches!(
            set.command,
            Some(Command::Config(ConfigArgs {
                action: Some(ConfigAction::SetOption {
                    provider,
                    key,
                    value: Some(value),
                    clear: false,
                })
            })) if provider == "codex" && key == "source" && value == "oauth"
        ));

        let clear = Cli::try_parse_from([
            "omarchy-ai-bar",
            "config",
            "set-option",
            "codex",
            "source",
            "--clear",
        ])
        .expect("parse provider option removal");
        assert!(matches!(
            clear.command,
            Some(Command::Config(ConfigArgs {
                action: Some(ConfigAction::SetOption {
                    provider,
                    key,
                    value: None,
                    clear: true,
                })
            })) if provider == "codex" && key == "source"
        ));

        assert!(
            Cli::try_parse_from(["omarchy-ai-bar", "config", "set-option", "codex", "source",])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "omarchy-ai-bar",
                "config",
                "set-option",
                "codex",
                "source",
                "oauth",
                "--clear",
            ])
            .is_err()
        );
    }
}
