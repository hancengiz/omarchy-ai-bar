//! Process-mode selection, dependency wiring, and stdout/stderr separation.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use oab_auth::credential_slot::CredentialSlotId;
use oab_auth::secret_store::{
    MAX_SECRET_BYTES, SecretKey, SecretServiceStore, SecretStore, SecretStoreError, SecretValue,
};
use oab_cli::args::{
    BridgeTransport, CacheAction, CacheArgs, Cli, Command, CompletionShell, ConfigAction,
    ConfigArgs, CookieAction, CookieArgs, CopilotAction, CopilotArgs, GuardArgs, HooksAction,
    HooksArgs, OutputArgs, PluginsAction, PluginsArgs,
};
use oab_cli::commands::bridge::{
    BridgeError, BridgeManager, BridgeStatus, PACKAGED_PLUGIN_PATH, SystemOmarchyCommands,
};
use oab_cli::exit_code::AppExitCode;
use oab_cli::output::{OutputFormat, write_json_line, write_toon};
use oab_domain::{
    AccountKey, AccountScope, ClassifiedError, ErrorKind, ProviderId, ProviderInstanceId,
};
use oab_providers::providers::copilot::{
    CopilotDeviceFlow, CopilotLoginValidator, ValidatedCopilotCredential, normalize_enterprise_host,
};
use oab_providers::settings_descriptor::{
    ProviderSettingId, ProviderSettingsAvailability, ProviderSettingsControlDescriptor,
    settings_for,
};
use oab_storage::atomic_file::{atomic_write, read_private_file};
use oab_storage::config::{
    AppConfig, CURRENT_SCHEMA_VERSION, MAX_CONFIG_BYTES, ProviderConfig, ProviderCookieSource,
    ProviderOptionValue, ProviderOptions, ProviderSourceMode, load_config_bytes, validate_config,
};
use oab_storage::paths::AppPaths;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

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
const COPILOT_SERVICE_RESTART_ARGS: [&str; 3] = ["--user", "restart", "omarchy-ai-bar.service"];
const HOOK_EVENTS: [&str; 5] = [
    "daemon-started",
    "provider-updated",
    "refresh-completed",
    "warning",
    "session-detected",
];

/// Runs one parsed process mode and returns its stable exit class.
pub(crate) fn run(cli: Cli) -> AppExitCode {
    match cli.command {
        None | Some(Command::Daemon) => run_daemon_or_forward(),
        Some(Command::Usage(arguments)) => run_safe(ControlAction::Usage, arguments),
        Some(Command::Cards(arguments)) => run_safe(ControlAction::Cards, arguments),
        Some(Command::Dashboard(arguments)) => run_dashboard(arguments),
        Some(Command::Cost(arguments)) => run_safe(ControlAction::Cost, arguments),
        Some(Command::Sessions(arguments)) => run_safe(ControlAction::Sessions, arguments),
        Some(Command::Guard(arguments)) => run_guard(&arguments),
        Some(Command::Config(arguments)) => run_config(&arguments),
        Some(Command::Serve(arguments)) => run_server(&arguments),
        Some(Command::Cache(arguments)) => run_cache(&arguments),
        Some(Command::Credential(arguments) | Command::Cookie(arguments)) => run_cookie(&arguments),
        Some(Command::Copilot(arguments)) => run_copilot(&arguments),
        Some(Command::Hooks(arguments)) => run_hooks(&arguments),
        Some(Command::Plugins(arguments)) => run_plugins(&arguments),
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
    }
}

fn run_server(arguments: &oab_cli::args::ServeArgs) -> AppExitCode {
    if !arguments.listen.ip().is_loopback() {
        eprintln!("omarchy-ai-bar: the local server may only listen on a loopback address");
        return AppExitCode::Usage;
    }
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    match crate::server::run(arguments, paths.socket_path()) {
        Ok(()) => AppExitCode::Success,
        Err(error) => {
            eprintln!("omarchy-ai-bar: {error}");
            AppExitCode::Internal
        }
    }
}

fn run_cache(arguments: &CacheArgs) -> AppExitCode {
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    match arguments.action.as_ref() {
        None | Some(CacheAction::Status(_)) => {
            let format = match arguments.action.as_ref() {
                Some(CacheAction::Status(output)) => output.format,
                _ => OutputFormat::Human,
            };
            show_cache_status(paths.cache_dir(), format)
        }
        Some(CacheAction::Clear) => clear_cache(paths.cache_dir()),
    }
}

fn run_cookie(arguments: &CookieArgs) -> AppExitCode {
    match arguments.action.as_ref() {
        None | Some(CookieAction::List(_)) => {
            let format = match arguments.action.as_ref() {
                Some(CookieAction::List(output)) => output.format,
                _ => OutputFormat::Human,
            };
            list_manual_credentials(format)
        }
        Some(CookieAction::Set {
            provider,
            account,
            slot,
        }) => {
            let Some(key) = credential_secret_key(provider, account, slot.as_deref()) else {
                return AppExitCode::Usage;
            };
            if io::stdin().is_terminal() {
                eprintln!(
                    "omarchy-ai-bar: pipe the provider credential on standard input; interactive echo is refused"
                );
                return AppExitCode::Usage;
            }
            let bytes = match read_one_line_secret(&mut io::stdin().lock()) {
                Ok(bytes) => bytes,
                Err(SecretInputError::Invalid) => {
                    eprintln!("omarchy-ai-bar: credential is empty or exceeds the size limit");
                    return AppExitCode::Usage;
                }
                Err(SecretInputError::Read) => {
                    eprintln!("{INTERNAL_MESSAGE}");
                    return AppExitCode::Internal;
                }
            };
            let Ok(secret) = SecretValue::new(bytes) else {
                eprintln!("omarchy-ai-bar: credential is empty or exceeds the size limit");
                return AppExitCode::Usage;
            };
            run_secret_service(SecretOperation::Set { key, secret })
        }
        Some(CookieAction::Status {
            provider,
            account,
            slot,
        }) => {
            let Some(key) = credential_secret_key(provider, account, slot.as_deref()) else {
                return AppExitCode::Usage;
            };
            run_secret_service(SecretOperation::Status { key })
        }
        Some(CookieAction::Delete {
            provider,
            account,
            slot,
        }) => {
            let Some(key) = credential_secret_key(provider, account, slot.as_deref()) else {
                return AppExitCode::Usage;
            };
            run_secret_service(SecretOperation::Delete { key })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretInputError {
    Read,
    Invalid,
}

/// Reads one bounded credential record without waiting for the writer to close
/// its pipe. Quickshell's `Process.write()` keeps stdin open, so an EOF-based
/// reader deadlocks the settings UI even after it writes its newline.
fn read_one_line_secret(reader: &mut impl BufRead) -> Result<Vec<u8>, SecretInputError> {
    let maximum = u64::try_from(MAX_SECRET_BYTES).map_err(|_| SecretInputError::Invalid)?;
    let mut bytes = Vec::new();
    reader
        .take(maximum.saturating_add(2))
        .read_until(b'\n', &mut bytes)
        .map_err(|_| SecretInputError::Read)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty()
        || bytes.len() > MAX_SECRET_BYTES
        || bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(SecretInputError::Invalid);
    }
    Ok(bytes)
}

fn run_copilot(arguments: &CopilotArgs) -> AppExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_error) => return AppExitCode::Internal,
    };
    let enterprise_host = if matches!(arguments.action, Some(CopilotAction::Login { .. })) {
        match configured_copilot_enterprise_host() {
            Ok(host) => host,
            Err(code) => return code,
        }
    } else {
        None
    };
    let (result, login_transaction) =
        runtime.block_on(run_copilot_async(arguments, enterprise_host.as_deref()));
    if result == AppExitCode::Success
        && matches!(arguments.action, Some(CopilotAction::Login { .. }))
    {
        let Some(paths) = resolved_paths() else {
            rollback_copilot_login(&runtime, login_transaction);
            return AppExitCode::Internal;
        };
        let enabled = set_provider_enabled(&paths, ProviderId::Copilot.as_str(), true);
        if enabled != AppExitCode::Success {
            return if rollback_copilot_login(&runtime, login_transaction) {
                enabled
            } else {
                AppExitCode::Internal
            };
        }
        restart_user_service_after_copilot_change();
    } else if result == AppExitCode::Success
        && matches!(arguments.action, Some(CopilotAction::Logout))
    {
        restart_user_service_after_copilot_change();
    }
    result
}

fn configured_copilot_enterprise_host() -> Result<Option<String>, AppExitCode> {
    if let Some(host) = env::var("OMARCHY_AI_BAR_COPILOT_ENTERPRISE_HOST")
        .ok()
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
    {
        return Ok(Some(host));
    }
    let Some(paths) = resolved_paths() else {
        return Err(AppExitCode::Internal);
    };
    let bytes = read_private_file(paths.config_file(), MAX_CONFIG_BYTES).map_err(|_error| {
        eprintln!("omarchy-ai-bar: active configuration could not be read safely");
        AppExitCode::Internal
    })?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let config = load_config_bytes(&bytes).map_err(|error| {
        eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
        AppExitCode::Usage
    })?;
    Ok(config
        .providers
        .iter()
        .find(|route| route.id == ProviderId::Copilot && route.instance_id.as_str() == "default")
        .and_then(|route| route.options.enterprise_host.clone()))
}

struct CopilotLoginTransaction {
    store: SecretServiceStore,
    key: SecretKey,
    previous_secret: Option<SecretValue>,
}

impl CopilotLoginTransaction {
    async fn rollback(self) -> Result<(), SecretStoreError> {
        let Self {
            store,
            key,
            previous_secret,
        } = self;
        rollback_copilot_secret(&store, &key, previous_secret).await
    }
}

async fn rollback_copilot_secret<S: SecretStore + ?Sized>(
    store: &S,
    key: &SecretKey,
    previous_secret: Option<SecretValue>,
) -> Result<(), SecretStoreError> {
    match previous_secret {
        Some(secret) => store.put(key, secret).await,
        None => store.delete(key).await,
    }
}

async fn copilot_secret_configured<S: SecretStore + ?Sized>(
    store: &S,
    key: &SecretKey,
) -> Result<bool, SecretStoreError> {
    store.get(key).await.map(|secret| secret.is_some())
}

async fn replace_copilot_secret<S: SecretStore + ?Sized>(
    store: &S,
    key: &SecretKey,
    secret: SecretValue,
) -> Result<Option<SecretValue>, SecretStoreError> {
    let previous_secret = store.get(key).await?;
    store.put(key, secret).await?;
    Ok(previous_secret)
}

#[derive(Debug)]
enum CopilotLoginWriteError {
    Validation(ClassifiedError),
    InvalidSecret,
    Storage(SecretStoreError),
}

async fn validate_and_replace_copilot_secret<S, F>(
    store: &S,
    key: &SecretKey,
    validation: F,
) -> Result<Option<SecretValue>, CopilotLoginWriteError>
where
    S: SecretStore + ?Sized,
    F: std::future::Future<Output = Result<ValidatedCopilotCredential, ClassifiedError>>,
{
    let credential = validation
        .await
        .map_err(CopilotLoginWriteError::Validation)?;
    let secret = SecretValue::from_zeroizing(credential.into_secret_bytes())
        .map_err(|_error| CopilotLoginWriteError::InvalidSecret)?;
    replace_copilot_secret(store, key, secret)
        .await
        .map_err(CopilotLoginWriteError::Storage)
}

async fn delete_copilot_secret<S: SecretStore + ?Sized>(
    store: &S,
    key: &SecretKey,
) -> Result<(), SecretStoreError> {
    store.delete(key).await
}

fn rollback_copilot_login(
    runtime: &tokio::runtime::Runtime,
    transaction: Option<CopilotLoginTransaction>,
) -> bool {
    let Some(transaction) = transaction else {
        eprintln!("omarchy-ai-bar: Copilot login transaction was not retained");
        return false;
    };
    if runtime.block_on(transaction.rollback()).is_ok() {
        true
    } else {
        eprintln!("omarchy-ai-bar: could not roll back the incomplete Copilot login");
        false
    }
}

async fn run_copilot_async(
    arguments: &CopilotArgs,
    enterprise_host: Option<&str>,
) -> (AppExitCode, Option<CopilotLoginTransaction>) {
    let store = match SecretServiceStore::connect().await {
        Ok(store) => store,
        Err(_error) => {
            eprintln!("omarchy-ai-bar: desktop Secret Service is unavailable or locked");
            return (AppExitCode::Authentication, None);
        }
    };
    let key = match crate::credentials::copilot_oauth_key() {
        Ok(key) => key,
        Err(_error) => return (AppExitCode::Internal, None),
    };
    match arguments.action.as_ref() {
        None | Some(CopilotAction::Status) => match copilot_secret_configured(&store, &key).await {
            Ok(true) => {
                println!("Omarchy AI Bar Copilot session: configured");
                (AppExitCode::Success, None)
            }
            Ok(false) => {
                println!("Omarchy AI Bar Copilot session: not configured");
                (AppExitCode::Unavailable, None)
            }
            Err(_error) => (secret_service_failure(), None),
        },
        Some(CopilotAction::Logout) => match delete_copilot_secret(&store, &key).await {
            Ok(()) => {
                println!("Removed Omarchy AI Bar's stored Copilot session.");
                println!("Copilot CLI and GitHub CLI credentials were not changed.");
                println!(
                    "An explicit COPILOT_API_TOKEN environment override, if configured, remains active."
                );
                (AppExitCode::Success, None)
            }
            Err(_error) => (secret_service_failure(), None),
        },
        Some(CopilotAction::Login { no_open_browser }) => {
            // Only this explicit CLI/UI action can mint an OAuth token. Daemon
            // refresh loads the existing app-owned item and performs usage
            // GETs; it never enters the device flow or writes credential state.
            let flow = match CopilotDeviceFlow::new(enterprise_host) {
                Ok(flow) => flow,
                Err(error) => return (copilot_login_failure(error.kind()), None),
            };
            let cancellation = CancellationToken::new();
            let challenge = match flow.request_device_code(&cancellation).await {
                Ok(challenge) => challenge,
                Err(error) => return (copilot_login_failure(error.kind()), None),
            };
            println!("Sign in to GitHub for Omarchy AI Bar");
            println!("Code: {}", challenge.user_code());
            println!("Open: {}", challenge.verification_url_to_open());
            println!("Waiting for GitHub authorization…");
            let _ignored = io::stdout().flush();
            if !no_open_browser {
                open_copilot_verification_url(challenge.verification_url_to_open().as_str());
            }
            let token = match flow.poll_for_token(&challenge, &cancellation).await {
                Ok(token) => token,
                Err(error) => return (copilot_login_failure(error.kind()), None),
            };
            let validator = match CopilotLoginValidator::new(token, enterprise_host) {
                Ok(validator) => validator,
                Err(error) => return (copilot_login_failure(error.kind()), None),
            };
            match validate_and_replace_copilot_secret(
                &store,
                &key,
                validator.validate(&cancellation),
            )
            .await
            {
                Ok(previous_secret) => {
                    println!("GitHub authorization completed for Omarchy AI Bar.");
                    println!("Copilot CLI and GitHub CLI credentials were not changed.");
                    (
                        AppExitCode::Success,
                        Some(CopilotLoginTransaction {
                            store,
                            key,
                            previous_secret,
                        }),
                    )
                }
                Err(CopilotLoginWriteError::Validation(error)) => {
                    (copilot_login_failure(error.kind()), None)
                }
                Err(CopilotLoginWriteError::InvalidSecret) => (AppExitCode::Internal, None),
                Err(CopilotLoginWriteError::Storage(_error)) => (secret_service_failure(), None),
            }
        }
    }
}

fn open_copilot_verification_url(url: &str) {
    let launcher = std::path::Path::new("/usr/share/omarchy/bin/omarchy");
    let result = ProcessCommand::new(launcher)
        .args(["launch", "browser", url])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if result.is_err() {
        eprintln!("omarchy-ai-bar: could not open the browser; use the URL shown above");
    }
}

fn copilot_login_failure(kind: ErrorKind) -> AppExitCode {
    match kind {
        ErrorKind::PermissionDenied => {
            eprintln!("omarchy-ai-bar: GitHub denied the Copilot authorization request");
            AppExitCode::Authentication
        }
        ErrorKind::AuthenticationExpired => {
            eprintln!("omarchy-ai-bar: the GitHub device code expired; start login again");
            AppExitCode::Authentication
        }
        ErrorKind::Network => {
            eprintln!("omarchy-ai-bar: GitHub could not be reached");
            AppExitCode::Unavailable
        }
        _ => {
            eprintln!("omarchy-ai-bar: GitHub device authorization could not be completed");
            AppExitCode::Unavailable
        }
    }
}

fn restart_user_service_after_copilot_change() {
    let status = ProcessCommand::new("/usr/bin/systemctl")
        .args(COPILOT_SERVICE_RESTART_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !status.is_ok_and(|status| status.success()) {
        eprintln!("omarchy-ai-bar: restart the user service to apply the Copilot session");
    }
}

fn run_hooks(arguments: &HooksArgs) -> AppExitCode {
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    let hook_directory = paths.config_dir().join("hooks.d");
    match arguments.action.as_ref() {
        Some(HooksAction::Path) => {
            println!("{}", hook_directory.display());
            AppExitCode::Success
        }
        None | Some(HooksAction::List(_)) => {
            let format = match arguments.action.as_ref() {
                Some(HooksAction::List(output)) => output.format,
                _ => OutputFormat::Human,
            };
            list_hooks(&hook_directory, format)
        }
        Some(HooksAction::Run { event }) => run_hook(&hook_directory, event),
    }
}

fn run_plugins(arguments: &PluginsArgs) -> AppExitCode {
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    let plugin_directory = paths.config_dir().join("plugins");
    match arguments.action.as_ref() {
        Some(PluginsAction::Path) => {
            println!("{}", plugin_directory.display());
            AppExitCode::Success
        }
        None | Some(PluginsAction::List(_)) => {
            let format = match arguments.action.as_ref() {
                Some(PluginsAction::List(output)) => output.format,
                _ => OutputFormat::Human,
            };
            list_plugins(&plugin_directory, format)
        }
        Some(PluginsAction::Validate { path }) => match evaluate_plugin_file(path) {
            Ok(evaluation) => {
                println!(
                    "Plugin {} ({}) is valid.",
                    evaluation.manifest.name, evaluation.manifest.id
                );
                AppExitCode::Success
            }
            Err(code) => code,
        },
        Some(PluginsAction::Run { path, output }) => match evaluate_plugin_file(path) {
            Ok(evaluation) => match output.format {
                OutputFormat::Human => {
                    println!("{} ({})", evaluation.manifest.name, evaluation.manifest.id);
                    match serde_json::to_string_pretty(&evaluation.sample) {
                        Ok(sample) => {
                            println!("{sample}");
                            AppExitCode::Success
                        }
                        Err(_error) => AppExitCode::Internal,
                    }
                }
                OutputFormat::Json | OutputFormat::Toon => {
                    let value = serde_json::to_value(evaluation).unwrap_or(Value::Null);
                    write_local_value(output.format, &value)
                }
            },
            Err(code) => code,
        },
    }
}

fn list_plugins(directory: &std::path::Path, format: OutputFormat) -> AppExitCode {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return render_plugin_list(directory, format, &[]);
        }
        Err(_error) => {
            eprintln!("omarchy-ai-bar: plugin directory could not be read safely");
            return AppExitCode::Internal;
        }
    };
    let mut sources = Vec::new();
    for entry in entries.take(129) {
        let Ok(entry) = entry else {
            return AppExitCode::Internal;
        };
        let path = entry.path();
        let is_javascript = path.extension().and_then(OsStr::to_str) == Some("js");
        if is_javascript && safe_owned_regular_file(&path).is_ok() {
            sources.push(path);
        }
    }
    if sources.len() > 128 {
        eprintln!("omarchy-ai-bar: plugin directory exceeds the source-file limit");
        return AppExitCode::Usage;
    }
    sources.sort();
    render_plugin_list(directory, format, &sources)
}

fn render_plugin_list(
    directory: &std::path::Path,
    format: OutputFormat,
    sources: &[PathBuf],
) -> AppExitCode {
    let rows = sources
        .iter()
        .map(|path| {
            json!({
                "file": path.file_name().and_then(OsStr::to_str).unwrap_or("unknown"),
                "path": path,
            })
        })
        .collect::<Vec<_>>();
    match format {
        OutputFormat::Human => {
            println!("Plugins: {}", directory.display());
            if rows.is_empty() {
                println!("No user-provider plugin sources are installed.");
            } else {
                for row in rows {
                    println!("{}", row["file"].as_str().unwrap_or("unknown"));
                }
            }
            AppExitCode::Success
        }
        OutputFormat::Json | OutputFormat::Toon => write_local_value(format, &Value::Array(rows)),
    }
}

fn evaluate_plugin_file(
    path: &std::path::Path,
) -> Result<oab_plugins::PluginEvaluation, AppExitCode> {
    if safe_owned_regular_file(path).is_err() {
        eprintln!("omarchy-ai-bar: plugin source is missing or unsafe");
        return Err(AppExitCode::Unavailable);
    }
    let mut file = std::fs::File::open(path).map_err(|_error| AppExitCode::Unavailable)?;
    let mut source = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(oab_plugins::MAX_PLUGIN_SOURCE_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut source)
        .map_err(|_error| AppExitCode::Internal)?;
    match oab_plugins::evaluate(&source) {
        Ok(evaluation) => Ok(evaluation),
        Err(error) => {
            eprintln!("omarchy-ai-bar: {error}");
            Err(AppExitCode::Usage)
        }
    }
}

fn safe_owned_regular_file(path: &std::path::Path) -> io::Result<()> {
    let metadata = path.symlink_metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe source file",
        ));
    }
    Ok(())
}

fn list_hooks(directory: &std::path::Path, format: OutputFormat) -> AppExitCode {
    let rows = HOOK_EVENTS
        .into_iter()
        .map(|event| {
            json!({
                "event": event,
                "installed": validate_hook_executable(&directory.join(event)).is_ok(),
            })
        })
        .collect::<Vec<_>>();
    match format {
        OutputFormat::Human => {
            println!("Hooks: {}", directory.display());
            for row in &rows {
                let event = row["event"].as_str().unwrap_or("unknown");
                let state = if row["installed"].as_bool() == Some(true) {
                    "installed"
                } else {
                    "not installed"
                };
                println!("{event}: {state}");
            }
            AppExitCode::Success
        }
        OutputFormat::Json | OutputFormat::Toon => write_local_value(format, &Value::Array(rows)),
    }
}

fn run_hook(directory: &std::path::Path, event: &str) -> AppExitCode {
    if !HOOK_EVENTS.contains(&event) {
        eprintln!("omarchy-ai-bar: unsupported hook event");
        return AppExitCode::Usage;
    }
    let executable = directory.join(event);
    if validate_hook_executable(&executable).is_err() {
        eprintln!("omarchy-ai-bar: hook executable is missing or unsafe");
        return AppExitCode::Unavailable;
    }
    let mut command = ProcessCommand::new(&executable);
    command
        .env_clear()
        .env("OMARCHY_AI_BAR_EVENT", event)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(path) = env::var_os("PATH") {
        command.env("PATH", path);
    }
    let Ok(mut child) = command.spawn() else {
        eprintln!("omarchy-ai-bar: hook could not be started");
        return AppExitCode::Internal;
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                println!("Hook {event} completed.");
                return AppExitCode::Success;
            }
            Ok(Some(_status)) => {
                eprintln!("omarchy-ai-bar: hook reported failure");
                return AppExitCode::Unavailable;
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                eprintln!("omarchy-ai-bar: hook exceeded the 30 second limit");
                return AppExitCode::Unavailable;
            }
            Err(_error) => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                eprintln!("omarchy-ai-bar: hook status could not be read");
                return AppExitCode::Internal;
            }
        }
    }
}

fn validate_hook_executable(path: &std::path::Path) -> io::Result<()> {
    let metadata = path.symlink_metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe hook executable",
        ));
    }
    Ok(())
}

fn list_manual_credentials(format: OutputFormat) -> AppExitCode {
    let rows = crate::credentials::MANUAL_CREDENTIALS
        .iter()
        .map(|entry| {
            json!({
                "provider": entry.provider,
                "environment_override": entry.environment,
                "managed_store": "Secret Service",
            })
        })
        .collect::<Vec<_>>();
    match format {
        OutputFormat::Human => {
            println!("Managed credential providers:");
            for entry in crate::credentials::MANUAL_CREDENTIALS {
                println!("{} ({})", entry.provider, entry.environment);
            }
            AppExitCode::Success
        }
        OutputFormat::Json | OutputFormat::Toon => write_local_value(format, &Value::Array(rows)),
    }
}

fn manual_secret_key(provider: &str, account: &str) -> Option<SecretKey> {
    if crate::credentials::credential_for(provider).is_none() {
        eprintln!("omarchy-ai-bar: provider does not accept a managed credential");
        return None;
    }
    match SecretKey::new(
        provider,
        account,
        crate::credentials::MANUAL_SESSION_PURPOSE,
    ) {
        Ok(key) => Some(key),
        Err(_error) => {
            eprintln!("omarchy-ai-bar: provider or account identifier is invalid");
            None
        }
    }
}

fn credential_secret_key(provider: &str, account: &str, slot: Option<&str>) -> Option<SecretKey> {
    let Some(slot) = slot else {
        return manual_secret_key(provider, account);
    };
    let Ok(provider) = provider.parse::<ProviderId>() else {
        eprintln!("omarchy-ai-bar: unknown provider");
        return None;
    };
    let supported = settings_for(provider).is_some_and(|settings| {
        settings.controls.iter().any(|control| match control {
            ProviderSettingsControlDescriptor::SecretSlot(descriptor) => {
                descriptor.item.availability.is_implemented() && descriptor.slot.as_str() == slot
            }
            _ => false,
        })
    });
    if !supported {
        eprintln!("omarchy-ai-bar: credential slot is unavailable for this provider");
        return None;
    }
    // z.ai's typed API-key control is the same primary credential shipped in
    // 0.2.x. Preserve that exact key so existing users can replace or delete
    // it without creating a shadow credential.
    if provider == ProviderId::Zai && slot == "zai-api-key" {
        return manual_secret_key(provider.as_str(), account);
    }
    let (Ok(instance), Ok(account)) =
        (ProviderInstanceId::new("default"), AccountKey::new(account))
    else {
        eprintln!("omarchy-ai-bar: provider or account identifier is invalid");
        return None;
    };
    let scope = AccountScope::new(provider, instance, account);
    match CredentialSlotId::new(scope, slot) {
        Ok(slot) => Some(slot.into_secret_key()),
        Err(_error) => {
            eprintln!("omarchy-ai-bar: credential slot is invalid");
            None
        }
    }
}

enum SecretOperation {
    Set { key: SecretKey, secret: SecretValue },
    Status { key: SecretKey },
    Delete { key: SecretKey },
}

fn run_secret_service(operation: SecretOperation) -> AppExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_error) => return AppExitCode::Internal,
    };
    runtime.block_on(async move {
        let store = match SecretServiceStore::connect().await {
            Ok(store) => store,
            Err(_error) => {
                eprintln!("omarchy-ai-bar: desktop Secret Service is unavailable or locked");
                return AppExitCode::Authentication;
            }
        };
        match operation {
            SecretOperation::Set { key, secret } => match store.put(&key, secret).await {
                Ok(()) => {
                    println!("Stored the credential in desktop Secret Service.");
                    AppExitCode::Success
                }
                Err(_error) => secret_service_failure(),
            },
            SecretOperation::Status { key } => match store.get(&key).await {
                Ok(Some(_secret)) => {
                    println!("Managed credential: configured");
                    AppExitCode::Success
                }
                Ok(None) => {
                    println!("Managed credential: not configured");
                    AppExitCode::Unavailable
                }
                Err(_error) => secret_service_failure(),
            },
            SecretOperation::Delete { key } => match store.delete(&key).await {
                Ok(()) => {
                    println!("Deleted the managed credential.");
                    AppExitCode::Success
                }
                Err(_error) => secret_service_failure(),
            },
        }
    })
}

fn secret_service_failure() -> AppExitCode {
    eprintln!("omarchy-ai-bar: desktop Secret Service operation failed");
    AppExitCode::Authentication
}

fn show_cache_status(path: &std::path::Path, format: OutputFormat) -> AppExitCode {
    let (entries, bytes) = match cache_stats(path) {
        Ok(stats) => stats,
        Err(_error) => {
            eprintln!("omarchy-ai-bar: application cache could not be inspected safely");
            return AppExitCode::Internal;
        }
    };
    match format {
        OutputFormat::Human => {
            println!("Cache: {}", path.display());
            println!("Entries: {entries}");
            println!("Bytes: {bytes}");
            AppExitCode::Success
        }
        OutputFormat::Json | OutputFormat::Toon => write_local_value(
            format,
            &json!({"path": path, "entries": entries, "bytes": bytes}),
        ),
    }
}

fn cache_stats(path: &std::path::Path) -> io::Result<(u64, u64)> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe cache root",
        ));
    }
    cache_directory_stats(path, 0)
}

fn cache_directory_stats(path: &std::path::Path, depth: u8) -> io::Result<(u64, u64)> {
    if depth > 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "cache nesting"));
    }
    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.path().symlink_metadata()?;
        entries = entries.saturating_add(1);
        if entries > 100_000 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cache entries"));
        }
        if metadata.file_type().is_file() {
            bytes = bytes.saturating_add(metadata.len());
        } else if metadata.file_type().is_dir() {
            let (nested_entries, nested_bytes) = cache_directory_stats(&entry.path(), depth + 1)?;
            entries = entries.saturating_add(nested_entries);
            bytes = bytes.saturating_add(nested_bytes);
        }
    }
    Ok((entries, bytes))
}

fn clear_cache(path: &std::path::Path) -> AppExitCode {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("Application cache is already empty.");
            return AppExitCode::Success;
        }
        Ok(_) | Err(_) => {
            eprintln!("omarchy-ai-bar: application cache root is unsafe");
            return AppExitCode::Internal;
        }
    }
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_error) => return AppExitCode::Internal,
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return AppExitCode::Internal;
        };
        let entry_path = entry.path();
        let Ok(metadata) = entry_path.symlink_metadata() else {
            return AppExitCode::Internal;
        };
        let result = if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            std::fs::remove_dir_all(&entry_path)
        } else {
            std::fs::remove_file(&entry_path)
        };
        if result.is_err() {
            eprintln!("omarchy-ai-bar: application cache could not be cleared");
            return AppExitCode::Internal;
        }
    }
    println!("Cleared {}", path.display());
    AppExitCode::Success
}

fn run_config(arguments: &ConfigArgs) -> AppExitCode {
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    match arguments.action.as_ref() {
        Some(ConfigAction::Path) => {
            println!("{}", paths.config_file().display());
            AppExitCode::Success
        }
        None | Some(ConfigAction::Show(_)) => {
            let format = match arguments.action.as_ref() {
                Some(ConfigAction::Show(output)) => output.format,
                _ => OutputFormat::Human,
            };
            show_config(&paths, format)
        }
        Some(ConfigAction::Validate { path }) => {
            let active_path = paths.config_file();
            validate_config_path(path.as_deref().unwrap_or(&active_path))
        }
        Some(ConfigAction::Init { force }) => initialize_config(&paths, *force),
        Some(ConfigAction::Describe { provider, output }) => {
            describe_provider_settings(provider.as_deref(), output.format)
        }
        Some(ConfigAction::Enable { provider }) => set_provider_enabled(&paths, provider, true),
        Some(ConfigAction::Disable { provider }) => set_provider_enabled(&paths, provider, false),
        Some(ConfigAction::SetEndpoint {
            provider,
            endpoint,
            clear,
        }) => set_provider_endpoint(
            &paths,
            provider,
            if *clear { None } else { endpoint.as_deref() },
        ),
        Some(ConfigAction::SetOption {
            provider,
            key,
            value,
            clear,
        }) => set_provider_option(
            &paths,
            provider,
            key,
            if *clear { None } else { value.as_deref() },
        ),
    }
}

fn show_config(paths: &AppPaths, format: OutputFormat) -> AppExitCode {
    let file = paths.config_file();
    let bytes = match std::fs::symlink_metadata(&file) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_error) => {
            eprintln!("omarchy-ai-bar: active configuration could not be inspected safely");
            return AppExitCode::Internal;
        }
        Ok(_) => match read_private_file(&file, MAX_CONFIG_BYTES) {
            Ok(bytes) => bytes,
            Err(_error) => {
                eprintln!("omarchy-ai-bar: active configuration could not be read safely");
                return AppExitCode::Internal;
            }
        },
    };
    let value = match bytes {
        Some(bytes) => match load_config_bytes(&bytes) {
            Ok(config) => serde_json::to_value(config).ok(),
            Err(error) => {
                eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
                return AppExitCode::Usage;
            }
        },
        None => None,
    };
    match format {
        OutputFormat::Human => {
            println!("Configuration: {}", file.display());
            match value {
                Some(value) => match serde_json::to_string_pretty(&value) {
                    Ok(rendered) => println!("{rendered}"),
                    Err(_error) => return AppExitCode::Internal,
                },
                None => {
                    println!(
                        "State: not initialized (environment provider settings remain active)"
                    );
                }
            }
            AppExitCode::Success
        }
        OutputFormat::Json | OutputFormat::Toon => write_local_value(
            format,
            &json!({
                "path": file,
                "initialized": value.is_some(),
                "config": value,
            }),
        ),
    }
}

fn validate_config_path(path: &std::path::Path) -> AppExitCode {
    let bytes = match std::fs::read(path) {
        Ok(bytes) if bytes.len() <= MAX_CONFIG_BYTES => bytes,
        Ok(_) => {
            eprintln!("omarchy-ai-bar: invalid configuration (config_too_large)");
            return AppExitCode::Usage;
        }
        Err(_error) => {
            eprintln!("omarchy-ai-bar: configuration file could not be read");
            return AppExitCode::Unavailable;
        }
    };
    match load_config_bytes(&bytes) {
        Ok(_config) => {
            println!("Configuration is valid.");
            AppExitCode::Success
        }
        Err(error) => {
            eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
            AppExitCode::Usage
        }
    }
}

fn initialize_config(paths: &AppPaths, force: bool) -> AppExitCode {
    if paths.create_private_directories().is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    let file = paths.config_file();
    if !force {
        match read_private_file(&file, MAX_CONFIG_BYTES) {
            Ok(Some(_)) => {
                eprintln!(
                    "omarchy-ai-bar: configuration already exists; use --force to replace it"
                );
                return AppExitCode::Usage;
            }
            Ok(None) => {}
            Err(_error) => {
                eprintln!("{INTERNAL_MESSAGE}");
                return AppExitCode::Internal;
            }
        }
    }
    let document = json!({
        "schema_version": CURRENT_SCHEMA_VERSION,
        "providers": [],
        "provider_order": [],
    });
    let mut bytes = match serde_json::to_vec_pretty(&document) {
        Ok(bytes) => bytes,
        Err(_error) => return AppExitCode::Internal,
    };
    bytes.push(b'\n');
    if atomic_write(&file, &bytes).is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    println!("Initialized {}", file.display());
    AppExitCode::Success
}

fn describe_provider_settings(provider: Option<&str>, format: OutputFormat) -> AppExitCode {
    let providers = if let Some(provider) = provider {
        let Ok(provider) = provider.parse::<ProviderId>() else {
            eprintln!("omarchy-ai-bar: unknown provider");
            return AppExitCode::Usage;
        };
        vec![provider]
    } else {
        ProviderId::ALL.to_vec()
    };
    let descriptors = providers
        .into_iter()
        .filter_map(|provider| settings_for(provider))
        .collect::<Vec<_>>();
    if provider.is_some() && descriptors.is_empty() {
        eprintln!("omarchy-ai-bar: provider settings are not typed in this build");
        return AppExitCode::Unavailable;
    }

    match format {
        OutputFormat::Human => {
            println!("Typed provider settings:");
            for descriptor in descriptors {
                println!("{}:", descriptor.provider.as_str());
                for control in descriptor.controls {
                    let item = control.item();
                    let state = match item.availability {
                        ProviderSettingsAvailability::Implemented => "available",
                        ProviderSettingsAvailability::Unavailable { .. } => "unavailable",
                    };
                    println!("  {} [{}] — {}", item.id.as_str(), state, item.title);
                }
            }
            AppExitCode::Success
        }
        OutputFormat::Json | OutputFormat::Toon => write_local_value(
            format,
            &json!({
                "schema_version": 1,
                "providers": descriptors,
            }),
        ),
    }
}

#[derive(Debug)]
enum ProviderOptionUpdate {
    Source(Option<ProviderSourceMode>),
    ExternalOauthSources(Option<bool>),
    ExtrasEnabled(Option<bool>),
    CookieSource(Option<ProviderCookieSource>),
    EnterpriseHost(Option<String>),
    Region(Option<String>),
}

fn set_provider_option(
    paths: &AppPaths,
    provider: &str,
    key: &str,
    value: Option<&str>,
) -> AppExitCode {
    let Ok(provider) = provider.parse::<ProviderId>() else {
        eprintln!("omarchy-ai-bar: unknown provider");
        return AppExitCode::Usage;
    };
    let update = match provider_option_update(provider, key, value) {
        Ok(update) => update,
        Err(message) => {
            eprintln!("omarchy-ai-bar: {message}");
            return AppExitCode::Usage;
        }
    };
    if paths.create_private_directories().is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    let file = paths.config_file();
    let mut config = match read_private_file(&file, MAX_CONFIG_BYTES) {
        Ok(Some(bytes)) => match load_config_bytes(&bytes) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
                return AppExitCode::Usage;
            }
        },
        Ok(None) => AppConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            providers: Vec::new(),
            provider_order: Vec::new(),
        },
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            return AppExitCode::Internal;
        }
    };
    let default_instance = ProviderInstanceId::new("default")
        .expect("the fixed default provider instance is canonical");
    let route = if let Some(index) = config
        .providers
        .iter()
        .position(|route| route.id == provider && route.instance_id == default_instance)
    {
        &mut config.providers[index]
    } else {
        config.providers.push(ProviderConfig {
            id: provider,
            instance_id: default_instance,
            enabled: false,
            endpoint: None,
            config_path: None,
            options: ProviderOptions::default(),
            accounts: Vec::new(),
        });
        if !config.provider_order.contains(&provider) {
            config.provider_order.push(provider);
        }
        config
            .providers
            .last_mut()
            .expect("one provider route was just inserted")
    };
    apply_provider_option_update(route, update);
    if let Err(error) = validate_config(&config) {
        eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
        return AppExitCode::Usage;
    }
    let mut bytes = match serde_json::to_vec_pretty(&config) {
        Ok(bytes) => bytes,
        Err(_error) => return AppExitCode::Internal,
    };
    bytes.push(b'\n');
    if atomic_write(&file, &bytes).is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    println!(
        "{} {} for {}. Restart the user service to apply collection changes.",
        if value.is_some() {
            "Configured"
        } else {
            "Cleared"
        },
        key,
        provider.as_str()
    );
    AppExitCode::Success
}

fn provider_option_update(
    provider: ProviderId,
    key: &str,
    value: Option<&str>,
) -> Result<ProviderOptionUpdate, &'static str> {
    let descriptor =
        settings_for(provider).ok_or("provider settings are not typed in this build")?;
    let control = descriptor
        .controls
        .iter()
        .find(|control| control.item().id.as_str() == key)
        .ok_or("unknown provider option")?;
    if !control.item().availability.is_implemented() {
        return Err("provider option is unavailable in this build");
    }
    validate_provider_option_value(control, value)?;

    match control.item().id {
        ProviderSettingId::CodexUsageSource => Ok(ProviderOptionUpdate::Source(
            value.map(parse_codex_source).transpose()?,
        )),
        ProviderSettingId::ClaudeUsageSource => Ok(ProviderOptionUpdate::Source(
            value.map(parse_claude_source).transpose()?,
        )),
        ProviderSettingId::GrokUsageSource => Ok(ProviderOptionUpdate::Source(
            value.map(parse_grok_source).transpose()?,
        )),
        ProviderSettingId::GrokCookieSource => Ok(ProviderOptionUpdate::CookieSource(
            value.map(parse_grok_cookie_source).transpose()?,
        )),
        ProviderSettingId::CodexExternalOauthSources => Ok(
            ProviderOptionUpdate::ExternalOauthSources(value.map(parse_boolean).transpose()?),
        ),
        ProviderSettingId::CopilotBudgetExtras => Ok(ProviderOptionUpdate::ExtrasEnabled(
            value.map(parse_boolean).transpose()?,
        )),
        ProviderSettingId::CopilotBudgetCookieSource => Ok(ProviderOptionUpdate::CookieSource(
            value.map(parse_copilot_cookie_source).transpose()?,
        )),
        ProviderSettingId::CopilotEnterpriseHost => Ok(ProviderOptionUpdate::EnterpriseHost(
            value.map(parse_copilot_enterprise_host).transpose()?,
        )),
        ProviderSettingId::ZaiApiRegion => {
            Ok(ProviderOptionUpdate::Region(value.map(str::to_owned)))
        }
        _ => Err("provider option is not connected to runtime configuration"),
    }
}

fn validate_provider_option_value(
    control: &ProviderSettingsControlDescriptor,
    value: Option<&str>,
) -> Result<(), &'static str> {
    let Some(value) = value else {
        return Ok(());
    };
    match control {
        ProviderSettingsControlDescriptor::Picker(picker) => {
            let choice = picker
                .options
                .iter()
                .find(|option| option.choice.as_str() == value)
                .ok_or("unknown provider option value")?;
            if choice.availability.is_implemented() {
                Ok(())
            } else {
                Err("provider option value is unavailable in this build")
            }
        }
        ProviderSettingsControlDescriptor::Toggle(_) => parse_boolean(value).map(|_| ()),
        ProviderSettingsControlDescriptor::PlainOption(_) => {
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
                Err("provider option value is invalid")
            } else {
                Ok(())
            }
        }
        ProviderSettingsControlDescriptor::SecretSlot(_) => {
            Err("use the credential command for secret provider settings")
        }
    }
}

fn parse_boolean(value: &str) -> Result<bool, &'static str> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("provider toggle must be true or false"),
    }
}

fn parse_codex_source(value: &str) -> Result<ProviderSourceMode, &'static str> {
    match value {
        "auto" => Ok(ProviderSourceMode::Auto),
        "pat" => Ok(ProviderSourceMode::Pat),
        "oauth" => Ok(ProviderSourceMode::Oauth),
        "cli" => Ok(ProviderSourceMode::Cli),
        _ => Err("Codex source is unavailable in this build"),
    }
}

fn parse_claude_source(value: &str) -> Result<ProviderSourceMode, &'static str> {
    match value {
        "auto" => Ok(ProviderSourceMode::Auto),
        "oauth" => Ok(ProviderSourceMode::Oauth),
        "cli" => Ok(ProviderSourceMode::Cli),
        _ => Err("Claude source is unavailable in this build"),
    }
}

fn parse_grok_source(value: &str) -> Result<ProviderSourceMode, &'static str> {
    match value {
        "auto" => Ok(ProviderSourceMode::Auto),
        "cli" => Ok(ProviderSourceMode::Cli),
        "oauth" => Ok(ProviderSourceMode::Oauth),
        "web" => Ok(ProviderSourceMode::Web),
        _ => Err("Grok source is unavailable in this build"),
    }
}

fn parse_grok_cookie_source(value: &str) -> Result<ProviderCookieSource, &'static str> {
    match value {
        "auto" => Ok(ProviderCookieSource::Auto),
        "manual" => Ok(ProviderCookieSource::Manual),
        "off" => Ok(ProviderCookieSource::Off),
        _ => Err("Grok cookie source is unavailable in this build"),
    }
}

fn parse_copilot_cookie_source(value: &str) -> Result<ProviderCookieSource, &'static str> {
    match value {
        "manual" => Ok(ProviderCookieSource::Manual),
        _ => Err("automatic Copilot budget-cookie discovery is unavailable in this build"),
    }
}

fn parse_copilot_enterprise_host(value: &str) -> Result<String, &'static str> {
    let host = normalize_enterprise_host(Some(value))
        .map_err(|_error| "Copilot enterprise host is invalid")?;
    CopilotDeviceFlow::new(Some(&host)).map_err(|_error| "Copilot enterprise host is invalid")?;
    Ok(host)
}

fn apply_provider_option_update(route: &mut ProviderConfig, update: ProviderOptionUpdate) {
    match update {
        ProviderOptionUpdate::Source(value) => route.options.source = value,
        ProviderOptionUpdate::ExternalOauthSources(value) => match value {
            Some(value) => {
                route.options.extensions.insert(
                    "external_oauth_sources".to_owned(),
                    ProviderOptionValue::Boolean(value),
                );
            }
            None => {
                route.options.extensions.remove("external_oauth_sources");
            }
        },
        ProviderOptionUpdate::ExtrasEnabled(value) => route.options.extras_enabled = value,
        ProviderOptionUpdate::CookieSource(value) => route.options.cookie_source = value,
        ProviderOptionUpdate::EnterpriseHost(value) => route.options.enterprise_host = value,
        ProviderOptionUpdate::Region(value) => route.options.region = value,
    }
}

fn set_provider_enabled(paths: &AppPaths, provider: &str, enabled: bool) -> AppExitCode {
    let Ok(provider) = provider.parse::<ProviderId>() else {
        eprintln!("omarchy-ai-bar: unknown provider");
        return AppExitCode::Usage;
    };
    if paths.create_private_directories().is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    let file = paths.config_file();
    let mut config = match read_private_file(&file, MAX_CONFIG_BYTES) {
        Ok(Some(bytes)) => match load_config_bytes(&bytes) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
                return AppExitCode::Usage;
            }
        },
        Ok(None) => AppConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            providers: Vec::new(),
            provider_order: Vec::new(),
        },
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            return AppExitCode::Internal;
        }
    };
    let default_instance = ProviderInstanceId::new("default")
        .expect("the fixed default provider instance is canonical");
    if let Some(route) = config
        .providers
        .iter_mut()
        .find(|route| route.id == provider && route.instance_id == default_instance)
    {
        route.enabled = enabled;
    } else {
        config.providers.push(ProviderConfig {
            id: provider,
            instance_id: default_instance.clone(),
            enabled,
            endpoint: None,
            config_path: None,
            options: ProviderOptions::default(),
            accounts: Vec::new(),
        });
        if !config.provider_order.contains(&provider) {
            config.provider_order.push(provider);
        }
    }
    let mut bytes = match serde_json::to_vec_pretty(&config) {
        Ok(bytes) => bytes,
        Err(_error) => return AppExitCode::Internal,
    };
    bytes.push(b'\n');
    if atomic_write(&file, &bytes).is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    println!(
        "{} {}. Restart the user service to apply collection changes.",
        if enabled { "Enabled" } else { "Disabled" },
        provider.as_str()
    );
    AppExitCode::Success
}

fn set_provider_endpoint(paths: &AppPaths, provider: &str, endpoint: Option<&str>) -> AppExitCode {
    let Ok(provider) = provider.parse::<ProviderId>() else {
        eprintln!("omarchy-ai-bar: unknown provider");
        return AppExitCode::Usage;
    };
    if !crate::provider_config::supports_provider_endpoint(provider) {
        eprintln!("omarchy-ai-bar: provider does not support one configurable endpoint");
        return AppExitCode::Usage;
    }
    if paths.create_private_directories().is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    let file = paths.config_file();
    let mut config = match read_private_file(&file, MAX_CONFIG_BYTES) {
        Ok(Some(bytes)) => match load_config_bytes(&bytes) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
                return AppExitCode::Usage;
            }
        },
        Ok(None) => AppConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            providers: Vec::new(),
            provider_order: Vec::new(),
        },
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            return AppExitCode::Internal;
        }
    };
    let default_instance = ProviderInstanceId::new("default")
        .expect("the fixed default provider instance is canonical");
    let endpoint = endpoint.map(str::to_owned);
    if let Some(route) = config
        .providers
        .iter_mut()
        .find(|route| route.id == provider && route.instance_id == default_instance)
    {
        route.endpoint = endpoint;
    } else {
        config.providers.push(ProviderConfig {
            id: provider,
            instance_id: default_instance.clone(),
            enabled: false,
            endpoint,
            config_path: None,
            options: ProviderOptions::default(),
            accounts: Vec::new(),
        });
        if !config.provider_order.contains(&provider) {
            config.provider_order.push(provider);
        }
    }
    if let Err(error) = validate_config(&config) {
        eprintln!("omarchy-ai-bar: invalid configuration ({})", error.code());
        return AppExitCode::Usage;
    }
    let mut bytes = match serde_json::to_vec_pretty(&config) {
        Ok(bytes) => bytes,
        Err(_error) => return AppExitCode::Internal,
    };
    bytes.push(b'\n');
    if atomic_write(&file, &bytes).is_err() {
        eprintln!("{INTERNAL_MESSAGE}");
        return AppExitCode::Internal;
    }
    println!(
        "{} endpoint for {}. Restart the user service to apply collection changes.",
        if config
            .providers
            .iter()
            .find(|route| route.id == provider && route.instance_id == default_instance)
            .and_then(|route| route.endpoint.as_ref())
            .is_some()
        {
            "Configured"
        } else {
            "Cleared"
        },
        provider.as_str()
    );
    AppExitCode::Success
}

fn write_local_value(format: OutputFormat, value: &Value) -> AppExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let result = match format {
        OutputFormat::Json => write_json_line(&mut output, value),
        OutputFormat::Toon => write_toon(&mut output, value),
        OutputFormat::Human => unreachable!("human values are rendered by their command"),
    };
    if result.is_ok() {
        AppExitCode::Success
    } else {
        eprintln!("{INTERNAL_MESSAGE}");
        AppExitCode::Internal
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
            let active_config = match read_private_file(paths.config_file(), MAX_CONFIG_BYTES) {
                Ok(Some(bytes)) => match load_config_bytes(&bytes) {
                    Ok(config) => Some(config),
                    Err(_error) => {
                        eprintln!("{INTERNAL_MESSAGE}");
                        return AppExitCode::Internal;
                    }
                },
                Ok(None) => None,
                Err(_error) => {
                    eprintln!("{INTERNAL_MESSAGE}");
                    return AppExitCode::Internal;
                }
            };
            let providers = match crate::provider_bootstrap::discover(active_config.as_ref()) {
                Ok(providers) => providers,
                Err(_error) => {
                    eprintln!("{INTERNAL_MESSAGE}");
                    return AppExitCode::Internal;
                }
            };
            let snapshot_cache = paths.cache_dir().join("last-known-good.json");
            match daemon::run(socket, &display_socket, &snapshot_cache, providers) {
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

fn run_guard(arguments: &GuardArgs) -> AppExitCode {
    let Some(paths) = resolved_paths() else {
        return AppExitCode::Internal;
    };
    let payload = match forward(&paths.socket_path(), ControlAction::Usage) {
        Ok(ForwardOutcome::Response(response)) if response.status() == ControlStatus::Accepted => {
            response.payload().cloned()
        }
        Ok(ForwardOutcome::Response(_) | ForwardOutcome::NoDaemon) => None,
        Err(_error) => {
            eprintln!("{INTERNAL_MESSAGE}");
            return AppExitCode::Internal;
        }
    };
    let Some(payload) = payload else {
        eprintln!("{DAEMON_UNAVAILABLE_MESSAGE}");
        return AppExitCode::Unavailable;
    };
    let snapshots = payload
        .get("snapshots")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut evaluated = 0_usize;
    let mut denied = Vec::new();
    for snapshot in snapshots {
        let provider = provider_id(snapshot);
        if arguments
            .provider
            .as_deref()
            .is_some_and(|requested| requested != provider)
        {
            continue;
        }
        let Some(percent) = snapshot
            .pointer("/last_known_good/primary/usage/used_percent")
            .and_then(Value::as_f64)
        else {
            continue;
        };
        evaluated += 1;
        if percent >= f64::from(arguments.max_used) {
            denied.push((provider.to_owned(), percent));
        }
    }
    if arguments.provider.is_some() && evaluated == 0 {
        eprintln!("omarchy-ai-bar: requested provider has no available quota sample");
        return AppExitCode::Unavailable;
    }
    if !denied.is_empty() {
        if !arguments.quiet {
            for (provider, percent) in denied {
                println!(
                    "DENY {}: {}% used (limit {}%)",
                    provider_label(&provider),
                    format_percent(percent),
                    arguments.max_used
                );
            }
        }
        return AppExitCode::GuardDenied;
    }
    if !arguments.quiet {
        println!(
            "ALLOW: {evaluated} available provider sample(s) below {}% used",
            arguments.max_used
        );
    }
    AppExitCode::Success
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
        ControlAction::Cost => write_cost_human(output, payload),
        ControlAction::Sessions => write_sessions_human(output, payload),
        ControlAction::Activate | ControlAction::Dashboard => Ok(()),
    }
}

fn write_cost_human(output: &mut impl Write, payload: &Value) -> io::Result<()> {
    let rows = payload
        .get("providers")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if rows.is_empty() {
        writeln!(output, "No provider cost data is currently available.")?;
        return Ok(());
    }
    for row in rows {
        let provider = row
            .get("provider")
            .and_then(Value::as_str)
            .map_or("Unknown", provider_label);
        let amount = row.pointer("/cost/used/amount").and_then(Value::as_str);
        let currency = row.pointer("/cost/used/currency").and_then(Value::as_str);
        match (amount, currency) {
            (Some(amount), Some(currency)) => writeln!(output, "{provider}: {amount} {currency}")?,
            _ => writeln!(output, "{provider}: cost details available")?,
        }
    }
    Ok(())
}

fn write_sessions_human(output: &mut impl Write, payload: &Value) -> io::Result<()> {
    let rows = payload
        .get("sessions")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if rows.is_empty() {
        return writeln!(
            output,
            "No active provider sessions are currently reported."
        );
    }
    for row in rows {
        let provider = row
            .get("provider")
            .and_then(Value::as_str)
            .map_or("Unknown", provider_label);
        let session = row
            .get("session")
            .and_then(Value::as_str)
            .unwrap_or("active");
        writeln!(output, "{provider}: {session}")?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Mutex, PoisonError};

    use oab_auth::secret_store::{SecretFuture, SecretStore};

    use super::*;

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<HashMap<SecretKey, Vec<u8>>>,
    }

    impl SecretStore for MemorySecretStore {
        fn get<'a>(
            &'a self,
            key: &'a SecretKey,
        ) -> SecretFuture<'a, Result<Option<SecretValue>, SecretStoreError>> {
            Box::pin(async move {
                self.values
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(key)
                    .cloned()
                    .map(SecretValue::new)
                    .transpose()
                    .map_err(|_| SecretStoreError::InvalidData)
            })
        }

        fn put<'a>(
            &'a self,
            key: &'a SecretKey,
            secret: SecretValue,
        ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
            Box::pin(async move {
                self.values
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(key.clone(), secret.expose_secret().to_vec());
                Ok(())
            })
        }

        fn delete<'a>(
            &'a self,
            key: &'a SecretKey,
        ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
            Box::pin(async move {
                self.values
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(key);
                Ok(())
            })
        }
    }

    struct StoreMustNotBeReached;

    impl SecretStore for StoreMustNotBeReached {
        fn get<'a>(
            &'a self,
            _key: &'a SecretKey,
        ) -> SecretFuture<'a, Result<Option<SecretValue>, SecretStoreError>> {
            Box::pin(async { panic!("validation failure must not read the secret store") })
        }

        fn put<'a>(
            &'a self,
            _key: &'a SecretKey,
            _secret: SecretValue,
        ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
            Box::pin(async { panic!("validation failure must not write the secret store") })
        }

        fn delete<'a>(
            &'a self,
            _key: &'a SecretKey,
        ) -> SecretFuture<'a, Result<(), SecretStoreError>> {
            Box::pin(async { panic!("validation failure must not delete from the secret store") })
        }
    }

    #[tokio::test]
    async fn failed_copilot_identity_validation_never_reaches_secret_storage() {
        let key = crate::credentials::copilot_oauth_key().expect("fixed key");
        let result = validate_and_replace_copilot_secret(&StoreMustNotBeReached, &key, async {
            Err(ClassifiedError::new(ErrorKind::Parse))
        })
        .await;

        assert!(matches!(
            result,
            Err(CopilotLoginWriteError::Validation(error))
                if error.kind() == ErrorKind::Parse
        ));
    }

    #[tokio::test]
    async fn incomplete_copilot_login_restores_or_deletes_the_exact_app_secret() {
        let store = MemorySecretStore::default();
        let key = crate::credentials::copilot_oauth_key().expect("fixed key");

        store
            .put(&key, SecretValue::new(b"new-token".to_vec()).expect("new"))
            .await
            .expect("put new");
        rollback_copilot_secret(&store, &key, None)
            .await
            .expect("delete incomplete first login");
        assert!(store.get(&key).await.expect("get missing").is_none());

        store
            .put(
                &key,
                SecretValue::new(b"replacement".to_vec()).expect("replacement"),
            )
            .await
            .expect("put replacement");
        rollback_copilot_secret(
            &store,
            &key,
            Some(SecretValue::new(b"previous".to_vec()).expect("previous")),
        )
        .await
        .expect("restore previous");
        assert_eq!(
            store
                .get(&key)
                .await
                .expect("get previous")
                .expect("previous present")
                .expose_secret(),
            b"previous"
        );
    }

    #[tokio::test]
    async fn copilot_status_login_and_logout_preserve_every_non_session_secret() {
        let store = MemorySecretStore::default();
        let session_key = crate::credentials::copilot_oauth_key().expect("fixed session key");
        let decoys = [
            SecretKey::new("copilot", "ambient", "copilot-cli").expect("CLI decoy"),
            SecretKey::new("github", "ambient", "oauth-token").expect("GitHub CLI decoy"),
            SecretKey::new(
                "copilot",
                "ambient",
                "credential-slot/v1/default/copilot-budget-cookie",
            )
            .expect("budget decoy"),
        ];
        for (index, key) in decoys.iter().enumerate() {
            store
                .put(
                    key,
                    SecretValue::new(format!("decoy-{index}").into_bytes()).expect("decoy value"),
                )
                .await
                .expect("seed decoy");
        }

        assert!(
            !copilot_secret_configured(&store, &session_key)
                .await
                .expect("missing status")
        );
        let previous = replace_copilot_secret(
            &store,
            &session_key,
            SecretValue::new(b"app-session".to_vec()).expect("session value"),
        )
        .await
        .expect("store app session");
        assert!(previous.is_none());
        assert!(
            copilot_secret_configured(&store, &session_key)
                .await
                .expect("configured status")
        );

        delete_copilot_secret(&store, &session_key)
            .await
            .expect("delete app session");
        assert!(
            !copilot_secret_configured(&store, &session_key)
                .await
                .expect("deleted status")
        );
        for (index, key) in decoys.iter().enumerate() {
            assert_eq!(
                store
                    .get(key)
                    .await
                    .expect("read decoy")
                    .expect("decoy retained")
                    .expose_secret(),
                format!("decoy-{index}").as_bytes()
            );
        }
    }

    #[test]
    fn copilot_changes_start_an_inactive_user_service() {
        assert_eq!(
            COPILOT_SERVICE_RESTART_ARGS,
            ["--user", "restart", "omarchy-ai-bar.service"]
        );
    }

    #[test]
    fn credential_slots_accept_only_implemented_provider_descriptor_slots() {
        let named = credential_secret_key("zai", "ambient", Some("zai-api-key"))
            .expect("implemented z.ai credential slot");
        assert_eq!(named.provider(), "zai");
        assert_eq!(named.account(), "ambient");
        assert_eq!(named.purpose(), crate::credentials::MANUAL_SESSION_PURPOSE);

        assert!(credential_secret_key("zai", "ambient", Some("unknown-slot")).is_none());
        let budget = credential_secret_key("copilot", "ambient", Some("copilot-budget-cookie"))
            .expect("implemented Copilot budget-cookie slot");
        assert_eq!(
            budget.purpose(),
            "credential-slot/v1/default/copilot-budget-cookie"
        );
        assert!(credential_secret_key("codex", "ambient", Some("codex-web-cookie")).is_none());
        let grok = credential_secret_key("grok", "ambient", Some("grok-web-cookie"))
            .expect("implemented Grok web-cookie slot");
        assert_eq!(grok.purpose(), "credential-slot/v1/default/grok-web-cookie");
        let legacy = credential_secret_key("zai", "ambient", None)
            .expect("backwards-compatible primary credential");
        assert_eq!(legacy.purpose(), crate::credentials::MANUAL_SESSION_PURPOSE);
    }
}

#[cfg(test)]
mod secret_input_tests {
    use std::io::{BufReader, Cursor};

    use super::{MAX_SECRET_BYTES, SecretInputError, read_one_line_secret};

    #[test]
    fn newline_terminated_secret_does_not_require_eof() {
        let input = Cursor::new(b"provider-secret\nbytes-that-must-not-be-read".to_vec());
        let mut reader = BufReader::new(input);
        assert_eq!(
            read_one_line_secret(&mut reader).expect("bounded first record"),
            b"provider-secret"
        );
    }

    #[test]
    fn secret_input_accepts_eof_and_crlf_but_rejects_invalid_records() {
        for (input, expected) in [
            (b"secret".as_slice(), b"secret".as_slice()),
            (b"secret\r\n".as_slice(), b"secret".as_slice()),
        ] {
            let mut reader = BufReader::new(Cursor::new(input));
            assert_eq!(
                read_one_line_secret(&mut reader).expect("valid credential record"),
                expected
            );
        }

        for input in [
            b"".as_slice(),
            b"\n".as_slice(),
            b"embedded\rsecret\n".as_slice(),
        ] {
            let mut reader = BufReader::new(Cursor::new(input));
            assert_eq!(
                read_one_line_secret(&mut reader),
                Err(SecretInputError::Invalid)
            );
        }

        let oversized = vec![b'x'; MAX_SECRET_BYTES + 1];
        let mut reader = BufReader::new(Cursor::new(oversized));
        assert_eq!(
            read_one_line_secret(&mut reader),
            Err(SecretInputError::Invalid)
        );
    }
}
