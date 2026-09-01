//! Claude Code OAuth usage adapter for Linux.

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, DataConfidence, ErrorKind, ExactDecimal, NamedRateWindow, ProviderId, RateWindow,
    Timestamp, UsagePercent, UsageSample, WindowDuration, WindowUsage,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use time::{Date, Duration as TimeDuration, Month, PrimitiveDateTime, Time, UtcOffset};
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::classify_https_endpoint;
use crate::executable::ExecutablePath;
use crate::fixed_api::{ApiKeyCredential, FixedApiClient};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{StderrClassifier, SubprocessError, SubprocessRequest};
use crate::transport::TransportConfig;

const USAGE_ENDPOINT: &str = "https://api.anthropic.com/api/oauth/usage";
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const SESSION_WINDOW_MINUTES: i64 = 300;
const WEEKLY_WINDOW_MINUTES: i64 = 10_080;
const CLI_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const CLI_USAGE_TIMEOUT: Duration = Duration::from_secs(20);
const CLI_MAX_AUTH_STDOUT_BYTES: usize = 32 * 1024;
const CLI_MAX_USAGE_STDOUT_BYTES: usize = 128 * 1024;
const CLI_MAX_STDERR_BYTES: usize = 32 * 1024;
const CLI_RATE_LIMIT_TAG: u8 = 1;
const CLI_AUTH_TAG: u8 = 2;
const CLI_RATE_LIMIT_MINUTES: i64 = 5;
const CLI_SUCCESS_CACHE_TTL: Duration = Duration::from_mins(15);
const CLI_STARTUP_DELAY: Duration = Duration::from_secs(2);
const CLI_CAPTURE_SETTLE: Duration = Duration::from_secs(1);
const CLI_INPUT_INTERVAL: Duration = Duration::from_millis(800);
const CLI_TICK: Duration = Duration::from_millis(50);
const CLI_TRUST_SELECTION_SETTLE: Duration = Duration::from_millis(200);
const CLI_TERMINATION_GRACE: Duration = Duration::from_millis(250);
const CLI_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const CLI_LABEL_SCAN_LINES: usize = 12;
const CLI_PROBE_SESSION_ID: &str = "4f6d6172-6368-792d-6169-626172000001";
const CLI_INPUT_USAGE_SENT: u16 = 1 << 0;
const CLI_INPUT_TRUST_ANSWERED: u16 = 1 << 1;
const CLI_INPUT_QUICK_SAFETY_ANSWERED: u16 = 1 << 2;
const CLI_INPUT_TRUST_SELECTION_ANSWERED: u16 = 1 << 3;
const CLI_INPUT_READY_ANSWERED: u16 = 1 << 4;
const CLI_INPUT_CONTINUE_ANSWERED: u16 = 1 << 5;
const CLI_INPUT_PALETTE_ANSWERED: u16 = 1 << 6;
const CLI_INPUT_TRUST_CONFIRMED: u16 = 1 << 7;

const OAUTH_ONLY_PLAN: &[ClaudeFetchSource] = &[ClaudeFetchSource::OAuth];
const CLI_ONLY_PLAN: &[ClaudeFetchSource] = &[ClaudeFetchSource::Cli];
const AUTO_PLAN: &[ClaudeFetchSource] = &[ClaudeFetchSource::OAuth, ClaudeFetchSource::Cli];

/// Claude usage source selected by ordinary, non-secret configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeSourceMode {
    /// Prefer the read-only OAuth usage API, then use Claude Code when the
    /// OAuth failure is safe to hand back to its credential owner.
    Auto,
    /// Use only the exact OAuth credential selected by the application.
    OAuth,
    /// Use only the provider-owned Claude Code executable.
    Cli,
}

/// One concrete source in the immutable Claude fetch plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeFetchSource {
    /// Read the OAuth credential without refreshing or rewriting it.
    OAuth,
    /// Ask the provider-owned CLI for its bounded usage report.
    Cli,
}

/// CodexBar-compatible source ordering projected onto Linux-supported paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaudeSourcePlan {
    ordered_steps: &'static [ClaudeFetchSource],
}

impl ClaudeSourcePlan {
    /// Concrete sources in stable execution order.
    #[must_use]
    pub const fn ordered_steps(self) -> &'static [ClaudeFetchSource] {
        self.ordered_steps
    }
}

/// Resolves Claude source selection without inspecting or mutating credentials.
pub struct ClaudeSourcePlanner;

impl ClaudeSourcePlanner {
    /// Returns an immutable execution plan for one configured source mode.
    #[must_use]
    pub const fn resolve(mode: ClaudeSourceMode) -> ClaudeSourcePlan {
        let ordered_steps = match mode {
            ClaudeSourceMode::Auto => AUTO_PLAN,
            ClaudeSourceMode::OAuth => OAUTH_ONLY_PLAN,
            ClaudeSourceMode::Cli => CLI_ONLY_PLAN,
        };
        ClaudeSourcePlan { ordered_steps }
    }
}

/// Credential discovery selected once while preserving file re-reads on each refresh.
pub enum ClaudeCredentialSource {
    Environment(Zeroizing<String>),
    File(PathBuf),
}

impl std::fmt::Debug for ClaudeCredentialSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Environment(_) => formatter.write_str("Environment(<redacted>)"),
            Self::File(_) => formatter.write_str("File(<redacted>)"),
        }
    }
}

/// Validated Claude Code host discovery inputs.
#[derive(Debug)]
pub struct ClaudeSettings {
    credentials: ClaudeCredentialSource,
    config_root: Option<PathBuf>,
    config_root_override: Option<PathBuf>,
    source_mode: ClaudeSourceMode,
    cli_executable: Option<ExecutablePath>,
    cli_limits: ClaudeCliLimits,
}

#[derive(Debug, Clone, Copy)]
struct ClaudeCliLimits {
    auth_timeout: Duration,
    usage_timeout: Duration,
    max_auth_stdout_bytes: usize,
    max_usage_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl Default for ClaudeCliLimits {
    fn default() -> Self {
        Self {
            auth_timeout: CLI_AUTH_TIMEOUT,
            usage_timeout: CLI_USAGE_TIMEOUT,
            max_auth_stdout_bytes: CLI_MAX_AUTH_STDOUT_BYTES,
            max_usage_stdout_bytes: CLI_MAX_USAGE_STDOUT_BYTES,
            max_stderr_bytes: CLI_MAX_STDERR_BYTES,
        }
    }
}

impl ClaudeSettings {
    /// Resolves an explicit token or Claude Code's profile-owned credential file.
    /// Construction does not read the credential file.
    ///
    /// # Errors
    ///
    /// Returns a missing-credential classification when the trusted home is
    /// not absolute.
    pub fn resolve(
        environment: &BTreeMap<String, String>,
        home: &Path,
    ) -> Result<Self, ClassifiedError> {
        let config_root = resolve_config_root(environment, home);
        let config_root_override = resolve_config_root_override(environment, home);
        if let Some(token) = environment
            .get("OMARCHY_AI_BAR_CLAUDE_OAUTH_TOKEN")
            .or_else(|| environment.get("CLAUDE_OAUTH_TOKEN"))
            .or_else(|| environment.get("ANTHROPIC_OAUTH_TOKEN"))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        {
            return Ok(Self {
                credentials: ClaudeCredentialSource::Environment(Zeroizing::new(token.to_owned())),
                config_root,
                config_root_override,
                source_mode: ClaudeSourceMode::OAuth,
                cli_executable: None,
                cli_limits: ClaudeCliLimits::default(),
            });
        }
        let config_root =
            config_root.ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        Ok(Self {
            credentials: ClaudeCredentialSource::File(config_root.join(".credentials.json")),
            config_root: Some(config_root),
            config_root_override,
            source_mode: ClaudeSourceMode::OAuth,
            cli_executable: None,
            cli_limits: ClaudeCliLimits::default(),
        })
    }

    /// Selects source behavior and the already validated provider executable.
    ///
    /// The executable remains optional so an explicitly configured but
    /// unavailable CLI is reported as a normal missing-credential state at
    /// refresh time instead of preventing the daemon from starting.
    #[must_use]
    pub fn with_source(
        mut self,
        source_mode: ClaudeSourceMode,
        cli_executable: Option<ExecutablePath>,
    ) -> Self {
        self.source_mode = source_mode;
        self.cli_executable = cli_executable;
        self
    }
}

fn resolve_config_root(environment: &BTreeMap<String, String>, home: &Path) -> Option<PathBuf> {
    if !home.is_absolute() {
        return None;
    }
    let configured = environment
        .get("CLAUDE_SECURESTORAGE_CONFIG_DIR")
        .or_else(|| environment.get("CLAUDE_CONFIG_DIR"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    Some(match configured {
        Some(root) if root.is_absolute() => root,
        Some(root) => home.join(root),
        None => home.join(".claude"),
    })
}

fn resolve_config_root_override(
    environment: &BTreeMap<String, String>,
    home: &Path,
) -> Option<PathBuf> {
    if !home.is_absolute() {
        return None;
    }
    environment
        .get("CLAUDE_SECURESTORAGE_CONFIG_DIR")
        .or_else(|| environment.get("CLAUDE_CONFIG_DIR"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|root| {
            if root.is_absolute() {
                root
            } else {
                home.join(root)
            }
        })
}

/// Claude OAuth usage fetched from the same endpoint as Claude Code.
pub struct ClaudeProvider {
    scope: AccountScope,
    settings: ClaudeSettings,
    cli_cache: Mutex<Option<CachedClaudeCliUsage>>,
}

struct CachedClaudeCliUsage {
    cached_at: Instant,
    sample: UsageSample,
}

impl ClaudeProvider {
    /// Binds Claude usage to one exact account scope.
    ///
    /// # Errors
    ///
    /// Returns an API classification when the scope is not Claude.
    pub fn new(scope: AccountScope, settings: ClaudeSettings) -> Result<Self, ClassifiedError> {
        if scope.provider() != ProviderId::Claude {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            scope,
            settings,
            cli_cache: Mutex::new(None),
        })
    }

    async fn fetch_usage(&self, context: &ProviderContext) -> Result<UsageSample, ClassifiedError> {
        let plan = ClaudeSourcePlanner::resolve(self.settings.source_mode);
        let mut oauth_error = None;
        for step in plan.ordered_steps() {
            match step {
                ClaudeFetchSource::OAuth => match self.fetch_oauth_usage(context).await {
                    Ok(sample) => return Ok(sample),
                    Err(error) => {
                        if self.settings.source_mode != ClaudeSourceMode::Auto
                            || !should_auto_fallback_to_cli(&error)
                        {
                            return Err(error);
                        }
                        oauth_error = Some(error);
                    }
                },
                ClaudeFetchSource::Cli => match self.fetch_cli_usage(context).await {
                    Ok(sample) => return Ok(sample),
                    Err(cli_error) => {
                        return Err(oauth_error.map_or(cli_error.clone(), |oauth_error| {
                            resolve_auto_fallback_error(oauth_error, cli_error)
                        }));
                    }
                },
            }
        }
        Err(oauth_error.unwrap_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential)))
    }

    async fn fetch_oauth_usage(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        let credential = self.load_credential()?;
        let fetched_at = system_timestamp()?;
        let url = Url::parse(USAGE_ENDPOINT).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let class =
            classify_https_endpoint(&url).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let config = TransportConfig::new(
            Duration::from_secs(5),
            Duration::from_secs(30),
            2 * 1024 * 1024,
            0,
            RetryPolicy::none(),
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let client = FixedApiClient::new_bearer(
            self.scope.clone(),
            url.clone(),
            class,
            credential.token,
            config,
        )?
        .with_source(ProviderSource::OAuth)?;
        let response = client
            .get_json_with_public_headers(
                context,
                url,
                &[
                    ("anthropic-beta", "oauth-2025-04-20"),
                    ("user-agent", "claude-code/2.1.0"),
                ],
            )
            .await?;
        let usage: ClaudeUsageResponse = response.json()?;
        normalize_usage(
            context.scope().clone(),
            fetched_at,
            &usage,
            credential.login_method,
        )
    }

    async fn fetch_cli_usage(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        let now = Instant::now();
        let wall_now = system_timestamp()?;
        let mut cache = self.cli_cache.lock().await;
        let cache_is_valid = cache
            .as_ref()
            .is_some_and(|cached| cached_cli_usage_is_valid(cached, now, wall_now));
        if !cache_is_valid {
            *cache = None;
        } else if !context.provider_cache_bypass() {
            return Ok(cache
                .as_ref()
                .expect("a valid Claude CLI cache entry is present")
                .sample
                .clone());
        }

        let result = self.fetch_cli_usage_uncached(context).await;
        if let Ok(sample) = &result {
            *cache = Some(CachedClaudeCliUsage {
                cached_at: Instant::now(),
                sample: sample.clone(),
            });
        }
        result
    }

    async fn fetch_cli_usage_uncached(
        &self,
        context: &ProviderContext,
    ) -> Result<UsageSample, ClassifiedError> {
        let executable = self
            .settings
            .cli_executable
            .as_ref()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let classifier = cli_stderr_classifier()?;
        let auth_request = self.cli_request(
            executable,
            ["auth", "status", "--json"],
            self.settings.cli_limits.auth_timeout,
            self.settings.cli_limits.max_auth_stdout_bytes,
            classifier,
        )?;
        let auth_output = auth_request
            .run(context.cancellation())
            .await
            .map_err(classify_cli_subprocess_error)?;
        let auth = parse_cli_auth_status(auth_output.stdout())?;
        if !auth.logged_in {
            return Err(ClassifiedError::new(ErrorKind::MissingCredential));
        }

        let usage_output = capture_cli_usage_pty(
            executable,
            self.settings.config_root.as_deref(),
            self.settings.config_root_override.as_deref(),
            self.settings.cli_limits.usage_timeout,
            self.settings.cli_limits.max_usage_stdout_bytes,
            context.cancellation(),
        )
        .await?;
        normalize_cli_usage(
            context.scope().clone(),
            system_timestamp()?,
            usage_output.as_slice(),
            &auth,
        )
    }

    fn cli_request<I, S>(
        &self,
        executable: &ExecutablePath,
        arguments: I,
        timeout: Duration,
        max_stdout_bytes: usize,
        classifier: StderrClassifier,
    ) -> Result<SubprocessRequest, ClassifiedError>
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        let mut request = SubprocessRequest::new(
            executable.as_path(),
            arguments,
            timeout,
            max_stdout_bytes,
            self.settings.cli_limits.max_stderr_bytes,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
        .with_stderr_classifier(classifier);
        for name in [
            "OMARCHY_AI_BAR_CLAUDE_OAUTH_TOKEN",
            "CLAUDE_OAUTH_TOKEN",
            "ANTHROPIC_OAUTH_TOKEN",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_ADMIN_KEY",
        ] {
            request = request
                .without_environment(name)
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        }
        request = request
            .with_environment("DISABLE_AUTOUPDATER", "1")
            .and_then(|request| {
                request.with_environment("CLAUDECODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
            })
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        if let Some(config_root) = &self.settings.config_root_override {
            request = request
                .with_environment("CLAUDE_CONFIG_DIR", config_root.as_os_str())
                .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        }
        Ok(request)
    }

    fn load_credential(&self) -> Result<LoadedClaudeCredential, ClassifiedError> {
        match &self.settings.credentials {
            ClaudeCredentialSource::Environment(token) => Ok(LoadedClaudeCredential {
                token: ApiKeyCredential::new(token.as_str())?,
                login_method: Some("Claude Code OAuth".to_owned()),
            }),
            ClaudeCredentialSource::File(path) => load_file_credential(path),
        }
    }
}

impl ProviderAdapter for ClaudeProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Claude)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move { self.fetch_usage(context).await })
    }
}

fn cached_cli_usage_is_valid(
    cached: &CachedClaudeCliUsage,
    now: Instant,
    wall_now: Timestamp,
) -> bool {
    let within_ttl = now
        .checked_duration_since(cached.cached_at)
        .is_some_and(|age| age < CLI_SUCCESS_CACHE_TTL);
    within_ttl
        && !cached
            .sample
            .primary()
            .into_iter()
            .chain(cached.sample.secondary())
            .chain(cached.sample.tertiary())
            .chain(
                cached
                    .sample
                    .extra_windows()
                    .iter()
                    .map(NamedRateWindow::window),
            )
            .filter_map(RateWindow::resets_at)
            .any(|reset| reset <= wall_now)
}

fn should_auto_fallback_to_cli(error: &ClassifiedError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::MissingCredential
            | ErrorKind::AuthenticationExpired
            | ErrorKind::ProviderUnavailable
            | ErrorKind::Network
            | ErrorKind::Parse
            | ErrorKind::Api
    )
}

fn resolve_auto_fallback_error(
    oauth_error: ClassifiedError,
    cli_error: ClassifiedError,
) -> ClassifiedError {
    match cli_error.kind() {
        ErrorKind::MissingCredential
            if !matches!(
                oauth_error.kind(),
                ErrorKind::MissingCredential | ErrorKind::AuthenticationExpired
            ) =>
        {
            oauth_error
        }
        _ => cli_error,
    }
}

fn cli_stderr_classifier() -> Result<StderrClassifier, ClassifiedError> {
    StderrClassifier::ascii_case_insensitive([
        (CLI_RATE_LIMIT_TAG, "rate_limit_error"),
        (CLI_RATE_LIMIT_TAG, "rate limited"),
        (CLI_RATE_LIMIT_TAG, "too many requests"),
        (CLI_AUTH_TAG, "not logged in"),
        (CLI_AUTH_TAG, "authentication required"),
    ])
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn classify_cli_subprocess_error(error: SubprocessError) -> ClassifiedError {
    match error {
        SubprocessError::Cancelled | SubprocessError::Timeout | SubprocessError::OutputRead => {
            ClassifiedError::new(ErrorKind::Network)
        }
        SubprocessError::Spawn
        | SubprocessError::NonZero {
            stderr_tag: Some(CLI_AUTH_TAG),
            ..
        } => ClassifiedError::new(ErrorKind::MissingCredential),
        SubprocessError::NonZero {
            stderr_tag: Some(CLI_RATE_LIMIT_TAG),
            ..
        } => cli_rate_limit_error(),
        SubprocessError::StdoutTooLarge
        | SubprocessError::StderrTooLarge
        | SubprocessError::InvalidConfiguration => ClassifiedError::new(ErrorKind::Parse),
        SubprocessError::NonZero { .. } | SubprocessError::Wait => {
            ClassifiedError::new(ErrorKind::Api)
        }
    }
}

fn cli_rate_limit_error() -> ClassifiedError {
    let duration = WindowDuration::from_provider_minutes(CLI_RATE_LIMIT_MINUTES)
        .expect("the fixed Claude CLI cooldown is a valid domain duration");
    ClassifiedError::new(ErrorKind::RateLimited)
        .with_retry_after(duration)
        .expect("rate-limited errors accept a retry delay")
}

struct ClaudePtyProcess {
    child: Child,
    master: AsyncFd<File>,
    process_group: ClaudePtyProcessGroup,
    artifact_directory: Option<PathBuf>,
    _working_directory: tempfile::TempDir,
}

struct ClaudePtyCapture {
    deadline: tokio::time::Instant,
    usage_command_due: tokio::time::Instant,
    last_input_at: tokio::time::Instant,
    input_state: u16,
    cursor_queries_answered: usize,
    trust_transition_output_len: Option<usize>,
    complete_since: Option<tokio::time::Instant>,
    output: Zeroizing<Vec<u8>>,
    buffer: Zeroizing<Vec<u8>>,
}

impl ClaudePtyCapture {
    fn new(timeout: Duration, max_output_bytes: usize) -> Self {
        let started_at = tokio::time::Instant::now();
        Self {
            deadline: started_at + timeout,
            usage_command_due: started_at + CLI_STARTUP_DELAY,
            last_input_at: started_at,
            input_state: 0,
            cursor_queries_answered: 0,
            trust_transition_output_len: None,
            complete_since: None,
            output: Zeroizing::new(Vec::with_capacity(max_output_bytes.min(16 * 1024))),
            buffer: Zeroizing::new(vec![0_u8; 8 * 1024]),
        }
    }

    fn has_settled(&self, now: tokio::time::Instant) -> bool {
        self.complete_since
            .is_some_and(|complete_since| now.duration_since(complete_since) >= CLI_CAPTURE_SETTLE)
    }

    const fn input_done(&self, input: u16) -> bool {
        self.input_state & input != 0
    }

    fn mark_input_done(&mut self, input: u16) {
        self.input_state |= input;
    }
}

struct ClaudePtyProcessGroup {
    id: Option<Pid>,
}

impl ClaudePtyProcessGroup {
    fn new(process_id: Option<u32>) -> Self {
        Self {
            id: process_id
                .and_then(|process_id| i32::try_from(process_id).ok())
                .map(Pid::from_raw),
        }
    }

    fn signal(&self, signal: Signal) {
        if let Some(id) = self.id {
            let _ = killpg(id, signal);
        }
    }

    fn disarm(&mut self) {
        self.id = None;
    }
}

impl Drop for ClaudePtyProcessGroup {
    fn drop(&mut self) {
        self.signal(Signal::SIGKILL);
    }
}

fn spawn_claude_usage_pty(
    executable: &ExecutablePath,
    profile_root: Option<&Path>,
    config_root_override: Option<&Path>,
) -> Result<ClaudePtyProcess, ClassifiedError> {
    let working_directory = tempfile::Builder::new()
        .prefix("omarchy-ai-bar-claude-")
        .tempdir()
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let winsize = Winsize {
        ws_row: 50,
        ws_col: 160,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = openpty(Some(&winsize), None).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let master = File::from(pty.master);
    let slave = File::from(pty.slave);
    let flags = fcntl(&master, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    fcntl(&master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let master = AsyncFd::new(master).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let stdin = slave
        .try_clone()
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let stdout = slave
        .try_clone()
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;

    let mut command = Command::new(executable.as_path());
    command
        .args([
            "--allowed-tools",
            "",
            "--strict-mcp-config",
            "--session-id",
            CLI_PROBE_SESSION_ID,
        ])
        .current_dir(working_directory.path())
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave))
        .env_clear()
        .kill_on_drop(true)
        .process_group(0);
    install_claude_cli_environment(&mut command, config_root_override, working_directory.path());
    let child = command
        .spawn()
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    drop(command);
    let process_group = ClaudePtyProcessGroup::new(child.id());
    let artifact_directory = profile_root
        .and_then(|root| claude_probe_project_directory(root, working_directory.path()));
    Ok(ClaudePtyProcess {
        child,
        master,
        process_group,
        artifact_directory,
        _working_directory: working_directory,
    })
}

fn claude_probe_project_directory(config_root: &Path, working_directory: &Path) -> Option<PathBuf> {
    let working_directory = working_directory.to_str()?;
    let name = working_directory
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    (!name.is_empty() && name.len() <= 200).then(|| config_root.join("projects").join(name))
}

fn install_claude_cli_environment(command: &mut Command, config_root: Option<&Path>, cwd: &Path) {
    for name in [
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "LANG",
        "LC_ALL",
        "SHELL",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("PWD", cwd)
        .env("TERM", "xterm-256color")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("CLAUDECODE_DISABLE_NONESSENTIAL_TRAFFIC", "1");
    if let Some(config_root) = config_root {
        command.env("CLAUDE_CONFIG_DIR", config_root);
    }
}

async fn capture_cli_usage_pty(
    executable: &ExecutablePath,
    profile_root: Option<&Path>,
    config_root_override: Option<&Path>,
    timeout: Duration,
    max_output_bytes: usize,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    let mut process = spawn_claude_usage_pty(executable, profile_root, config_root_override)?;
    let mut capture = ClaudePtyCapture::new(timeout, max_output_bytes);
    let result =
        capture_cli_usage_pty_inner(&mut process, &mut capture, max_output_bytes, cancellation)
            .await;
    stop_claude_pty(&mut process).await;
    result.map(|()| capture.output)
}

async fn capture_cli_usage_pty_inner(
    process: &mut ClaudePtyProcess,
    capture: &mut ClaudePtyCapture,
    max_output_bytes: usize,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<(), ClassifiedError> {
    loop {
        let now = tokio::time::Instant::now();
        if capture.has_settled(now) {
            return Ok(());
        }
        if now >= capture.deadline {
            return Err(classify_cli_capture_failure(capture.output.as_slice()));
        }

        if capture.input_done(CLI_INPUT_USAGE_SENT)
            && now.duration_since(capture.last_input_at) >= CLI_INPUT_INTERVAL
        {
            write_claude_pty(&process.master, b"\r", cancellation, capture.deadline).await?;
            capture.last_input_at = now;
        }

        poll_claude_pty_output(process, capture, max_output_bytes, cancellation).await?;

        let now = tokio::time::Instant::now();
        let scan = normalized_cli_scan(capture.output.as_slice());
        drive_claude_pty_inputs(process, capture, &scan, now, cancellation).await?;
        if capture.complete_since.is_none() && cli_capture_is_complete(&scan) {
            capture.complete_since = Some(now);
        }
        if process
            .child
            .try_wait()
            .map_err(|_| ClassifiedError::new(ErrorKind::Network))?
            .is_some()
        {
            return if cli_capture_is_complete(&scan) {
                Ok(())
            } else {
                Err(classify_cli_capture_failure(capture.output.as_slice()))
            };
        }
    }
}

async fn poll_claude_pty_output(
    process: &mut ClaudePtyProcess,
    capture: &mut ClaudePtyCapture,
    max_output_bytes: usize,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<(), ClassifiedError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(ClassifiedError::new(ErrorKind::Network)),
        () = tokio::time::sleep_until(capture.deadline) => Ok(()),
        ready = process.master.readable() => {
            let Ok(mut ready) = ready else {
                return Err(ClassifiedError::new(ErrorKind::Network));
            };
            let read = ready.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(capture.buffer.as_mut_slice())
            });
            let Ok(read) = read else {
                return Ok(());
            };
            match read {
                Ok(0) => Ok(()),
                Ok(read) if read <= max_output_bytes.saturating_sub(capture.output.len()) => {
                    capture.output.extend_from_slice(&capture.buffer[..read]);
                    Ok(())
                }
                Ok(_) => Err(ClassifiedError::new(ErrorKind::Parse)),
                Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => Ok(()),
                Err(_) => Err(ClassifiedError::new(ErrorKind::Network)),
            }
        }
        () = tokio::time::sleep(CLI_TICK) => Ok(()),
    }
}

async fn drive_claude_pty_inputs(
    process: &ClaudePtyProcess,
    capture: &mut ClaudePtyCapture,
    scan: &str,
    now: tokio::time::Instant,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<(), ClassifiedError> {
    let cursor_queries = capture
        .output
        .windows(b"\x1b[6n".len())
        .filter(|window| *window == b"\x1b[6n")
        .count();
    while capture.cursor_queries_answered < cursor_queries {
        write_claude_pty(
            &process.master,
            b"\x1b[1;1R",
            cancellation,
            capture.deadline,
        )
        .await?;
        capture.cursor_queries_answered += 1;
        capture.last_input_at = now;
    }
    if !capture.input_done(CLI_INPUT_TRUST_ANSWERED)
        && scan.contains("doyoutrustthefilesinthisfolder")
    {
        write_claude_pty(&process.master, b"y\r", cancellation, capture.deadline).await?;
        capture.mark_input_done(CLI_INPUT_TRUST_ANSWERED);
        capture.usage_command_due = now + Duration::from_millis(500);
        capture.last_input_at = now;
        return Ok(());
    }
    let quick_safety_visible =
        scan.contains("quicksaftycheck") || scan.contains("quicksafetycheck");
    if !capture.input_done(CLI_INPUT_QUICK_SAFETY_ANSWERED)
        && quick_safety_visible
        && !scan.contains("yes,itrustthisfolder")
    {
        // The chooser can arrive across several PTY reads. Do not send the
        // slash command while its default "No, exit" row is still focused.
        capture.usage_command_due = now + Duration::from_millis(500);
        return Ok(());
    }
    if !capture.input_done(CLI_INPUT_TRUST_SELECTION_ANSWERED)
        && scan.contains("yes,itrustthisfolder")
    {
        let selected_yes = scan.rfind("❯yes,itrustthisfolder") > scan.rfind("❯no,exit");
        if !selected_yes && now.duration_since(capture.last_input_at) >= CLI_TICK {
            // Claude 2.1.251 focuses "No, exit". Select the rendered trust
            // row explicitly, then wait for its stable selected redraw.
            write_claude_pty(&process.master, b"\x1b[B", cancellation, capture.deadline).await?;
            capture.last_input_at = now;
            return Ok(());
        }
        if selected_yes && now.duration_since(capture.last_input_at) >= CLI_TRUST_SELECTION_SETTLE {
            write_claude_pty(&process.master, b"\r", cancellation, capture.deadline).await?;
            capture.mark_input_done(
                CLI_INPUT_TRUST_SELECTION_ANSWERED | CLI_INPUT_QUICK_SAFETY_ANSWERED,
            );
            capture.trust_transition_output_len = Some(capture.output.len());
            capture.last_input_at = now;
        }
        return Ok(());
    }
    if capture.input_done(CLI_INPUT_TRUST_SELECTION_ANSWERED)
        && !capture.input_done(CLI_INPUT_TRUST_CONFIRMED)
    {
        let main_ui_is_visible = capture.trust_transition_output_len.is_some_and(|offset| {
            let scan = normalized_cli_scan(&capture.output[offset..]);
            scan.contains("claudecodev") || scan.contains("❯try\"")
        });
        if main_ui_is_visible {
            capture.mark_input_done(CLI_INPUT_TRUST_CONFIRMED);
            capture.usage_command_due = now + Duration::from_millis(500);
        }
        return Ok(());
    }
    let enter_prompt = [
        (CLI_INPUT_READY_ANSWERED, scan.contains("readytocodehere")),
        (
            CLI_INPUT_CONTINUE_ANSWERED,
            scan.contains("pressentertocontinue"),
        ),
    ];
    if let Some((input, _)) = enter_prompt
        .into_iter()
        .find(|(input, present)| *present && !capture.input_done(*input))
    {
        write_claude_pty(&process.master, b"\r", cancellation, capture.deadline).await?;
        capture.mark_input_done(input);
        capture.usage_command_due = now + Duration::from_millis(500);
        capture.last_input_at = now;
        return Ok(());
    }
    if !capture.input_done(CLI_INPUT_PALETTE_ANSWERED)
        && capture.input_done(CLI_INPUT_USAGE_SENT)
        && (scan.contains("showplanusagelimits") || scan.contains("showplan"))
    {
        write_claude_pty(&process.master, b"\r", cancellation, capture.deadline).await?;
        capture.mark_input_done(CLI_INPUT_PALETTE_ANSWERED);
        capture.last_input_at = now;
    }
    if !capture.input_done(CLI_INPUT_USAGE_SENT) && now >= capture.usage_command_due {
        write_claude_pty(&process.master, b"/usage\r", cancellation, capture.deadline).await?;
        capture.mark_input_done(CLI_INPUT_USAGE_SENT);
        capture.last_input_at = now;
    }
    Ok(())
}

fn normalized_cli_scan(bytes: &[u8]) -> String {
    strip_terminal_sequences(bytes)
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
        .to_ascii_lowercase()
        .chars()
        .filter(|character| !character.is_whitespace() && !character.is_control())
        .collect()
}

fn cli_capture_is_complete(scan: &str) -> bool {
    compact_scan_has_session_usage(scan)
        || is_cli_rate_limit_text(scan)
        || scan.contains("failedtoloadusage")
        || scan.contains("couldnotloadusage")
        || scan.contains("usingyoursubscription")
        || scan.contains("notloggedin")
}

fn compact_scan_has_session_usage(scan: &str) -> bool {
    let Some(session_index) = scan.rfind("currentsession") else {
        return false;
    };
    let tail = &scan[session_index..];
    let session = tail
        .find("currentweek")
        .map_or(tail, |boundary| &tail[..boundary]);
    [
        "%used",
        "%spent",
        "%consumed",
        "%left",
        "%remaining",
        "%available",
    ]
    .iter()
    .any(|marker| session.contains(marker))
}

fn classify_cli_capture_failure(bytes: &[u8]) -> ClassifiedError {
    let scan = normalized_cli_scan(bytes);
    if is_cli_rate_limit_text(&scan) {
        cli_rate_limit_error()
    } else if scan.contains("notloggedin")
        || scan.contains("pleaselogin")
        || scan.contains("authenticationrequired")
    {
        ClassifiedError::new(ErrorKind::MissingCredential)
    } else if scan.contains("failedtoloadusage")
        || scan.contains("couldnotloadusage")
        || scan.contains("usingyoursubscription")
    {
        ClassifiedError::new(ErrorKind::ProviderUnavailable)
    } else {
        ClassifiedError::new(ErrorKind::Network)
    }
}

async fn write_claude_pty(
    master: &AsyncFd<File>,
    bytes: &[u8],
    cancellation: &tokio_util::sync::CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<(), ClassifiedError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let mut ready = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            () = tokio::time::sleep_until(deadline) => {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            ready = master.writable() => {
                ready.map_err(|_| ClassifiedError::new(ErrorKind::Network))?
            }
        };
        if let Ok(write) = ready.try_io(|inner| {
            let mut file = inner.get_ref();
            file.write(&bytes[offset..])
        }) {
            let written = write.map_err(|_| ClassifiedError::new(ErrorKind::Network))?;
            if written == 0 {
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            offset += written;
        }
    }
    Ok(())
}

async fn stop_claude_pty(process: &mut ClaudePtyProcess) {
    let _ = write_pty_best_effort(&process.master, b"/exit\r");
    if process.child.try_wait().ok().flatten().is_none() {
        process.process_group.signal(Signal::SIGTERM);
        let _ = tokio::time::timeout(CLI_TERMINATION_GRACE, process.child.wait()).await;
    }
    if process.child.try_wait().ok().flatten().is_none() {
        process.process_group.signal(Signal::SIGKILL);
        let _ = process.child.start_kill();
        let _ = tokio::time::timeout(CLI_REAP_TIMEOUT, process.child.wait()).await;
    }
    process.process_group.disarm();
    if let Some(directory) = &process.artifact_directory {
        cleanup_claude_probe_artifacts(directory);
    }
}

fn cleanup_claude_probe_artifacts(directory: &Path) {
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return;
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("jsonl") {
            continue;
        }
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file()) {
            let _ = fs::remove_file(path);
        }
    }
    if fs::read_dir(directory).is_ok_and(|mut entries| entries.next().is_none()) {
        let _ = fs::remove_dir(directory);
    }
}

fn write_pty_best_effort(master: &AsyncFd<File>, bytes: &[u8]) -> io::Result<()> {
    let mut file = master.get_ref();
    file.write_all(bytes)
}

#[derive(Debug)]
struct LoadedClaudeCredential {
    token: ApiKeyCredential,
    login_method: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeCliAuthStatus {
    #[serde(default)]
    logged_in: bool,
    email: Option<String>,
    org_name: Option<String>,
    subscription_type: Option<String>,
    auth_method: Option<String>,
}

fn parse_cli_auth_status(bytes: &[u8]) -> Result<ClaudeCliAuthStatus, ClassifiedError> {
    serde_json::from_slice(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn normalize_cli_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    bytes: &[u8],
    auth: &ClaudeCliAuthStatus,
) -> Result<UsageSample, ClassifiedError> {
    let text = strip_terminal_sequences(bytes)?;
    let lower = text.to_ascii_lowercase();
    if is_cli_rate_limit_text(&lower) {
        return Err(cli_rate_limit_error());
    }
    if lower.contains("not logged in")
        || lower.contains("please log in")
        || lower.contains("authentication required")
    {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let usage_panel = latest_cli_usage_panel(&text);
    let windows = parse_cli_usage_windows(usage_panel, fetched_at)?;
    let login_method = claude_login_method(auth.subscription_type.as_deref(), None).or_else(|| {
        auth.auth_method
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("Claude CLI ({value})"))
            .or_else(|| Some("Claude CLI".to_owned()))
    });
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(windows.primary)
        .confidence(DataConfidence::PercentOnly)
        .email(clean_cli_identity(auth.email.as_deref()))?
        .organization(clean_cli_identity(auth.org_name.as_deref()))?
        .login_method(login_method)?;
    if let Some(secondary) = windows.secondary {
        builder = builder.secondary(secondary);
    }
    if let Some(tertiary) = windows.tertiary {
        builder = builder.tertiary(tertiary);
    }
    builder
        .extra_windows(windows.extra)
        .provenance("claude", "cli")?
        .build()
}

struct ClaudeCliUsageWindows {
    primary: RateWindow,
    secondary: Option<RateWindow>,
    tertiary: Option<RateWindow>,
    extra: Vec<NamedRateWindow>,
}

enum ClaudeCliQuotaLabel {
    Session,
    Weekly(String),
}

struct ClaudeCliQuotaObservation {
    label: ClaudeCliQuotaLabel,
    used_percent: f64,
    reset_description: Option<String>,
}

fn parse_cli_usage_windows(
    text: &str,
    fetched_at: Timestamp,
) -> Result<ClaudeCliUsageWindows, ClassifiedError> {
    let mut primary = None;
    let mut secondary = None;
    let mut tertiary = None;
    let mut extras = BTreeMap::new();
    for observation in cli_quota_observations(text) {
        let (duration, model) = match observation.label {
            ClaudeCliQuotaLabel::Session => (SESSION_WINDOW_MINUTES, None),
            ClaudeCliQuotaLabel::Weekly(model) => (WEEKLY_WINDOW_MINUTES, Some(model)),
        };
        let window = cli_rate_window(
            observation.used_percent,
            duration,
            observation.reset_description,
            fetched_at,
        )?;
        let Some(model) = model else {
            primary = Some(window);
            continue;
        };
        let normalized_model = model.to_ascii_lowercase();
        if matches!(normalized_model.as_str(), "all" | "all models") {
            secondary = Some(window);
        } else if matches!(
            normalized_model.as_str(),
            "opus" | "opus only" | "sonnet" | "sonnet only"
        ) {
            tertiary = Some(window);
        } else if extras.len() < 16 {
            let model_slug = slug(&model);
            if !model_slug.is_empty() {
                let title = if normalized_model.ends_with(" only") {
                    model
                } else {
                    format!("{model} only")
                };
                extras.insert(model_slug, (title, window));
            }
        }
    }
    let Some(primary) = primary else {
        return Err(classify_missing_cli_usage(text));
    };
    let extra = extras
        .into_iter()
        .map(|(model_slug, (title, window))| {
            named_window(format!("claude-weekly-scoped-{model_slug}"), title, window)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ClaudeCliUsageWindows {
        primary,
        secondary,
        tertiary,
        extra,
    })
}

fn cli_quota_observations(text: &str) -> Vec<ClaudeCliQuotaObservation> {
    // Claude's TUI redraws rows with standalone carriage returns as well as
    // CRLF/newline boundaries. Treat each as a row separator before applying
    // the bounded label window.
    let lines = text.split(['\n', '\r']).map(str::trim).collect::<Vec<_>>();
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let label = cli_quota_label(line)?;
            let mut used_percent = None;
            let mut reset_description = None;
            for (offset, candidate) in lines[index..].iter().take(CLI_LABEL_SCAN_LINES).enumerate()
            {
                if offset > 0 && cli_quota_label(candidate).is_some() {
                    break;
                }
                if used_percent.is_none() {
                    used_percent = cli_used_percent(candidate);
                }
                if reset_description.is_none() {
                    reset_description = cli_reset_description(candidate);
                }
            }
            Some(ClaudeCliQuotaObservation {
                label,
                used_percent: used_percent?,
                reset_description,
            })
        })
        .collect()
}

fn cli_quota_label(line: &str) -> Option<ClaudeCliQuotaLabel> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("current session") {
        return Some(ClaudeCliQuotaLabel::Session);
    }
    lower.contains("current week").then(|| {
        ClaudeCliQuotaLabel::Weekly(
            cli_weekly_model(line).unwrap_or_else(|| "all models".to_owned()),
        )
    })
}

fn latest_cli_usage_panel(text: &str) -> &str {
    let lower = text.to_ascii_lowercase();
    let settings_index = lower
        .rfind("settings:")
        .or_else(|| lower.rfind("settingsstatusconfig"));
    let Some(settings_index) = settings_index else {
        return text;
    };
    let tail = &text[settings_index..];
    if lower[settings_index..].contains("usage") {
        tail
    } else {
        text
    }
}

fn classify_missing_cli_usage(text: &str) -> ClassifiedError {
    let compact = text
        .to_ascii_lowercase()
        .chars()
        .filter(|character| !character.is_whitespace() && !character.is_control())
        .collect::<String>();
    let unavailable = compact.contains("loadingusage")
        || compact.contains("stillloading")
        || compact.contains("failedtoloadusage")
        || compact.contains("couldnotloadusage")
        || compact.contains("usingyoursubscription");
    ClassifiedError::new(if unavailable {
        ErrorKind::ProviderUnavailable
    } else {
        ErrorKind::Parse
    })
}

fn clean_cli_identity(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .map(str::to_owned)
}

fn cli_used_percent(line: &str) -> Option<f64> {
    let lower = line.to_ascii_lowercase();
    if is_cli_status_context_line(&lower)
        || ![
            "used",
            "spent",
            "consumed",
            "left",
            "remaining",
            "available",
        ]
        .iter()
        .any(|keyword| lower.contains(keyword))
    {
        return None;
    }
    let percent_index = line.find('%')?;
    let prefix = &line[..percent_index];
    let number_start = prefix
        .char_indices()
        .rev()
        .find(|(_, character)| !character.is_ascii_digit() && *character != '.')
        .map_or(0, |(index, character)| index + character.len_utf8());
    let raw = prefix[number_start..].trim();
    let value = raw.parse::<f64>().ok()?;
    if !value.is_finite() {
        return None;
    }
    let clamped = value.clamp(0.0, 100.0);
    if ["left", "remaining", "available"]
        .iter()
        .any(|keyword| lower.contains(keyword))
    {
        Some(100.0 - clamped)
    } else {
        Some(clamped)
    }
}

fn is_cli_status_context_line(lower: &str) -> bool {
    lower.contains('|')
        && ["opus", "sonnet", "haiku", "default"]
            .iter()
            .any(|model| lower.contains(model))
}

fn cli_rate_window(
    percent: f64,
    duration_minutes: i64,
    reset_description: Option<String>,
    fetched_at: Timestamp,
) -> Result<RateWindow, ClassifiedError> {
    let used = UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let duration = WindowDuration::from_provider_minutes(duration_minutes)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let reset = reset_description.as_deref().and_then(|description| {
        parse_cli_reset_timestamp(description, fetched_at, duration_minutes)
    });
    let description = reset_description
        .map(BoundedText::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(used),
        Some(duration),
        reset,
        description,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn parse_cli_reset_timestamp(
    description: &str,
    fetched_at: Timestamp,
    duration_minutes: i64,
) -> Option<Timestamp> {
    let raw = description.strip_prefix("Resets ")?.trim();
    if let Some(seconds) = parse_cli_relative_reset(raw) {
        return bounded_cli_reset(
            fetched_at.as_offset_date_time() + TimeDuration::seconds(seconds),
            fetched_at,
            duration_minutes,
        );
    }
    let (value, zone) = raw
        .rfind(" (")
        .filter(|_| raw.ends_with(')'))
        .map_or((raw, None), |index| {
            (&raw[..index], Some(&raw[index + 2..raw.len() - 1]))
        });
    let offset = if zone.is_some_and(|zone| matches!(zone, "UTC" | "Etc/UTC" | "GMT")) {
        UtcOffset::UTC
    } else {
        UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC)
    };
    let fetched = fetched_at.as_offset_date_time().to_offset(offset);
    let candidate = if let Some((date, clock)) = value.split_once(',') {
        let (month, day) = parse_cli_month_day(date.trim())?;
        let clock = parse_cli_clock(clock.trim())?;
        let mut year = fetched.year();
        let mut candidate =
            PrimitiveDateTime::new(Date::from_calendar_date(year, month, day).ok()?, clock);
        if candidate <= PrimitiveDateTime::new(fetched.date(), fetched.time()) {
            year = year.checked_add(1)?;
            candidate =
                PrimitiveDateTime::new(Date::from_calendar_date(year, month, day).ok()?, clock);
        }
        candidate.assume_offset(offset)
    } else {
        let clock = parse_cli_clock(value.trim())?;
        let mut date = fetched.date();
        let mut candidate = PrimitiveDateTime::new(date, clock);
        if candidate <= PrimitiveDateTime::new(fetched.date(), fetched.time()) {
            date = date.next_day()?;
            candidate = PrimitiveDateTime::new(date, clock);
        }
        candidate.assume_offset(offset)
    };
    bounded_cli_reset(candidate, fetched_at, duration_minutes)
}

fn bounded_cli_reset(
    candidate: time::OffsetDateTime,
    fetched_at: Timestamp,
    duration_minutes: i64,
) -> Option<Timestamp> {
    let reset = Timestamp::new(candidate).ok()?;
    let delta = reset
        .unix_timestamp()
        .checked_sub(fetched_at.unix_timestamp())?;
    let maximum = duration_minutes
        .checked_mul(60)?
        .checked_add(24 * 60 * 60)?;
    (delta > 0 && delta <= maximum).then_some(reset)
}

fn parse_cli_relative_reset(value: &str) -> Option<i64> {
    let value = value.to_ascii_lowercase();
    let tokens = value.strip_prefix("in ")?.split_whitespace();
    let mut seconds = 0_i64;
    let mut found = false;
    for token in tokens {
        let (number, multiplier) = if let Some(number) = token.strip_suffix('h') {
            (number, 60 * 60)
        } else if let Some(number) = token.strip_suffix('m') {
            (number, 60)
        } else {
            let number = token.strip_suffix('s')?;
            (number, 1)
        };
        seconds = seconds.checked_add(number.parse::<i64>().ok()?.checked_mul(multiplier)?)?;
        found = true;
    }
    (found && seconds > 0).then_some(seconds)
}

fn parse_cli_month_day(value: &str) -> Option<(Month, u8)> {
    let mut parts = value.split_whitespace();
    let month = match parts.next()?.to_ascii_lowercase().as_str() {
        "jan" | "january" => Month::January,
        "feb" | "february" => Month::February,
        "mar" | "march" => Month::March,
        "apr" | "april" => Month::April,
        "may" => Month::May,
        "jun" | "june" => Month::June,
        "jul" | "july" => Month::July,
        "aug" | "august" => Month::August,
        "sep" | "sept" | "september" => Month::September,
        "oct" | "october" => Month::October,
        "nov" | "november" => Month::November,
        "dec" | "december" => Month::December,
        _ => return None,
    };
    let day = parts
        .next()?
        .trim_end_matches(|character: char| !character.is_ascii_digit());
    (parts.next().is_none())
        .then(|| day.parse::<u8>().ok())
        .flatten()
        .map(|day| (month, day))
}

fn parse_cli_clock(value: &str) -> Option<Time> {
    let value = value.to_ascii_lowercase();
    let (clock, is_pm) = if let Some(clock) = value.strip_suffix("am") {
        (clock, false)
    } else {
        let clock = value.strip_suffix("pm")?;
        (clock, true)
    };
    let mut parts = clock.trim().split([':', '.']);
    let mut hour = parts.next()?.parse::<u8>().ok()?;
    let minute = parts
        .next()
        .map_or(Some(0), |minute| minute.parse::<u8>().ok())?;
    if parts.next().is_some() || !(1..=12).contains(&hour) {
        return None;
    }
    if hour == 12 {
        hour = 0;
    }
    if is_pm {
        hour = hour.checked_add(12)?;
    }
    Time::from_hms(hour, minute, 0).ok()
}

fn cli_reset_description(line: &str) -> Option<String> {
    let index = ascii_case_insensitive_find(line.as_bytes(), b"resets")?;
    let value = line[index + "resets".len()..].trim_matches(|character: char| {
        character.is_whitespace() || matches!(character, ':' | '-' | '\u{b7}')
    });
    if value.is_empty() {
        return None;
    }
    let value = value.chars().take(110).collect::<String>();
    Some(format!("Resets {value}"))
}

fn cli_weekly_model(line: &str) -> Option<String> {
    let open = line.find('(')?;
    let close = line[open + 1..].find(')')? + open + 1;
    let model = line[open + 1..close].trim();
    if model.is_empty() || model.len() > 80 || model.chars().any(char::is_control) {
        return None;
    }
    Some(model.to_owned())
}

fn ascii_case_insensitive_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn is_cli_rate_limit_text(lower: &str) -> bool {
    lower.contains("rate_limit_error")
        || lower.contains("rate limited")
        || lower.contains("too many requests")
        || lower.contains("asked us to slow down")
}

fn strip_terminal_sequences(bytes: &[u8]) -> Result<String, ClassifiedError> {
    let mut clean = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != 0x1b {
            if bytes[index] == b'\n'
                || bytes[index] == b'\r'
                || bytes[index] == b'\t'
                || !bytes[index].is_ascii_control()
            {
                clean.push(bytes[index]);
            }
            index += 1;
            continue;
        }
        index += 1;
        let Some(kind) = bytes.get(index).copied() else {
            break;
        };
        index += 1;
        match kind {
            b'[' => {
                while let Some(byte) = bytes.get(index).copied() {
                    index += 1;
                    if (0x40..=0x7e).contains(&byte) {
                        break;
                    }
                }
            }
            b']' => {
                while let Some(byte) = bytes.get(index).copied() {
                    index += 1;
                    if byte == 0x07 {
                        break;
                    }
                    if byte == 0x1b && bytes.get(index) == Some(&b'\\') {
                        index += 1;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    String::from_utf8(clean).map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn load_file_credential(path: &Path) -> Result<LoadedClaudeCredential, ClassifiedError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let bytes = fs::read(path).map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    parse_file_credential(&bytes, system_timestamp()?)
}

fn parse_file_credential(
    bytes: &[u8],
    now: Timestamp,
) -> Result<LoadedClaudeCredential, ClassifiedError> {
    let root: CredentialRoot =
        serde_json::from_slice(bytes).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let mut oauth = root
        .claude_ai_oauth
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let expires_at_ms = oauth
        .expires_at
        .ok_or_else(|| ClassifiedError::new(ErrorKind::AuthenticationExpired))?;
    let now_ms = now
        .unix_timestamp()
        .checked_mul(1000)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if expires_at_ms <= now_ms {
        // Claude Code owns this credential and its rotating refresh token.  As
        // in CodexBar, never consume that refresh token or rewrite this file;
        // re-read the owner-managed file after Claude refreshes it.
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if !oauth.scopes.iter().any(|scope| scope == "user:profile") {
        return Err(ClassifiedError::new(ErrorKind::PermissionDenied));
    }
    let token = oauth
        .access_token
        .take()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    Ok(LoadedClaudeCredential {
        token: ApiKeyCredential::from_zeroizing(Zeroizing::new(token))?,
        login_method: claude_login_method(
            oauth.subscription_type.as_deref(),
            oauth.rate_limit_tier.as_deref(),
        )
        .or_else(|| Some("Claude Code OAuth".to_owned())),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialRoot {
    claude_ai_oauth: Option<CredentialOauth>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialOauth {
    access_token: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    scopes: Vec<String>,
    rate_limit_tier: Option<String>,
    subscription_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClaudeUsageResponse {
    five_hour: Option<ClaudeUsageWindow>,
    seven_day: Option<ClaudeUsageWindow>,
    seven_day_oauth_apps: Option<ClaudeUsageWindow>,
    seven_day_opus: Option<ClaudeUsageWindow>,
    seven_day_sonnet: Option<ClaudeUsageWindow>,
    #[serde(
        alias = "seven_day_claude_routines",
        alias = "claude_routines",
        alias = "routines",
        alias = "routine",
        alias = "seven_day_cowork",
        alias = "cowork"
    )]
    seven_day_routines: Option<ClaudeUsageWindow>,
    limits: Option<Vec<ClaudeLimitEntry>>,
    extra_usage: Option<ClaudeExtraUsage>,
}

#[derive(Debug, Deserialize)]
struct ClaudeUsageWindow {
    utilization: Option<f64>,
    resets_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClaudeLimitEntry {
    kind: Option<String>,
    group: Option<String>,
    percent: Option<f64>,
    resets_at: Option<String>,
    scope: Option<ClaudeLimitScope>,
}

#[derive(Debug, Deserialize)]
struct ClaudeLimitScope {
    model: Option<ClaudeLimitModel>,
}

#[derive(Debug, Deserialize)]
struct ClaudeLimitModel {
    id: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClaudeExtraUsage {
    is_enabled: Option<bool>,
    monthly_limit: Option<f64>,
    used_credits: Option<f64>,
    utilization: Option<f64>,
    currency: Option<String>,
}

fn normalize_usage(
    scope: AccountScope,
    fetched_at: Timestamp,
    response: &ClaudeUsageResponse,
    login_method: Option<String>,
) -> Result<UsageSample, ClassifiedError> {
    let primary = [
        response.five_hour.as_ref(),
        response.seven_day.as_ref(),
        response.seven_day_oauth_apps.as_ref(),
        response.seven_day_sonnet.as_ref(),
        response.seven_day_opus.as_ref(),
    ]
    .into_iter()
    .flatten()
    .next()
    .map(|window| {
        let minutes = if response
            .five_hour
            .as_ref()
            .is_some_and(|five| std::ptr::eq(five, window))
        {
            SESSION_WINDOW_MINUTES
        } else {
            WEEKLY_WINDOW_MINUTES
        };
        normalize_window(window, minutes)
    })
    .transpose()?;
    let cost = response
        .extra_usage
        .as_ref()
        .map(|extra| normalize_extra_usage_cost(extra, fetched_at))
        .transpose()?
        .flatten();
    let primary = match (primary, response.extra_usage.as_ref(), cost.as_ref()) {
        (Some(primary), _, _) => Some(primary),
        (None, Some(extra), Some(cost)) if cost.limit().get() > Decimal::ZERO => {
            Some(normalize_spend_limit(extra, cost.limit().get())?)
        }
        _ => None,
    };
    if primary.is_none() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut builder = UsageSampleBuilder::new(scope, fetched_at).login_method(login_method)?;
    if let Some(primary) = primary {
        builder = builder.primary(primary);
    }
    if let Some(weekly) = response.seven_day.as_ref() {
        builder = builder.secondary(normalize_window(weekly, WEEKLY_WINDOW_MINUTES)?);
    }
    if let Some(model_specific) = response
        .seven_day_sonnet
        .as_ref()
        .or(response.seven_day_opus.as_ref())
    {
        builder = builder.tertiary(normalize_window(model_specific, WEEKLY_WINDOW_MINUTES)?);
    }
    let mut extra = Vec::new();
    if let Some(routines) = response.seven_day_routines.as_ref() {
        extra.push(named_window(
            "claude-routines",
            "Daily Routines",
            normalize_window(routines, WEEKLY_WINDOW_MINUTES)?,
        )?);
    }
    extra.extend(scoped_weekly_windows(
        response.limits.as_deref().unwrap_or_default(),
    )?);
    if let Some(cost) = cost {
        builder = builder.cost(cost);
    }
    builder
        .extra_windows(extra)
        .provenance("claude", "oauth")?
        .build()
}

fn named_window(
    id: impl AsRef<str>,
    title: impl AsRef<str>,
    window: RateWindow,
) -> Result<NamedRateWindow, ClassifiedError> {
    Ok(NamedRateWindow::new(
        BoundedText::new(id).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        BoundedText::new(title).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        window,
    ))
}

fn scoped_weekly_windows(
    limits: &[ClaudeLimitEntry],
) -> Result<Vec<NamedRateWindow>, ClassifiedError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut windows = Vec::new();
    for limit in limits {
        if limit.group.as_deref() != Some("weekly")
            || limit.kind.as_deref() != Some("weekly_scoped")
        {
            continue;
        }
        let Some(percent) = limit.percent.filter(|percent| percent.is_finite()) else {
            continue;
        };
        let Some(model) = limit.scope.as_ref().and_then(|scope| scope.model.as_ref()) else {
            continue;
        };
        let Some(name) = model
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let identity = model
            .id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(name);
        let model_slug = slug(identity);
        if model_slug.is_empty()
            || model_slug == "all-models"
            || model_slug.ends_with("-all-models")
            || slug(name) == "all-models"
            || !seen.insert(model_slug.clone())
        {
            continue;
        }
        let window = normalize_window(
            &ClaudeUsageWindow {
                utilization: Some(percent),
                resets_at: limit.resets_at.clone(),
            },
            WEEKLY_WINDOW_MINUTES,
        )?;
        windows.push(named_window(
            format!("claude-weekly-scoped-{model_slug}"),
            format!("{name} only"),
            window,
        )?);
    }
    Ok(windows)
}

fn slug(value: &str) -> String {
    let mut result = String::new();
    let mut last_was_dash = false;
    for character in value.chars().flat_map(char::to_lowercase) {
        if character.is_alphanumeric() {
            result.push(character);
            last_was_dash = false;
        } else if !last_was_dash && !result.is_empty() {
            result.push('-');
            last_was_dash = true;
        }
    }
    result.trim_matches('-').to_owned()
}

fn normalize_extra_usage_cost(
    extra: &ClaudeExtraUsage,
    fetched_at: Timestamp,
) -> Result<Option<CostSummary>, ClassifiedError> {
    if extra.is_enabled != Some(true) {
        return Ok(None);
    }
    let (Some(used), Some(limit)) = (extra.used_credits, extra.monthly_limit) else {
        return Ok(None);
    };
    if !used.is_finite() || !limit.is_finite() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if used < 0.0 || limit < 0.0 {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let used = Decimal::from_f64_retain(used)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        / Decimal::from(100_u8);
    let limit = Decimal::from_f64_retain(limit)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?
        / Decimal::from(100_u8);
    let currency = extra
        .currency
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("USD")
        .to_ascii_uppercase();
    let Ok(currency) = CurrencyCode::new(currency) else {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    };
    Ok(Some(
        CostSummary::new(
            CostAmount::money(ExactDecimal::new(used), currency),
            ExactDecimal::new(limit),
            Some("Monthly cap".to_owned()),
            None,
            None,
            None,
            None,
            fetched_at,
            None,
            None,
            CostProvenance::VendorMetered,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
    ))
}

fn normalize_spend_limit(
    extra: &ClaudeExtraUsage,
    limit: Decimal,
) -> Result<RateWindow, ClassifiedError> {
    let used = extra
        .used_credits
        .filter(|value| value.is_finite())
        .and_then(Decimal::from_f64_retain)
        .map(|value| value / Decimal::from(100_u8));
    let percent = extra
        .utilization
        .filter(|value| value.is_finite())
        .or_else(|| {
            used.and_then(|used| {
                (limit > Decimal::ZERO)
                    .then(|| used * Decimal::from(100_u8) / limit)
                    .and_then(|value| rust_decimal::prelude::ToPrimitive::to_f64(&value))
            })
        })
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent.clamp(0.0, 100.0))
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        None,
        Some(BoundedText::new("Spend limit").map_err(|_| ClassifiedError::new(ErrorKind::Api))?),
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn claude_login_method(
    subscription_type: Option<&str>,
    rate_limit_tier: Option<&str>,
) -> Option<String> {
    let source = [subscription_type, rate_limit_tier]
        .into_iter()
        .flatten()
        .find(|value| {
            let words = normalized_words(value);
            ["max", "pro", "team", "enterprise", "ultra"]
                .iter()
                .any(|plan| words.iter().any(|word| word == plan))
        })?;
    let words = normalized_words(source);
    let plan = ["max", "pro", "team", "enterprise", "ultra"]
        .into_iter()
        .find(|plan| words.iter().any(|word| word == plan))?;
    let mut label = format!("Claude {}", uppercase_first(plan));
    let rate_limit_words = rate_limit_tier.map(normalized_words).unwrap_or_default();
    if plan == "max"
        && let Some(index) = rate_limit_words.iter().position(|word| word == "max")
        && let Some(multiplier) = rate_limit_words.get(index + 1)
        && multiplier.ends_with('x')
        && multiplier[..multiplier.len() - 1].parse::<u16>().is_ok()
    {
        label.push(' ');
        label.push_str(multiplier);
    }
    Some(label)
}

fn normalized_words(value: &str) -> Vec<String> {
    value
        .to_ascii_lowercase()
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

fn uppercase_first(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

fn normalize_window(
    window: &ClaudeUsageWindow,
    minutes: i64,
) -> Result<RateWindow, ClassifiedError> {
    let usage = match window.utilization {
        Some(value) if value.is_finite() => WindowUsage::known(
            UsagePercent::new(value.clamp(0.0, 100.0))
                .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        Some(_) => return Err(ClassifiedError::new(ErrorKind::Parse)),
        None => WindowUsage::unknown(),
    };
    let reset = window
        .resets_at
        .as_deref()
        .map(Timestamp::parse)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let duration = WindowDuration::from_provider_minutes(minutes)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(usage, Some(duration), reset, None, None, false)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use oab_domain::{AccountKey, ProviderInstanceId};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::executable::resolve_executable;

    fn scope() -> AccountScope {
        AccountScope::new(
            ProviderId::Claude,
            ProviderInstanceId::new("default").unwrap(),
            AccountKey::new("ambient").unwrap(),
        )
    }

    #[test]
    fn normalizes_claude_oauth_windows() {
        let response: ClaudeUsageResponse = serde_json::from_str(
            r#"{
              "five_hour":{"utilization":42.5,"resets_at":"2026-08-30T12:00:00Z"},
              "seven_day":{"utilization":17.0,"resets_at":"2026-09-01T00:00:00Z"},
              "seven_day_opus":{"utilization":3.0,"resets_at":null}
            }"#,
        )
        .expect("Claude fixture");
        let sample = normalize_usage(
            scope(),
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            &response,
            Some("Claude Max 5x".to_owned()),
        )
        .expect("normalized usage");
        let primary = sample.primary().unwrap().used_percent().unwrap().get();
        let secondary = sample.secondary().unwrap().used_percent().unwrap().get();
        assert!((primary - 42.5).abs() < f64::EPSILON);
        assert!((secondary - 17.0).abs() < f64::EPSILON);
        assert!(
            (sample.tertiary().unwrap().used_percent().unwrap().get() - 3.0).abs() < f64::EPSILON
        );
        assert!(sample.extra_windows().is_empty());
        assert_eq!(
            sample.identity().login_method().map(BoundedText::as_str),
            Some("Claude Max 5x")
        );
    }

    #[test]
    fn claude_owned_oauth_lifecycle_is_read_only_and_expiry_aware() {
        let valid = br#"{
          "claudeAiOauth": {
            "accessToken":"owner-managed-token",
            "refreshToken":"must-never-be-consumed",
            "expiresAt":1800000000000,
            "scopes":["user:profile","user:inference"],
            "subscriptionType":"max",
            "rateLimitTier":"default_claude_max_20x"
          }
        }"#;
        let loaded =
            parse_file_credential(valid, Timestamp::parse("2026-08-30T10:00:00Z").unwrap())
                .expect("valid owner-managed credential");
        assert_eq!(loaded.login_method.as_deref(), Some("Claude Max 20x"));

        let expired =
            parse_file_credential(valid, Timestamp::parse("2030-01-01T00:00:00Z").unwrap())
                .expect_err("expired Claude-owned token must be delegated back to Claude");
        assert_eq!(expired.kind(), ErrorKind::AuthenticationExpired);

        let missing_scope = valid
            .windows(b"user:profile".len())
            .position(|window| window == b"user:profile")
            .map(|offset| {
                let mut bytes = valid.to_vec();
                bytes.splice(
                    offset..offset + b"user:profile".len(),
                    b"user:sessions".iter().copied(),
                );
                bytes
            })
            .expect("fixture contains profile scope");
        let missing_scope = parse_file_credential(
            &missing_scope,
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
        )
        .expect_err("OAuth usage requires user:profile");
        assert_eq!(missing_scope.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn modern_claude_payload_surfaces_scoped_limits_routines_and_extra_usage() {
        let response: ClaudeUsageResponse = serde_json::from_str(
            r#"{
              "five_hour":{"utilization":12.5,"resets_at":"2026-08-30T12:00:00Z"},
              "seven_day":{"utilization":31.0,"resets_at":"2026-09-01T00:00:00Z"},
              "seven_day_cowork":{"utilization":9.0,"resets_at":"2026-09-01T00:00:00Z"},
              "limits":[
                {"kind":"weekly_scoped","group":"weekly","percent":44.0,
                 "resets_at":"2026-09-01T00:00:00Z",
                 "scope":{"model":{"id":"claude-fable-5","display_name":"Fable"}}},
                {"kind":"weekly_scoped","group":"weekly","percent":99.0,
                 "scope":{"model":{"id":"all-models","display_name":"All models"}}}
              ],
              "extra_usage":{"is_enabled":true,"monthly_limit":5000,"used_credits":1234,
                "utilization":24.68,"currency":"usd"}
            }"#,
        )
        .expect("modern Claude payload");
        let sample = normalize_usage(
            scope(),
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            &response,
            Some("Claude Max".to_owned()),
        )
        .expect("modern payload normalizes");

        assert_eq!(sample.extra_windows().len(), 2);
        assert!(
            sample
                .extra_windows()
                .iter()
                .any(|window| window.id().as_str() == "claude-routines")
        );
        assert!(sample.extra_windows().iter().any(|window| {
            window.id().as_str() == "claude-weekly-scoped-claude-fable-5"
                && window.title().as_str() == "Fable only"
        }));
        let cost = sample.cost().expect("extra usage cost");
        assert_eq!(cost.used().amount(), ExactDecimal::parse("12.34").unwrap());
        assert_eq!(cost.limit(), ExactDecimal::parse("50").unwrap());
    }

    #[test]
    fn null_limits_remain_compatible_with_older_oauth_payloads() {
        let response: ClaudeUsageResponse = serde_json::from_str(
            r#"{"five_hour":{"utilization":1.0,"resets_at":null},"limits":null}"#,
        )
        .expect("null limits");
        let sample = normalize_usage(
            scope(),
            Timestamp::parse("2026-08-30T10:00:00Z").unwrap(),
            &response,
            None,
        )
        .expect("null limits normalize");
        assert!(sample.extra_windows().is_empty());
    }

    #[test]
    fn source_planner_keeps_explicit_authority_and_auto_order() {
        assert_eq!(
            ClaudeSourcePlanner::resolve(ClaudeSourceMode::OAuth).ordered_steps(),
            [ClaudeFetchSource::OAuth]
        );
        assert_eq!(
            ClaudeSourcePlanner::resolve(ClaudeSourceMode::Cli).ordered_steps(),
            [ClaudeFetchSource::Cli]
        );
        assert_eq!(
            ClaudeSourcePlanner::resolve(ClaudeSourceMode::Auto).ordered_steps(),
            [ClaudeFetchSource::OAuth, ClaudeFetchSource::Cli]
        );
    }

    #[test]
    fn auto_fallback_never_amplifies_oauth_rate_limits_or_permissions() {
        assert!(!should_auto_fallback_to_cli(&ClassifiedError::new(
            ErrorKind::RateLimited
        )));
        assert!(!should_auto_fallback_to_cli(&ClassifiedError::new(
            ErrorKind::PermissionDenied
        )));
        for kind in [
            ErrorKind::MissingCredential,
            ErrorKind::AuthenticationExpired,
            ErrorKind::ProviderUnavailable,
            ErrorKind::Network,
            ErrorKind::Parse,
            ErrorKind::Api,
        ] {
            assert!(should_auto_fallback_to_cli(&ClassifiedError::new(kind)));
        }
        assert_eq!(
            cli_rate_limit_error()
                .retry_after()
                .expect("CLI rate limit cooldown")
                .seconds(),
            5 * 60
        );
    }

    #[test]
    fn parses_current_linux_cli_usage_without_retaining_terminal_output() {
        let auth = ClaudeCliAuthStatus {
            logged_in: true,
            email: Some("person@example.com".to_owned()),
            org_name: Some("Example".to_owned()),
            subscription_type: Some("max".to_owned()),
            auth_method: Some("claude.ai".to_owned()),
        };
        let sample = normalize_cli_usage(
            scope(),
            Timestamp::parse("2026-08-31T21:00:00Z").unwrap(),
            b"\x1b[32mCurrent session: 1% used \xc2\xb7 resets Sep 1, 12:50am\x1b[0m\n\
              Current week (all models): 26% used \xc2\xb7 resets Sep 3, 2pm\n\
              Current week (Fable): 46% used \xc2\xb7 resets Sep 3, 2pm\n",
            &auth,
        )
        .expect("CLI usage");

        assert_eq!(sample.confidence(), DataConfidence::PercentOnly);
        assert!(
            (sample.primary().unwrap().used_percent().unwrap().get() - 1.0).abs() < f64::EPSILON
        );
        assert!(
            (sample.secondary().unwrap().used_percent().unwrap().get() - 26.0).abs() < f64::EPSILON
        );
        assert!(sample.extra_windows().iter().any(|window| {
            window.id().as_str() == "claude-weekly-scoped-fable"
                && window.title().as_str() == "Fable only"
                && (window.window().used_percent().unwrap().get() - 46.0).abs() < f64::EPSILON
        }));
        assert_eq!(
            sample.identity().login_method().map(BoundedText::as_str),
            Some("Claude Max")
        );
        assert_eq!(sample.provenance()[0].strategy(), "cli");
    }

    #[test]
    fn parses_split_line_cli_windows_resets_and_scoped_models() {
        let auth = ClaudeCliAuthStatus {
            logged_in: true,
            email: None,
            org_name: None,
            subscription_type: Some("pro".to_owned()),
            auth_method: Some("claude.ai".to_owned()),
        };
        let sample = normalize_cli_usage(
            scope(),
            Timestamp::parse("2026-08-31T21:00:00Z").unwrap(),
            b"Settings: Status Config Usage\n\
              Current session\n\
              1% used\n\
              Resets Sep 1, 12:50am\n\
              Current week (all models)\n\
              26% used\n\
              Resets Sep 3, 2pm\n\
              Current week (Fable)\n\
              46% used\n\
              Resets Sep 3, 2pm\n",
            &auth,
        )
        .expect("split-line CLI usage");

        let primary = sample.primary().expect("session window");
        assert!((primary.used_percent().unwrap().get() - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            primary.reset_description().map(BoundedText::as_str),
            Some("Resets Sep 1, 12:50am")
        );
        assert!(
            (sample.secondary().unwrap().used_percent().unwrap().get() - 26.0).abs() < f64::EPSILON
        );
        assert!(sample.extra_windows().iter().any(|window| {
            window.id().as_str() == "claude-weekly-scoped-fable"
                && (window.window().used_percent().unwrap().get() - 46.0).abs() < f64::EPSILON
        }));
    }

    #[test]
    fn latest_usage_panel_excludes_status_context_and_stale_redraws() {
        let auth = ClaudeCliAuthStatus {
            logged_in: true,
            email: None,
            org_name: None,
            subscription_type: None,
            auth_method: Some("claude.ai".to_owned()),
        };
        let sample = normalize_cli_usage(
            scope(),
            Timestamp::parse("2026-08-31T21:00:00Z").unwrap(),
            b"Current session\n2% used\n\
              Default | context left 0%\n\
              Settings: Status Config Usage\n\
              Sonnet | context left 0%\n\
              Current session\n\
              7% left\n\
              Resets tomorrow\n\
              Current week (all models)\n\
              80% remaining\n",
            &auth,
        )
        .expect("latest complete Usage panel");

        assert!(
            (sample.primary().unwrap().used_percent().unwrap().get() - 93.0).abs() < f64::EPSILON
        );
        assert!(
            (sample.secondary().unwrap().used_percent().unwrap().get() - 20.0).abs() < f64::EPSILON
        );
    }

    #[test]
    fn parses_real_tui_carriage_return_rows_and_compact_header() {
        let auth = ClaudeCliAuthStatus {
            logged_in: true,
            email: None,
            org_name: None,
            subscription_type: Some("max".to_owned()),
            auth_method: Some("claude.ai".to_owned()),
        };
        let sample = normalize_cli_usage(
            scope(),
            Timestamp::parse("2026-08-31T21:00:00Z").unwrap(),
            b"SettingsStatusConfig Usage Stats\r\
              Current session\r                                                  0%used\r\
              Resets 12:50am (Europe/Istanbul)\r\
              Current week (all models)\r                          26%used\r\
              Resets Sep 3, 2pm (Europe/Istanbul)\r\
              Current week (Fable)\r                               46%used\r",
            &auth,
        )
        .expect("real Claude TUI redraw layout");

        assert!(
            sample
                .primary()
                .unwrap()
                .used_percent()
                .unwrap()
                .get()
                .abs()
                < f64::EPSILON
        );
        assert!(
            (sample.secondary().unwrap().used_percent().unwrap().get() - 26.0).abs() < f64::EPSILON
        );
        assert!(sample.extra_windows().iter().any(|window| {
            window.id().as_str() == "claude-weekly-scoped-fable"
                && (window.window().used_percent().unwrap().get() - 46.0).abs() < f64::EPSILON
        }));
    }

    #[test]
    fn loading_or_subscription_only_panel_is_not_misreported_as_zero_usage() {
        let auth = ClaudeCliAuthStatus {
            logged_in: true,
            email: None,
            org_name: None,
            subscription_type: None,
            auth_method: None,
        };
        for fixture in [
            b"Current session\n1% used\nSettings: Status Config Usage\nLoading usage data...\n"
                .as_slice(),
            b"Settings: Status Config Usage\nYou are currently using your subscription to power your Claude Code usage\n"
                .as_slice(),
        ] {
            let error = normalize_cli_usage(
                scope(),
                Timestamp::parse("2026-08-31T21:00:00Z").unwrap(),
                fixture,
                &auth,
            )
            .expect_err("incomplete panels must not produce usage");
            assert_eq!(error.kind(), ErrorKind::ProviderUnavailable);
        }
    }

    #[tokio::test]
    async fn auto_uses_bounded_owner_cli_only_after_oauth_is_missing() {
        let fixture = tempfile::tempdir().expect("temporary Claude fixture");
        let log = fixture.path().join("invocations.log");
        let executable = fake_claude_cli(fixture.path(), &log, false);
        let settings = ClaudeSettings::resolve(&BTreeMap::new(), fixture.path())
            .expect("deferred missing credential")
            .with_source(ClaudeSourceMode::Auto, Some(executable));
        let provider = ClaudeProvider::new(scope(), settings).expect("Claude provider");
        let context =
            ProviderContext::new(scope(), ProviderSource::OAuth, CancellationToken::new());

        let sample = provider.fetch(&context).await.expect("CLI fallback usage");
        assert_eq!(sample.confidence(), DataConfidence::PercentOnly);
        let invocations = fs::read_to_string(log).expect("invocation log");
        assert!(invocations.starts_with("auth status --json\n"));
        assert!(invocations.contains("args:--allowed-tools"));
        assert!(invocations.contains("input:/usage\n"));
    }

    #[tokio::test]
    async fn successful_cli_cache_is_background_only_and_manual_bypasses_it() {
        let fixture = tempfile::tempdir().expect("temporary Claude fixture");
        let log = fixture.path().join("invocations.log");
        let executable = fake_claude_cli(fixture.path(), &log, false);
        let settings = ClaudeSettings::resolve(&BTreeMap::new(), fixture.path())
            .expect("deferred missing credential")
            .with_source(ClaudeSourceMode::Cli, Some(executable));
        let provider = ClaudeProvider::new(scope(), settings).expect("Claude provider");
        let background =
            ProviderContext::new(scope(), ProviderSource::Cli, CancellationToken::new());

        let first = provider.fetch(&background).await.expect("first CLI usage");
        let first_log = fs::read_to_string(&log).expect("first invocation log");
        let cached = provider
            .fetch(&background)
            .await
            .expect("background cache hit");
        assert_eq!(cached, first);
        assert_eq!(fs::read_to_string(&log).unwrap(), first_log);

        let manual = background.clone().with_provider_cache_bypass();
        let refreshed = provider.fetch(&manual).await.expect("manual CLI usage");
        assert_eq!(refreshed.primary(), first.primary());
        let manual_log = fs::read_to_string(log).expect("manual invocation log");
        assert_eq!(manual_log.matches("auth status --json\n").count(), 2);
        assert_eq!(manual_log.matches("input:/usage\n").count(), 2);
    }

    #[test]
    fn successful_cli_cache_expires_at_ttl_or_reported_reset() {
        let response: ClaudeUsageResponse = serde_json::from_str(
            r#"{"five_hour":{"utilization":5.0,"resets_at":"2026-09-01T00:00:00Z"}}"#,
        )
        .expect("Claude response");
        let sample = normalize_usage(
            scope(),
            Timestamp::parse("2026-08-31T21:00:00Z").unwrap(),
            &response,
            None,
        )
        .expect("usage sample");
        let cached_at = Instant::now();
        let cached = CachedClaudeCliUsage { cached_at, sample };

        assert!(cached_cli_usage_is_valid(
            &cached,
            cached_at + Duration::from_secs(60),
            Timestamp::parse("2026-08-31T23:00:00Z").unwrap()
        ));
        assert!(!cached_cli_usage_is_valid(
            &cached,
            cached_at + Duration::from_secs(60),
            Timestamp::parse("2026-09-01T00:00:00Z").unwrap()
        ));
        assert!(!cached_cli_usage_is_valid(
            &cached,
            cached_at + CLI_SUCCESS_CACHE_TTL,
            Timestamp::parse("2026-08-31T23:00:00Z").unwrap()
        ));
    }

    #[tokio::test]
    async fn explicit_oauth_never_falls_through_to_configured_cli() {
        let fixture = tempfile::tempdir().expect("temporary Claude fixture");
        let log = fixture.path().join("invocations.log");
        let executable = fake_claude_cli(fixture.path(), &log, false);
        let settings = ClaudeSettings::resolve(&BTreeMap::new(), fixture.path())
            .expect("deferred missing credential")
            .with_source(ClaudeSourceMode::OAuth, Some(executable));
        let provider = ClaudeProvider::new(scope(), settings).expect("Claude provider");
        let context =
            ProviderContext::new(scope(), ProviderSource::OAuth, CancellationToken::new());

        let error = provider
            .fetch(&context)
            .await
            .expect_err("explicit OAuth must remain exact");
        assert_eq!(error.kind(), ErrorKind::MissingCredential);
        assert!(!log.exists());
    }

    #[tokio::test]
    async fn cli_usage_process_has_a_hard_deadline() {
        let fixture = tempfile::tempdir().expect("temporary Claude fixture");
        let log = fixture.path().join("invocations.log");
        let executable = fake_claude_cli(fixture.path(), &log, true);
        let mut settings = ClaudeSettings::resolve(&BTreeMap::new(), fixture.path())
            .expect("deferred missing credential")
            .with_source(ClaudeSourceMode::Cli, Some(executable));
        settings.cli_limits.usage_timeout = Duration::from_millis(50);
        let provider = ClaudeProvider::new(scope(), settings).expect("Claude provider");
        let context = ProviderContext::new(scope(), ProviderSource::Cli, CancellationToken::new());

        let error = provider
            .fetch(&context)
            .await
            .expect_err("sleeping usage process must be terminated");
        assert_eq!(error.kind(), ErrorKind::Network);
    }

    #[tokio::test]
    #[ignore = "requires an installed, authenticated Claude Code CLI"]
    async fn live_installed_claude_cli_uses_interactive_pty() {
        let path = std::env::var_os("PATH");
        let executable = resolve_executable("claude", None, path.as_deref(), &[])
            .expect("valid PATH")
            .expect("installed Claude CLI");
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
        let mut environment = BTreeMap::new();
        for name in ["CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR"] {
            if let Ok(value) = std::env::var(name) {
                environment.insert(name.to_owned(), value);
            }
        }
        let settings = ClaudeSettings::resolve(&environment, &home)
            .expect("Claude settings")
            .with_source(ClaudeSourceMode::Cli, Some(executable));
        let provider = ClaudeProvider::new(scope(), settings).expect("Claude provider");
        let context = ProviderContext::new(scope(), ProviderSource::Cli, CancellationToken::new());

        let sample = provider.fetch(&context).await.expect("live PTY usage");
        assert!(
            sample
                .primary()
                .and_then(RateWindow::used_percent)
                .is_some()
        );
        assert_eq!(sample.provenance()[0].strategy(), "cli");
    }

    fn fake_claude_cli(root: &Path, log: &Path, slow_usage: bool) -> ExecutablePath {
        let executable = root.join("claude");
        let sleep = if slow_usage { "sleep 30" } else { "" };
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$DISABLE_AUTOUPDATER\" != 1 ] || \
                [ \"$CLAUDECODE_DISABLE_NONESSENTIAL_TRAFFIC\" != 1 ]; then\n\
               printf '%s\\n' 'passive flags missing' >&2\n\
               exit 8\n\
             fi\n\
             if [ -n \"$OMARCHY_AI_BAR_CLAUDE_OAUTH_TOKEN\" ] || \
                [ -n \"$CLAUDE_OAUTH_TOKEN\" ] || \
                [ -n \"$ANTHROPIC_OAUTH_TOKEN\" ] || \
                [ -n \"$ANTHROPIC_API_KEY\" ] || \
                [ -n \"$ANTHROPIC_ADMIN_KEY\" ]; then\n\
               printf '%s\\n' 'secret environment leaked' >&2\n\
               exit 9\n\
             fi\n\
             if [ \"$1\" = auth ]; then\n\
               printf '%s\\n' '{{\"loggedIn\":true,\"email\":\"person@example.com\",\"subscriptionType\":\"pro\"}}'\n\
               exit 0\n\
             fi\n\
             printf '%s\\n' \"args:$*\" >> '{}'\n\
             printf '%s\\n' 'Claude Code ready'\n\
             while IFS= read -r input; do\n\
               printf 'input:%s\\n' \"$input\" >> '{}'\n\
               case \"$input\" in\n\
                 *'/usage'*)\n\
                   {sleep}\n\
                   printf '%s\\n' 'Current session: 2% used - resets tomorrow'\n\
                   printf '%s\\n' 'Current week (all models): 12% used - resets Friday'\n\
                   ;;\n\
                 *'/exit'*) exit 0 ;;\n\
               esac\n\
             done\n",
            log.display(),
            log.display(),
            log.display()
        );
        fs::write(&executable, script).expect("fake Claude executable");
        let mut permissions = fs::metadata(&executable)
            .expect("fake metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("fake permissions");
        resolve_executable("claude", executable.to_str(), None, &[])
            .expect("valid executable lookup")
            .expect("fake Claude is executable")
    }
}
