//! Kiro CLI credits, context usage, and best-effort overage enrichment.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl, open};
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::stat::{Mode, fstat};
use nix::unistd::{Pid, Uid};
use oab_domain::{
    AccountScope, BoundedText, ClassifiedError, CostAmount, CostProvenance, CostSummary,
    CurrencyCode, DetailRow, DetailSection, DetailSensitivity, ErrorKind, ExactDecimal,
    NamedRateWindow, ProviderId, RateWindow, Timestamp, UsagePercent, UsageSample, WindowUsage,
};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde::Deserialize;
use serde::de::IgnoredAny;
use time::{Date, Duration as TimeDuration, Month, Time, UtcOffset};
use tokio::io::AsyncReadExt;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::context::{ProviderAdapter, ProviderContext, ProviderFuture};
use crate::descriptor::ProviderSource;
use crate::endpoint::{EndpointClass, EndpointPolicy};
use crate::executable::{ExecutablePath, resolve_executable};
use crate::normalize::{UsageSampleBuilder, system_timestamp};
use crate::registry::descriptor_for;
use crate::retry::RetryPolicy;
use crate::subprocess::{SubprocessError, SubprocessRequest};
use crate::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
};

const CLI_OVERRIDE: &str = "OMARCHY_AI_BAR_KIRO_CLI_PATH";
const DATA_DIR_OVERRIDE: &str = "KIRO_DATA_DIR";
const DEBUG_LIVE_STATE_OPT_IN: &str = "OMARCHY_AI_BAR_KIRO_ALLOW_LIVE_STATE_IN_DEBUG";
const TEST_HARNESS_GUARD: &str = "OMARCHY_AI_BAR_KIRO_TEST_HARNESS_GUARD";
const DEFAULT_ENDPOINT: &str = "https://codewhisperer.us-east-1.amazonaws.com/";
const API_TARGET: &str = "AmazonCodeWhispererService.GetUsageLimits";
const SQLITE_QUERY: &str = "SELECT 'T' || hex(CAST(value AS BLOB)) FROM auth_kv WHERE key = 'kirocli:odic:token' UNION ALL SELECT 'P' || hex(CAST(value AS BLOB)) FROM state WHERE key = 'api.codewhisperer.profile';";
const CLI_STDOUT_BYTES: usize = 384 * 1024;
const CLI_STDERR_BYTES: usize = 128 * 1024;
const PTY_OUTPUT_BYTES: usize = 512 * 1024;
const SQLITE_OUTPUT_BYTES: usize = 192 * 1024;
const MAX_STATE_DATABASE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JSON_VALUE_BYTES: usize = 64 * 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_PROFILE_ARN_BYTES: usize = 4 * 1024;
const MAX_CLI_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1024;
const MAX_PLAN_BYTES: usize = 120;
const MAX_ACCOUNT_VALUE_BYTES: usize = 256;
const MAX_API_ROWS: usize = 128;
const MAX_BONUS_ROWS: usize = 4_096;
const MAX_BONUS_EXPIRY_DAYS: u32 = 36_600;
const MAX_CREDITS: f64 = 1_000_000_000_000_000.0;
const RESET_MIN: i64 = 1_000_000_000;
const RESET_MAX: i64 = 4_102_444_800;
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(250);
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const PROC_SCAN_TIMEOUT: Duration = Duration::from_millis(500);
const DROP_SCAN_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_PROC_ENTRIES: usize = 32_768;
const MAX_PROC_FDS: usize = 4_096;
const MAX_PROC_STAT_BYTES: u64 = 16 * 1024;
const PTY_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_REAPER_RESPONSIBILITIES: usize = 64;
const REAPER_SCAN_TIMEOUT: Duration = Duration::from_millis(250);
const REAPER_RETRY_DELAY: Duration = Duration::from_millis(100);
const GROUP_CAPTURE_TIMEOUT: Duration = Duration::from_millis(50);

static ACTIVE_REAPER_RESPONSIBILITIES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
struct ProcScanConfig {
    force_indeterminate: bool,
    cleanup_timeout: Duration,
}

impl Default for ProcScanConfig {
    fn default() -> Self {
        Self {
            force_indeterminate: false,
            cleanup_timeout: PROCESS_CLEANUP_TIMEOUT,
        }
    }
}

const CLI_ENVIRONMENT_NAMES: [&str; 18] = [
    "HOME",
    "PATH",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    DATA_DIR_OVERRIDE,
    "LANG",
    "LC_ALL",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "AWS_CA_BUNDLE",
];

/// Bounded command deadlines used by the Kiro CLI probe.
#[derive(Debug, Clone, Copy)]
pub struct KiroCommandTimeouts {
    account: Duration,
    usage: Duration,
    context: Duration,
    fallback_cap: Duration,
}

impl KiroCommandTimeouts {
    /// Builds explicit deadlines for deterministic integration tests.
    ///
    /// # Errors
    ///
    /// Returns an API error for zero or excessively large values.
    pub fn new(
        account: Duration,
        usage: Duration,
        context: Duration,
        fallback_cap: Duration,
    ) -> Result<Self, ClassifiedError> {
        if [account, usage, context]
            .into_iter()
            .any(|value| value.is_zero())
            || [account, usage, context]
                .into_iter()
                .any(|value| value > Duration::from_mins(5))
            || fallback_cap > Duration::from_secs(30)
        {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        Ok(Self {
            account,
            usage,
            context,
            fallback_cap,
        })
    }
}

impl Default for KiroCommandTimeouts {
    fn default() -> Self {
        Self {
            account: Duration::from_secs(3),
            usage: Duration::from_secs(20),
            context: Duration::from_secs(8),
            fallback_cap: Duration::from_secs(5),
        }
    }
}

/// Resolved shell-free Kiro CLI and optional local enrichment paths.
#[derive(Clone)]
pub struct KiroCliSettings {
    executable: ExecutablePath,
    environment: Vec<(String, String)>,
    state_database: Option<PathBuf>,
    sqlite: Option<ExecutablePath>,
    timeouts: KiroCommandTimeouts,
    proc_scan: ProcScanConfig,
    fallback_commit_observation: Duration,
    allow_live_state_in_debug: bool,
}

impl KiroCliSettings {
    /// Resolves `kiro-cli`, the Linux state database, and optional `sqlite3`.
    ///
    /// The CLI override is authoritative. Missing or malformed optional local
    /// state disables API enrichment without disabling the CLI report.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-credential error when `kiro-cli` is absent,
    /// or API when an explicit executable/environment setting is unsafe.
    pub fn resolve(environment: &BTreeMap<String, String>) -> Result<Self, ClassifiedError> {
        let executable = resolve_kiro_cli(environment)?;
        let sanitized = sanitized_environment(environment)?;
        let allow_live_state_in_debug = debug_live_state_opted_in(environment);
        let state_database = state_database_path(environment)
            .ok()
            .filter(|path| state_database_allowed(path, allow_live_state_in_debug));
        let sqlite = resolve_sqlite(environment).ok().flatten();
        Ok(Self {
            executable,
            environment: sanitized,
            state_database,
            sqlite,
            timeouts: KiroCommandTimeouts::default(),
            proc_scan: ProcScanConfig::default(),
            fallback_commit_observation: Duration::ZERO,
            allow_live_state_in_debug,
        })
    }

    /// Constructs settings around explicit absolute test/embedding paths.
    ///
    /// # Errors
    ///
    /// Returns API when an executable or state path is not bounded and
    /// absolute, and missing-credential when the CLI is not executable.
    pub fn from_paths(
        executable: impl AsRef<Path>,
        state_database: Option<impl AsRef<Path>>,
        sqlite: Option<impl AsRef<Path>>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ClassifiedError> {
        let executable_text = executable
            .as_ref()
            .to_str()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        let executable = resolve_executable("kiro-cli", Some(executable_text), None, &[])
            .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
            .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
        let allow_live_state_in_debug = debug_live_state_opted_in(environment);
        let state_database = state_database
            .map(|path| validate_absolute_path(path.as_ref()).map(Path::to_path_buf))
            .transpose()?
            .filter(|path| state_database_allowed(path, allow_live_state_in_debug));
        let sqlite = sqlite
            .map(|path| {
                let text = path
                    .as_ref()
                    .to_str()
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
                resolve_executable("sqlite3", Some(text), None, &[])
                    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
                    .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
            })
            .transpose()?;
        Ok(Self {
            executable,
            environment: sanitized_environment(environment)?,
            state_database,
            sqlite,
            timeouts: KiroCommandTimeouts::default(),
            proc_scan: ProcScanConfig::default(),
            fallback_commit_observation: Duration::ZERO,
            allow_live_state_in_debug,
        })
    }

    /// Replaces command deadlines while preserving all account paths.
    #[must_use]
    pub const fn with_timeouts(mut self, timeouts: KiroCommandTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Forces `/proc` ownership scans to return indeterminate.
    ///
    /// This fault-injection seam verifies fail-closed cleanup behavior without
    /// depending on host process-table size or timing.
    #[doc(hidden)]
    #[must_use]
    pub const fn with_forced_incomplete_proc_scan(mut self) -> Self {
        self.proc_scan = ProcScanConfig {
            force_indeterminate: true,
            cleanup_timeout: Duration::from_millis(500),
        };
        self
    }

    /// Keeps polling the pipe briefly after a no-activity fallback decision.
    ///
    /// The decision remains latched; this seam makes post-cutoff output races
    /// deterministic in integration tests.
    ///
    /// # Errors
    ///
    /// Returns API when the observation window exceeds one second.
    #[doc(hidden)]
    pub fn with_fallback_commit_observation(
        mut self,
        observation: Duration,
    ) -> Result<Self, ClassifiedError> {
        if observation > Duration::from_secs(1) {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        self.fallback_commit_observation = observation;
        Ok(self)
    }

    /// Resolved Kiro executable for setup diagnostics.
    #[must_use]
    pub fn executable(&self) -> &Path {
        self.executable.as_path()
    }

    /// Optional Linux Kiro state database used only for enrichment.
    #[must_use]
    pub fn state_database(&self) -> Option<&Path> {
        self.state_database.as_deref()
    }
}

impl Debug for KiroCliSettings {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KiroCliSettings")
            .field("executable", &"<redacted>")
            .field("environment_entries", &self.environment.len())
            .field(
                "state_database",
                &self.state_database.as_ref().map(|_| "<redacted>"),
            )
            .field("sqlite", &self.sqlite.as_ref().map(|_| "<redacted>"))
            .field("timeouts", &self.timeouts)
            .field(
                "proc_scan_fault_injected",
                &self.proc_scan.force_indeterminate,
            )
            .field(
                "fallback_commit_observation",
                &self.fallback_commit_observation,
            )
            .field("allow_live_state_in_debug", &self.allow_live_state_in_debug)
            .finish()
    }
}

/// Parsed context-window proportions from `kiro-cli /context`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KiroContextUsage {
    /// Total context percentage.
    pub total: f64,
    /// Context-file contribution.
    pub context_files: Option<f64>,
    /// Tool contribution.
    pub tools: Option<f64>,
    /// Kiro-response contribution.
    pub responses: Option<f64>,
    /// User-prompt contribution.
    pub prompts: Option<f64>,
}

/// Parsed authoritative CLI report before optional API enrichment.
#[derive(Clone, PartialEq)]
pub struct KiroUsageReport {
    /// Raw plan label.
    pub plan_name: String,
    /// Provider-formatted plan label.
    pub display_plan_name: String,
    /// Account email from `whoami`.
    pub account_email: Option<String>,
    /// Login mechanism from `whoami`.
    pub auth_method: Option<String>,
    /// Plan credits spent.
    pub credits_used: f64,
    /// Included plan credits.
    pub credits_total: f64,
    /// Plan percentage as rendered by the CLI.
    pub credits_percent: f64,
    /// Bonus credits spent.
    pub bonus_used: Option<f64>,
    /// Bonus credit ceiling.
    pub bonus_total: Option<f64>,
    /// Relative bonus expiry.
    pub bonus_expiry_days: Option<u32>,
    /// CLI overage status line.
    pub overage_status: Option<String>,
    /// CLI overage credits spent.
    pub overage_used: Option<f64>,
    /// CLI's estimated USD overage charge.
    pub estimated_overage_cost_usd: Option<f64>,
    /// Optional fixed management URL.
    pub manage_url: Option<String>,
    /// Optional context breakdown.
    pub context: Option<KiroContextUsage>,
    /// Plan reset instant.
    pub resets_at: Option<Timestamp>,
}

impl Debug for KiroUsageReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KiroUsageReport")
            .field("plan_name", &self.plan_name)
            .field("display_plan_name", &self.display_plan_name)
            .field(
                "account_email",
                &self.account_email.as_ref().map(|_| "<redacted>"),
            )
            .field("auth_method", &self.auth_method)
            .field("credits_used", &self.credits_used)
            .field("credits_total", &self.credits_total)
            .field("credits_percent", &self.credits_percent)
            .field("bonus_used", &self.bonus_used)
            .field("bonus_total", &self.bonus_total)
            .field("bonus_expiry_days", &self.bonus_expiry_days)
            .field("overage_status", &self.overage_status)
            .field("overage_used", &self.overage_used)
            .field(
                "estimated_overage_cost_usd",
                &self.estimated_overage_cost_usd,
            )
            .field("manage_url", &self.manage_url)
            .field("context", &self.context)
            .field("resets_at", &self.resets_at)
            .finish()
    }
}

/// Exact plan/overage ceilings returned by `GetUsageLimits`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KiroUsageLimits {
    /// Credits included in the plan.
    pub plan_limit: Decimal,
    /// Plan credits spent, excluding overage.
    pub plan_used: Decimal,
    /// Credits spent beyond the plan.
    pub overage_used: Decimal,
    /// Maximum overage credits when explicitly enabled.
    pub overage_cap: Option<Decimal>,
    /// Explicit enabled/disabled state, or `None` for incomplete/unknown.
    pub overage_enabled: Option<bool>,
    /// Accrued overage charges in `currency_code`.
    pub overage_charges: Option<Decimal>,
    /// Charge per overage credit.
    pub overage_rate: Option<Decimal>,
    /// Provider-reported currency, defaulting to USD.
    pub currency_code: String,
    /// Billing reset instant.
    pub resets_at: Timestamp,
    /// Whether bonus spend cannot be separated from plan spend.
    pub has_unseparated_bonus: bool,
}

impl KiroUsageLimits {
    /// Currency ceiling corresponding to the overage-credit ceiling.
    #[must_use]
    pub fn overage_charge_limit(&self) -> Option<Decimal> {
        let cap = self.overage_cap?;
        let rate = self.overage_rate?;
        (cap > Decimal::ZERO && rate > Decimal::ZERO)
            .then(|| cap.checked_mul(rate))
            .flatten()
    }
}

/// Native Kiro adapter permanently bound to one CLI account scope.
pub struct KiroProvider {
    scope: AccountScope,
    settings: KiroCliSettings,
    endpoint: Url,
    transport: HttpTransport,
}

impl KiroProvider {
    /// Creates the production CLI provider and fixed AWS usage endpoint.
    ///
    /// # Errors
    ///
    /// Returns API for another provider scope or invalid transport setup.
    pub fn new(scope: AccountScope, settings: KiroCliSettings) -> Result<Self, ClassifiedError> {
        let endpoint =
            Url::parse(DEFAULT_ENDPOINT).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let policy = EndpointPolicy::new([(
            endpoint.origin().ascii_serialization(),
            EndpointClass::PublicHttps,
        )])
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let transport =
            HttpTransport::new(policy, transport_config()?).map_err(|error| error.classified())?;
        Self::from_transport(scope, settings, endpoint, transport)
    }

    /// Deterministic loopback seam retaining endpoint-policy validation.
    ///
    /// # Errors
    ///
    /// Rejects another provider scope, credential-bearing URLs, and non-root
    /// endpoint paths.
    #[doc(hidden)]
    pub fn from_transport(
        scope: AccountScope,
        settings: KiroCliSettings,
        endpoint: Url,
        transport: HttpTransport,
    ) -> Result<Self, ClassifiedError> {
        validate_scope(&scope)?;
        validate_endpoint(&endpoint)?;
        Ok(Self {
            scope,
            settings,
            endpoint,
            transport,
        })
    }

    /// Source to which this provider is permanently bound.
    #[must_use]
    pub const fn source() -> ProviderSource {
        ProviderSource::Cli
    }

    /// Detects the exact installed CLI version with the bounded pipe runner.
    ///
    /// # Errors
    ///
    /// Returns stable subprocess or parse classifications.
    pub async fn detect_version(
        settings: &KiroCliSettings,
        cancellation: &CancellationToken,
    ) -> Result<String, ClassifiedError> {
        let capture = run_pipe(
            settings.clone(),
            vec!["--version".to_owned()],
            Duration::from_secs(3),
            Duration::from_secs(1),
            cancellation.child_token(),
            None,
        )
        .await?;
        if is_login_required(&capture.output) {
            return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
        }
        if capture.status != 0 || capture.stopped_after_output {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }
        let output = clean_inline(&capture.output);
        let version = output.strip_prefix("kiro-cli ").unwrap_or(&output).trim();
        if version.is_empty() || version.len() > 128 || version.chars().any(char::is_control) {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
        Ok(version.to_owned())
    }

    /// Fetches at an injected instant for deterministic reset and expiry math.
    ///
    /// The CLI report is required. SQLite/API enrichment is read-only and
    /// best-effort; only caller cancellation is allowed to replace CLI data.
    ///
    /// # Errors
    ///
    /// Returns stable source, authentication, process, or parse failures.
    pub async fn fetch_at(
        &self,
        context: &ProviderContext,
        fetched_at: Timestamp,
    ) -> Result<UsageSample, ClassifiedError> {
        if context.scope() != &self.scope || context.source() != ProviderSource::Cli {
            return Err(ClassifiedError::new(ErrorKind::Api));
        }

        let account_future = self.fetch_account(context.cancellation());
        let usage_future = run_command(
            self.settings.clone(),
            vec![
                "chat".to_owned(),
                "--no-interactive".to_owned(),
                "/usage".to_owned(),
            ],
            CommandKind::Usage,
            self.settings.timeouts.usage,
            Duration::from_secs(4),
            context.cancellation().clone(),
        );
        let (account_result, usage_result) = tokio::join!(account_future, usage_future);
        let account_authentication_failed = account_result
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthenticationExpired);
        let account = account_result.ok();
        let usage_capture = match usage_result {
            Ok(capture) => capture,
            Err(error)
                if account_authentication_failed
                    || error.kind() == ErrorKind::AuthenticationExpired =>
            {
                return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
            }
            Err(error) => return Err(error),
        };

        let context_usage = match run_command(
            self.settings.clone(),
            vec![
                "chat".to_owned(),
                "--no-interactive".to_owned(),
                "/context".to_owned(),
            ],
            CommandKind::Context,
            self.settings.timeouts.context,
            Duration::from_secs(3),
            context.cancellation().clone(),
        )
        .await
        {
            Ok(capture) => parse_context_report(&capture.output),
            Err(error) if context.cancellation().is_cancelled() => return Err(error),
            Err(_) => None,
        };

        let (email, auth_method) =
            account.map_or((None, None), |account| (account.email, account.auth_method));
        let report = parse_usage_report(
            &usage_capture.output,
            fetched_at,
            email,
            auth_method,
            context_usage,
        )?;

        let limits = match self.fetch_usage_limits(context.cancellation()).await {
            Ok(limits) => Some(limits),
            Err(error) if context.cancellation().is_cancelled() => return Err(error),
            Err(_) => None,
        };
        if let Some(limits) = limits.as_ref() {
            let mut enriched = report.clone();
            if let Ok(sample) = normalize_report(
                context.scope().clone(),
                fetched_at,
                &mut enriched,
                Some(limits),
            ) {
                return Ok(sample);
            }
        }
        let mut report = report;
        normalize_report(context.scope().clone(), fetched_at, &mut report, None)
    }

    async fn fetch_account(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<KiroAccount, ClassifiedError> {
        let capture = run_command(
            self.settings.clone(),
            vec!["whoami".to_owned()],
            CommandKind::WhoAmI,
            self.settings.timeouts.account,
            Duration::from_millis(1_500),
            cancellation.clone(),
        )
        .await?;
        parse_account(&capture.output)
    }

    async fn fetch_usage_limits(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<KiroUsageLimits, ClassifiedError> {
        let identity = read_cli_identity(&self.settings, cancellation).await?;
        let body = serde_json::to_vec(&serde_json::json!({
            "profileArn": identity.profile_arn.as_str(),
        }))
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
        let request = HttpRequest::post(self.endpoint.clone(), body)
            .map_err(|error| error.classified())?
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::AwsJson10)
            .public_header("X-Amz-Target", API_TARGET)
            .map_err(|error| error.classified())?
            .authentication(
                Authentication::bearer(identity.access_token.as_str().to_owned())
                    .map_err(|error| error.classified())?,
            );
        let response = self
            .transport
            .send(&request, cancellation)
            .await
            .map_err(|error| error.classified())?;
        parse_usage_limits(response.body())
    }
}

impl Debug for KiroProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KiroProvider")
            .field("scope", &self.scope)
            .field("source", &Self::source())
            .field("settings", &self.settings)
            .field("endpoint", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ProviderAdapter for KiroProvider {
    fn descriptor(&self) -> &'static crate::descriptor::ProviderDescriptor {
        descriptor_for(ProviderId::Kiro)
    }

    fn fetch<'a>(&'a self, context: &'a ProviderContext) -> ProviderFuture<'a> {
        Box::pin(async move {
            let fetched_at = system_timestamp()?;
            self.fetch_at(context, fetched_at).await
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommandKind {
    WhoAmI,
    Usage,
    Context,
}

struct CliCapture {
    output: Zeroizing<String>,
    status: i32,
    stopped_after_output: bool,
}

impl Debug for CliCapture {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliCapture")
            .field("output_bytes", &self.output.len())
            .field("status", &self.status)
            .field("stopped_after_output", &self.stopped_after_output)
            .finish()
    }
}

async fn run_command(
    settings: KiroCliSettings,
    arguments: Vec<String>,
    kind: CommandKind,
    timeout: Duration,
    idle_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<CliCapture, ClassifiedError> {
    if cancellation.is_cancelled() {
        return Err(ClassifiedError::new(ErrorKind::Network));
    }
    let started = tokio::time::Instant::now();
    let fallback_delay = settings.timeouts.fallback_cap.min(timeout / 2);
    let pipe_cancellation = cancellation.child_token();
    let pipe_token = pipe_cancellation.clone();
    let pipe_settings = settings.clone();
    let pipe_arguments = arguments.clone();
    let (activity_sender, activity_receiver) = watch::channel(false);
    let pipe = run_pipe(
        pipe_settings,
        pipe_arguments,
        timeout,
        idle_timeout,
        pipe_token,
        Some(activity_sender),
    );
    tokio::pin!(pipe);

    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            pipe_cancellation.cancel();
            let _ = (&mut pipe).await;
            return Err(ClassifiedError::new(ErrorKind::Network));
        }
        result = &mut pipe => {
            if result.as_ref().is_ok_and(|capture| acceptable_capture(capture, kind)) {
                return validate_capture(result?, kind);
            }
            if result.as_ref().is_err_and(|error| critical_cli_error(error.kind())) {
                return result;
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return finish_without_fallback(result, kind);
            }
            if *activity_receiver.borrow() {
                return finish_without_fallback(result, kind);
            }
            let fallback = run_pty(settings, arguments, remaining, idle_timeout, cancellation).await;
            return resolve_command_results(result, fallback, kind);
        }
        () = tokio::time::sleep(fallback_delay) => {}
    }

    if *activity_receiver.borrow() {
        let result = (&mut pipe).await;
        return finish_without_fallback(result, kind);
    }

    // The no-activity decision is now committed. Later pipe bytes can still
    // be drained, but cannot revoke the PTY fallback after cleanup succeeds.
    let mut pipe_result = None;
    if !settings.fallback_commit_observation.is_zero() {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                pipe_cancellation.cancel();
                let _ = (&mut pipe).await;
                return Err(ClassifiedError::new(ErrorKind::Network));
            }
            result = &mut pipe => pipe_result = Some(result),
            () = tokio::time::sleep(settings.fallback_commit_observation) => {}
        }
    }
    // A PTY must never overlap a pipe process. Cancellation waits for the
    // pipe's root and any escaped pipe holders to be fully cleaned first.
    let pipe_result = if let Some(result) = pipe_result {
        result
    } else {
        pipe_cancellation.cancel();
        (&mut pipe).await
    };
    if pipe_result
        .as_ref()
        .is_err_and(|error| critical_cli_error(error.kind()))
    {
        return pipe_result;
    }
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(ClassifiedError::new(ErrorKind::Network));
    }
    let fallback = run_pty(settings, arguments, remaining, idle_timeout, cancellation).await;
    resolve_command_results(pipe_result, fallback, kind)
}

fn finish_without_fallback(
    result: Result<CliCapture, ClassifiedError>,
    kind: CommandKind,
) -> Result<CliCapture, ClassifiedError> {
    let capture = result?;
    if acceptable_capture(&capture, kind) {
        return validate_capture(capture, kind);
    }
    if is_login_required(&capture.output) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if capture.status != 0 {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Err(ClassifiedError::new(if capture.stopped_after_output {
        ErrorKind::Network
    } else {
        ErrorKind::Parse
    }))
}

fn resolve_command_results(
    pipe: Result<CliCapture, ClassifiedError>,
    pty: Result<CliCapture, ClassifiedError>,
    kind: CommandKind,
) -> Result<CliCapture, ClassifiedError> {
    let pipe = pipe.and_then(|capture| validate_capture(capture, kind));
    let pty = pty.and_then(|capture| validate_capture(capture, kind));
    match pty {
        Ok(capture) => Ok(capture),
        Err(error) if critical_cli_error(error.kind()) => Err(error),
        Err(pty_error) => match pipe {
            Ok(capture) => Ok(capture),
            Err(error) if critical_cli_error(error.kind()) => Err(error),
            Err(_) => Err(pty_error),
        },
    }
}

const fn critical_cli_error(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::AuthenticationExpired
            | ErrorKind::MissingCredential
            | ErrorKind::ProviderUnavailable
    )
}

fn acceptable_capture(capture: &CliCapture, kind: CommandKind) -> bool {
    if is_login_required(&capture.output) {
        return true;
    }
    if capture.status != 0 && !capture.stopped_after_output {
        return false;
    }
    match kind {
        CommandKind::WhoAmI => {
            let account = parse_account_fields(&capture.output);
            account.email.is_some() || account.auth_method.is_some()
        }
        CommandKind::Usage => parse_usage_core(&capture.output, None).is_ok(),
        CommandKind::Context => {
            parse_context_report(&capture.output).is_some()
                || (capture.status == 0
                    && !capture.stopped_after_output
                    && capture.output.trim().is_empty())
        }
    }
}

fn validate_capture(capture: CliCapture, kind: CommandKind) -> Result<CliCapture, ClassifiedError> {
    if is_login_required(&capture.output) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if capture.stopped_after_output && !acceptable_capture(&capture, kind) {
        return Err(ClassifiedError::new(ErrorKind::Network));
    }
    if capture.status != 0 && !capture.stopped_after_output {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(capture)
}

async fn run_pipe(
    settings: KiroCliSettings,
    arguments: Vec<String>,
    timeout: Duration,
    idle_timeout: Duration,
    cancellation: CancellationToken,
    activity_sender: Option<watch::Sender<bool>>,
) -> Result<CliCapture, ClassifiedError> {
    if cancellation.is_cancelled() {
        return Err(ClassifiedError::new(ErrorKind::Network));
    }
    let PipeProcess {
        mut child,
        mut stdout,
        mut stderr,
        mut cleanup,
    } = spawn_pipe_process(&settings, arguments)?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut tick = process_tick();
    let mut stdout_output = Zeroizing::new(Vec::new());
    let mut stderr_output = Zeroizing::new(Vec::new());
    let mut stdout_buffer = Zeroizing::new(vec![0_u8; 8 * 1024]);
    let mut stderr_buffer = Zeroizing::new(vec![0_u8; 8 * 1024]);
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    let mut last_activity = None;
    let mut stopped_after_output = false;
    let mut drain_deadline = None;

    loop {
        if stdout_eof && stderr_eof && status.is_some() {
            break;
        }
        tokio::select! {
            biased;
            result = stdout.read(stdout_buffer.as_mut_slice()), if !stdout_eof => {
                match record_pipe_read(result, &stdout_buffer, &mut stdout_output, CLI_STDOUT_BYTES) {
                    Ok(eof) => stdout_eof = eof,
                    Err(error) => {
                        return Err(cleanup_error(&mut child, &mut cleanup, status.is_some(), error).await);
                    }
                }
                note_pipe_activity(stdout_eof, activity_sender.as_ref(), &mut last_activity);
                capture_group_after_read(stdout_eof, &mut cleanup);
            }
            result = stderr.read(stderr_buffer.as_mut_slice()), if !stderr_eof => {
                match record_pipe_read(result, &stderr_buffer, &mut stderr_output, CLI_STDERR_BYTES) {
                    Ok(eof) => stderr_eof = eof,
                    Err(error) => {
                        return Err(cleanup_error(&mut child, &mut cleanup, status.is_some(), error).await);
                    }
                }
                note_pipe_activity(stderr_eof, activity_sender.as_ref(), &mut last_activity);
                capture_group_after_read(stderr_eof, &mut cleanup);
            }
            () = cancellation.cancelled() => {
                return Err(cleanup_error(
                    &mut child,
                    &mut cleanup,
                    false,
                    ClassifiedError::new(ErrorKind::Network),
                ).await);
            }
            process_status = child.wait(), if status.is_none() => {
                let Ok(process_status) = process_status else {
                    return Err(cleanup_error(
                        &mut child,
                        &mut cleanup,
                        false,
                        ClassifiedError::new(ErrorKind::Api),
                    ).await);
                };
                status = Some(process_status);
                cleanup_process(&mut child, &mut cleanup, true).await?;
                drain_deadline = Some(tokio::time::Instant::now() + PTY_DRAIN_TIMEOUT);
            }
            _ = tick.tick() => {
                let now = tokio::time::Instant::now();
                let hit_deadline = now >= deadline;
                let hit_idle = status.is_none()
                    && last_activity.is_some_and(|activity| now.duration_since(activity) >= idle_timeout);
                if (hit_deadline || hit_idle) && status.is_none() {
                    let received_output = last_activity.is_some();
                    cleanup_process(&mut child, &mut cleanup, false).await?;
                    if !received_output {
                        return Err(ClassifiedError::new(ErrorKind::Network));
                    }
                    stopped_after_output = true;
                    status = Some(synthetic_success_status());
                    drain_deadline = Some(tokio::time::Instant::now() + PTY_DRAIN_TIMEOUT);
                }
                if status.is_some()
                    && drain_deadline.is_some_and(|drain| now >= drain)
                {
                    break;
                }
            }
        }
    }

    finish_pipe_capture(
        &stdout_output,
        &stderr_output,
        status.and_then(|value| value.code()).unwrap_or(1),
        stopped_after_output,
    )
}

fn record_pipe_read(
    result: std::io::Result<usize>,
    buffer: &[u8],
    output: &mut Zeroizing<Vec<u8>>,
    maximum: usize,
) -> Result<bool, ClassifiedError> {
    let read = result.map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if read == 0 {
        return Ok(true);
    }
    append_bounded(output, &buffer[..read], maximum)?;
    Ok(false)
}

fn finish_pipe_capture(
    stdout: &[u8],
    stderr: &[u8],
    status: i32,
    stopped_after_output: bool,
) -> Result<CliCapture, ClassifiedError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(stdout.len() + stderr.len() + 1));
    bytes.extend_from_slice(stdout);
    if !stdout.is_empty() && !stderr.is_empty() {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(stderr);
    finish_capture(bytes, status, stopped_after_output)
}

fn finish_capture(
    mut bytes: Zeroizing<Vec<u8>>,
    status: i32,
    stopped_after_output: bool,
) -> Result<CliCapture, ClassifiedError> {
    let output = String::from_utf8(std::mem::take(&mut *bytes))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    Ok(CliCapture {
        output: Zeroizing::new(output),
        status,
        stopped_after_output,
    })
}

fn append_bounded(
    output: &mut Zeroizing<Vec<u8>>,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), ClassifiedError> {
    if bytes.len() > maximum.saturating_sub(output.len()) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn mark_pipe_activity(sender: Option<&watch::Sender<bool>>) {
    if let Some(sender) = sender {
        sender.send_replace(true);
    }
}

fn note_pipe_activity(
    reached_eof: bool,
    sender: Option<&watch::Sender<bool>>,
    last_activity: &mut Option<tokio::time::Instant>,
) {
    if !reached_eof {
        mark_pipe_activity(sender);
        *last_activity = Some(tokio::time::Instant::now());
    }
}

fn capture_group_after_read(reached_eof: bool, cleanup: &mut ProcCleanupGuard) {
    if !reached_eof {
        cleanup.capture_group_members(GROUP_CAPTURE_TIMEOUT, false);
    }
}

fn process_tick() -> tokio::time::Interval {
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick
}

struct PipeProcess {
    child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    cleanup: ProcCleanupGuard,
}

fn spawn_pipe_process(
    settings: &KiroCliSettings,
    arguments: Vec<String>,
) -> Result<PipeProcess, ClassifiedError> {
    let reaper_slot = ReaperSlot::reserve()?;
    let mut command = configured_command(settings, arguments);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    drop(command);
    let mut cleanup = ProcCleanupGuard::new(
        child.id(),
        Vec::new(),
        Vec::new(),
        settings.proc_scan,
        reaper_slot,
    )?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
    cleanup.track_fd(&stdout)?;
    cleanup.track_fd(&stderr)?;
    Ok(PipeProcess {
        child,
        stdout,
        stderr,
        cleanup,
    })
}

struct PtyProcess {
    child: Child,
    master: AsyncFd<File>,
    cleanup: ProcCleanupGuard,
}

fn spawn_pty_process(
    settings: &KiroCliSettings,
    arguments: Vec<String>,
) -> Result<PtyProcess, ClassifiedError> {
    let reaper_slot = ReaperSlot::reserve()?;
    let winsize = Winsize {
        ws_row: 50,
        ws_col: 200,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = openpty(Some(&winsize), None).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let master = File::from(pty.master);
    let slave = File::from(pty.slave);
    let slave_identity = fd_identity(&slave)?;
    let slave_anchor = fd_anchor(&slave)?;
    let flags = fcntl(&master, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    fcntl(&master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let stdin = slave
        .try_clone()
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let stdout = slave
        .try_clone()
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    let mut command = configured_command(settings, arguments);
    command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave));
    let child = command
        .spawn()
        .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    // `Command` is reusable and therefore retains its configured slave FDs.
    // Drop it now so only the child keeps the PTY slave open.
    drop(command);
    let cleanup = ProcCleanupGuard::new(
        child.id(),
        vec![slave_identity],
        vec![slave_anchor],
        settings.proc_scan,
        reaper_slot,
    )?;
    let master = AsyncFd::new(master).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    Ok(PtyProcess {
        child,
        master,
        cleanup,
    })
}

fn configured_command(settings: &KiroCliSettings, arguments: Vec<String>) -> Command {
    let mut command = Command::new(settings.executable.as_path());
    command
        .args(arguments)
        .env_clear()
        .kill_on_drop(true)
        .process_group(0);
    for (name, value) in &settings.environment {
        command.env(name, value);
    }
    command.env("TERM", "xterm-256color");
    command
}

async fn run_pty(
    settings: KiroCliSettings,
    arguments: Vec<String>,
    timeout: Duration,
    idle_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<CliCapture, ClassifiedError> {
    let PtyProcess {
        mut child,
        master,
        mut cleanup,
    } = spawn_pty_process(&settings, arguments)?;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut tick = process_tick();
    let mut output = Zeroizing::new(Vec::new());
    let mut last_activity = None;
    let mut status: Option<ExitStatus> = None;
    let mut reached_eof = false;
    let mut stopped_after_output = false;
    let mut drain_deadline = None;
    let mut buffer = Zeroizing::new(vec![0_u8; 8 * 1024]);

    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(cleanup_error(
                    &mut child,
                    &mut cleanup,
                    status.is_some(),
                    ClassifiedError::new(ErrorKind::Network),
                ).await);
            }
            ready = master.readable(), if !reached_eof => {
                let Ok(mut ready) = ready else {
                    return Err(cleanup_error(
                        &mut child,
                        &mut cleanup,
                        status.is_some(),
                        ClassifiedError::new(ErrorKind::Parse),
                    ).await);
                };
                let result = ready.try_io(|inner| {
                    let mut file = inner.get_ref();
                    file.read(buffer.as_mut_slice())
                });
                if let Ok(result) = result {
                    match record_pty_read(
                        result,
                        &buffer,
                        &mut output,
                        &mut child,
                        &mut cleanup,
                        status.is_some(),
                    ).await? {
                        PtyRead::Eof => reached_eof = true,
                        PtyRead::Data => note_pty_activity(&mut last_activity, &mut cleanup),
                    }
                }
            }
            process_status = child.wait(), if status.is_none() => {
                let Ok(process_status) = process_status else {
                    return Err(cleanup_error(
                        &mut child,
                        &mut cleanup,
                        false,
                        ClassifiedError::new(ErrorKind::Api),
                    ).await);
                };
                status = Some(process_status);
                cleanup_process(&mut child, &mut cleanup, true).await?;
                drain_deadline = Some(tokio::time::Instant::now() + PTY_DRAIN_TIMEOUT);
            }
            _ = tick.tick() => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    if status.is_some() {
                        break;
                    }
                    return Err(cleanup_error(
                        &mut child,
                        &mut cleanup,
                        false,
                        ClassifiedError::new(ErrorKind::Network),
                    ).await);
                }
                if status.is_none()
                    && last_activity.is_some_and(|activity| now.duration_since(activity) >= idle_timeout)
                {
                    stopped_after_output = true;
                    cleanup_process(&mut child, &mut cleanup, false).await?;
                    status = Some(synthetic_success_status());
                    drain_deadline = Some(tokio::time::Instant::now() + PTY_DRAIN_TIMEOUT);
                }
                if status.is_some()
                    && (reached_eof || drain_deadline.is_some_and(|drain| now >= drain))
                {
                    break;
                }
            }
        }
    }

    let status = status
        .and_then(|status| status.code())
        .unwrap_or(i32::from(!stopped_after_output));
    finish_capture(output, status, stopped_after_output)
}

enum PtyRead {
    Eof,
    Data,
}

fn note_pty_activity(
    last_activity: &mut Option<tokio::time::Instant>,
    cleanup: &mut ProcCleanupGuard,
) {
    *last_activity = Some(tokio::time::Instant::now());
    cleanup.capture_group_members(GROUP_CAPTURE_TIMEOUT, false);
}

async fn record_pty_read(
    result: std::io::Result<usize>,
    buffer: &[u8],
    output: &mut Zeroizing<Vec<u8>>,
    child: &mut Child,
    cleanup: &mut ProcCleanupGuard,
    root_exited: bool,
) -> Result<PtyRead, ClassifiedError> {
    match result {
        Ok(0) => Ok(PtyRead::Eof),
        Ok(read) => {
            if let Err(error) = append_bounded(output, &buffer[..read], PTY_OUTPUT_BYTES) {
                return Err(cleanup_error(child, cleanup, root_exited, error).await);
            }
            Ok(PtyRead::Data)
        }
        Err(error) if error.raw_os_error() == Some(5) => Ok(PtyRead::Eof),
        Err(_) => Err(cleanup_error(
            child,
            cleanup,
            root_exited,
            ClassifiedError::new(ErrorKind::Parse),
        )
        .await),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FdIdentity {
    device: u64,
    inode: u64,
}

fn fd_identity(fd: &impl AsFd) -> Result<FdIdentity, ClassifiedError> {
    let metadata = fstat(fd).map_err(|_| ClassifiedError::new(ErrorKind::Api))?;
    Ok(FdIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn fd_anchor(fd: &impl AsFd) -> Result<File, ClassifiedError> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()));
    open(&path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
        .map(File::from)
        .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ProcTarget {
    pid: i32,
    start_time: u64,
}

struct ReaperSlot;

impl ReaperSlot {
    fn reserve() -> Result<Self, ClassifiedError> {
        cleanup_reaper_sender()?;
        ACTIVE_REAPER_RESPONSIBILITIES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_REAPER_RESPONSIBILITIES).then_some(active + 1)
            })
            .map_err(|_| ClassifiedError::new(ErrorKind::ProviderUnavailable))?;
        Ok(Self)
    }
}

impl Drop for ReaperSlot {
    fn drop(&mut self) {
        ACTIVE_REAPER_RESPONSIBILITIES.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ProcCleanupGuard {
    root: Option<ProcTarget>,
    process_group: i32,
    known_descendants: BTreeSet<ProcTarget>,
    group_scan_indeterminate: bool,
    identities: Vec<FdIdentity>,
    anchors: Vec<File>,
    scan_config: ProcScanConfig,
    reaper_slot: Option<ReaperSlot>,
    armed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanCompleteness {
    Complete,
    Indeterminate,
}

struct ScanOutcome {
    targets: Vec<ProcTarget>,
    completeness: ScanCompleteness,
}

impl ScanOutcome {
    fn indeterminate() -> Self {
        Self {
            targets: Vec::new(),
            completeness: ScanCompleteness::Indeterminate,
        }
    }
}

struct OwnershipScan {
    fd_holders: ScanOutcome,
    group_members: ScanOutcome,
}

impl OwnershipScan {
    fn proved_clean(&self) -> bool {
        self.fd_holders.completeness == ScanCompleteness::Complete
            && self.group_members.completeness == ScanCompleteness::Complete
            && self.fd_holders.targets.is_empty()
            && self.group_members.targets.is_empty()
    }
}

impl ProcCleanupGuard {
    fn new(
        process_id: Option<u32>,
        identities: Vec<FdIdentity>,
        anchors: Vec<File>,
        scan_config: ProcScanConfig,
        reaper_slot: ReaperSlot,
    ) -> Result<Self, ClassifiedError> {
        let process_id = process_id
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        let root = process_target(process_id);
        Ok(Self {
            root,
            process_group: process_id,
            known_descendants: root.into_iter().collect(),
            group_scan_indeterminate: false,
            identities,
            anchors,
            scan_config,
            reaper_slot: Some(reaper_slot),
            armed: true,
        })
    }

    fn track_fd(&mut self, fd: &impl AsFd) -> Result<(), ClassifiedError> {
        let identity = fd_identity(fd)?;
        let anchor = fd_anchor(fd)?;
        self.identities.push(identity);
        self.anchors.push(anchor);
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.anchors.clear();
        self.reaper_slot.take();
    }

    fn handoff_to_reaper(&mut self) -> Result<(), ClassifiedError> {
        let sender = cleanup_reaper_sender()?;
        let slot = self
            .reaper_slot
            .take()
            .ok_or_else(|| ClassifiedError::new(ErrorKind::ProviderUnavailable))?;
        let responsibility = Self {
            root: self.root,
            process_group: self.process_group,
            known_descendants: self.known_descendants.clone(),
            group_scan_indeterminate: self.group_scan_indeterminate,
            identities: self.identities.clone(),
            anchors: std::mem::take(&mut self.anchors),
            scan_config: self.scan_config,
            reaper_slot: Some(slot),
            armed: true,
        };
        match sender.try_send(responsibility) {
            Ok(()) => {
                self.armed = false;
                #[cfg(test)]
                REAPER_HANDOFFS.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(
                mpsc::TrySendError::Full(mut responsibility)
                | mpsc::TrySendError::Disconnected(mut responsibility),
            ) => {
                self.reaper_slot = responsibility.reaper_slot.take();
                self.anchors = std::mem::take(&mut responsibility.anchors);
                responsibility.armed = false;
                Err(ClassifiedError::new(ErrorKind::ProviderUnavailable))
            }
        }
    }

    fn capture_group_members(&mut self, budget: Duration, require_complete: bool) {
        let Some(root) = self.root else {
            self.group_scan_indeterminate = true;
            return;
        };
        if process_target(root.pid) != Some(root)
            || process_group_for(root) != Some(self.process_group)
        {
            return;
        }
        let outcome = scan_process_group(
            self.process_group,
            Instant::now() + budget,
            self.scan_config,
        );
        if process_target(root.pid) != Some(root)
            || process_group_for(root) != Some(self.process_group)
        {
            return;
        }
        if require_complete && outcome.completeness == ScanCompleteness::Indeterminate {
            self.group_scan_indeterminate = true;
        }
        self.remember_descendants(outcome.targets);
    }

    fn remember_descendants(&mut self, targets: impl IntoIterator<Item = ProcTarget>) {
        for target in targets {
            if self.known_descendants.contains(&target) {
                continue;
            }
            if self.known_descendants.len() >= MAX_PROC_ENTRIES {
                self.group_scan_indeterminate = true;
                break;
            }
            self.known_descendants.insert(target);
        }
    }

    fn scan_known_descendants(&self, deadline: Instant) -> ScanOutcome {
        if self.scan_config.force_indeterminate {
            return ScanOutcome::indeterminate();
        }
        let mut outcome = ScanOutcome {
            targets: Vec::new(),
            completeness: if self.group_scan_indeterminate {
                ScanCompleteness::Indeterminate
            } else {
                ScanCompleteness::Complete
            },
        };
        for target in &self.known_descendants {
            if Instant::now() >= deadline {
                outcome.completeness = ScanCompleteness::Indeterminate;
                break;
            }
            match process_target(target.pid) {
                Some(current) if current == *target => outcome.targets.push(*target),
                None if Path::new(&format!("/proc/{}", target.pid)).exists() => {
                    outcome.completeness = ScanCompleteness::Indeterminate;
                }
                Some(_) | None => {}
            }
        }
        outcome
    }

    fn recover_injected_scan_fault(&mut self) {
        if self.scan_config.force_indeterminate {
            self.scan_config.force_indeterminate = false;
            self.group_scan_indeterminate = false;
        }
    }

    fn scan_owned(&mut self, budget: Duration) -> OwnershipScan {
        let started = Instant::now();
        self.capture_group_members(budget / 4, true);
        OwnershipScan {
            fd_holders: scan_fd_holders(
                &self.identities,
                self.root.map(|root| root.start_time),
                started + budget.saturating_mul(3) / 4,
                self.scan_config,
            ),
            group_members: self.scan_known_descendants(started + budget),
        }
    }

    fn signal_all(
        &mut self,
        signal: Signal,
        include_root: bool,
        budget: Duration,
    ) -> OwnershipScan {
        if !self.armed {
            return OwnershipScan {
                fd_holders: ScanOutcome::indeterminate(),
                group_members: ScanOutcome::indeterminate(),
            };
        }
        let started = Instant::now();
        let slice = budget / 4;
        let deadline = started + budget;
        if include_root && let Some(root) = self.root {
            self.capture_group_members(slice, true);
            signal_verified_process_group(root, self.process_group, signal, deadline);
            signal_verified(root, signal, None, None, deadline);
        }
        // Keep independent bounded scan and verification slices for escaped FD
        // holders and private-PGID members. A loaded `/proc` cannot make one
        // ownership mechanism consume the other's cleanup opportunity.
        let holder_signal_deadline = started + slice.saturating_mul(2);
        let fd_holders = scan_fd_holders(
            &self.identities,
            self.root.map(|root| root.start_time),
            started + slice,
            self.scan_config,
        );
        for target in fd_holders.targets.iter().copied() {
            if Some(target) != self.root || !include_root {
                signal_verified(
                    target,
                    signal,
                    Some(&self.identities),
                    None,
                    holder_signal_deadline,
                );
            }
            if Instant::now() >= holder_signal_deadline {
                break;
            }
        }
        let group_members = self.scan_known_descendants(started + slice.saturating_mul(3));
        for target in group_members.targets.iter().copied() {
            if (Some(target) != self.root || !include_root) && Instant::now() < deadline {
                signal_verified(target, signal, None, None, deadline);
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        OwnershipScan {
            fd_holders,
            group_members,
        }
    }
}

impl Drop for ProcCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.signal_all(Signal::SIGKILL, true, DROP_SCAN_TIMEOUT);
            let _ = self.handoff_to_reaper();
        }
    }
}

fn cleanup_reaper_sender() -> Result<&'static mpsc::SyncSender<ProcCleanupGuard>, ClassifiedError> {
    static SENDER: OnceLock<Option<mpsc::SyncSender<ProcCleanupGuard>>> = OnceLock::new();
    SENDER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel(MAX_REAPER_RESPONSIBILITIES);
            thread::Builder::new()
                .name("oab-kiro-reaper".to_owned())
                .spawn(move || cleanup_reaper_loop(&receiver))
                .ok()
                .map(|_| sender)
        })
        .as_ref()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::ProviderUnavailable))
}

fn cleanup_reaper_loop(receiver: &mpsc::Receiver<ProcCleanupGuard>) {
    // Indeterminate responsibilities intentionally remain here indefinitely,
    // retaining their fixed-capacity slot and stable O_PATH anchors. This
    // bounds memory and causes later Kiro spawns to fail closed once all slots
    // are occupied. Without a cgroup/subreaper, a descendant that escaped the
    // verified PGID before census and closed every tracked FD is unidentifiable;
    // the worker never guesses at unrelated same-UID PIDs or a reused PGID.
    let mut active = Vec::with_capacity(MAX_REAPER_RESPONSIBILITIES);
    loop {
        if active.is_empty() {
            let Ok(mut responsibility) = receiver.recv() else {
                return;
            };
            responsibility.recover_injected_scan_fault();
            active.push(responsibility);
        }
        loop {
            match receiver.try_recv() {
                Ok(mut responsibility) => {
                    responsibility.recover_injected_scan_fault();
                    active.push(responsibility);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        let mut index = 0;
        while index < active.len() {
            let responsibility = &mut active[index];
            let _ = responsibility.signal_all(Signal::SIGKILL, true, REAPER_SCAN_TIMEOUT);
            if responsibility
                .scan_owned(REAPER_SCAN_TIMEOUT)
                .proved_clean()
            {
                responsibility.disarm();
                active.swap_remove(index);
                #[cfg(test)]
                REAPER_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
            } else {
                index += 1;
            }
        }
        thread::sleep(REAPER_RETRY_DELAY);
    }
}

#[cfg(test)]
static REAPER_HANDOFFS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static REAPER_COMPLETIONS: AtomicUsize = AtomicUsize::new(0);

async fn cleanup_process(
    child: &mut Child,
    cleanup: &mut ProcCleanupGuard,
    mut root_exited: bool,
) -> Result<(), ClassifiedError> {
    if !cleanup.armed {
        return Ok(());
    }
    if root_exited {
        cleanup.recover_injected_scan_fault();
    }
    if root_exited && cleanup.scan_owned(PROC_SCAN_TIMEOUT).proved_clean() {
        cleanup.disarm();
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + cleanup.scan_config.cleanup_timeout;
    let _ = cleanup.signal_all(Signal::SIGTERM, !root_exited, PROC_SCAN_TIMEOUT);
    sleep_before(deadline, PROCESS_TERM_GRACE).await;
    loop {
        let _ = cleanup.signal_all(Signal::SIGKILL, !root_exited, PROC_SCAN_TIMEOUT);
        if !root_exited {
            let remaining = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(PROCESS_REAP_TIMEOUT);
            if !remaining.is_zero()
                && tokio::time::timeout(remaining, child.wait())
                    .await
                    .is_ok_and(|result| result.is_ok())
            {
                root_exited = true;
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let scan_budget = remaining.min(PROC_SCAN_TIMEOUT);
        if !scan_budget.is_zero() && cleanup.scan_owned(scan_budget).proved_clean() {
            cleanup.disarm();
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        sleep_before(deadline, Duration::from_millis(25)).await;
    }
    cleanup.handoff_to_reaper()?;
    Err(ClassifiedError::new(ErrorKind::ProviderUnavailable))
}

async fn cleanup_error(
    child: &mut Child,
    cleanup: &mut ProcCleanupGuard,
    root_exited: bool,
    original: ClassifiedError,
) -> ClassifiedError {
    cleanup_process(child, cleanup, root_exited)
        .await
        .err()
        .unwrap_or(original)
}

async fn sleep_before(deadline: tokio::time::Instant, duration: Duration) {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if !remaining.is_zero() {
        tokio::time::sleep(duration.min(remaining)).await;
    }
}

fn scan_fd_holders(
    identities: &[FdIdentity],
    minimum_start_time: Option<u64>,
    deadline: Instant,
    config: ProcScanConfig,
) -> ScanOutcome {
    if identities.is_empty() {
        return ScanOutcome {
            targets: Vec::new(),
            completeness: ScanCompleteness::Complete,
        };
    }
    // O_PATH anchors keep each tracked kernel object alive, so an identity
    // cannot be recycled even when a very short-lived root escaped capture.
    let minimum_start_time = minimum_start_time.unwrap_or(0);
    if config.force_indeterminate {
        return ScanOutcome::indeterminate();
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return ScanOutcome::indeterminate();
    };
    let mut outcome = ScanOutcome {
        targets: Vec::new(),
        completeness: ScanCompleteness::Complete,
    };
    let own_pid = i32::try_from(std::process::id()).ok();
    let mut entries = entries.into_iter();
    for _ in 0..MAX_PROC_ENTRIES {
        if Instant::now() >= deadline {
            outcome.completeness = ScanCompleteness::Indeterminate;
            break;
        }
        let entry = match entries.next() {
            None => return outcome,
            Some(Ok(entry)) => entry,
            Some(Err(_)) => {
                outcome.completeness = ScanCompleteness::Indeterminate;
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        if Some(pid) == own_pid {
            continue;
        }
        let metadata = match fs::metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                outcome.completeness = ScanCompleteness::Indeterminate;
                continue;
            }
        };
        if metadata.uid() != Uid::effective().as_raw() {
            continue;
        }
        let Some(target) = process_target(pid) else {
            if entry.path().exists() {
                outcome.completeness = ScanCompleteness::Indeterminate;
            }
            continue;
        };
        if target.start_time < minimum_start_time {
            continue;
        }
        match holds_identity(pid, identities, deadline) {
            IdentityCheck::Holds => outcome.targets.push(target),
            IdentityCheck::DoesNotHold => {}
            IdentityCheck::Indeterminate => {
                outcome.completeness = ScanCompleteness::Indeterminate;
            }
        }
    }
    if entries.next().is_some() {
        outcome.completeness = ScanCompleteness::Indeterminate;
    }
    outcome
}

fn scan_process_group(
    process_group: i32,
    deadline: Instant,
    config: ProcScanConfig,
) -> ScanOutcome {
    if config.force_indeterminate {
        return ScanOutcome::indeterminate();
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return ScanOutcome::indeterminate();
    };
    let mut outcome = ScanOutcome {
        targets: Vec::new(),
        completeness: ScanCompleteness::Complete,
    };
    let own_pid = i32::try_from(std::process::id()).ok();
    let mut entries = entries.into_iter();
    for _ in 0..MAX_PROC_ENTRIES {
        if Instant::now() >= deadline {
            outcome.completeness = ScanCompleteness::Indeterminate;
            break;
        }
        let entry = match entries.next() {
            None => return outcome,
            Some(Ok(entry)) => entry,
            Some(Err(_)) => {
                outcome.completeness = ScanCompleteness::Indeterminate;
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        if Some(pid) == own_pid {
            continue;
        }
        let metadata = match fs::metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                outcome.completeness = ScanCompleteness::Indeterminate;
                continue;
            }
        };
        if metadata.uid() != Uid::effective().as_raw() {
            continue;
        }
        let Some(target) = process_target(pid) else {
            if entry.path().exists() {
                outcome.completeness = ScanCompleteness::Indeterminate;
            }
            continue;
        };
        match process_group_for(target) {
            Some(group) if group == process_group => outcome.targets.push(target),
            Some(_) => {}
            None => outcome.completeness = ScanCompleteness::Indeterminate,
        }
    }
    if entries.next().is_some() {
        outcome.completeness = ScanCompleteness::Indeterminate;
    }
    outcome
}

fn process_target(pid: i32) -> Option<ProcTarget> {
    let process_path = PathBuf::from(format!("/proc/{pid}"));
    let metadata = fs::metadata(&process_path).ok()?;
    if metadata.uid() != Uid::effective().as_raw() {
        return None;
    }
    Some(ProcTarget {
        pid,
        start_time: read_process_stat(&process_path.join("stat"))?.start_time,
    })
}

struct ProcStat {
    process_group: i32,
    start_time: u64,
}

fn read_process_stat(path: &Path) -> Option<ProcStat> {
    let mut file = File::open(path).ok()?.take(MAX_PROC_STAT_BYTES + 1);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    if u64::try_from(bytes.len()).ok()? > MAX_PROC_STAT_BYTES {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let after_name = text.get(text.rfind(')')? + 1..)?;
    let fields = after_name.split_whitespace().collect::<Vec<_>>();
    Some(ProcStat {
        process_group: fields.get(2)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
    })
}

fn process_group_for(target: ProcTarget) -> Option<i32> {
    let stat = read_process_stat(Path::new(&format!("/proc/{}/stat", target.pid)))?;
    (stat.start_time == target.start_time).then_some(stat.process_group)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdentityCheck {
    Holds,
    DoesNotHold,
    Indeterminate,
}

fn holds_identity(pid: i32, identities: &[FdIdentity], deadline: Instant) -> IdentityCheck {
    let process_path = PathBuf::from(format!("/proc/{pid}"));
    let Ok(entries) = fs::read_dir(process_path.join("fd")) else {
        return if process_path.exists() {
            IdentityCheck::Indeterminate
        } else {
            IdentityCheck::DoesNotHold
        };
    };
    let mut entries = entries.into_iter();
    for _ in 0..MAX_PROC_FDS {
        if Instant::now() >= deadline {
            return IdentityCheck::Indeterminate;
        }
        let entry = match entries.next() {
            None => return IdentityCheck::DoesNotHold,
            Some(Ok(entry)) => entry,
            Some(Err(_)) => return IdentityCheck::Indeterminate,
        };
        let metadata = match fs::metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return IdentityCheck::Indeterminate,
        };
        if identities
            .iter()
            .any(|identity| metadata.dev() == identity.device && metadata.ino() == identity.inode)
        {
            return IdentityCheck::Holds;
        }
    }
    if entries.next().is_some() {
        IdentityCheck::Indeterminate
    } else {
        IdentityCheck::DoesNotHold
    }
}

fn signal_verified(
    target: ProcTarget,
    signal: Signal,
    required_identities: Option<&[FdIdentity]>,
    required_process_group: Option<i32>,
    deadline: Instant,
) {
    if Instant::now() >= deadline || process_target(target.pid) != Some(target) {
        return;
    }
    if required_identities.is_some_and(|identities| {
        holds_identity(target.pid, identities, deadline) != IdentityCheck::Holds
    }) {
        return;
    }
    if required_process_group.is_some_and(|group| process_group_for(target) != Some(group)) {
        return;
    }
    let _ = kill(Pid::from_raw(target.pid), signal);
}

fn signal_verified_process_group(
    root: ProcTarget,
    process_group: i32,
    signal: Signal,
    deadline: Instant,
) {
    if Instant::now() >= deadline
        || process_target(root.pid) != Some(root)
        || process_group_for(root) != Some(process_group)
    {
        return;
    }
    let _ = killpg(Pid::from_raw(process_group), signal);
}

#[cfg(unix)]
fn synthetic_success_status() -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

fn classify_subprocess(error: SubprocessError) -> ClassifiedError {
    let kind = match error {
        SubprocessError::Spawn => ErrorKind::MissingCredential,
        SubprocessError::Cancelled | SubprocessError::Timeout | SubprocessError::Wait => {
            ErrorKind::Network
        }
        SubprocessError::StdoutTooLarge
        | SubprocessError::StderrTooLarge
        | SubprocessError::OutputRead => ErrorKind::Parse,
        SubprocessError::InvalidConfiguration | SubprocessError::NonZero { .. } => ErrorKind::Api,
    };
    ClassifiedError::new(kind)
}

#[derive(Default)]
struct KiroAccount {
    auth_method: Option<String>,
    email: Option<String>,
}

fn parse_account(output: &str) -> Result<KiroAccount, ClassifiedError> {
    if is_login_required(output) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    if output.trim().is_empty() {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(parse_account_fields(output))
}

fn parse_account_fields(output: &str) -> KiroAccount {
    let stripped = strip_ansi(output);
    let mut account = KiroAccount::default();
    for raw_line in stripped.lines() {
        let line = clean_inline(raw_line);
        if line.is_empty() || line.len() > MAX_ACCOUNT_VALUE_BYTES {
            continue;
        }
        let lowered = line.to_ascii_lowercase();
        if let Some(index) = lowered.find("logged in with") {
            account.auth_method = clean_account_value(&line[index + "logged in with".len()..]);
        } else if let Some(index) = lowered.find("email:") {
            account.email = clean_account_value(&line[index + "email:".len()..]);
        } else if account.email.is_none() && !line.contains(' ') && line.contains('@') {
            account.email = clean_account_value(&line);
        }
    }
    account
}

fn clean_account_value(value: &str) -> Option<String> {
    let value = clean_inline(value);
    (!value.is_empty()
        && value.len() <= MAX_ACCOUNT_VALUE_BYTES
        && !value.chars().any(char::is_control))
    .then_some(value)
}

fn is_login_required(output: &str) -> bool {
    let output = strip_ansi(output).to_ascii_lowercase();
    [
        "not logged in",
        "login required",
        "failed to initialize auth portal",
        "kiro-cli login",
        "oauth error",
    ]
    .into_iter()
    .any(|needle| output.contains(needle))
}

/// Parses one ANSI-decorated Kiro usage transcript.
///
/// # Errors
///
/// Returns `AuthenticationExpired` for login prompts and `Parse` when required
/// usage markers, bounds, or numeric invariants are absent.
pub fn parse_usage_report(
    output: &str,
    fetched_at: Timestamp,
    account_email: Option<String>,
    auth_method: Option<String>,
    context: Option<KiroContextUsage>,
) -> Result<KiroUsageReport, ClassifiedError> {
    parse_usage_report_inner(
        output,
        fetched_at,
        account_email,
        auth_method,
        context,
        None,
    )
}

/// Parses a report using an injected fixed local offset.
///
/// This deterministic seam exists for timezone parity tests. Production uses
/// the operating system's local timezone, including offset changes at the
/// target reset date.
///
/// # Errors
///
/// Returns the same stable classifications as [`parse_usage_report`].
#[doc(hidden)]
pub fn parse_usage_report_with_local_offset(
    output: &str,
    fetched_at: Timestamp,
    account_email: Option<String>,
    auth_method: Option<String>,
    context: Option<KiroContextUsage>,
    local_offset: UtcOffset,
) -> Result<KiroUsageReport, ClassifiedError> {
    parse_usage_report_inner(
        output,
        fetched_at,
        account_email,
        auth_method,
        context,
        Some(local_offset),
    )
}

fn parse_usage_report_inner(
    output: &str,
    fetched_at: Timestamp,
    account_email: Option<String>,
    auth_method: Option<String>,
    context: Option<KiroContextUsage>,
    local_offset: Option<UtcOffset>,
) -> Result<KiroUsageReport, ClassifiedError> {
    let mut report = parse_usage_core_with_offset(output, Some(fetched_at), local_offset)?;
    report.account_email = account_email.and_then(|value| clean_account_value(&value));
    report.auth_method = auth_method.and_then(|value| clean_account_value(&value));
    report.context = context;
    Ok(report)
}

fn parse_usage_core(
    output: &str,
    fetched_at: Option<Timestamp>,
) -> Result<KiroUsageReport, ClassifiedError> {
    parse_usage_core_with_offset(output, fetched_at, None)
}

fn parse_usage_core_with_offset(
    output: &str,
    fetched_at: Option<Timestamp>,
    local_offset: Option<UtcOffset>,
) -> Result<KiroUsageReport, ClassifiedError> {
    let stripped = strip_ansi(output);
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    if is_login_required(&stripped) {
        return Err(ClassifiedError::new(ErrorKind::AuthenticationExpired));
    }
    let lowered = stripped.to_ascii_lowercase();
    if lowered.contains("could not retrieve usage information") {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }

    let (plan_name, new_format) = parse_plan(&stripped)?;
    let managed =
        lowered.contains("managed by admin") || lowered.contains("managed by organization");
    let credits_pair = parse_credits_pair(&stripped);
    let credits_percent = parse_usage_bar_percent(&stripped);
    let (bonus_used, bonus_total, bonus_expiry_days) = parse_bonus(&stripped);
    if new_format && managed && credits_pair.is_none() && credits_percent.is_none() {
        return Ok(KiroUsageReport {
            display_plan_name: display_plan_name(&plan_name),
            plan_name,
            account_email: None,
            auth_method: None,
            credits_used: 0.0,
            credits_total: 0.0,
            credits_percent: 0.0,
            bonus_used,
            bonus_total,
            bonus_expiry_days,
            overage_status: parse_line_value(&stripped, "Overages:"),
            overage_used: parse_labeled_number(&stripped, "Credits used:"),
            estimated_overage_cost_usd: parse_labeled_number(&stripped, "Est. cost:"),
            manage_url: stripped
                .contains("https://app.kiro.dev/account/usage")
                .then(|| "https://app.kiro.dev/account/usage".to_owned()),
            context: None,
            resets_at: None,
        });
    }
    let (credits_used, credits_total) = match credits_pair {
        Some(credits) => credits,
        None if credits_percent.is_some() => (0.0, 50.0),
        None => return Err(ClassifiedError::new(ErrorKind::Parse)),
    };
    let credits_percent = credits_percent.unwrap_or_else(|| {
        if credits_total > 0.0 {
            credits_used / credits_total * 100.0
        } else {
            0.0
        }
    });
    let resets_at = fetched_at.and_then(|at| parse_reset(&stripped, at, local_offset));

    Ok(KiroUsageReport {
        display_plan_name: display_plan_name(&plan_name),
        plan_name,
        account_email: None,
        auth_method: None,
        credits_used,
        credits_total,
        credits_percent,
        bonus_used,
        bonus_total,
        bonus_expiry_days,
        overage_status: parse_line_value(&stripped, "Overages:"),
        overage_used: parse_labeled_number(&stripped, "Credits used:"),
        estimated_overage_cost_usd: parse_labeled_number(&stripped, "Est. cost:"),
        manage_url: stripped
            .contains("https://app.kiro.dev/account/usage")
            .then(|| "https://app.kiro.dev/account/usage".to_owned()),
        context: None,
        resets_at,
    })
}

/// Parses the optional Kiro context transcript.
#[must_use]
pub fn parse_context_report(output: &str) -> Option<KiroContextUsage> {
    let stripped = strip_ansi(output);
    let total_percent = parse_labeled_percent(&stripped, "Context window:")?;
    Some(KiroContextUsage {
        total: total_percent,
        context_files: parse_labeled_percent(&stripped, "Context files"),
        tools: parse_labeled_percent(&stripped, "Tools"),
        responses: parse_labeled_percent(&stripped, "Kiro responses"),
        prompts: parse_labeled_percent(&stripped, "Your prompts"),
    })
}

fn parse_plan(text: &str) -> Result<(String, bool), ClassifiedError> {
    let mut plan = None;
    let mut new_format = false;
    for line in text.lines() {
        let line = clean_inline(line);
        if let Some(value) = line.strip_prefix("Plan:") {
            plan = Some(clean_inline(value));
            new_format = true;
            continue;
        }
        if line.contains("Estimated Usage")
            && let Some(value) = line.rsplit('|').next()
        {
            let value = clean_inline(value);
            if !value.is_empty() {
                plan = Some(value);
            }
            continue;
        }
        for part in line.split('|').map(clean_inline) {
            if part.to_ascii_uppercase().starts_with("KIRO ") {
                plan = Some(part);
            }
        }
    }
    let plan = plan.unwrap_or_else(|| "Kiro".to_owned());
    if plan.is_empty() || plan.len() > MAX_PLAN_BYTES || plan.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    Ok((plan, new_format))
}

fn display_plan_name(plan: &str) -> String {
    let cleaned = clean_inline(plan);
    if !cleaned.to_ascii_uppercase().contains("KIRO") {
        return cleaned;
    }
    cleaned
        .split_whitespace()
        .map(|word| {
            if word.eq_ignore_ascii_case("kiro") {
                return "Kiro".to_owned();
            }
            let mut characters = word.chars();
            characters.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(characters.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_credits_pair(text: &str) -> Option<(f64, f64)> {
    text.lines().find_map(|line| {
        let lowered = line.to_ascii_lowercase();
        let covered = lowered.find("covered")?;
        let before = &line[..covered];
        let open = before.rfind('(')?;
        let words = before[open + 1..].split_whitespace().collect::<Vec<_>>();
        let of = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case("of"))?;
        let used = words.get(of.checked_sub(1)?)?;
        let total = words.get(of + 1)?;
        Some((parse_credit_number(used)?, parse_credit_number(total)?))
    })
}

fn parse_usage_bar_percent(text: &str) -> Option<f64> {
    text.lines()
        .filter(|line| line.contains('█'))
        .find_map(parse_first_percent)
}

fn parse_first_percent(line: &str) -> Option<f64> {
    let percent = line.find('%')?;
    let before = &line[..percent];
    let token = before.split_whitespace().next_back()?;
    parse_credit_number(token)
}

fn parse_labeled_percent(text: &str, label: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        let index = ascii_find_case_insensitive(line, label)?;
        parse_first_percent(&line[index + label.len()..])
    })
}

fn parse_labeled_number(text: &str, label: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        let index = ascii_find_case_insensitive(line, label)?;
        let rest = line[index + label.len()..].trim_start();
        let token = rest
            .trim_start_matches('$')
            .split_whitespace()
            .next()?
            .trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
        parse_credit_number(token)
    })
}

fn parse_line_value(text: &str, label: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let index = ascii_find_case_insensitive(line, label)?;
        let value = clean_inline(&line[index + label.len()..]);
        (!value.is_empty() && value.len() <= MAX_PLAN_BYTES).then_some(value)
    })
}

fn parse_bonus(text: &str) -> (Option<f64>, Option<f64>, Option<u32>) {
    let mut used = None;
    let mut total = None;
    let mut expiry = None;
    for line in text.lines() {
        if let Some(index) = ascii_find_case_insensitive(line, "Bonus credits:") {
            let rest = &line[index + "Bonus credits:".len()..];
            if let Some((left, right)) = rest.split_once('/') {
                used = left
                    .split_whitespace()
                    .next_back()
                    .and_then(parse_credit_number);
                total = right
                    .split_whitespace()
                    .next()
                    .and_then(parse_credit_number);
            }
        }
        if let Some(index) = ascii_find_case_insensitive(line, "expires in ") {
            expiry = line[index + "expires in ".len()..]
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|days| *days <= MAX_BONUS_EXPIRY_DAYS);
        }
    }
    (used, total, expiry)
}

fn parse_credit_number(value: &str) -> Option<f64> {
    let value = value.parse::<f64>().ok()?;
    (value.is_finite() && (0.0..=MAX_CREDITS).contains(&value)).then_some(value)
}

fn parse_reset(
    text: &str,
    fetched_at: Timestamp,
    fixed_local_offset: Option<UtcOffset>,
) -> Option<Timestamp> {
    let lowered = text.to_ascii_lowercase();
    let index = lowered.find("resets on ")?;
    let token = text[index + "resets on ".len()..]
        .split_whitespace()
        .next()?
        .trim_matches(|character: char| {
            !character.is_ascii_digit() && character != '-' && character != '/'
        });
    if token.contains('-') {
        let mut parts = token.split('-');
        let year = parts.next()?.parse::<i32>().ok()?;
        let month = Month::try_from(parts.next()?.parse::<u8>().ok()?).ok()?;
        let day = parts.next()?.parse::<u8>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let date = Date::from_calendar_date(year, month, day).ok()?;
        return local_midnight(date, fetched_at, fixed_local_offset);
    }
    let (month, day) = token.split_once('/')?;
    let month = Month::try_from(month.parse::<u8>().ok()?).ok()?;
    let day = day.parse::<u8>().ok()?;
    let fallback_offset = fixed_local_offset
        .or_else(|| UtcOffset::local_offset_at(fetched_at.as_offset_date_time()).ok())
        .unwrap_or(UtcOffset::UTC);
    let local_now = fetched_at.as_offset_date_time().to_offset(fallback_offset);
    let current = Date::from_calendar_date(local_now.year(), month, day).ok()?;
    let current_reset = local_midnight(current, fetched_at, fixed_local_offset)?;
    if current_reset.as_offset_date_time() > fetched_at.as_offset_date_time() {
        return Some(current_reset);
    }
    let next = Date::from_calendar_date(local_now.year().checked_add(1)?, month, day).ok()?;
    local_midnight(next, fetched_at, fixed_local_offset)
}

fn local_midnight(
    date: Date,
    fetched_at: Timestamp,
    fixed_local_offset: Option<UtcOffset>,
) -> Option<Timestamp> {
    let wall = date.with_time(Time::MIDNIGHT);
    if let Some(offset) = fixed_local_offset {
        return Timestamp::new(wall.assume_offset(offset)).ok();
    }
    let mut offset =
        UtcOffset::local_offset_at(fetched_at.as_offset_date_time()).unwrap_or(UtcOffset::UTC);
    for _ in 0..4 {
        let candidate = wall.assume_offset(offset);
        let observed = UtcOffset::local_offset_at(candidate).unwrap_or(offset);
        if observed == offset {
            return Timestamp::new(candidate).ok();
        }
        offset = observed;
    }
    None
}

fn strip_ansi(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != 0x1b {
            output.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        match bytes.get(index).copied() {
            Some(b'[') => {
                index += 1;
                while index < bytes.len() {
                    let byte = bytes[index];
                    index += 1;
                    if (0x40..=0x7e).contains(&byte) {
                        break;
                    }
                }
            }
            Some(b']') => {
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == 0x07 {
                        index += 1;
                        break;
                    }
                    if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'\\') {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            Some(_) => index += 1,
            None => {}
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn clean_inline(text: &str) -> String {
    strip_ansi(text)
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>()
        .trim()
        .to_owned()
}

fn ascii_find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

/// Parses and validates one bounded `GetUsageLimits` response.
///
/// # Errors
///
/// Rejects malformed numeric types, ambiguous credit rows, impossible
/// plan/overage relationships, excessive arrays, and implausible resets.
pub fn parse_usage_limits(body: &[u8]) -> Result<KiroUsageLimits, ClassifiedError> {
    let response: UsageLimitsResponse =
        serde_json::from_slice(body).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    if response.usage_breakdown_list.len() > MAX_API_ROWS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let mut credits = response
        .usage_breakdown_list
        .into_iter()
        .filter(|row| row.resource_type == "CREDIT");
    let credit = credits
        .next()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    if credits.next().is_some() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let plan_limit = non_negative_decimal(credit.usage_limit_with_precision.0)?;
    let total_used = non_negative_decimal(credit.current_usage_with_precision.0)?;
    let overage_used = non_negative_decimal(
        credit
            .current_overages_with_precision
            .map_or(Decimal::ZERO, |value| value.0),
    )?;
    if total_used < overage_used {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let plan_used = total_used - overage_used;
    let bonuses = credit.bonuses.unwrap_or_default();
    if bonuses.len() > MAX_BONUS_ROWS {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let has_unseparated_bonus = !bonuses.is_empty();
    if !has_unseparated_bonus && plan_used > plan_limit {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let availability = match response
        .overage_configuration
        .as_ref()
        .map(|configuration| configuration.overage_status.as_str())
    {
        Some(status) if status.eq_ignore_ascii_case("ENABLED") => Some(true),
        Some(status) if status.eq_ignore_ascii_case("DISABLED") => Some(false),
        _ => None,
    };
    let overage_cap = if availability == Some(true) {
        credit
            .overage_cap_with_precision
            .map(|value| non_negative_decimal(value.0))
            .transpose()?
    } else {
        None
    };
    let overage_enabled = if availability == Some(true) && overage_cap.is_none() {
        None
    } else {
        availability
    };
    let reset = credit.next_date_reset.or(response.next_date_reset);
    let resets_at = reset
        .and_then(|value| decimal_unix_seconds(value.0))
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))?;
    let maximum = Decimal::from(1_000_000_000_000_000_i64);
    let overage_charges = credit
        .overage_charges
        .map(|value| value.0)
        .filter(|value| (Decimal::ZERO..=maximum).contains(value));
    let overage_rate = credit
        .overage_rate
        .map(|value| value.0)
        .filter(|value| *value > Decimal::ZERO && *value <= maximum);
    let currency_code = CurrencyCode::new(credit.currency.as_deref().unwrap_or("USD"))
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?
        .as_str()
        .to_owned();
    Ok(KiroUsageLimits {
        plan_limit,
        plan_used,
        overage_used,
        overage_cap,
        overage_enabled,
        overage_charges,
        overage_rate,
        currency_code,
        resets_at,
        has_unseparated_bonus,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageLimitsResponse {
    usage_breakdown_list: Vec<UsageBreakdown>,
    overage_configuration: Option<OverageConfiguration>,
    next_date_reset: Option<JsonDecimal>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageBreakdown {
    resource_type: String,
    current_usage_with_precision: JsonDecimal,
    usage_limit_with_precision: JsonDecimal,
    current_overages_with_precision: Option<JsonDecimal>,
    overage_cap_with_precision: Option<JsonDecimal>,
    overage_charges: Option<JsonDecimal>,
    overage_rate: Option<JsonDecimal>,
    currency: Option<String>,
    next_date_reset: Option<JsonDecimal>,
    bonuses: Option<Vec<IgnoredAny>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OverageConfiguration {
    overage_status: String,
}

#[derive(Clone, Copy)]
struct JsonDecimal(Decimal);

impl<'de> Deserialize<'de> for JsonDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let number = serde_json::Number::deserialize(deserializer)?;
        let raw = number.to_string();
        Decimal::from_scientific(&raw)
            .or_else(|_| Decimal::from_str(&raw))
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid decimal"))
    }
}

fn non_negative_decimal(value: Decimal) -> Result<Decimal, ClassifiedError> {
    (value >= Decimal::ZERO && value <= Decimal::from(1_000_000_000_000_000_i64))
        .then_some(value)
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

fn decimal_unix_seconds(value: Decimal) -> Option<Timestamp> {
    if !value.fract().is_zero() {
        return None;
    }
    let seconds = value.to_i64()?;
    (RESET_MIN..=RESET_MAX)
        .contains(&seconds)
        .then(|| Timestamp::from_unix_timestamp(seconds).ok())?
}

fn normalize_report(
    scope: AccountScope,
    fetched_at: Timestamp,
    report: &mut KiroUsageReport,
    limits: Option<&KiroUsageLimits>,
) -> Result<UsageSample, ClassifiedError> {
    if let Some(limits) = limits {
        if !limits.has_unseparated_bonus {
            report.credits_used = decimal_f64(limits.plan_used)?;
            report.credits_total = decimal_f64(limits.plan_limit)?;
            report.credits_percent = if limits.plan_limit > Decimal::ZERO {
                decimal_f64(limits.plan_used / limits.plan_limit * Decimal::from(100_u8))?
            } else {
                report.credits_percent
            };
        }
        report.resets_at = Some(limits.resets_at);
        report.overage_used = Some(decimal_f64(limits.overage_used)?);
        if limits.overage_enabled == Some(false) {
            report.overage_status = Some("Disabled".to_owned());
        } else if limits.overage_enabled == Some(true) && report.overage_status.is_none() {
            report.overage_status = Some("Enabled".to_owned());
        }
        report.estimated_overage_cost_usd = limits
            .overage_charges
            .map(decimal_f64)
            .transpose()?
            .or((limits.currency_code.eq_ignore_ascii_case("USD"))
                .then_some(report.estimated_overage_cost_usd)
                .flatten());
    }

    let primary = rate_window(report.credits_percent, report.resets_at, None)?;
    let mut builder = UsageSampleBuilder::new(scope, fetched_at)
        .primary(primary)
        .email(report.account_email.clone())?
        .organization(Some(report.display_plan_name.clone()))?
        .login_method(report.auth_method.clone())?;

    if let (Some(used), Some(total)) = (report.bonus_used, report.bonus_total)
        && total > 0.0
    {
        let expiry = report
            .bonus_expiry_days
            .filter(|days| *days <= MAX_BONUS_EXPIRY_DAYS)
            .and_then(|days| i64::from(days).checked_mul(86_400))
            .and_then(|seconds| {
                fetched_at
                    .as_offset_date_time()
                    .checked_add(TimeDuration::seconds(seconds))
            })
            .and_then(|value| Timestamp::new(value).ok());
        let description = report
            .bonus_expiry_days
            .map(|days| format!("expires in {days}d"));
        builder = builder.secondary(rate_window(used / total * 100.0, expiry, description)?);
    }

    let mut extras = Vec::new();
    if let Some(limits) = limits
        && let Some(cap) = limits.overage_cap
        && cap > Decimal::ZERO
    {
        let used_percent =
            (limits.overage_used / cap * Decimal::from(100_u8)).min(Decimal::from(100_u8));
        extras.push(NamedRateWindow::new(
            BoundedText::new("kiro-overage").map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            BoundedText::new("Overage").map_err(|_| ClassifiedError::new(ErrorKind::Api))?,
            rate_window(decimal_f64(used_percent)?, Some(limits.resets_at), None)?,
        ));
    }
    builder = builder.extra_windows(extras);

    if let Some(limits) = limits
        && let (Some(charges), Some(charge_limit)) =
            (limits.overage_charges, limits.overage_charge_limit())
    {
        let currency = CurrencyCode::new(&limits.currency_code)
            .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        let cost = CostSummary::new(
            CostAmount::money(ExactDecimal::new(charges), currency),
            ExactDecimal::new(charge_limit),
            Some("Overage".to_owned()),
            Some(limits.resets_at),
            None,
            None,
            None,
            fetched_at,
            None,
            None,
            CostProvenance::VendorMetered,
        )
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
        builder = builder.cost(cost);
    }

    let details = detail_section(report, limits)?;
    builder
        .detail_sections(vec![details])
        .provenance("kiro", "cli")?
        .build()
}

fn rate_window(
    percent: f64,
    reset: Option<Timestamp>,
    description: Option<String>,
) -> Result<RateWindow, ClassifiedError> {
    let description = description
        .map(BoundedText::new)
        .transpose()
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    RateWindow::new(
        WindowUsage::known(
            UsagePercent::new(percent).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?,
        ),
        None,
        reset,
        description,
        None,
        false,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn detail_section(
    report: &KiroUsageReport,
    limits: Option<&KiroUsageLimits>,
) -> Result<DetailSection, ClassifiedError> {
    let remaining = (report.credits_total - report.credits_used).max(0.0);
    let mut rows = vec![
        detail_row("Plan", report.display_plan_name.clone(), None)?,
        detail_row("Credits left", format_credit(remaining), None)?,
        detail_row("Credits used", format_credit(report.credits_used), None)?,
        detail_row("Credits total", format_credit(report.credits_total), None)?,
    ];
    if let (Some(used), Some(total)) = (report.bonus_used, report.bonus_total) {
        let secondary = Some(
            [
                Some(format!("of {}", format_credit(total))),
                report
                    .bonus_expiry_days
                    .map(|days| format!("expires in {days}d")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · "),
        );
        rows.push(detail_row(
            "Bonus credits left",
            format_credit((total - used).max(0.0)),
            secondary,
        )?);
    }
    if let Some(status) = &report.overage_status {
        rows.push(detail_row("Overages", status.clone(), None)?);
    }
    let overage_enabled = limits.map_or_else(
        || status_is_enabled(report.overage_status.as_deref()),
        |limits| {
            limits.overage_enabled.map_or_else(
                || status_is_enabled(report.overage_status.as_deref()),
                |enabled| enabled && limits.overage_cap.is_some(),
            )
        },
    );
    if overage_enabled && let Some(used) = report.overage_used {
        let cap = limits.and_then(|limits| limits.overage_cap);
        rows.push(detail_row(
            "Overage usage",
            format!("{} credits", format_credit(used)),
            cap.map(|cap| format!("of {}", format_credit(decimal_f64(cap).unwrap_or(0.0)))),
        )?);
        if let Some(cap) = cap {
            rows.push(detail_row(
                "Overage credits left",
                format_credit((decimal_f64(cap)? - used).max(0.0)),
                None,
            )?);
        }
    }
    if overage_enabled && let Some(cost) = report.estimated_overage_cost_usd {
        let currency = limits.map_or("USD", |limits| limits.currency_code.as_str());
        let secondary = limits
            .and_then(KiroUsageLimits::overage_charge_limit)
            .map(|limit| format!("of {currency} {limit:.2}"));
        rows.push(detail_row(
            "Overage cost",
            format!("{currency} {cost:.2}"),
            secondary,
        )?);
    }
    if let Some(context) = report.context {
        rows.push(detail_row(
            "Context used",
            format!("{:.1}%", context.total),
            None,
        )?);
        for (label, value) in [
            ("Context files", context.context_files),
            ("Tools", context.tools),
            ("Kiro responses", context.responses),
            ("Prompts", context.prompts),
        ] {
            if let Some(value) = value {
                rows.push(detail_row(label, format!("{value:.1}%"), None)?);
            }
        }
    }
    if let Some(url) = &report.manage_url {
        rows.push(detail_row("Manage", url.clone(), None)?);
    }
    DetailSection::new(Some("Usage".to_owned()), rows, None)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn detail_row(
    label: &str,
    value: String,
    secondary: Option<String>,
) -> Result<DetailRow, ClassifiedError> {
    DetailRow::new(label, value, secondary, DetailSensitivity::Public)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))
}

fn status_is_enabled(status: Option<&str>) -> bool {
    status.is_some_and(|status| status.trim().to_ascii_lowercase().starts_with("enabled"))
}

fn format_credit(value: f64) -> String {
    let value = format!("{value:.2}");
    value.trim_end_matches('0').trim_end_matches('.').to_owned()
}

fn decimal_f64(value: Decimal) -> Result<f64, ClassifiedError> {
    value
        .to_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| ClassifiedError::new(ErrorKind::Parse))
}

struct KiroCliIdentity {
    access_token: Zeroizing<String>,
    profile_arn: Zeroizing<String>,
}

#[derive(Deserialize)]
struct StoredToken {
    access_token: ZeroizingSecret,
}

struct ZeroizingSecret(Zeroizing<String>);

impl ZeroizingSecret {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn into_zeroizing(mut self) -> Zeroizing<String> {
        std::mem::take(&mut self.0)
    }
}

impl<'de> Deserialize<'de> for ZeroizingSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecretVisitor;

        impl serde::de::Visitor<'_> for SecretVisitor {
            type Value = ZeroizingSecret;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("a secret string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ZeroizingSecret(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(SecretVisitor)
    }
}

impl Drop for ZeroizingSecret {
    fn drop(&mut self) {
        #[cfg(test)]
        SECRET_WRAPPER_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
static SECRET_WRAPPER_DROPS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[derive(Deserialize)]
struct StoredProfile {
    arn: String,
}

async fn read_cli_identity(
    settings: &KiroCliSettings,
    cancellation: &CancellationToken,
) -> Result<KiroCliIdentity, ClassifiedError> {
    let database = settings
        .state_database
        .as_ref()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if !state_database_allowed(database, settings.allow_live_state_in_debug) {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let sqlite = settings
        .sqlite
        .as_ref()
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let metadata =
        fs::metadata(database).map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
    if !metadata.is_file() || metadata.len() > MAX_STATE_DATABASE_BYTES {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    let request = SubprocessRequest::new(
        sqlite.as_path(),
        [
            OsString::from("-readonly"),
            OsString::from("-batch"),
            OsString::from("-noheader"),
            database.as_os_str().to_owned(),
            OsString::from(SQLITE_QUERY),
        ],
        Duration::from_secs(2),
        SQLITE_OUTPUT_BYTES,
        32 * 1024,
    )
    .map_err(classify_subprocess)?
    .with_cleared_environment()
    .with_environment("LC_ALL", "C")
    .map_err(classify_subprocess)?;
    let output = request
        .run(cancellation)
        .await
        .map_err(classify_subprocess)?;
    parse_identity_rows(output.stdout())
}

fn parse_identity_rows(output: &[u8]) -> Result<KiroCliIdentity, ClassifiedError> {
    let text = std::str::from_utf8(output).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let mut token_json = None;
    let mut profile_json = None;
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix('T') {
            if token_json.is_some() {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            token_json = Some(decode_hex(hex)?);
        } else if let Some(hex) = line.strip_prefix('P') {
            if profile_json.is_some() {
                return Err(ClassifiedError::new(ErrorKind::Parse));
            }
            profile_json = Some(decode_hex(hex)?);
        } else if !line.trim().is_empty() {
            return Err(ClassifiedError::new(ErrorKind::Parse));
        }
    }
    let token_json =
        token_json.ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let profile_json =
        profile_json.ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let token: StoredToken =
        serde_json::from_slice(&token_json).map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    let profile: StoredProfile = serde_json::from_slice(&profile_json)
        .map_err(|_| ClassifiedError::new(ErrorKind::Parse))?;
    validate_secret(token.access_token.as_str(), MAX_ACCESS_TOKEN_BYTES)?;
    validate_secret(&profile.arn, MAX_PROFILE_ARN_BYTES)?;
    Ok(KiroCliIdentity {
        access_token: token.access_token.into_zeroizing(),
        profile_arn: Zeroizing::new(profile.arn),
    })
}

fn decode_hex(value: &str) -> Result<Zeroizing<Vec<u8>>, ClassifiedError> {
    if value.len() > MAX_JSON_VALUE_BYTES * 2 || !value.len().is_multiple_of(2) {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ClassifiedError::new(ErrorKind::Parse));
    }
    pairs
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok(high << 4 | low)
        })
        .collect::<Result<Vec<_>, ClassifiedError>>()
        .map(Zeroizing::new)
}

fn hex_digit(value: u8) -> Result<u8, ClassifiedError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ClassifiedError::new(ErrorKind::Parse)),
    }
}

fn validate_secret(value: &str, maximum: usize) -> Result<(), ClassifiedError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ClassifiedError::new(ErrorKind::MissingCredential));
    }
    Ok(())
}

fn resolve_kiro_cli(
    environment: &BTreeMap<String, String>,
) -> Result<ExecutablePath, ClassifiedError> {
    let configured = clean_environment(environment, CLI_OVERRIDE);
    let path = environment.get("PATH").map(String::as_str);
    let mut fallbacks = Vec::new();
    if let Some(home) = clean_environment(environment, "HOME")
        && let Ok(home) = validate_absolute_path(Path::new(home))
    {
        fallbacks.push(home.join(".local/bin/kiro-cli"));
    }
    fallbacks.extend([
        PathBuf::from("/usr/local/bin/kiro-cli"),
        PathBuf::from("/usr/bin/kiro-cli"),
    ]);
    resolve_executable(
        "kiro-cli",
        configured,
        path.map(std::ffi::OsStr::new),
        &fallbacks,
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))?
    .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))
}

fn resolve_sqlite(
    environment: &BTreeMap<String, String>,
) -> Result<Option<ExecutablePath>, ClassifiedError> {
    let path = environment.get("PATH").map(String::as_str);
    resolve_executable(
        "sqlite3",
        None,
        path.map(std::ffi::OsStr::new),
        &[
            PathBuf::from("/usr/bin/sqlite3"),
            PathBuf::from("/usr/local/bin/sqlite3"),
        ],
    )
    .map_err(|_| ClassifiedError::new(ErrorKind::Api))
}

fn state_database_path(environment: &BTreeMap<String, String>) -> Result<PathBuf, ClassifiedError> {
    if let Some(directory) = clean_environment(environment, DATA_DIR_OVERRIDE) {
        let path = expand_home_path(directory, environment)?.join("data.sqlite3");
        return validate_absolute_path(&path).map(Path::to_path_buf);
    }
    if let Some(directory) = clean_environment(environment, "XDG_DATA_HOME") {
        let path = expand_home_path(directory, environment)?.join("kiro-cli/data.sqlite3");
        return validate_absolute_path(&path).map(Path::to_path_buf);
    }
    let home = clean_environment(environment, "HOME")
        .ok_or_else(|| ClassifiedError::new(ErrorKind::MissingCredential))?;
    let path = expand_home_path(home, environment)?.join(".local/share/kiro-cli/data.sqlite3");
    validate_absolute_path(&path).map(Path::to_path_buf)
}

fn debug_live_state_opted_in(environment: &BTreeMap<String, String>) -> bool {
    clean_environment(environment, DEBUG_LIVE_STATE_OPT_IN) == Some("1")
}

fn state_database_allowed(path: &Path, opted_in: bool) -> bool {
    let Ok(environment) = process_state_environment() else {
        return opted_in || !live_state_guard_enabled();
    };
    state_database_allowed_with_environment(
        path,
        opted_in,
        live_state_guard_enabled(),
        &environment,
    )
}

fn state_database_allowed_with_environment(
    path: &Path,
    opted_in: bool,
    guard_enabled: bool,
    process_environment: &BTreeMap<String, String>,
) -> bool {
    opted_in
        || !guard_enabled
        || state_database_path(process_environment)
            .is_ok_and(|live| !paths_equivalent_without_opening(path, &live))
}

fn live_state_guard_enabled() -> bool {
    cfg!(debug_assertions)
        || cfg!(test)
        || std::env::var(TEST_HARNESS_GUARD).as_deref() == Ok("1")
        || std::env::current_exe().is_ok_and(|executable| is_test_harness_executable(&executable))
}

fn is_test_harness_executable(executable: &Path) -> bool {
    executable.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("deps"))
}

fn process_state_environment() -> Result<BTreeMap<String, String>, ClassifiedError> {
    let mut environment = BTreeMap::new();
    for name in [DATA_DIR_OVERRIDE, "XDG_DATA_HOME", "HOME"] {
        if let Some(value) = std::env::var_os(name) {
            let value = value
                .into_string()
                .map_err(|_| ClassifiedError::new(ErrorKind::MissingCredential))?;
            environment.insert(name.to_owned(), value);
        }
    }
    Ok(environment)
}

fn paths_equivalent_without_opening(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    if fs::canonicalize(left)
        .ok()
        .zip(fs::canonicalize(right).ok())
        .is_some_and(|(canonical_left, canonical_right)| canonical_left == canonical_right)
    {
        return true;
    }
    let canonical_parent = |path: &Path| {
        let parent = fs::canonicalize(path.parent()?).ok()?;
        Some(parent.join(path.file_name()?))
    };
    canonical_parent(left)
        .zip(canonical_parent(right))
        .is_some_and(|(canonical_left, canonical_right)| canonical_left == canonical_right)
}

fn expand_home_path(
    value: &str,
    environment: &BTreeMap<String, String>,
) -> Result<PathBuf, ClassifiedError> {
    let path = if let Some(rest) = value.strip_prefix("~/") {
        let home = clean_environment(environment, "HOME")
            .ok_or_else(|| ClassifiedError::new(ErrorKind::Api))?;
        Path::new(home).join(rest)
    } else {
        PathBuf::from(value)
    };
    validate_absolute_path(&path).map(Path::to_path_buf)
}

fn validate_absolute_path(path: &Path) -> Result<&Path, ClassifiedError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute() || bytes.is_empty() || bytes.len() > 4 * 1024 || bytes.contains(&0) {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(path)
}

fn sanitized_environment(
    environment: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, ClassifiedError> {
    let mut result = Vec::new();
    for name in CLI_ENVIRONMENT_NAMES {
        if let Some(value) = environment.get(name) {
            if value.len() > MAX_CLI_ENVIRONMENT_VALUE_BYTES || value.contains('\0') {
                return Err(ClassifiedError::new(ErrorKind::Api));
            }
            result.push((name.to_owned(), value.clone()));
        }
    }
    Ok(result)
}

fn clean_environment<'a>(environment: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    environment.get(name).map(String::as_str).and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })
}

fn validate_scope(scope: &AccountScope) -> Result<(), ClassifiedError> {
    if scope.provider() != ProviderId::Kiro {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn validate_endpoint(endpoint: &Url) -> Result<(), ClassifiedError> {
    let loopback = matches!(endpoint.scheme(), "http" | "https")
        && endpoint.host().is_some_and(|host| match host {
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
            url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        });
    let production = endpoint.as_str() == DEFAULT_ENDPOINT;
    if endpoint.cannot_be_a_base()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || (!production && !loopback)
    {
        return Err(ClassifiedError::new(ErrorKind::Api));
    }
    Ok(())
}

fn transport_config() -> Result<TransportConfig, ClassifiedError> {
    TransportConfig::new(
        Duration::from_secs(5),
        Duration::from_secs(10),
        2 * 1024 * 1024,
        0,
        RetryPolicy::none(),
    )
    .map_err(|error| error.classified())
}

#[cfg(test)]
mod internal_tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn malformed_trailing_token_drops_zeroizing_wrapper() {
        let before = SECRET_WRAPPER_DROPS.load(Ordering::Relaxed);
        let result = serde_json::from_slice::<StoredToken>(
            br#"{"access_token":"zeroize-this-fixture"} trailing"#,
        );

        assert!(result.is_err());
        assert_eq!(
            SECRET_WRAPPER_DROPS.load(Ordering::Relaxed),
            before + 1,
            "the custom secret wrapper must be dropped on trailing JSON errors"
        );
    }

    #[test]
    fn live_state_guard_follows_process_override_precedence() {
        let mut process_environment = BTreeMap::from([
            ("HOME".to_owned(), "/fixture/process-home".to_owned()),
            (
                "XDG_DATA_HOME".to_owned(),
                "/fixture/process-xdg".to_owned(),
            ),
            (
                DATA_DIR_OVERRIDE.to_owned(),
                "/fixture/process-kiro".to_owned(),
            ),
        ]);
        let kiro_override = Path::new("/fixture/process-kiro/data.sqlite3");
        assert!(!state_database_allowed_with_environment(
            kiro_override,
            false,
            true,
            &process_environment,
        ));
        assert!(state_database_allowed_with_environment(
            Path::new("/fixture/process-xdg/kiro-cli/data.sqlite3"),
            false,
            true,
            &process_environment,
        ));

        process_environment.remove(DATA_DIR_OVERRIDE);
        let xdg_override = Path::new("/fixture/process-xdg/kiro-cli/data.sqlite3");
        assert!(!state_database_allowed_with_environment(
            xdg_override,
            false,
            true,
            &process_environment,
        ));

        process_environment.remove("XDG_DATA_HOME");
        let home_default = Path::new("/fixture/process-home/.local/share/kiro-cli/data.sqlite3");
        assert!(!state_database_allowed_with_environment(
            home_default,
            false,
            true,
            &process_environment,
        ));
        assert!(state_database_allowed_with_environment(
            home_default,
            true,
            true,
            &process_environment,
        ));
    }

    #[test]
    fn release_test_harness_path_enables_guard_without_debug_assertions() {
        assert!(is_test_harness_executable(Path::new(
            "/workspace/target/release/deps/provider_kiro-deadbeef",
        )));
        assert!(!is_test_harness_executable(Path::new(
            "/usr/bin/omarchy-ai-bar",
        )));
    }

    #[test]
    fn remembered_descendants_are_hard_capped_and_fail_closed() {
        let slot = ReaperSlot::reserve().expect("reaper slot");
        let mut guard = ProcCleanupGuard {
            root: None,
            process_group: -1,
            known_descendants: BTreeSet::new(),
            group_scan_indeterminate: false,
            identities: Vec::new(),
            anchors: Vec::new(),
            scan_config: ProcScanConfig::default(),
            reaper_slot: Some(slot),
            armed: true,
        };
        guard.remember_descendants((0..=MAX_PROC_ENTRIES).map(|value| ProcTarget {
            pid: i32::try_from(value + 1).expect("bounded fixture PID"),
            start_time: 1,
        }));

        assert_eq!(guard.known_descendants.len(), MAX_PROC_ENTRIES);
        assert!(guard.group_scan_indeterminate);
        guard.disarm();
    }

    #[tokio::test]
    async fn indeterminate_cleanup_transfers_armed_responsibility() {
        let before_handoffs = REAPER_HANDOFFS.load(Ordering::Relaxed);
        let before_completions = REAPER_COMPLETIONS.load(Ordering::Relaxed);
        let slot = ReaperSlot::reserve().expect("reaper slot");
        let mut command = Command::new("/usr/bin/sleep");
        command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = command.spawn().expect("fixture child");
        let config = ProcScanConfig {
            force_indeterminate: true,
            cleanup_timeout: Duration::from_millis(500),
        };
        let mut guard = ProcCleanupGuard::new(child.id(), Vec::new(), Vec::new(), config, slot)
            .expect("cleanup guard");

        let error = cleanup_process(&mut child, &mut guard, false)
            .await
            .expect_err("indeterminate scan must fail closed");

        assert_eq!(error.kind(), ErrorKind::ProviderUnavailable);
        assert!(!guard.armed, "responsibility must move out of the caller");
        assert!(
            REAPER_HANDOFFS.load(Ordering::Relaxed) > before_handoffs,
            "the armed responsibility was not accepted by the supervisor"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while REAPER_COMPLETIONS.load(Ordering::Relaxed) <= before_completions {
            assert!(
                tokio::time::Instant::now() < deadline,
                "supervisor did not prove cleanup complete"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
