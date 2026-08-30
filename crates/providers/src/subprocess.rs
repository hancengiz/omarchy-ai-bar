//! Bounded, shell-free subprocess execution for provider helpers.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::Pid;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const MAX_EXECUTABLE_BYTES: usize = 4 * 1024;
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_TOTAL_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_CHANGES: usize = 64;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 256;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_ENVIRONMENT_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STDERR_CLASSIFIER_RULES: usize = 16;
const MAX_STDERR_NEEDLE_BYTES: usize = 256;
const MAX_TOTAL_STDERR_NEEDLE_BYTES: usize = 2 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_mins(5);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// Safe subprocess construction and execution failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SubprocessError {
    /// An executable, argument, environment, deadline, or output limit was invalid.
    #[error("subprocess configuration is invalid")]
    InvalidConfiguration,
    /// The operating system could not start the configured executable.
    #[error("subprocess could not be started")]
    Spawn,
    /// The child status could not be collected.
    #[error("subprocess status could not be collected")]
    Wait,
    /// A captured output stream could not be read.
    #[error("subprocess output could not be read")]
    OutputRead,
    /// Cooperative cancellation won the execution race.
    #[error("subprocess was cancelled")]
    Cancelled,
    /// The configured execution deadline elapsed.
    #[error("subprocess timed out")]
    Timeout,
    /// Standard output exceeded its explicit byte ceiling.
    #[error("subprocess standard output exceeded its size limit")]
    StdoutTooLarge,
    /// Standard error exceeded its explicit byte ceiling.
    #[error("subprocess standard error exceeded its size limit")]
    StderrTooLarge,
    /// The executable completed with an unsuccessful status.
    #[error("subprocess exited unsuccessfully (code: {code:?})")]
    NonZero {
        /// Numeric exit code, or `None` when the process ended by signal.
        code: Option<i32>,
        /// Safe caller-declared stderr classification tag, when matched.
        stderr_tag: Option<u8>,
    },
}

/// Successful bounded subprocess output.
#[derive(PartialEq, Eq)]
pub struct SubprocessOutput {
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

impl Debug for SubprocessOutput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubprocessOutput")
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish()
    }
}

impl SubprocessOutput {
    /// Returns the captured standard output bytes.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns the captured standard error bytes from a successful process.
    ///
    /// Some provider CLIs intentionally print their successful report to
    /// standard error. The bytes remain bounded, zeroized on drop, and absent
    /// from [`Debug`] output.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Consumes the result and returns its standard output bytes.
    #[must_use]
    pub fn into_stdout(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.stdout)
    }
}

struct StderrRule {
    tag: u8,
    needle: Zeroizing<Vec<u8>>,
}

/// Bounded, caller-declared classification of nonzero standard error.
pub struct StderrClassifier {
    rules: Vec<StderrRule>,
}

impl StderrClassifier {
    /// Builds an ordered ASCII-case-insensitive classifier.
    ///
    /// The first declared needle found in standard error wins. Needles are
    /// never included in [`Debug`] output.
    ///
    /// # Errors
    ///
    /// Returns [`SubprocessError::InvalidConfiguration`] when there are more
    /// than 16 rules, a needle is empty, longer than 256 bytes, contains
    /// non-printable/non-ASCII bytes, or all needles exceed 2 KiB.
    pub fn ascii_case_insensitive<I, S>(rules: I) -> Result<Self, SubprocessError>
    where
        I: IntoIterator<Item = (u8, S)>,
        S: AsRef<str>,
    {
        let mut collected = Vec::new();
        let mut total_bytes = 0_usize;
        for (tag, needle) in rules {
            if collected.len() == MAX_STDERR_CLASSIFIER_RULES {
                return Err(SubprocessError::InvalidConfiguration);
            }
            let needle = needle.as_ref().as_bytes();
            if needle.is_empty()
                || needle.len() > MAX_STDERR_NEEDLE_BYTES
                || !needle
                    .iter()
                    .all(|byte| *byte == b' ' || byte.is_ascii_graphic())
            {
                return Err(SubprocessError::InvalidConfiguration);
            }
            total_bytes = total_bytes
                .checked_add(needle.len())
                .ok_or(SubprocessError::InvalidConfiguration)?;
            if total_bytes > MAX_TOTAL_STDERR_NEEDLE_BYTES {
                return Err(SubprocessError::InvalidConfiguration);
            }
            collected.push(StderrRule {
                tag,
                needle: Zeroizing::new(needle.to_vec()),
            });
        }
        Ok(Self { rules: collected })
    }

    fn classify(&self, stderr: &[u8]) -> Option<u8> {
        self.rules.iter().find_map(|rule| {
            stderr
                .windows(rule.needle.len())
                .any(|window| window.eq_ignore_ascii_case(&rule.needle))
                .then_some(rule.tag)
        })
    }
}

impl Debug for StderrClassifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let rules = self
            .rules
            .iter()
            .map(|rule| (rule.tag, rule.needle.len()))
            .collect::<Vec<_>>();
        formatter
            .debug_struct("StderrClassifier")
            .field("rules_as_tag_and_byte_count", &rules)
            .finish()
    }
}

struct EnvironmentValue(OsString);

impl Debug for EnvironmentValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

enum EnvironmentChange {
    Set {
        name: OsString,
        value: EnvironmentValue,
    },
    Remove {
        name: OsString,
    },
}

impl EnvironmentChange {
    fn name(&self) -> &OsStr {
        match self {
            Self::Set { name, .. } | Self::Remove { name } => name,
        }
    }
}

impl Debug for EnvironmentChange {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set { name, value } => formatter
                .debug_struct("Set")
                .field("name", name)
                .field("value", value)
                .finish(),
            Self::Remove { name } => formatter.debug_tuple("Remove").field(name).finish(),
        }
    }
}

/// A validated, shell-free subprocess invocation with explicit resource bounds.
pub struct SubprocessRequest {
    executable: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<EnvironmentChange>,
    stderr_classifier: Option<StderrClassifier>,
    clear_environment: bool,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl Debug for SubprocessRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubprocessRequest")
            .field("executable", &"<redacted>")
            .field("argument_count", &self.arguments.len())
            .field("environment_change_count", &self.environment.len())
            .field("stderr_classifier", &self.stderr_classifier)
            .field("clear_environment", &self.clear_environment)
            .field("timeout", &self.timeout)
            .field("max_stdout_bytes", &self.max_stdout_bytes)
            .field("max_stderr_bytes", &self.max_stderr_bytes)
            .finish()
    }
}

impl SubprocessRequest {
    /// Creates a bounded invocation of the exact absolute executable path and
    /// argument vector.
    ///
    /// The executable is passed directly to the operating system. No shell is
    /// inserted and no argument interpolation is performed.
    ///
    /// # Errors
    ///
    /// Returns [`SubprocessError::InvalidConfiguration`] when the executable,
    /// arguments, deadline, or output limits exceed the hard safety ceilings.
    pub fn new<I, S>(
        executable: impl Into<PathBuf>,
        arguments: I,
        timeout: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, SubprocessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let executable = executable.into();
        let arguments = collect_arguments(arguments)?;
        validate_invocation(
            &executable,
            &arguments,
            timeout,
            max_stdout_bytes,
            max_stderr_bytes,
        )?;

        Ok(Self {
            executable,
            arguments,
            environment: Vec::new(),
            stderr_classifier: None,
            clear_environment: false,
            timeout,
            max_stdout_bytes,
            max_stderr_bytes,
        })
    }

    /// Starts the child with an empty environment before applying explicit changes.
    #[must_use]
    pub const fn with_cleared_environment(mut self) -> Self {
        self.clear_environment = true;
        self
    }

    /// Attaches safe classification rules for unsuccessful standard error.
    #[must_use]
    pub fn with_stderr_classifier(mut self, classifier: StderrClassifier) -> Self {
        self.stderr_classifier = Some(classifier);
        self
    }

    /// Sets one environment variable without exposing its value through [`Debug`].
    ///
    /// Repeated changes to the same name replace the earlier change.
    ///
    /// # Errors
    ///
    /// Returns [`SubprocessError::InvalidConfiguration`] for invalid names,
    /// values, counts, or aggregate environment size.
    pub fn with_environment(
        mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Result<Self, SubprocessError> {
        let change = EnvironmentChange::Set {
            name: name.into(),
            value: EnvironmentValue(value.into()),
        };
        self.replace_environment_change(change)?;
        Ok(self)
    }

    /// Removes one inherited environment variable from the child.
    ///
    /// Repeated changes to the same name replace the earlier change.
    ///
    /// # Errors
    ///
    /// Returns [`SubprocessError::InvalidConfiguration`] for invalid names,
    /// counts, or aggregate environment size.
    pub fn without_environment(
        mut self,
        name: impl Into<OsString>,
    ) -> Result<Self, SubprocessError> {
        let change = EnvironmentChange::Remove { name: name.into() };
        self.replace_environment_change(change)?;
        Ok(self)
    }

    /// Runs the configured executable until completion, cancellation, or timeout.
    ///
    /// Standard input is always closed. Standard output and standard error are
    /// drained concurrently. Both bounded streams are returned on success;
    /// raw standard error is never included in failures.
    ///
    /// # Errors
    ///
    /// Returns a stable [`SubprocessError`] for spawn/read/wait failures,
    /// cancellation, timeout, oversized output, or an unsuccessful exit status.
    pub async fn run(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SubprocessOutput, SubprocessError> {
        if cancellation.is_cancelled() {
            return Err(SubprocessError::Cancelled);
        }

        let mut command = Command::new(&self.executable);
        command
            .args(&self.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);

        if self.clear_environment {
            command.env_clear();
        }
        for change in &self.environment {
            match change {
                EnvironmentChange::Set { name, value } => {
                    command.env(name, &value.0);
                }
                EnvironmentChange::Remove { name } => {
                    command.env_remove(name);
                }
            }
        }

        let mut child = command.spawn().map_err(|_| SubprocessError::Spawn)?;
        let mut group = ProcessGroupGuard::new(child.id());
        let Some(stdout) = child.stdout.take() else {
            terminate(&mut child, &mut group).await;
            return Err(SubprocessError::Spawn);
        };
        let Some(stderr) = child.stderr.take() else {
            terminate(&mut child, &mut group).await;
            return Err(SubprocessError::Spawn);
        };

        let stdout_read = read_bounded(stdout, self.max_stdout_bytes);
        let stderr_read = read_bounded(stderr, self.max_stderr_bytes);
        let deadline = tokio::time::sleep(self.timeout);
        tokio::pin!(stdout_read, stderr_read, deadline);

        let mut stdout_result: Option<Zeroizing<Vec<u8>>> = None;
        let mut stderr_result: Option<Zeroizing<Vec<u8>>> = None;
        let mut status = None;

        loop {
            if stderr_result.is_some()
                && status.is_some()
                && let Some(stdout) = stdout_result.take()
                && let Some(stderr) = stderr_result.take()
                && let Some(completed_status) = status.take()
            {
                group.disarm();
                return finish(
                    completed_status,
                    stdout,
                    stderr,
                    self.stderr_classifier.as_ref(),
                );
            }

            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    terminate(&mut child, &mut group).await;
                    return Err(SubprocessError::Cancelled);
                }
                () = &mut deadline => {
                    terminate(&mut child, &mut group).await;
                    return Err(SubprocessError::Timeout);
                }
                result = &mut stdout_read, if stdout_result.is_none() => {
                    match result {
                        Ok(stdout) => stdout_result = Some(stdout),
                        Err(ReadFailure::TooLarge) => {
                            terminate(&mut child, &mut group).await;
                            return Err(SubprocessError::StdoutTooLarge);
                        }
                        Err(ReadFailure::Io) => {
                            terminate(&mut child, &mut group).await;
                            return Err(SubprocessError::OutputRead);
                        }
                    }
                }
                result = &mut stderr_read, if stderr_result.is_none() => {
                    match result {
                        Ok(stderr) => stderr_result = Some(stderr),
                        Err(ReadFailure::TooLarge) => {
                            terminate(&mut child, &mut group).await;
                            return Err(SubprocessError::StderrTooLarge);
                        }
                        Err(ReadFailure::Io) => {
                            terminate(&mut child, &mut group).await;
                            return Err(SubprocessError::OutputRead);
                        }
                    }
                }
                result = child.wait(), if status.is_none() => {
                    status = Some(result.map_err(|_| SubprocessError::Wait)?);
                }
            }
        }
    }

    fn replace_environment_change(
        &mut self,
        change: EnvironmentChange,
    ) -> Result<(), SubprocessError> {
        validate_environment_change(&change)?;
        if let Some(existing) = self
            .environment
            .iter_mut()
            .find(|existing| existing.name() == change.name())
        {
            *existing = change;
        } else {
            self.environment.push(change);
        }
        validate_environment_set(&self.environment)
    }
}

fn collect_arguments<I, S>(arguments: I) -> Result<Vec<OsString>, SubprocessError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut collected = Vec::new();
    let mut total = 0_usize;
    for argument in arguments {
        if collected.len() == MAX_ARGUMENTS {
            return Err(SubprocessError::InvalidConfiguration);
        }
        let argument = argument.into();
        let bytes = argument.as_encoded_bytes();
        if bytes.len() > MAX_ARGUMENT_BYTES || bytes.contains(&0) {
            return Err(SubprocessError::InvalidConfiguration);
        }
        total = total
            .checked_add(bytes.len())
            .ok_or(SubprocessError::InvalidConfiguration)?;
        if total > MAX_TOTAL_ARGUMENT_BYTES {
            return Err(SubprocessError::InvalidConfiguration);
        }
        collected.push(argument);
    }
    Ok(collected)
}

fn validate_invocation(
    executable: &Path,
    arguments: &[OsString],
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> Result<(), SubprocessError> {
    let executable_bytes = executable.as_os_str().as_encoded_bytes();
    if !executable.is_absolute()
        || executable_bytes.is_empty()
        || executable_bytes.len() > MAX_EXECUTABLE_BYTES
        || executable_bytes.contains(&0)
        || arguments.len() > MAX_ARGUMENTS
        || timeout.is_zero()
        || timeout > MAX_TIMEOUT
        || max_stdout_bytes == 0
        || max_stdout_bytes > MAX_OUTPUT_BYTES
        || max_stderr_bytes == 0
        || max_stderr_bytes > MAX_OUTPUT_BYTES
    {
        return Err(SubprocessError::InvalidConfiguration);
    }

    Ok(())
}

fn validate_environment_change(change: &EnvironmentChange) -> Result<(), SubprocessError> {
    let name = change.name().as_encoded_bytes();
    if name.is_empty()
        || name.len() > MAX_ENVIRONMENT_NAME_BYTES
        || name.contains(&0)
        || name.contains(&b'=')
    {
        return Err(SubprocessError::InvalidConfiguration);
    }
    if let EnvironmentChange::Set { value, .. } = change {
        let value = value.0.as_encoded_bytes();
        if value.len() > MAX_ENVIRONMENT_VALUE_BYTES || value.contains(&0) {
            return Err(SubprocessError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn validate_environment_set(changes: &[EnvironmentChange]) -> Result<(), SubprocessError> {
    if changes.len() > MAX_ENVIRONMENT_CHANGES {
        return Err(SubprocessError::InvalidConfiguration);
    }
    let total = changes.iter().try_fold(0_usize, |total, change| {
        let value_bytes = match change {
            EnvironmentChange::Set { value, .. } => value.0.as_encoded_bytes().len(),
            EnvironmentChange::Remove { .. } => 0,
        };
        total
            .checked_add(change.name().as_encoded_bytes().len())
            .and_then(|total| total.checked_add(value_bytes))
    });
    if total.is_none_or(|total| total > MAX_TOTAL_ENVIRONMENT_BYTES) {
        return Err(SubprocessError::InvalidConfiguration);
    }
    Ok(())
}

fn finish(
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
    classifier: Option<&StderrClassifier>,
) -> Result<SubprocessOutput, SubprocessError> {
    if status.success() {
        Ok(SubprocessOutput { stdout, stderr })
    } else {
        Err(SubprocessError::NonZero {
            code: status.code(),
            stderr_tag: classifier.and_then(|classifier| classifier.classify(&stderr)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadFailure {
    Io,
    TooLarge,
}

async fn read_bounded<R>(mut reader: R, limit: usize) -> Result<Zeroizing<Vec<u8>>, ReadFailure>
where
    R: AsyncRead + Unpin,
{
    let mut output = Zeroizing::new(Vec::with_capacity(limit.min(8 * 1024)));
    let mut buffer = Zeroizing::new(vec![0_u8; 8 * 1024]);
    loop {
        let read = reader
            .read(buffer.as_mut_slice())
            .await
            .map_err(|_| ReadFailure::Io)?;
        if read == 0 {
            return Ok(output);
        }
        if read > limit.saturating_sub(output.len()) {
            return Err(ReadFailure::TooLarge);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

struct ProcessGroupGuard {
    #[cfg(unix)]
    process_group: Option<Pid>,
}

impl ProcessGroupGuard {
    fn new(process_id: Option<u32>) -> Self {
        #[cfg(unix)]
        let process_group = process_id
            .and_then(|process_id| i32::try_from(process_id).ok())
            .map(Pid::from_raw);
        #[cfg(not(unix))]
        let _ = process_id;
        Self {
            #[cfg(unix)]
            process_group,
        }
    }

    #[cfg(unix)]
    fn signal(&self, signal: Signal) {
        if let Some(process_group) = self.process_group {
            let _ = killpg(process_group, signal);
        }
    }

    fn kill(&self) {
        #[cfg(unix)]
        self.signal(Signal::SIGKILL);
    }

    fn disarm(&mut self) {
        #[cfg(unix)]
        {
            self.process_group = None;
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

async fn terminate(child: &mut Child, group: &mut ProcessGroupGuard) {
    #[cfg(unix)]
    group.signal(Signal::SIGTERM);
    let _ = tokio::time::timeout(TERMINATION_GRACE, child.wait()).await;
    group.kill();
    let _ = child.start_kill();
    let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await;
    group.disarm();
}
