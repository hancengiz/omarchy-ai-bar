//! Bounded newline-delimited JSON-RPC over a provider-owned child process.
//!
//! This transport deliberately owns only process and wire safety. Providers
//! remain responsible for executable discovery, initialization order, method
//! names, response schemas, and credential policy.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Formatter};
use std::process::Stdio;
use std::time::Duration;

#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::Pid;
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::executable::ExecutablePath;

const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_TOTAL_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_CHANGES: usize = 64;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 256;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_ENVIRONMENT_BYTES: usize = 256 * 1024;
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 1024 * 1024;
const MAX_METHOD_BYTES: usize = 256;
const MAX_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_SKIPPED_FRAMES: usize = 128;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 32 * 1024;
const MAX_JSON_STRING_BYTES: usize = 256 * 1024;
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// JSON-RPC envelope variant required by a provider CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonRpcVersion {
    /// Omit the `jsonrpc` member, as required by Codex app-server.
    Omitted,
    /// Send the standard `"jsonrpc":"2.0"` member, as required by Grok ACP.
    V2,
}

/// Stable, secret-free child transport failures.
#[derive(Error)]
pub enum JsonRpcChildError {
    /// An argument, environment change, bound, method, parameter, or timeout is invalid.
    #[error("JSON-RPC child configuration is invalid")]
    InvalidConfiguration,
    /// The operating system could not start the child.
    #[error("JSON-RPC child could not be started")]
    Spawn,
    /// The child standard-input stream could not accept a complete frame.
    #[error("JSON-RPC child standard input is closed")]
    StdinClosed,
    /// The child standard-output stream could not be read.
    #[error("JSON-RPC child standard output could not be read")]
    StdoutRead,
    /// The child standard-error stream could not be read safely.
    #[error("JSON-RPC child standard error could not be read")]
    StderrRead,
    /// Cooperative cancellation won the operation race.
    #[error("JSON-RPC child operation was cancelled")]
    Cancelled,
    /// The request or notification deadline elapsed.
    #[error("JSON-RPC child operation timed out")]
    Timeout,
    /// A single standard-output frame exceeded its configured byte ceiling.
    #[error("JSON-RPC child response exceeded its size limit")]
    StdoutTooLarge,
    /// Aggregate standard error exceeded its configured byte ceiling.
    #[error("JSON-RPC child standard error exceeded its size limit")]
    StderrTooLarge,
    /// Standard output closed before the matching response arrived.
    #[error("JSON-RPC child closed standard output")]
    Closed,
    /// A frame or response envelope violated the bounded protocol contract.
    #[error("JSON-RPC child returned an invalid response")]
    Protocol,
    /// The peer returned a JSON-RPC error object.
    #[error(transparent)]
    Remote(#[from] JsonRpcRemoteError),
}

impl Debug for JsonRpcChildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter.write_str("InvalidConfiguration"),
            Self::Spawn => formatter.write_str("Spawn"),
            Self::StdinClosed => formatter.write_str("StdinClosed"),
            Self::StdoutRead => formatter.write_str("StdoutRead"),
            Self::StderrRead => formatter.write_str("StderrRead"),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::StdoutTooLarge => formatter.write_str("StdoutTooLarge"),
            Self::StderrTooLarge => formatter.write_str("StderrTooLarge"),
            Self::Closed => formatter.write_str("Closed"),
            Self::Protocol => formatter.write_str("Protocol"),
            Self::Remote(error) => formatter.debug_tuple("Remote").field(error).finish(),
        }
    }
}

/// A peer error whose message is available only through an explicitly named accessor.
pub struct JsonRpcRemoteError {
    code: Option<i64>,
    message: Zeroizing<String>,
}

impl JsonRpcRemoteError {
    /// Optional numeric JSON-RPC error code.
    #[must_use]
    pub const fn code(&self) -> Option<i64> {
        self.code
    }

    /// Borrows the peer-provided message.
    ///
    /// Treat this value as potentially sensitive and never include it in logs.
    #[must_use]
    pub fn expose_message(&self) -> &str {
        &self.message
    }
}

impl Debug for JsonRpcRemoteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcRemoteError")
            .field("code", &self.code)
            .field("message", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for JsonRpcRemoteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "JSON-RPC peer returned an error (code: {:?})",
            self.code
        )
    }
}

impl std::error::Error for JsonRpcRemoteError {}

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

/// Validated construction policy for one long-lived JSON-RPC child.
pub struct JsonRpcChildRequest {
    executable: ExecutablePath,
    arguments: Vec<OsString>,
    environment: Vec<EnvironmentChange>,
    clear_environment: bool,
    version: JsonRpcVersion,
    max_frame_bytes: usize,
    max_stderr_bytes: usize,
}

impl Debug for JsonRpcChildRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcChildRequest")
            .field("executable", &"<redacted>")
            .field("argument_count", &self.arguments.len())
            .field("environment_change_count", &self.environment.len())
            .field("clear_environment", &self.clear_environment)
            .field("version", &self.version)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("max_stderr_bytes", &self.max_stderr_bytes)
            .finish()
    }
}

impl JsonRpcChildRequest {
    /// Creates a shell-free invocation with exact output bounds.
    ///
    /// # Errors
    ///
    /// Returns [`JsonRpcChildError::InvalidConfiguration`] when arguments or
    /// bounds exceed the hard transport ceilings.
    pub fn new<I, S>(
        executable: ExecutablePath,
        arguments: I,
        version: JsonRpcVersion,
        max_frame_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, JsonRpcChildError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let arguments = collect_arguments(arguments)?;
        if max_frame_bytes == 0
            || max_frame_bytes > MAX_FRAME_BYTES
            || max_stderr_bytes == 0
            || max_stderr_bytes > MAX_STDERR_BYTES
        {
            return Err(JsonRpcChildError::InvalidConfiguration);
        }
        Ok(Self {
            executable,
            arguments,
            environment: Vec::new(),
            clear_environment: false,
            version,
            max_frame_bytes,
            max_stderr_bytes,
        })
    }

    /// Starts the child with an empty environment before applying explicit changes.
    #[must_use]
    pub const fn with_cleared_environment(mut self) -> Self {
        self.clear_environment = true;
        self
    }

    /// Sets one environment variable without exposing its value through [`Debug`].
    ///
    /// Repeated changes to the same name replace the earlier change.
    ///
    /// # Errors
    ///
    /// Returns [`JsonRpcChildError::InvalidConfiguration`] for invalid names,
    /// values, counts, or aggregate environment size.
    pub fn with_environment(
        mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Result<Self, JsonRpcChildError> {
        self.replace_environment_change(EnvironmentChange::Set {
            name: name.into(),
            value: EnvironmentValue(value.into()),
        })?;
        Ok(self)
    }

    /// Removes one inherited environment variable from the child.
    ///
    /// # Errors
    ///
    /// Returns [`JsonRpcChildError::InvalidConfiguration`] for invalid names,
    /// counts, or aggregate environment size.
    pub fn without_environment(
        mut self,
        name: impl Into<OsString>,
    ) -> Result<Self, JsonRpcChildError> {
        self.replace_environment_change(EnvironmentChange::Remove { name: name.into() })?;
        Ok(self)
    }

    /// Spawns the validated child with piped standard streams.
    ///
    /// # Errors
    ///
    /// Returns [`JsonRpcChildError::Cancelled`] when already cancelled,
    /// [`JsonRpcChildError::Spawn`] when the process or pipes cannot be opened.
    pub async fn spawn(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<JsonRpcChild, JsonRpcChildError> {
        if cancellation.is_cancelled() {
            return Err(JsonRpcChildError::Cancelled);
        }

        let mut command = Command::new(self.executable.as_path());
        command
            .args(&self.arguments)
            .stdin(Stdio::piped())
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

        let mut child = command.spawn().map_err(|_| JsonRpcChildError::Spawn)?;
        let mut group = ProcessGroupGuard::new(child.id());
        let Some(stdin) = child.stdin.take() else {
            terminate_child(&mut child, &mut group).await;
            return Err(JsonRpcChildError::Spawn);
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_child(&mut child, &mut group).await;
            return Err(JsonRpcChildError::Spawn);
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_child(&mut child, &mut group).await;
            return Err(JsonRpcChildError::Spawn);
        };

        let (stderr_failure_sender, stderr_failure_receiver) = mpsc::channel(1);
        let stderr_limit = self.max_stderr_bytes;
        let stderr_group = group.process_group();
        let stderr_task = tokio::spawn(async move {
            match drain_stderr(stderr, stderr_limit).await {
                Ok(()) => std::future::pending::<()>().await,
                Err(failure) => {
                    kill_process_group(stderr_group);
                    let _ = stderr_failure_sender.send(failure).await;
                }
            }
        });

        Ok(JsonRpcChild {
            child: Some(child),
            stdin: Some(stdin),
            stdout: Some(BufReader::with_capacity(8 * 1024, stdout)),
            stderr_failure: stderr_failure_receiver,
            stderr_task: Some(stderr_task),
            group,
            version: self.version,
            max_frame_bytes: self.max_frame_bytes,
            next_id: 1,
        })
    }

    fn replace_environment_change(
        &mut self,
        change: EnvironmentChange,
    ) -> Result<(), JsonRpcChildError> {
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

/// One sequential, bidirectional newline-delimited JSON-RPC session.
///
/// Methods require mutable access so request IDs, stdin writes, and stdout
/// matching cannot race. Providers that need concurrency should serialize it
/// in an owning task rather than sharing this object directly.
pub struct JsonRpcChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
    stderr_failure: mpsc::Receiver<StderrFailure>,
    stderr_task: Option<JoinHandle<()>>,
    group: ProcessGroupGuard,
    version: JsonRpcVersion,
    max_frame_bytes: usize,
    next_id: u64,
}

impl Debug for JsonRpcChild {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRpcChild")
            .field("running", &self.child.is_some())
            .field("version", &self.version)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish_non_exhaustive()
    }
}

impl JsonRpcChild {
    /// Sends one request and returns its `result` value.
    ///
    /// Notifications and responses for other numeric IDs are skipped up to a
    /// fixed ceiling. Any cancellation, timeout, stream failure, oversized
    /// frame, or invalid matching response tears down the entire process group.
    ///
    /// # Errors
    ///
    /// Returns a stable [`JsonRpcChildError`] for invalid input, transport and
    /// protocol failures, cancellation, timeout, or a peer error response.
    pub async fn request(
        &mut self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<Value, JsonRpcChildError> {
        validate_operation(method, params.as_ref(), timeout)?;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(JsonRpcChildError::InvalidConfiguration)?;
        let frame = encode_frame(self.version, Some(id), method, params, self.max_frame_bytes)?;
        let deadline = Instant::now() + timeout;

        if let Err(error) = self.write_frame(&frame, deadline, cancellation).await {
            self.fail().await;
            return Err(error);
        }

        let mut skipped = 0_usize;
        loop {
            let line = match self.read_frame(deadline, cancellation).await {
                Ok(line) => line,
                Err(error) => {
                    self.fail().await;
                    return Err(error);
                }
            };
            if line.iter().all(u8::is_ascii_whitespace) {
                skipped += 1;
                if skipped > MAX_SKIPPED_FRAMES {
                    self.fail().await;
                    return Err(JsonRpcChildError::Protocol);
                }
                continue;
            }
            let message: Value = if let Ok(message) = serde_json::from_slice(&line) {
                message
            } else {
                self.fail().await;
                return Err(JsonRpcChildError::Protocol);
            };
            if validate_json_tree(&message).is_err() {
                self.fail().await;
                return Err(JsonRpcChildError::Protocol);
            }
            let Some(object) = message.as_object() else {
                self.fail().await;
                return Err(JsonRpcChildError::Protocol);
            };
            if !response_matches_id(object, id) {
                skipped += 1;
                if skipped > MAX_SKIPPED_FRAMES {
                    self.fail().await;
                    return Err(JsonRpcChildError::Protocol);
                }
                continue;
            }
            return match decode_matching_response(object, self.version) {
                Ok(result) => Ok(result),
                Err(error @ JsonRpcChildError::Remote(_)) => Err(error),
                Err(error) => {
                    self.fail().await;
                    Err(error)
                }
            };
        }
    }

    /// Sends one notification without waiting for a response.
    ///
    /// # Errors
    ///
    /// Returns a stable [`JsonRpcChildError`] for invalid input, transport
    /// failure, cancellation, timeout, or an asynchronous stderr failure.
    pub async fn notify(
        &mut self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<(), JsonRpcChildError> {
        validate_operation(method, params.as_ref(), timeout)?;
        let frame = encode_frame(self.version, None, method, params, self.max_frame_bytes)?;
        let deadline = Instant::now() + timeout;
        match self.write_frame(&frame, deadline, cancellation).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.fail().await;
                Err(error)
            }
        }
    }

    /// Closes stdin, then applies bounded TERM-to-KILL process-group teardown.
    pub async fn shutdown(&mut self) {
        self.stdin.take();
        self.stdout.take();
        if let Some(child) = self.child.as_mut() {
            terminate_child(child, &mut self.group).await;
        }
        self.child.take();
        if let Some(task) = self.stderr_task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    async fn write_frame(
        &mut self,
        frame: &[u8],
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), JsonRpcChildError> {
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(JsonRpcChildError::StdinClosed);
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(JsonRpcChildError::Cancelled),
            Some(failure) = self.stderr_failure.recv() => Err(failure.into()),
            result = tokio::time::timeout_at(deadline, stdin.write_all(frame)) => {
                match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(JsonRpcChildError::StdinClosed),
                    Err(_) => Err(JsonRpcChildError::Timeout),
                }
            }
        }
    }

    async fn read_frame(
        &mut self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, JsonRpcChildError> {
        let Some(stdout) = self.stdout.as_mut() else {
            return Err(JsonRpcChildError::Closed);
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(JsonRpcChildError::Cancelled),
            Some(failure) = self.stderr_failure.recv() => Err(failure.into()),
            result = tokio::time::timeout_at(
                deadline,
                read_bounded_line(stdout, self.max_frame_bytes),
            ) => {
                match result {
                    Ok(Ok(Some(line))) => Ok(line),
                    Ok(Ok(None)) => Err(JsonRpcChildError::Closed),
                    Ok(Err(ReadLineFailure::Io)) => Err(JsonRpcChildError::StdoutRead),
                    Ok(Err(ReadLineFailure::TooLarge)) => Err(JsonRpcChildError::StdoutTooLarge),
                    Ok(Err(ReadLineFailure::Unterminated)) => Err(JsonRpcChildError::Protocol),
                    Err(_) => Err(JsonRpcChildError::Timeout),
                }
            }
        }
    }

    async fn fail(&mut self) {
        self.shutdown().await;
    }
}

impl Drop for JsonRpcChild {
    fn drop(&mut self) {
        self.stdin.take();
        self.stdout.take();
        self.group.kill();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        self.group.disarm();
        if let Some(task) = self.stderr_task.take() {
            task.abort();
        }
    }
}

fn collect_arguments<I, S>(arguments: I) -> Result<Vec<OsString>, JsonRpcChildError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut collected = Vec::new();
    let mut total = 0_usize;
    for argument in arguments {
        if collected.len() == MAX_ARGUMENTS {
            return Err(JsonRpcChildError::InvalidConfiguration);
        }
        let argument = argument.into();
        let bytes = argument.as_encoded_bytes();
        if bytes.len() > MAX_ARGUMENT_BYTES || bytes.contains(&0) {
            return Err(JsonRpcChildError::InvalidConfiguration);
        }
        total = total
            .checked_add(bytes.len())
            .ok_or(JsonRpcChildError::InvalidConfiguration)?;
        if total > MAX_TOTAL_ARGUMENT_BYTES {
            return Err(JsonRpcChildError::InvalidConfiguration);
        }
        collected.push(argument);
    }
    Ok(collected)
}

fn validate_environment_change(change: &EnvironmentChange) -> Result<(), JsonRpcChildError> {
    let name = change.name().as_encoded_bytes();
    if name.is_empty()
        || name.len() > MAX_ENVIRONMENT_NAME_BYTES
        || name.contains(&0)
        || name.contains(&b'=')
    {
        return Err(JsonRpcChildError::InvalidConfiguration);
    }
    if let EnvironmentChange::Set { value, .. } = change {
        let value = value.0.as_encoded_bytes();
        if value.len() > MAX_ENVIRONMENT_VALUE_BYTES || value.contains(&0) {
            return Err(JsonRpcChildError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn validate_environment_set(changes: &[EnvironmentChange]) -> Result<(), JsonRpcChildError> {
    if changes.len() > MAX_ENVIRONMENT_CHANGES {
        return Err(JsonRpcChildError::InvalidConfiguration);
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
        return Err(JsonRpcChildError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_operation(
    method: &str,
    params: Option<&Value>,
    timeout: Duration,
) -> Result<(), JsonRpcChildError> {
    if method.is_empty()
        || method.len() > MAX_METHOD_BYTES
        || method.bytes().any(|byte| byte.is_ascii_control())
        || timeout.is_zero()
        || timeout > MAX_TIMEOUT
        || params.is_some_and(|value| !value.is_object() && !value.is_array())
    {
        return Err(JsonRpcChildError::InvalidConfiguration);
    }
    if let Some(params) = params {
        validate_json_tree(params).map_err(|_| JsonRpcChildError::InvalidConfiguration)?;
    }
    Ok(())
}

fn encode_frame(
    version: JsonRpcVersion,
    id: Option<u64>,
    method: &str,
    params: Option<Value>,
    max_frame_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, JsonRpcChildError> {
    let mut object = Map::new();
    if version == JsonRpcVersion::V2 {
        object.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
    }
    if let Some(id) = id {
        object.insert("id".to_owned(), Value::Number(id.into()));
    }
    object.insert("method".to_owned(), Value::String(method.to_owned()));
    object.insert(
        "params".to_owned(),
        params.unwrap_or_else(|| Value::Object(Map::new())),
    );
    let mut encoded = Zeroizing::new(
        serde_json::to_vec(&Value::Object(object))
            .map_err(|_| JsonRpcChildError::InvalidConfiguration)?,
    );
    if encoded.len() >= max_frame_bytes {
        return Err(JsonRpcChildError::InvalidConfiguration);
    }
    encoded.push(b'\n');
    Ok(encoded)
}

fn validate_json_tree(value: &Value) -> Result<(), JsonRpcChildError> {
    let mut pending = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes.checked_add(1).ok_or(JsonRpcChildError::Protocol)?;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return Err(JsonRpcChildError::Protocol);
        }
        match value {
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                return Err(JsonRpcChildError::Protocol);
            }
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.keys().any(|key| key.len() > MAX_JSON_STRING_BYTES) {
                    return Err(JsonRpcChildError::Protocol);
                }
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn response_matches_id(object: &Map<String, Value>, id: u64) -> bool {
    object
        .get("id")
        .and_then(Value::as_u64)
        .is_some_and(|message_id| message_id == id)
}

fn decode_matching_response(
    object: &Map<String, Value>,
    version: JsonRpcVersion,
) -> Result<Value, JsonRpcChildError> {
    if version == JsonRpcVersion::V2 && object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
    {
        return Err(JsonRpcChildError::Protocol);
    }
    let result = object.get("result");
    let error = object.get("error");
    match (result, error) {
        (Some(result), None) => Ok(result.clone()),
        (None, Some(Value::Object(error))) => {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .ok_or(JsonRpcChildError::Protocol)?;
            let code = match error.get("code") {
                Some(value) => Some(value.as_i64().ok_or(JsonRpcChildError::Protocol)?),
                None => None,
            };
            Err(JsonRpcRemoteError {
                code,
                message: Zeroizing::new(message.to_owned()),
            }
            .into())
        }
        _ => Err(JsonRpcChildError::Protocol),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadLineFailure {
    Io,
    TooLarge,
    Unterminated,
}

async fn read_bounded_line<R>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, ReadLineFailure>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Zeroizing::new(Vec::with_capacity(limit.min(8 * 1024)));
    loop {
        let available = reader.fill_buf().await.map_err(|_| ReadLineFailure::Io)?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(ReadLineFailure::Unterminated)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if take > limit.saturating_sub(line.len()) {
            return Err(ReadLineFailure::TooLarge);
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StderrFailure {
    Read,
    TooLarge,
}

impl From<StderrFailure> for JsonRpcChildError {
    fn from(failure: StderrFailure) -> Self {
        match failure {
            StderrFailure::Read => Self::StderrRead,
            StderrFailure::TooLarge => Self::StderrTooLarge,
        }
    }
}

async fn drain_stderr<R>(mut reader: R, limit: usize) -> Result<(), StderrFailure>
where
    R: AsyncRead + Unpin,
{
    let mut total = 0_usize;
    let mut buffer = Zeroizing::new(vec![0_u8; 8 * 1024]);
    loop {
        let read = reader
            .read(buffer.as_mut_slice())
            .await
            .map_err(|_| StderrFailure::Read)?;
        if read == 0 {
            return Ok(());
        }
        if read > limit.saturating_sub(total) {
            return Err(StderrFailure::TooLarge);
        }
        total += read;
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
    const fn process_group(&self) -> Option<Pid> {
        self.process_group
    }

    #[cfg(not(unix))]
    const fn process_group(&self) -> Option<()> {
        None
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

#[cfg(unix)]
fn kill_process_group(process_group: Option<Pid>) {
    if let Some(process_group) = process_group {
        let _ = killpg(process_group, Signal::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_process_group: Option<()>) {}

async fn terminate_child(child: &mut Child, group: &mut ProcessGroupGuard) {
    #[cfg(unix)]
    group.signal(Signal::SIGTERM);
    let _ = tokio::time::timeout(TERMINATION_GRACE, child.wait()).await;
    group.kill();
    let _ = child.start_kill();
    let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await;
    group.disarm();
}
