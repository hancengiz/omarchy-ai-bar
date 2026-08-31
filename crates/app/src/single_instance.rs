//! Same-UID daemon discovery and bounded control-socket framing.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use oab_ipc::codec::{JsonLineDecoder, encode_json_line};
use oab_ipc::permissions::{PermissionError, effective_uid};
use oab_ipc::socket::{DisplaySocket, DisplaySocketError, verify_peer_uid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const CONTROL_PROTOCOL: u8 = 1;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_millis(100);
const FORWARD_RETRY_WINDOW: Duration = Duration::from_millis(500);
const FORWARD_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const IO_CHUNK_BYTES: usize = 8 * 1024;

/// A bounded action accepted by the local daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlAction {
    Activate,
    Usage,
    Cards,
    Dashboard,
    Cost,
    Sessions,
    Diagnose,
}

/// Stable daemon reply state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlStatus {
    Accepted,
    Unavailable,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlRequest {
    protocol: u8,
    action: ControlAction,
}

impl ControlRequest {
    pub(crate) const fn new(action: ControlAction) -> Self {
        Self {
            protocol: CONTROL_PROTOCOL,
            action,
        }
    }

    pub(crate) const fn action(&self) -> ControlAction {
        self.action
    }

    pub(crate) const fn has_supported_protocol(&self) -> bool {
        self.protocol == CONTROL_PROTOCOL
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlResponse {
    protocol: u8,
    status: ControlStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
}

impl ControlResponse {
    pub(crate) const fn accepted() -> Self {
        Self {
            protocol: CONTROL_PROTOCOL,
            status: ControlStatus::Accepted,
            payload: None,
        }
    }

    pub(crate) const fn with_payload(payload: Value) -> Self {
        Self {
            protocol: CONTROL_PROTOCOL,
            status: ControlStatus::Accepted,
            payload: Some(payload),
        }
    }

    pub(crate) const fn unavailable() -> Self {
        Self {
            protocol: CONTROL_PROTOCOL,
            status: ControlStatus::Unavailable,
            payload: None,
        }
    }

    pub(crate) const fn status(&self) -> ControlStatus {
        self.status
    }

    pub(crate) fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }

    const fn has_supported_protocol(&self) -> bool {
        self.protocol == CONTROL_PROTOCOL
    }
}

/// Result of acquiring the daemon endpoint or forwarding to its owner.
pub(crate) enum InstanceRole {
    Primary(DisplaySocket),
    Forwarded(ControlResponse),
}

/// Safe-command daemon discovery result.
pub(crate) enum ForwardOutcome {
    NoDaemon,
    Response(ControlResponse),
}

/// Path-free failure at the single-instance boundary.
#[derive(Debug, Error)]
pub(crate) enum SingleInstanceError {
    #[error("could not establish the private daemon endpoint")]
    Bind(#[source] DisplaySocketError),
    #[error("could not connect to the running daemon")]
    Connect,
    #[error("could not authenticate the running daemon")]
    Authenticate,
    #[error("the running daemon control exchange failed")]
    Exchange,
    #[error("the running daemon returned an invalid control response")]
    InvalidResponse,
}

/// Acquires the private daemon socket or forwards activation to its owner.
pub(crate) fn acquire_or_forward(path: &Path) -> Result<InstanceRole, SingleInstanceError> {
    match DisplaySocket::bind(path) {
        Ok(socket) => Ok(InstanceRole::Primary(socket)),
        Err(error) if indicates_active_owner(&error) => {
            let deadline = Instant::now()
                .checked_add(FORWARD_RETRY_WINDOW)
                .unwrap_or_else(Instant::now);
            loop {
                match forward(path, ControlAction::Activate)? {
                    ForwardOutcome::Response(response) => {
                        return Ok(InstanceRole::Forwarded(response));
                    }
                    ForwardOutcome::NoDaemon if Instant::now() < deadline => {
                        thread::sleep(FORWARD_RETRY_INTERVAL);
                    }
                    ForwardOutcome::NoDaemon => return Err(SingleInstanceError::Connect),
                }
            }
        }
        Err(error) => Err(SingleInstanceError::Bind(error)),
    }
}

/// Sends one bounded control action when a daemon is reachable.
pub(crate) fn forward(
    path: &Path,
    action: ControlAction,
) -> Result<ForwardOutcome, SingleInstanceError> {
    let mut stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(ForwardOutcome::NoDaemon);
        }
        Err(_) => return Err(SingleInstanceError::Connect),
    };
    configure_stream(&stream)?;
    verify_peer_uid(&stream, effective_uid())
        .map_err(|_error| SingleInstanceError::Authenticate)?;

    write_frame(&mut stream, &ControlRequest::new(action))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_error| SingleInstanceError::Exchange)?;
    let response: ControlResponse = read_frame(&mut stream)?;
    if !response.has_supported_protocol() {
        return Err(SingleInstanceError::InvalidResponse);
    }
    Ok(ForwardOutcome::Response(response))
}

pub(crate) fn configure_stream(stream: &UnixStream) -> Result<(), SingleInstanceError> {
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(CONTROL_IO_TIMEOUT)))
        .and_then(|()| stream.set_write_timeout(Some(CONTROL_IO_TIMEOUT)))
        .map_err(|_error| SingleInstanceError::Exchange)
}

pub(crate) fn read_frame<T>(stream: &mut UnixStream) -> Result<T, SingleInstanceError>
where
    T: serde::de::DeserializeOwned,
{
    let mut decoder = JsonLineDecoder::<T>::new();
    let mut chunk = [0_u8; IO_CHUNK_BYTES];
    loop {
        let bytes_read = stream
            .read(&mut chunk)
            .map_err(|_error| SingleInstanceError::Exchange)?;
        if bytes_read == 0 {
            decoder
                .finish()
                .map_err(|_error| SingleInstanceError::InvalidResponse)?;
            return Err(SingleInstanceError::InvalidResponse);
        }
        let mut frames = decoder
            .feed(&chunk[..bytes_read])
            .map_err(|_error| SingleInstanceError::InvalidResponse)?;
        if frames.len() > 1 || (!frames.is_empty() && decoder.buffered_bytes() != 0) {
            return Err(SingleInstanceError::InvalidResponse);
        }
        if let Some(frame) = frames.pop() {
            return Ok(frame);
        }
    }
}

pub(crate) fn write_frame<T>(stream: &mut UnixStream, frame: &T) -> Result<(), SingleInstanceError>
where
    T: Serialize + ?Sized,
{
    let encoded = encode_json_line(frame).map_err(|_error| SingleInstanceError::Exchange)?;
    stream
        .write_all(&encoded)
        .map_err(|_error| SingleInstanceError::Exchange)
}

fn indicates_active_owner(error: &DisplaySocketError) -> bool {
    matches!(
        error,
        DisplaySocketError::AlreadyActive
            | DisplaySocketError::Permissions(PermissionError::EndpointLockBusy)
    )
}
