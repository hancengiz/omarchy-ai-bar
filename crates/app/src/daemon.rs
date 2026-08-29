//! Foreground daemon lifecycle and bounded same-UID control handling.

use std::io;
use std::net::Shutdown;
use std::path::Path;
use std::sync::Arc;

use oab_ipc::socket::{DisplaySocket, DisplaySocketError, VerifiedDisplayStream};
use oab_runtime::actor::{RuntimeActor, RuntimeBuildError, RuntimeConfig, RuntimeJoinError};
use oab_runtime::scheduler::{Clock, SystemClock};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::runtime::Builder;
use tokio::signal::unix::{SignalKind, signal};

use crate::single_instance::{
    ControlAction, ControlRequest, ControlResponse, SingleInstanceError, configure_stream,
    read_frame, write_frame,
};

const MAX_ACCEPT_BATCH: usize = 4;

/// Path-free daemon lifecycle failure.
#[derive(Debug, Error)]
pub(crate) enum DaemonError {
    #[error("could not initialize the daemon runtime")]
    Runtime(#[source] io::Error),
    #[error("could not install the daemon shutdown signal handler")]
    Signal(#[source] io::Error),
    #[error("the private daemon listener failed")]
    Listener(#[source] DisplaySocketError),
    #[error("could not initialize the application state actor")]
    StateBuild(#[source] RuntimeBuildError),
    #[error("the application state actor task failed")]
    StateJoin(#[source] RuntimeJoinError),
    #[error("the application state actor stopped after an internal fault")]
    StateFault,
}

/// Runs the primary daemon until SIGTERM or SIGINT.
pub(crate) fn run(
    control_socket: DisplaySocket,
    display_socket_path: &Path,
) -> Result<(), DaemonError> {
    let display_socket = DisplaySocket::bind(display_socket_path).map_err(DaemonError::Listener)?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)?;
    runtime.block_on(run_loop(control_socket, display_socket))
}

async fn run_loop(
    control_socket: DisplaySocket,
    display_socket: DisplaySocket,
) -> Result<(), DaemonError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let (actor, _state) =
        RuntimeActor::new(RuntimeConfig::default(), clock, []).map_err(DaemonError::StateBuild)?;
    let state_task = actor.spawn();
    control_socket
        .set_nonblocking(true)
        .map_err(DaemonError::Listener)?;
    display_socket
        .set_nonblocking(true)
        .map_err(DaemonError::Listener)?;
    let control_socket = AsyncFd::new(control_socket).map_err(DaemonError::Runtime)?;
    let display_socket = AsyncFd::new(display_socket).map_err(DaemonError::Runtime)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(DaemonError::Signal)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(DaemonError::Signal)?;

    let listener_result = loop {
        tokio::select! {
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            readiness = control_socket.readable() => {
                match readiness {
                    Ok(mut readiness) => {
                        let result = accept_ready_control_clients(control_socket.get_ref());
                        readiness.clear_ready();
                        if let Err(error) = result {
                            break Err(error);
                        }
                    }
                    Err(error) => break Err(DaemonError::Runtime(error)),
                }
            },
            readiness = display_socket.readable() => {
                match readiness {
                    Ok(mut readiness) => {
                        let result = reject_unwired_display_clients(display_socket.get_ref());
                        readiness.clear_ready();
                        if let Err(error) = result {
                            break Err(error);
                        }
                    }
                    Err(error) => break Err(DaemonError::Runtime(error)),
                }
            },
        }
    };

    let state_exit = state_task
        .shutdown()
        .await
        .map_err(DaemonError::StateJoin)?;
    if state_exit.fault().is_some() {
        return Err(DaemonError::StateFault);
    }
    listener_result
}

fn accept_ready_control_clients(socket: &DisplaySocket) -> Result<(), DaemonError> {
    for _ in 0..MAX_ACCEPT_BATCH {
        match socket.accept_verified() {
            Ok(stream) => handle_client(stream),
            Err(DisplaySocketError::Operation { source, .. })
                if source.kind() == io::ErrorKind::WouldBlock =>
            {
                return Ok(());
            }
            Err(error) if is_peer_rejection(&error) => {}
            Err(error) => return Err(DaemonError::Listener(error)),
        }
    }
    Ok(())
}

fn reject_unwired_display_clients(socket: &DisplaySocket) -> Result<(), DaemonError> {
    for _ in 0..MAX_ACCEPT_BATCH {
        match socket.accept_verified() {
            Ok(stream) => {
                let _ignored = stream.stream().shutdown(Shutdown::Both);
            }
            Err(DisplaySocketError::Operation { source, .. })
                if source.kind() == io::ErrorKind::WouldBlock =>
            {
                return Ok(());
            }
            Err(error) if is_peer_rejection(&error) => {}
            Err(error) => return Err(DaemonError::Listener(error)),
        }
    }
    Ok(())
}

fn is_peer_rejection(error: &DisplaySocketError) -> bool {
    matches!(
        error,
        DisplaySocketError::PeerUidMismatch { .. }
            | DisplaySocketError::PeerCredentials(_)
            | DisplaySocketError::PeerCredentialsUnsupported
    )
}

fn handle_client(mut verified: VerifiedDisplayStream) {
    let stream = verified.stream_mut();
    if configure_stream(stream).is_err() {
        let _ignored = stream.shutdown(Shutdown::Both);
        return;
    }

    let result = read_frame::<ControlRequest>(stream).and_then(|request| {
        if !request.has_supported_protocol() {
            return Err(SingleInstanceError::InvalidResponse);
        }
        let response = match request.action() {
            ControlAction::Activate => ControlResponse::accepted(),
            ControlAction::Usage
            | ControlAction::Cards
            | ControlAction::Dashboard
            | ControlAction::Cost
            | ControlAction::Sessions
            | ControlAction::Diagnose => ControlResponse::unavailable(),
        };
        write_frame(stream, &response)
    });
    let _ignored = stream.shutdown(if result.is_ok() {
        Shutdown::Write
    } else {
        Shutdown::Both
    });
}
