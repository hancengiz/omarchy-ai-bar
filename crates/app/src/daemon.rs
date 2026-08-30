//! Foreground daemon lifecycle and bounded same-UID control handling.

use std::io;
use std::net::Shutdown;
use std::path::Path;
use std::sync::Arc;

use oab_domain::{AccountScope, SurfaceSnapshotEnvelope};
use oab_ipc::codec::{JsonLineDecoder, encode_json_line};
use oab_ipc::protocol::{
    AcceptedClientFrame, ActionProgressState, Capability, CapabilitySet, ClientMessage,
    RuntimeAction, Sequence, ServerHandshakeContext, ServerMessage,
};
use oab_ipc::socket::{DisplaySocket, DisplaySocketError, VerifiedDisplayStream};
use oab_runtime::actor::{
    RuntimeActor, RuntimeBuildError, RuntimeConfig, RuntimeHandle, RuntimeJoinError,
};
use oab_runtime::command::RefreshTrigger;
use oab_runtime::scheduler::{Clock, SystemClock};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use tokio::signal::unix::{SignalKind, signal};

use crate::provider_bootstrap::ProductionProviders;
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
    #[error("could not initialize the display protocol")]
    DisplayProtocol,
}

/// Runs the primary daemon until SIGTERM or SIGINT.
pub(crate) fn run(
    control_socket: DisplaySocket,
    display_socket_path: &Path,
    providers: ProductionProviders,
) -> Result<(), DaemonError> {
    let display_socket = DisplaySocket::bind(display_socket_path).map_err(DaemonError::Listener)?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)?;
    runtime.block_on(run_loop(control_socket, display_socket, providers))
}

async fn run_loop(
    control_socket: DisplaySocket,
    display_socket: DisplaySocket,
    providers: ProductionProviders,
) -> Result<(), DaemonError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let scopes = Arc::new(providers.scopes);
    let (actor, state) =
        RuntimeActor::new(RuntimeConfig::default(), clock, providers.registrations)
            .map_err(DaemonError::StateBuild)?;
    let state_task = actor.spawn();
    for scope in scopes.iter().cloned() {
        let _admission = state.refresh(scope, RefreshTrigger::Manual).await;
    }
    let capabilities = CapabilitySet::new([
        Capability::DisplaySnapshots,
        Capability::RuntimeActions,
        Capability::ActionProgress,
    ])
    .map_err(|_| DaemonError::DisplayProtocol)?;
    let handshake = Arc::new(
        ServerHandshakeContext::new(capabilities).map_err(|_| DaemonError::DisplayProtocol)?,
    );
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
                        let result = accept_ready_display_clients(
                            display_socket.get_ref(),
                            &state,
                            &handshake,
                            &scopes,
                        );
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

fn accept_ready_display_clients(
    socket: &DisplaySocket,
    state: &RuntimeHandle,
    handshake: &Arc<ServerHandshakeContext>,
    scopes: &Arc<Vec<AccountScope>>,
) -> Result<(), DaemonError> {
    for _ in 0..MAX_ACCEPT_BATCH {
        match socket.accept_verified() {
            Ok(verified) => {
                let stream = verified.into_stream();
                stream.set_nonblocking(true).map_err(DaemonError::Runtime)?;
                let stream = UnixStream::from_std(stream).map_err(DaemonError::Runtime)?;
                let state = state.clone();
                let handshake = Arc::clone(handshake);
                let scopes = Arc::clone(scopes);
                tokio::spawn(async move {
                    let _result = serve_display_client(stream, state, handshake, scopes).await;
                });
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

async fn serve_display_client(
    stream: UnixStream,
    state: RuntimeHandle,
    handshake: Arc<ServerHandshakeContext>,
    scopes: Arc<Vec<AccountScope>>,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let mut snapshots = state.subscribe();
    let mut guard = handshake.connection();
    let mut decoder = JsonLineDecoder::<ClientMessage>::new();
    let mut chunk = [0_u8; 8 * 1024];

    loop {
        tokio::select! {
            read = reader.read(&mut chunk) => {
                let read = read?;
                if read == 0 {
                    decoder.finish().map_err(invalid_wire)?;
                    return Ok(());
                }
                let messages = decoder.feed(&chunk[..read]).map_err(invalid_wire)?;
                for message in messages {
                    match guard.accept(&message).map_err(invalid_wire)? {
                        AcceptedClientFrame::Hello(hello) => {
                            write_message(&mut writer, &ServerMessage::hello(hello)).await?;
                            let publication = snapshots.borrow().clone();
                            write_snapshot(&mut writer, publication.as_ref()).await?;
                        }
                        AcceptedClientFrame::Action { request_id, action, .. } => {
                            run_action(&mut writer, &state, scopes.as_slice(), request_id, action).await?;
                        }
                        AcceptedClientFrame::SnapshotAck { .. } => {}
                    }
                }
            }
            changed = snapshots.changed(), if guard.is_complete() => {
                changed.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "runtime stopped"))?;
                let publication = snapshots.borrow().clone();
                write_snapshot(&mut writer, publication.as_ref()).await?;
            }
        }
    }
}

async fn run_action(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    state: &RuntimeHandle,
    scopes: &[AccountScope],
    request_id: oab_ipc::protocol::RequestId,
    action: &RuntimeAction,
) -> io::Result<()> {
    write_message(
        writer,
        &ServerMessage::ActionProgress {
            request_id,
            state: ActionProgressState::Running,
        },
    )
    .await?;

    let selected = match action {
        RuntimeAction::RefreshAll {} => scopes.iter().collect::<Vec<_>>(),
        RuntimeAction::RefreshProvider { provider } => scopes
            .iter()
            .filter(|scope| scope.provider() == *provider)
            .collect(),
        _ => Vec::new(),
    };
    let popup = match action {
        RuntimeAction::OpenPanel {} | RuntimeAction::TogglePanel {} => Some(true),
        RuntimeAction::ClosePanel {} => Some(false),
        _ => None,
    };
    let refresh_supported = matches!(
        action,
        RuntimeAction::RefreshAll {} | RuntimeAction::RefreshProvider { .. }
    );
    let mut succeeded = refresh_supported && !selected.is_empty();
    for scope in selected {
        if state
            .refresh(scope.clone(), RefreshTrigger::Manual)
            .await
            .is_err()
        {
            succeeded = false;
        }
    }
    if let Some(open) = popup {
        succeeded = state.set_popup_open(open).await.is_ok();
    }
    write_message(
        writer,
        &ServerMessage::ActionProgress {
            request_id,
            state: if succeeded {
                ActionProgressState::Completed
            } else {
                ActionProgressState::Failed
            },
        },
    )
    .await
}

async fn write_snapshot(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    publication: &oab_runtime::snapshot_store::PublishedSnapshot,
) -> io::Result<()> {
    let sequence = Sequence::new(publication.sequence()).map_err(invalid_wire)?;
    let snapshot = SurfaceSnapshotEnvelope::Trusted(publication.envelope().private_view());
    write_message(writer, &ServerMessage::Snapshot { sequence, snapshot }).await
}

async fn write_message(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    message: &ServerMessage<'_>,
) -> io::Result<()> {
    let encoded = encode_json_line(message).map_err(invalid_wire)?;
    writer.write_all(&encoded).await
}

fn invalid_wire(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
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
