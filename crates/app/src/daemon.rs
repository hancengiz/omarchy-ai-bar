//! Foreground daemon lifecycle and bounded same-UID control handling.

use std::io;
use std::net::Shutdown;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use oab_domain::{AccountScope, ProviderSnapshot, SnapshotEnvelopeV1, SurfaceSnapshotEnvelope};
use oab_ipc::codec::{JsonLineDecoder, encode_json_line};
use oab_ipc::frontend_presence::SniStatus;
use oab_ipc::protocol::{
    AcceptedClientFrame, ActionProgressState, Capability, CapabilitySet, ClientMessage,
    RuntimeAction, Sequence, ServerHandshakeContext, ServerMessage,
};
use oab_ipc::socket::{DisplaySocket, DisplaySocketError, VerifiedDisplayStream};
use oab_ipc::tray::TrayController;
use oab_runtime::actor::{
    RuntimeActor, RuntimeBuildError, RuntimeConfig, RuntimeHandle, RuntimeJoinError,
};
use oab_runtime::command::RefreshTrigger;
use oab_runtime::scheduler::{Clock, SystemClock};
use oab_storage::atomic_file::{atomic_write, read_private_file};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, Instant, interval, timeout};

use crate::provider_bootstrap::ProductionProviders;
use crate::single_instance::{
    ControlAction, ControlRequest, ControlResponse, SingleInstanceError, configure_stream,
    read_frame, write_frame,
};

const MAX_ACCEPT_BATCH: usize = 4;
const FRONTEND_GRACE: Duration = Duration::from_secs(5);
const TRAY_TICK: Duration = Duration::from_millis(250);
const SNAPSHOT_CACHE_BYTES: usize = 4 * 1024 * 1024;

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
    snapshot_cache_path: &Path,
    providers: ProductionProviders,
) -> Result<(), DaemonError> {
    let display_socket = DisplaySocket::bind(display_socket_path).map_err(DaemonError::Listener)?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)?;
    runtime.block_on(run_loop(
        control_socket,
        display_socket,
        snapshot_cache_path,
        providers,
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "the select loop keeps socket, signal, tray, and actor shutdown ownership in one lifecycle"
)]
async fn run_loop(
    control_socket: DisplaySocket,
    display_socket: DisplaySocket,
    snapshot_cache_path: &Path,
    providers: ProductionProviders,
) -> Result<(), DaemonError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let scopes = Arc::new(providers.scopes);
    let retained = read_retained_snapshots(snapshot_cache_path);
    let (actor, state) = RuntimeActor::new_with_retained(
        RuntimeConfig::default(),
        clock,
        providers.registrations,
        retained,
    )
    .map_err(DaemonError::StateBuild)?;
    let persistence_task = tokio::spawn(persist_snapshots(
        state.subscribe(),
        snapshot_cache_path.to_path_buf(),
    ));
    let state_task = actor.spawn();
    for scope in scopes.iter().cloned() {
        // Startup is automatic work: retained rate-limit Retry-After state
        // must remain authoritative across a daemon restart. Explicit user
        // refresh actions still use `Manual` and bypass that cooldown.
        let _admission = state.refresh(scope, RefreshTrigger::Periodic).await;
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
    let compatible_frontends = Arc::new(AtomicUsize::new(0));
    let (tray_actions, tray_action_receiver) = mpsc::sync_channel(16);
    let tray = timeout(
        Duration::from_secs(2),
        TrayController::spawn(SniStatus::Passive, tray_actions),
    )
    .await
    .ok()
    .and_then(Result::ok);
    let tray_started_at = Instant::now();
    let mut tray_tick = interval(TRAY_TICK);
    let mut tray_status = SniStatus::Passive;

    let listener_result = 'listener: loop {
        tokio::select! {
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            readiness = control_socket.readable() => {
                match readiness {
                    Ok(mut readiness) => {
                        let result = accept_ready_control_clients(control_socket.get_ref(), &state);
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
                            &compatible_frontends,
                        );
                        readiness.clear_ready();
                        if let Err(error) = result {
                            break Err(error);
                        }
                    }
                    Err(error) => break Err(DaemonError::Runtime(error)),
                }
            },
            _ = tray_tick.tick() => {
                let mut should_quit = false;
                while let Ok(action) = tray_action_receiver.try_recv() {
                    if run_tray_action(&state, scopes.as_slice(), action).await {
                        should_quit = true;
                        break;
                    }
                }
                if should_quit {
                    break 'listener Ok(());
                }
                let desired = if compatible_frontends.load(Ordering::Acquire) > 0
                    || tray_started_at.elapsed() < FRONTEND_GRACE
                {
                    SniStatus::Passive
                } else {
                    SniStatus::Active
                };
                if desired != tray_status {
                    if let Some(tray) = tray.as_ref() {
                        let _updated = tray.set_status(desired).await;
                    }
                    tray_status = desired;
                }
            }
        }
    };

    let state_exit = state_task
        .shutdown()
        .await
        .map_err(DaemonError::StateJoin)?;
    persistence_task.abort();
    let _ = persistence_task.await;
    if let Some(tray) = tray {
        tray.shutdown().await;
    }
    if state_exit.fault().is_some() {
        return Err(DaemonError::StateFault);
    }
    listener_result
}

fn read_retained_snapshots(path: &Path) -> Vec<ProviderSnapshot> {
    let Ok(Some(bytes)) = read_private_file(path, SNAPSHOT_CACHE_BYTES) else {
        return Vec::new();
    };
    serde_json::from_slice::<SnapshotEnvelopeV1>(&bytes)
        .map(|envelope| envelope.snapshots().to_vec())
        .unwrap_or_default()
}

async fn persist_snapshots(
    mut snapshots: tokio::sync::watch::Receiver<
        Arc<oab_runtime::snapshot_store::PublishedSnapshot>,
    >,
    path: std::path::PathBuf,
) {
    while snapshots.changed().await.is_ok() {
        let publication = snapshots.borrow().clone();
        let Ok(mut bytes) = serde_json::to_vec(&publication.envelope().private_view()) else {
            continue;
        };
        bytes.push(b'\n');
        let _ = atomic_write(&path, &bytes);
    }
}

async fn run_tray_action(
    state: &RuntimeHandle,
    scopes: &[AccountScope],
    action: RuntimeAction,
) -> bool {
    match action {
        RuntimeAction::RefreshAll {} => {
            for scope in scopes {
                let _admission = state.refresh(scope.clone(), RefreshTrigger::Manual).await;
            }
            false
        }
        RuntimeAction::Quit {} => true,
        RuntimeAction::RefreshProvider { provider } => {
            for scope in scopes.iter().filter(|scope| scope.provider() == provider) {
                let _admission = state.refresh(scope.clone(), RefreshTrigger::Manual).await;
            }
            false
        }
        RuntimeAction::Navigate { .. }
        | RuntimeAction::OpenPanel {}
        | RuntimeAction::ClosePanel {}
        | RuntimeAction::TogglePanel {}
        | RuntimeAction::SwitchAccount { .. }
        | RuntimeAction::BeginLogin { .. }
        | RuntimeAction::LogOut { .. }
        | RuntimeAction::OpenProviderDashboard { .. }
        | RuntimeAction::Export { .. }
        | RuntimeAction::InstallPlugin { .. }
        | RuntimeAction::ResolveApproval { .. }
        | RuntimeAction::CancelRequest { .. } => false,
    }
}

fn accept_ready_control_clients(
    socket: &DisplaySocket,
    state: &RuntimeHandle,
) -> Result<(), DaemonError> {
    for _ in 0..MAX_ACCEPT_BATCH {
        match socket.accept_verified() {
            Ok(stream) => handle_client(stream, state),
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
    compatible_frontends: &Arc<AtomicUsize>,
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
                let compatible_frontends = Arc::clone(compatible_frontends);
                tokio::spawn(async move {
                    let _result = serve_display_client(
                        stream,
                        state,
                        handshake,
                        scopes,
                        compatible_frontends,
                    )
                    .await;
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
    compatible_frontends: Arc<AtomicUsize>,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let mut snapshots = state.subscribe();
    let mut guard = handshake.connection();
    let mut decoder = JsonLineDecoder::<ClientMessage>::new();
    let mut chunk = [0_u8; 8 * 1024];
    let mut frontend_presence = None;

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
                            debug_assert!(frontend_presence.is_none());
                            frontend_presence = Some(ConnectedFrontend::new(Arc::clone(
                                &compatible_frontends,
                            )));
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

struct ConnectedFrontend {
    count: Arc<AtomicUsize>,
}

impl ConnectedFrontend {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self { count }
    }
}

impl Drop for ConnectedFrontend {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
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

fn handle_client(mut verified: VerifiedDisplayStream, state: &RuntimeHandle) {
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
            ControlAction::Usage | ControlAction::Cards => {
                ControlResponse::with_payload(current_snapshot_value(state)?)
            }
            ControlAction::Diagnose => {
                let snapshot = current_snapshot_value(state)?;
                ControlResponse::with_payload(diagnostics_value(&snapshot))
            }
            ControlAction::Cost => {
                let snapshot = current_snapshot_value(state)?;
                ControlResponse::with_payload(cost_value(&snapshot))
            }
            ControlAction::Sessions => {
                let snapshot = current_snapshot_value(state)?;
                ControlResponse::with_payload(sessions_value(&snapshot))
            }
            ControlAction::Dashboard => ControlResponse::unavailable(),
        };
        write_frame(stream, &response)
    });
    let _ignored = stream.shutdown(if result.is_ok() {
        Shutdown::Write
    } else {
        Shutdown::Both
    });
}

fn cost_value(snapshot: &Value) -> Value {
    let providers = snapshot
        .get("snapshots")
        .and_then(Value::as_array)
        .map(|snapshots| {
            snapshots
                .iter()
                .filter_map(|entry| {
                    let sample = entry.get("last_known_good")?;
                    let cost = sample.get("cost")?;
                    Some(json!({
                        "provider": sample.pointer("/scope/provider").and_then(Value::as_str).unwrap_or("unknown"),
                        "cost": cost,
                        "cost_usage": sample.get("cost_usage"),
                        "balance": sample.get("balance"),
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "schema_version": 1,
        "generated_at": snapshot.get("generated_at").cloned().unwrap_or(Value::Null),
        "providers": providers,
    })
}

fn sessions_value(snapshot: &Value) -> Value {
    let sessions = snapshot
        .get("snapshots")
        .and_then(Value::as_array)
        .map(|snapshots| {
            snapshots
                .iter()
                .filter_map(|entry| {
                    let sample = entry.get("last_known_good")?;
                    let session = sample.get("session")?.as_object()?;
                    Some(json!({
                        "provider": sample.pointer("/scope/provider").and_then(Value::as_str).unwrap_or("unknown"),
                        "session": session.get("label").or_else(|| session.get("id")),
                        "status": session.get("status"),
                        "started_at": session.get("started_at"),
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "schema_version": 1,
        "generated_at": snapshot.get("generated_at").cloned().unwrap_or(Value::Null),
        "sessions": sessions,
    })
}

fn current_snapshot_value(state: &RuntimeHandle) -> Result<Value, SingleInstanceError> {
    let snapshots = state.subscribe();
    let publication = snapshots.borrow().clone();
    serde_json::to_value(publication.envelope().private_view())
        .map_err(|_error| SingleInstanceError::Exchange)
}

fn diagnostics_value(snapshot: &Value) -> Value {
    let providers = snapshot
        .get("snapshots")
        .and_then(Value::as_array)
        .map(|snapshots| {
            snapshots
                .iter()
                .map(|entry| {
                    json!({
                        "provider": entry.pointer("/last_known_good/scope/provider")
                            .or_else(|| entry.pointer("/scope/provider"))
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        "state": entry.get("state").and_then(Value::as_str).unwrap_or("unknown"),
                        "has_last_known_good": entry.get("last_known_good").is_some_and(|value| !value.is_null()),
                        "error_kind": entry.pointer("/error/kind").and_then(Value::as_str),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "schema_version": 1,
        "daemon": "running",
        "generated_at": snapshot.get("generated_at").cloned().unwrap_or(Value::Null),
        "providers": providers,
    })
}
