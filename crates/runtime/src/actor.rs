//! Single-owner runtime state actor and bounded provider refresh execution.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use oab_domain::{
    AccountScope, ClassifiedError, CostUsageSnapshot, ErrorKind, Freshness, ProviderId,
    ProviderSnapshot, RetryEligibility, Timestamp, UsageSample,
};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{AbortHandle, Id, JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::command::{
    CommandReceipt, RefreshAdmission, RefreshReceipt, RefreshTrigger, ResetScheduleAdmission,
    ResetScheduleReceipt, RuntimeCommand,
};
pub use crate::event::RuntimeEvent;
use crate::scheduler::{Clock, SchedulePolicy, ScheduledRefresh, Scheduler};
use crate::shutdown::{ShutdownReport, cancel_and_drain};
use crate::snapshot_store::{PublishedSnapshot, SnapshotStore, SnapshotStoreError};

const DEFAULT_COMMAND_CAPACITY: usize = 32;
const DEFAULT_PENDING_CAPACITY: usize = 256;
const DEFAULT_EVENT_CAPACITY: usize = 64;
const DEFAULT_MAX_IN_FLIGHT: usize = 4;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const MAX_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

fn automatic_minimum_interval(provider: ProviderId) -> Duration {
    match provider {
        ProviderId::Codex => Duration::from_mins(1),
        ProviderId::Grok => Duration::from_mins(5),
        _ => Duration::from_mins(2),
    }
}

fn automatic_backoff_delay(error: &ClassifiedError, failures: u8) -> Option<Duration> {
    let base = match error.kind() {
        ErrorKind::RateLimited => Duration::from_mins(5),
        ErrorKind::ProviderUnavailable | ErrorKind::Network | ErrorKind::Api => {
            Duration::from_secs(60)
        }
        ErrorKind::MissingCredential
        | ErrorKind::AuthenticationExpired
        | ErrorKind::PermissionDenied
        | ErrorKind::Parse => return None,
    };
    let multiplier = 1_u32 << u32::from(failures.saturating_sub(1).min(5));
    let exponential = base.saturating_mul(multiplier).min(Duration::from_hours(1));
    let requested = error
        .retry_after()
        .map(|delay| Duration::from_secs(delay.seconds()));
    Some(requested.map_or(exponential, |value| value.max(exponential)))
}

fn retained_automatic_backoff(
    retained: &[ProviderSnapshot],
    wall_now: Timestamp,
    monotonic_now: Instant,
) -> (BTreeMap<AccountScope, Instant>, BTreeMap<AccountScope, u8>) {
    let mut cooldowns: BTreeMap<AccountScope, Instant> = BTreeMap::new();
    let mut failures: BTreeMap<AccountScope, u8> = BTreeMap::new();
    for snapshot in retained {
        let (Some(error), Some(Freshness::Stale { since })) =
            (snapshot.error(), snapshot.freshness())
        else {
            continue;
        };
        let Some(delay) = automatic_backoff_delay(error, 1) else {
            continue;
        };
        let elapsed = if since >= wall_now {
            Duration::ZERO
        } else {
            Duration::try_from(wall_now.as_offset_date_time() - since.as_offset_date_time())
                .unwrap_or(delay)
        };
        let remaining = delay.saturating_sub(elapsed);
        if remaining.is_zero() {
            continue;
        }
        let until = monotonic_now + remaining;
        cooldowns
            .entry(snapshot.scope().clone())
            .and_modify(|current| *current = (*current).max(until))
            .or_insert(until);
        failures.insert(snapshot.scope().clone(), 1);
    }
    (cooldowns, failures)
}

fn needs_menu_open_refresh(snapshot: &ProviderSnapshot) -> bool {
    if let Some(error) = snapshot.error() {
        return error.retry() == RetryEligibility::Automatic;
    }
    snapshot.last_known_good().is_none() || !matches!(snapshot.freshness(), Some(Freshness::Fresh))
}

fn usage_reset_boundaries(sample: &UsageSample) -> Vec<Timestamp> {
    sample
        .primary()
        .into_iter()
        .chain(sample.secondary())
        .chain(sample.tertiary())
        .chain(
            sample
                .extra_windows()
                .iter()
                .map(oab_domain::NamedRateWindow::window),
        )
        .filter_map(oab_domain::RateWindow::resets_at)
        .collect()
}

/// Boxed, owned provider operation used by object-safe refresh sources.
pub type RefreshFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Required usage plus optional cost/history acquisition for one provider.
pub trait RefreshSource: Send + Sync + 'static {
    /// Fetches the display-critical usage sample for an exact routing scope.
    fn fetch_required(
        &self,
        scope: AccountScope,
        cancellation: CancellationToken,
    ) -> RefreshFuture<Result<UsageSample, ClassifiedError>>;

    /// Fetches display-critical usage with the admission trigger attached.
    ///
    /// Most sources do not vary their provider operation by trigger and keep
    /// this default. Sources that cache expensive provider-owned CLI results
    /// can override it so an explicit manual refresh bypasses that cache
    /// without weakening the runtime's normal coalescing and backoff rules.
    fn fetch_required_with_trigger(
        &self,
        scope: AccountScope,
        cancellation: CancellationToken,
        _trigger: RefreshTrigger,
    ) -> RefreshFuture<Result<UsageSample, ClassifiedError>> {
        self.fetch_required(scope, cancellation)
    }

    /// Optionally enriches an already successful required sample.
    ///
    /// Optional failure is reported as an event and never invalidates the
    /// required sample. Implementations that have no enrichment may keep this
    /// default.
    fn fetch_optional(
        &self,
        _required: UsageSample,
        _cancellation: CancellationToken,
    ) -> RefreshFuture<Result<Option<CostUsageSnapshot>, ClassifiedError>> {
        Box::pin(async { Ok(None) })
    }
}

/// One exact account scope and its refresh implementation.
#[derive(Clone)]
pub struct RefreshRegistration {
    scope: AccountScope,
    source: Arc<dyn RefreshSource>,
}

impl RefreshRegistration {
    /// Associates `scope` with one refresh implementation.
    #[must_use]
    pub const fn new(scope: AccountScope, source: Arc<dyn RefreshSource>) -> Self {
        Self { scope, source }
    }
}

/// Validated capacities for all bounded actor queues and active required work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLimits {
    command_capacity: NonZeroUsize,
    pending_capacity: NonZeroUsize,
    event_capacity: NonZeroUsize,
    max_in_flight: NonZeroUsize,
}

impl RuntimeLimits {
    /// Validates runtime queue and concurrency limits.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeConfigError::ZeroLimit`] when any value is zero.
    pub fn new(
        command_capacity: usize,
        pending_capacity: usize,
        event_capacity: usize,
        max_in_flight: usize,
    ) -> Result<Self, RuntimeConfigError> {
        Ok(Self {
            command_capacity: nonzero("command_capacity", command_capacity)?,
            pending_capacity: nonzero("pending_capacity", pending_capacity)?,
            event_capacity: nonzero("event_capacity", event_capacity)?,
            max_in_flight: nonzero("max_in_flight", max_in_flight)?,
        })
    }

    /// Bounded external command-channel capacity.
    #[must_use]
    pub const fn command_capacity(self) -> usize {
        self.command_capacity.get()
    }

    /// Maximum registered scopes and therefore maximum distinct pending work.
    #[must_use]
    pub const fn pending_capacity(self) -> usize {
        self.pending_capacity.get()
    }

    /// Bounded broadcast event-channel capacity.
    #[must_use]
    pub const fn event_capacity(self) -> usize {
        self.event_capacity.get()
    }

    /// Maximum concurrently active required-usage operations.
    #[must_use]
    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight.get()
    }
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            command_capacity: NonZeroUsize::new(DEFAULT_COMMAND_CAPACITY)
                .expect("default command capacity is nonzero"),
            pending_capacity: NonZeroUsize::new(DEFAULT_PENDING_CAPACITY)
                .expect("default pending capacity is nonzero"),
            event_capacity: NonZeroUsize::new(DEFAULT_EVENT_CAPACITY)
                .expect("default event capacity is nonzero"),
            max_in_flight: NonZeroUsize::new(DEFAULT_MAX_IN_FLIGHT)
                .expect("default concurrency is nonzero"),
        }
    }
}

/// Actor construction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    schedule: SchedulePolicy,
    limits: RuntimeLimits,
    shutdown_grace: Duration,
}

impl RuntimeConfig {
    /// Creates a validated actor policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the shutdown grace is zero or exceeds 30 seconds.
    pub fn new(
        schedule: SchedulePolicy,
        limits: RuntimeLimits,
        shutdown_grace: Duration,
    ) -> Result<Self, RuntimeConfigError> {
        if shutdown_grace.is_zero() {
            return Err(RuntimeConfigError::ZeroShutdownGrace);
        }
        if shutdown_grace > MAX_SHUTDOWN_GRACE {
            return Err(RuntimeConfigError::ShutdownGraceTooLong {
                maximum: MAX_SHUTDOWN_GRACE,
            });
        }
        Ok(Self {
            schedule,
            limits,
            shutdown_grace,
        })
    }

    /// Refresh scheduling policy.
    #[must_use]
    pub const fn schedule(self) -> SchedulePolicy {
        self.schedule
    }

    /// Queue and concurrency limits.
    #[must_use]
    pub const fn limits(self) -> RuntimeLimits {
        self.limits
    }

    /// Cooperative worker-drain deadline.
    #[must_use]
    pub const fn shutdown_grace(self) -> Duration {
        self.shutdown_grace
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            schedule: SchedulePolicy::default(),
            limits: RuntimeLimits::default(),
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

/// Invalid runtime configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RuntimeConfigError {
    /// One queue or concurrency limit was zero.
    #[error("runtime limit {name} must be nonzero")]
    ZeroLimit { name: &'static str },
    /// A zero grace would not permit cooperative cancellation.
    #[error("runtime shutdown grace must be nonzero")]
    ZeroShutdownGrace,
    /// Excessive grace would violate the runtime's bounded-shutdown contract.
    #[error("runtime shutdown grace exceeds the maximum {maximum:?}")]
    ShutdownGraceTooLong { maximum: Duration },
}

/// Actor construction failure.
#[derive(Debug, Error)]
pub enum RuntimeBuildError {
    /// Two registrations claimed the same exact provider/account scope.
    #[error("runtime contains a duplicate refresh scope")]
    DuplicateScope,
    /// Registration count exceeded the configured distinct-work bound.
    #[error("runtime source count {actual} exceeds pending capacity {maximum}")]
    TooManySources { actual: usize, maximum: usize },
    /// Initial loading-state construction failed.
    #[error(transparent)]
    Snapshot(#[from] SnapshotStoreError),
}

/// Internal actor failure that causes a controlled shutdown.
#[derive(Debug, Error)]
pub enum RuntimeFault {
    /// A snapshot transition or publication invariant failed.
    #[error(transparent)]
    Snapshot(#[from] SnapshotStoreError),
    /// A scope exhausted its checked refresh generation counter.
    #[error("refresh generation counter is exhausted")]
    GenerationExhausted,
}

/// Failure to place a command into the bounded channel immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TryCommandError {
    /// The configured command capacity is currently occupied.
    #[error("runtime command channel is full")]
    Full,
    /// The actor has stopped receiving commands.
    #[error("runtime actor is stopped")]
    Stopped,
}

/// Failure while asynchronously submitting or acknowledging a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("runtime actor is stopped")]
pub struct RuntimeHandleError;

/// Cloneable command and immutable-snapshot interface.
#[derive(Clone)]
pub struct RuntimeHandle {
    commands: mpsc::Sender<RuntimeCommand>,
    snapshots: watch::Receiver<Arc<PublishedSnapshot>>,
    events: broadcast::Sender<RuntimeEvent>,
    shutdown: CancellationToken,
}

impl RuntimeHandle {
    /// Subscribes to the current immutable state and all later publications.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Arc<PublishedSnapshot>> {
        self.snapshots.clone()
    }

    /// Subscribes to bounded runtime lifecycle events.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.events.subscribe()
    }

    /// Immediately submits a refresh or reports command-channel backpressure.
    ///
    /// # Errors
    ///
    /// Returns [`TryCommandError::Full`] when capacity is occupied or
    /// [`TryCommandError::Stopped`] after actor shutdown.
    pub fn try_refresh(
        &self,
        scope: AccountScope,
        trigger: RefreshTrigger,
    ) -> Result<RefreshReceipt, TryCommandError> {
        let (response, receiver) = oneshot::channel();
        let command = RuntimeCommand::Refresh {
            scope,
            trigger,
            response,
        };
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TryCommandError::Full,
                mpsc::error::TrySendError::Closed(_) => TryCommandError::Stopped,
            })?;
        Ok(RefreshReceipt::new(receiver))
    }

    /// Submits a refresh with bounded-channel backpressure.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeHandleError`] if the actor has stopped.
    pub async fn refresh(
        &self,
        scope: AccountScope,
        trigger: RefreshTrigger,
    ) -> Result<RefreshAdmission, RuntimeHandleError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(RuntimeCommand::Refresh {
                scope,
                trigger,
                response,
            })
            .await
            .map_err(|_| RuntimeHandleError)?;
        receiver.await.map_err(|_| RuntimeHandleError)
    }

    /// Updates scheduler cadence when the popup opens or closes.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeHandleError`] if the actor has stopped.
    pub async fn set_popup_open(&self, open: bool) -> Result<(), RuntimeHandleError> {
        let receipt = self
            .try_set_popup_open(open)
            .map_err(|_| RuntimeHandleError)?;
        receipt.applied().await.map_err(|_| RuntimeHandleError)
    }

    /// Immediately submits a popup-state command.
    ///
    /// # Errors
    ///
    /// Reports command-channel saturation or actor shutdown.
    pub fn try_set_popup_open(&self, open: bool) -> Result<CommandReceipt, TryCommandError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .try_send(RuntimeCommand::PopupOpen { open, response })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TryCommandError::Full,
                mpsc::error::TrySendError::Closed(_) => TryCommandError::Stopped,
            })?;
        Ok(CommandReceipt::new(receiver))
    }

    /// Immediately submits a provider reset boundary to the scheduler.
    ///
    /// # Errors
    ///
    /// Reports command-channel saturation or actor shutdown. Projection errors
    /// are delivered by the returned receipt.
    pub fn try_schedule_reset(
        &self,
        scope: AccountScope,
        boundary: Timestamp,
    ) -> Result<ResetScheduleReceipt, TryCommandError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .try_send(RuntimeCommand::ScheduleReset {
                scope,
                boundary,
                response,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TryCommandError::Full,
                mpsc::error::TrySendError::Closed(_) => TryCommandError::Stopped,
            })?;
        Ok(ResetScheduleReceipt::new(receiver))
    }

    /// Requests cooperative runtime shutdown without waiting for completion.
    pub fn request_shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Single-owner state machine. Construct it before spawning to make bounded
/// command-channel behavior deterministic in tests and embedding code.
pub struct RuntimeActor {
    config: RuntimeConfig,
    clock: Arc<dyn Clock>,
    scheduler: Scheduler,
    sources: BTreeMap<AccountScope, Arc<dyn RefreshSource>>,
    store: SnapshotStore,
    commands: mpsc::Receiver<RuntimeCommand>,
    commands_open: bool,
    events: broadcast::Sender<RuntimeEvent>,
    shutdown: CancellationToken,
    workers: JoinSet<WorkerExit>,
    work_metadata: HashMap<Id, WorkMetadata>,
    active_required: BTreeMap<AccountScope, u64>,
    active_optional: BTreeMap<AccountScope, OptionalWork>,
    pending: VecDeque<(AccountScope, RefreshTrigger)>,
    pending_scopes: BTreeSet<AccountScope>,
    generations: BTreeMap<AccountScope, u64>,
    automatic_cooldowns: BTreeMap<AccountScope, Instant>,
    automatic_failures: BTreeMap<AccountScope, u8>,
    automatic_last_attempts: BTreeMap<AccountScope, Instant>,
}

impl RuntimeActor {
    /// Builds an unspawned actor and a handle with an initial sequence-one
    /// loading publication.
    ///
    /// # Errors
    ///
    /// Rejects duplicate scopes, a registration count above the configured
    /// pending bound, or invalid initial snapshot state.
    pub fn new(
        config: RuntimeConfig,
        clock: Arc<dyn Clock>,
        registrations: impl IntoIterator<Item = RefreshRegistration>,
    ) -> Result<(Self, RuntimeHandle), RuntimeBuildError> {
        Self::new_with_retained(config, clock, registrations, std::iter::empty())
    }

    /// Builds an actor whose exact-scope last-known-good samples are restored
    /// before the first live refresh begins.
    ///
    /// Unavailable, loading, cross-scope, and error state is discarded. A
    /// retained sample starts stale and becomes fresh only after a successful
    /// provider fetch.
    ///
    /// # Errors
    ///
    /// Rejects duplicate scopes, excessive registrations, or invalid retained
    /// snapshot state.
    pub fn new_with_retained(
        config: RuntimeConfig,
        clock: Arc<dyn Clock>,
        registrations: impl IntoIterator<Item = RefreshRegistration>,
        retained: impl IntoIterator<Item = ProviderSnapshot>,
    ) -> Result<(Self, RuntimeHandle), RuntimeBuildError> {
        let mut sources = BTreeMap::new();
        for registration in registrations {
            if sources
                .insert(registration.scope, registration.source)
                .is_some()
            {
                return Err(RuntimeBuildError::DuplicateScope);
            }
        }
        if sources.len() > config.limits.pending_capacity() {
            return Err(RuntimeBuildError::TooManySources {
                actual: sources.len(),
                maximum: config.limits.pending_capacity(),
            });
        }

        let retained = retained.into_iter().collect::<Vec<_>>();
        let wall_now = clock.wall_now();
        let (automatic_cooldowns, automatic_failures) =
            retained_automatic_backoff(&retained, wall_now, clock.monotonic_now());
        let store = SnapshotStore::new_with_retained(sources.keys().cloned(), retained, wall_now)?;
        let snapshots = store.subscribe();
        let (command_sender, commands) = mpsc::channel(config.limits.command_capacity());
        let (events, _event_receiver) = broadcast::channel(config.limits.event_capacity());
        let shutdown = CancellationToken::new();
        let scheduler = Scheduler::new(config.schedule, clock.as_ref());
        let handle = RuntimeHandle {
            commands: command_sender,
            snapshots,
            events: events.clone(),
            shutdown: shutdown.clone(),
        };
        Ok((
            Self {
                config,
                clock,
                scheduler,
                sources,
                store,
                commands,
                commands_open: true,
                events,
                shutdown,
                workers: JoinSet::new(),
                work_metadata: HashMap::new(),
                active_required: BTreeMap::new(),
                active_optional: BTreeMap::new(),
                pending: VecDeque::new(),
                pending_scopes: BTreeSet::new(),
                generations: BTreeMap::new(),
                automatic_cooldowns,
                automatic_failures,
                automatic_last_attempts: BTreeMap::new(),
            },
            handle,
        ))
    }

    /// Spawns the actor on the current Tokio runtime.
    #[must_use]
    pub fn spawn(self) -> RuntimeTask {
        let shutdown = self.shutdown.clone();
        let grace = self.config.shutdown_grace;
        RuntimeTask {
            shutdown,
            grace,
            join: Some(tokio::spawn(self.run())),
        }
    }

    async fn run(mut self) -> RuntimeExit {
        let mut fault = None;
        loop {
            let deadline = self.scheduler.next_deadline();
            let input = tokio::select! {
                biased;
                () = self.shutdown.cancelled() => ActorInput::Shutdown,
                joined = self.workers.join_next_with_id(), if !self.workers.is_empty() => {
                    ActorInput::Worker(Box::new(
                        joined.expect("a nonempty join set yields one result"),
                    ))
                }
                command = self.commands.recv(), if self.commands_open => {
                    ActorInput::Command(command)
                }
                () = wait_for_deadline(deadline) => ActorInput::ScheduleDue,
            };

            let result = match input {
                ActorInput::Shutdown => break,
                ActorInput::Worker(joined) => self.handle_worker_result(*joined),
                ActorInput::Command(Some(command)) => self.handle_command(command),
                ActorInput::Command(None) => {
                    self.commands_open = false;
                    Ok(())
                }
                ActorInput::ScheduleDue => self.handle_schedule_due(),
            };
            if let Err(error) = result {
                fault = Some(error);
                break;
            }
        }

        for optional in self.active_optional.values() {
            optional.cancellation.cancel();
        }
        let shutdown = cancel_and_drain(
            &self.shutdown,
            &mut self.workers,
            self.config.shutdown_grace,
        )
        .await;
        RuntimeExit { shutdown, fault }
    }

    fn handle_command(&mut self, command: RuntimeCommand) -> Result<(), RuntimeFault> {
        match command {
            RuntimeCommand::Refresh {
                scope,
                trigger,
                response,
            } => {
                let admission = self.admit_refresh(scope, trigger)?;
                let _ignored = response.send(admission);
            }
            RuntimeCommand::PopupOpen { open, response } => {
                let transitioned = self.scheduler.set_popup_open(open, self.clock.as_ref());
                if transitioned && open {
                    let retry_scopes = self
                        .sources
                        .keys()
                        .filter(|scope| {
                            self.store
                                .snapshot(scope)
                                .is_some_and(needs_menu_open_refresh)
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for scope in retry_scopes {
                        self.admit_refresh(scope, RefreshTrigger::MenuOpen)?;
                    }
                }
                let _ignored = response.send(());
            }
            RuntimeCommand::ScheduleReset {
                scope,
                boundary,
                response,
            } => {
                if !self.sources.contains_key(&scope) {
                    let _ignored = response.send(Ok(ResetScheduleAdmission::UnknownScope));
                    return Ok(());
                }
                let result = self
                    .scheduler
                    .schedule_reset(scope.clone(), boundary, self.clock.as_ref())
                    .map(|changed| {
                        if changed {
                            ResetScheduleAdmission::Armed
                        } else {
                            ResetScheduleAdmission::Unchanged
                        }
                    });
                if matches!(result, Ok(ResetScheduleAdmission::Armed)) {
                    let generated_at = self.clock.wall_now();
                    self.store.mark_scheduled(&scope, boundary, generated_at)?;
                }
                let _ignored = response.send(result);
            }
        }
        Ok(())
    }

    fn handle_schedule_due(&mut self) -> Result<(), RuntimeFault> {
        for refresh in self.scheduler.take_due(self.clock.as_ref()) {
            match refresh {
                ScheduledRefresh::Periodic => {
                    let scopes: Vec<_> = self.sources.keys().cloned().collect();
                    for scope in scopes {
                        self.admit_refresh(scope, RefreshTrigger::Periodic)?;
                    }
                }
                ScheduledRefresh::ResetBoundary { scope, boundary } => {
                    self.admit_refresh(scope, RefreshTrigger::ResetBoundary { boundary })?;
                }
            }
        }
        Ok(())
    }

    fn admit_refresh(
        &mut self,
        scope: AccountScope,
        trigger: RefreshTrigger,
    ) -> Result<RefreshAdmission, RuntimeFault> {
        if !self.sources.contains_key(&scope) {
            return Ok(RefreshAdmission::UnknownScope);
        }
        if self.active_required.contains_key(&scope) || self.pending_scopes.contains(&scope) {
            return Ok(RefreshAdmission::Coalesced);
        }
        if !matches!(trigger, RefreshTrigger::Manual)
            && self
                .automatic_cooldowns
                .get(&scope)
                .is_some_and(|until| *until > self.clock.monotonic_now())
        {
            return Ok(RefreshAdmission::Coalesced);
        }
        if matches!(trigger, RefreshTrigger::Periodic)
            && self
                .automatic_last_attempts
                .get(&scope)
                .is_some_and(|last| {
                    *last + automatic_minimum_interval(scope.provider())
                        > self.clock.monotonic_now()
                })
        {
            return Ok(RefreshAdmission::Coalesced);
        }
        if self.active_required.len() < self.config.limits.max_in_flight() {
            self.start_required(scope, trigger)?;
            return Ok(RefreshAdmission::Started);
        }

        let scheduled_at = self.clock.wall_now();
        self.store
            .mark_scheduled(&scope, scheduled_at, scheduled_at)?;
        let inserted = self.pending_scopes.insert(scope.clone());
        debug_assert!(inserted, "a non-coalesced scope must be newly pending");
        self.pending.push_back((scope, trigger));
        Ok(RefreshAdmission::Queued)
    }

    fn start_required(
        &mut self,
        scope: AccountScope,
        trigger: RefreshTrigger,
    ) -> Result<(), RuntimeFault> {
        self.automatic_last_attempts
            .insert(scope.clone(), self.clock.monotonic_now());
        self.cancel_optional(&scope);
        let generation = self.next_generation(&scope)?;
        let source = Arc::clone(
            self.sources
                .get(&scope)
                .expect("admission verifies that the exact source exists"),
        );
        let cancellation = self.shutdown.child_token();
        let generated_at = self.clock.wall_now();
        self.store
            .mark_refreshing(&scope, generated_at, generated_at)?;
        self.active_required.insert(scope.clone(), generation);

        let worker_scope = scope.clone();
        let abort = self.workers.spawn(async move {
            let result = source
                .fetch_required_with_trigger(worker_scope.clone(), cancellation, trigger)
                .await;
            WorkerExit::Required {
                scope: worker_scope,
                generation,
                result: Box::new(result),
            }
        });
        self.work_metadata.insert(
            abort.id(),
            WorkMetadata::Required {
                scope: scope.clone(),
                generation,
            },
        );
        self.emit(RuntimeEvent::RefreshStarted {
            scope,
            generation,
            trigger,
        });
        Ok(())
    }

    fn spawn_optional(&mut self, scope: AccountScope, generation: u64, sample: UsageSample) {
        self.cancel_optional(&scope);
        let source = Arc::clone(
            self.sources
                .get(&scope)
                .expect("a successful required worker retains its registered source"),
        );
        let cancellation = self.shutdown.child_token();
        let worker_cancellation = cancellation.clone();
        let base_fetched_at = sample.fetched_at();
        let worker_scope = scope.clone();
        let abort = self.workers.spawn(async move {
            let result = source.fetch_optional(sample, worker_cancellation).await;
            WorkerExit::Optional {
                scope: worker_scope,
                generation,
                base_fetched_at,
                result: Box::new(result),
            }
        });
        self.work_metadata.insert(
            abort.id(),
            WorkMetadata::Optional {
                scope: scope.clone(),
                generation,
            },
        );
        self.active_optional.insert(
            scope,
            OptionalWork {
                generation,
                cancellation,
                abort,
            },
        );
    }

    fn handle_worker_result(
        &mut self,
        joined: Result<(Id, WorkerExit), JoinError>,
    ) -> Result<(), RuntimeFault> {
        match joined {
            Ok((id, exit)) => {
                self.work_metadata.remove(&id);
                match exit {
                    WorkerExit::Required {
                        scope,
                        generation,
                        result,
                    } => self.handle_required(scope, generation, *result),
                    WorkerExit::Optional {
                        scope,
                        generation,
                        base_fetched_at,
                        result,
                    } => self.handle_optional(scope, generation, base_fetched_at, *result),
                }
            }
            Err(error) => {
                let metadata = self.work_metadata.remove(&error.id());
                self.handle_abnormal_worker(metadata, &error)
            }
        }
    }

    fn handle_required(
        &mut self,
        scope: AccountScope,
        generation: u64,
        result: Result<UsageSample, ClassifiedError>,
    ) -> Result<(), RuntimeFault> {
        if !self.required_is_current(&scope, generation) {
            return Ok(());
        }

        match result {
            Ok(sample) if sample.scope() == &scope => {
                self.automatic_cooldowns.remove(&scope);
                self.automatic_failures.remove(&scope);
                let optional_sample = sample.clone();
                let generated_at = self.clock.wall_now();
                self.store.apply_success(&scope, sample, generated_at)?;
                self.reconcile_reset_boundaries(&scope);
                self.emit(RuntimeEvent::RequiredUsagePublished {
                    scope: scope.clone(),
                    generation,
                });
                self.finish_required(&scope, generation)?;
                self.spawn_optional(scope, generation, optional_sample);
            }
            Ok(_) => {
                let error = ClassifiedError::new(ErrorKind::Parse);
                self.publish_required_failure(&scope, generation, error)?;
                self.finish_required(&scope, generation)?;
            }
            Err(error) => {
                self.record_automatic_backoff(&scope, &error);
                if error.retry() != RetryEligibility::Automatic {
                    self.clear_reset_boundary(&scope);
                }
                self.publish_required_failure(&scope, generation, error)?;
                self.finish_required(&scope, generation)?;
            }
        }
        Ok(())
    }

    fn record_automatic_backoff(&mut self, scope: &AccountScope, error: &ClassifiedError) {
        let failures = self
            .automatic_failures
            .entry(scope.clone())
            .and_modify(|value| *value = value.saturating_add(1).min(6))
            .or_insert(1);
        let Some(delay) = automatic_backoff_delay(error, *failures) else {
            self.automatic_failures.remove(scope);
            self.automatic_cooldowns.remove(scope);
            return;
        };
        self.automatic_cooldowns
            .insert(scope.clone(), self.clock.monotonic_now() + delay);
    }

    fn reconcile_reset_boundaries(&mut self, scope: &AccountScope) {
        let Some(sample) = self
            .store
            .snapshot(scope)
            .and_then(ProviderSnapshot::last_known_good)
            .cloned()
        else {
            self.clear_reset_boundary(scope);
            return;
        };
        let boundaries = usage_reset_boundaries(&sample);
        let _ignored = self.scheduler.reconcile_reset_boundaries(
            scope.clone(),
            boundaries,
            sample.fetched_at(),
            self.clock.as_ref(),
        );
    }

    fn clear_reset_boundary(&mut self, scope: &AccountScope) {
        let _ignored = self.scheduler.reconcile_reset_boundaries(
            scope.clone(),
            std::iter::empty(),
            self.clock.wall_now(),
            self.clock.as_ref(),
        );
    }

    fn handle_optional(
        &mut self,
        scope: AccountScope,
        generation: u64,
        base_fetched_at: Timestamp,
        result: Result<Option<CostUsageSnapshot>, ClassifiedError>,
    ) -> Result<(), RuntimeFault> {
        if !self.optional_is_current(&scope, generation) {
            return Ok(());
        }
        self.active_optional.remove(&scope);
        match result {
            Ok(Some(cost_usage)) => {
                let generated_at = self.clock.wall_now();
                if self
                    .store
                    .apply_cost_usage(&scope, base_fetched_at, cost_usage, generated_at)?
                {
                    self.emit(RuntimeEvent::OptionalEnrichmentPublished { scope, generation });
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.emit(RuntimeEvent::OptionalEnrichmentFailed {
                    scope,
                    generation,
                    error,
                });
            }
        }
        Ok(())
    }

    fn handle_abnormal_worker(
        &mut self,
        metadata: Option<WorkMetadata>,
        error: &JoinError,
    ) -> Result<(), RuntimeFault> {
        let Some(metadata) = metadata else {
            return Ok(());
        };
        match metadata {
            WorkMetadata::Required { scope, generation }
                if self.required_is_current(&scope, generation) =>
            {
                let classified = ClassifiedError::new(ErrorKind::ProviderUnavailable);
                self.record_automatic_backoff(&scope, &classified);
                self.publish_required_failure(&scope, generation, classified)?;
                self.finish_required(&scope, generation)?;
            }
            WorkMetadata::Optional { scope, generation }
                if self.optional_is_current(&scope, generation) =>
            {
                self.active_optional.remove(&scope);
                if !error.is_cancelled() {
                    self.emit(RuntimeEvent::OptionalEnrichmentFailed {
                        scope,
                        generation,
                        error: ClassifiedError::new(ErrorKind::ProviderUnavailable),
                    });
                }
            }
            WorkMetadata::Required { .. } | WorkMetadata::Optional { .. } => {}
        }
        Ok(())
    }

    fn publish_required_failure(
        &mut self,
        scope: &AccountScope,
        generation: u64,
        error: ClassifiedError,
    ) -> Result<(), RuntimeFault> {
        let generated_at = self.clock.wall_now();
        self.store
            .apply_failure(scope, error.clone(), generated_at)?;
        self.emit(RuntimeEvent::RequiredUsageFailed {
            scope: scope.clone(),
            generation,
            error,
        });
        Ok(())
    }

    fn finish_required(
        &mut self,
        scope: &AccountScope,
        generation: u64,
    ) -> Result<(), RuntimeFault> {
        if self.required_is_current(scope, generation) {
            self.active_required.remove(scope);
            self.emit(RuntimeEvent::RefreshFinished {
                scope: scope.clone(),
                generation,
            });
            self.fill_required_slots()?;
        }
        Ok(())
    }

    fn fill_required_slots(&mut self) -> Result<(), RuntimeFault> {
        while self.active_required.len() < self.config.limits.max_in_flight() {
            let Some((scope, trigger)) = self.pending.pop_front() else {
                break;
            };
            let removed = self.pending_scopes.remove(&scope);
            debug_assert!(
                removed,
                "pending queue and membership set stay synchronized"
            );
            self.start_required(scope, trigger)?;
        }
        Ok(())
    }

    fn next_generation(&mut self, scope: &AccountScope) -> Result<u64, RuntimeFault> {
        let next = self
            .generations
            .get(scope)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RuntimeFault::GenerationExhausted)?;
        self.generations.insert(scope.clone(), next);
        Ok(next)
    }

    fn cancel_optional(&mut self, scope: &AccountScope) {
        if let Some(optional) = self.active_optional.remove(scope) {
            optional.cancellation.cancel();
            optional.abort.abort();
        }
    }

    fn required_is_current(&self, scope: &AccountScope, generation: u64) -> bool {
        self.active_required.get(scope).copied() == Some(generation)
    }

    fn optional_is_current(&self, scope: &AccountScope, generation: u64) -> bool {
        self.active_optional
            .get(scope)
            .is_some_and(|work| work.generation == generation)
    }

    fn emit(&self, event: RuntimeEvent) {
        let _ignored = self.events.send(event);
    }
}

enum ActorInput {
    Shutdown,
    Command(Option<RuntimeCommand>),
    Worker(Box<Result<(Id, WorkerExit), JoinError>>),
    ScheduleDue,
}

enum WorkerExit {
    Required {
        scope: AccountScope,
        generation: u64,
        result: Box<Result<UsageSample, ClassifiedError>>,
    },
    Optional {
        scope: AccountScope,
        generation: u64,
        base_fetched_at: Timestamp,
        result: Box<Result<Option<CostUsageSnapshot>, ClassifiedError>>,
    },
}

enum WorkMetadata {
    Required {
        scope: AccountScope,
        generation: u64,
    },
    Optional {
        scope: AccountScope,
        generation: u64,
    },
}

struct OptionalWork {
    generation: u64,
    cancellation: CancellationToken,
    abort: AbortHandle,
}

async fn wait_for_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn nonzero(name: &'static str, value: usize) -> Result<NonZeroUsize, RuntimeConfigError> {
    NonZeroUsize::new(value).ok_or(RuntimeConfigError::ZeroLimit { name })
}

/// Clean actor termination, including bounded worker-drain accounting.
#[derive(Debug)]
pub struct RuntimeExit {
    shutdown: ShutdownReport,
    fault: Option<RuntimeFault>,
}

impl RuntimeExit {
    /// Worker completion, cancellation, panic, and timeout counts.
    #[must_use]
    pub const fn shutdown_report(&self) -> &ShutdownReport {
        &self.shutdown
    }

    /// Controlled internal fault, if one ended the actor.
    #[must_use]
    pub const fn fault(&self) -> Option<&RuntimeFault> {
        self.fault.as_ref()
    }
}

/// Owned actor task with cooperative shutdown and drop-abort safety.
#[derive(Debug)]
pub struct RuntimeTask {
    shutdown: CancellationToken,
    grace: Duration,
    join: Option<JoinHandle<RuntimeExit>>,
}

impl RuntimeTask {
    /// Requests shutdown and waits for the actor's bounded worker drain.
    ///
    /// # Errors
    ///
    /// Returns the Tokio join error if the actor itself panics or is aborted.
    pub async fn shutdown(mut self) -> Result<RuntimeExit, RuntimeJoinError> {
        self.shutdown.cancel();
        self.take_join().await
    }

    /// Waits for shutdown requested through a cloned [`RuntimeHandle`].
    ///
    /// # Errors
    ///
    /// Returns the Tokio join error if the actor itself panics or is aborted.
    pub async fn join(mut self) -> Result<RuntimeExit, RuntimeJoinError> {
        self.take_join().await
    }

    /// Configured cooperative worker-drain grace.
    #[must_use]
    pub const fn shutdown_grace(&self) -> Duration {
        self.grace
    }

    async fn take_join(&mut self) -> Result<RuntimeExit, RuntimeJoinError> {
        self.join
            .take()
            .expect("runtime task join handle is consumed exactly once")
            .await
            .map_err(RuntimeJoinError)
    }
}

impl Drop for RuntimeTask {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(join) = &self.join {
            join.abort();
        }
    }
}

/// Tokio-level actor task failure.
#[derive(Debug, Error)]
#[error("runtime actor task failed")]
pub struct RuntimeJoinError(#[source] JoinError);

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn provider_level_automatic_admission_floors_remain_bounded() {
        assert_eq!(
            automatic_minimum_interval(ProviderId::Claude),
            Duration::from_mins(2)
        );
        assert_eq!(
            automatic_minimum_interval(ProviderId::Grok),
            Duration::from_mins(5)
        );
    }
}
