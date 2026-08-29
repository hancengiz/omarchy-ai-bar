//! Trait-neutral scripted provider behavior for deterministic runtime tests.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oab_domain::{AccountScope, ClassifiedError, CostUsageSnapshot, ErrorKind, UsageSample};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Whether a scripted call observes runtime cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationBehavior {
    /// Cancellation ends the call with a normalized provider-unavailable error.
    Cooperative,
    /// Cancellation is ignored, allowing deadline/abort behavior to be tested.
    Ignore,
}

/// A manually opened gate shared by one or more scripted calls.
#[derive(Debug, Clone)]
pub struct FakeGate {
    inner: Arc<FakeGateInner>,
}

#[derive(Debug)]
struct FakeGateInner {
    open: AtomicBool,
    notify: Notify,
}

impl FakeGate {
    /// Creates a closed gate.
    #[must_use]
    pub fn closed() -> Self {
        Self {
            inner: Arc::new(FakeGateInner {
                open: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Creates an open gate.
    #[must_use]
    pub fn open() -> Self {
        let gate = Self::closed();
        gate.release();
        gate
    }

    /// Opens the gate permanently and wakes all current waiters.
    pub fn release(&self) {
        self.inner.open.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    /// Reports whether the gate has been opened.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.inner.open.load(Ordering::Acquire)
    }

    async fn wait(&self) {
        while !self.is_open() {
            let notified = self.inner.notify.notified();
            if self.is_open() {
                break;
            }
            notified.await;
        }
    }
}

impl Default for FakeGate {
    fn default() -> Self {
        Self::closed()
    }
}

/// One queued provider result with deterministic delay and optional gating.
#[derive(Debug, Clone)]
pub struct ScriptedStep<T> {
    delay: Duration,
    gate: Option<FakeGate>,
    cancellation: CancellationBehavior,
    result: Result<T, ClassifiedError>,
}

impl<T> ScriptedStep<T> {
    /// Creates an immediately available successful result.
    pub fn success(value: T) -> Self {
        Self {
            delay: Duration::ZERO,
            gate: None,
            cancellation: CancellationBehavior::Cooperative,
            result: Ok(value),
        }
    }

    /// Creates an immediately available classified failure.
    #[must_use]
    pub fn failure(error: ClassifiedError) -> Self {
        Self {
            delay: Duration::ZERO,
            gate: None,
            cancellation: CancellationBehavior::Cooperative,
            result: Err(error),
        }
    }

    /// Delays the scripted result using Tokio's monotonic clock.
    #[must_use]
    pub const fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Holds the scripted result until `gate` is released.
    #[must_use]
    pub fn behind(mut self, gate: FakeGate) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Selects whether cancellation is cooperative or intentionally ignored.
    #[must_use]
    pub const fn cancellation(mut self, behavior: CancellationBehavior) -> Self {
        self.cancellation = behavior;
        self
    }
}

/// Script queues and counters shared by thin provider-trait adapters in tests.
#[derive(Debug, Default)]
pub struct ScriptedProvider {
    required: Mutex<VecDeque<ScriptedStep<UsageSample>>>,
    optional: Mutex<VecDeque<ScriptedStep<Option<CostUsageSnapshot>>>>,
    required_calls: AtomicUsize,
    optional_calls: AtomicUsize,
    optional_inputs: Mutex<Vec<UsageSample>>,
}

impl ScriptedProvider {
    /// Creates empty required and optional queues.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one required-usage result to the back of the queue.
    pub fn push_required(&self, step: ScriptedStep<UsageSample>) {
        self.required
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(step);
    }

    /// Adds one optional-enrichment result to the back of the queue.
    pub fn push_optional(&self, step: ScriptedStep<Option<CostUsageSnapshot>>) {
        self.optional
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(step);
    }

    /// Number of required calls started by adapters.
    #[must_use]
    pub fn required_calls(&self) -> usize {
        self.required_calls.load(Ordering::Acquire)
    }

    /// Number of optional calls started by adapters.
    #[must_use]
    pub fn optional_calls(&self) -> usize {
        self.optional_calls.load(Ordering::Acquire)
    }

    /// Required samples passed into optional enrichment, in call order.
    #[must_use]
    pub fn optional_inputs(&self) -> Vec<UsageSample> {
        self.optional_inputs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Executes the next required step.
    ///
    /// # Errors
    ///
    /// Returns the queued classified error, a safe fallback when the queue is
    /// empty, or a provider-unavailable error after cooperative cancellation.
    pub async fn run_required(
        &self,
        _scope: AccountScope,
        cancellation: CancellationToken,
    ) -> Result<UsageSample, ClassifiedError> {
        self.required_calls.fetch_add(1, Ordering::AcqRel);
        let step = self
            .required
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| {
                ScriptedStep::failure(ClassifiedError::new(ErrorKind::ProviderUnavailable))
            });
        run_step(step, cancellation).await
    }

    /// Executes the next optional step.
    ///
    /// # Errors
    ///
    /// Returns the queued classified error or a provider-unavailable error
    /// after cooperative cancellation. An empty optional queue means that the
    /// source has no optional enrichment and succeeds with `None`.
    pub async fn run_optional(
        &self,
        sample: UsageSample,
        cancellation: CancellationToken,
    ) -> Result<Option<CostUsageSnapshot>, ClassifiedError> {
        self.optional_calls.fetch_add(1, Ordering::AcqRel);
        self.optional_inputs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(sample);
        let step = self
            .optional
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| ScriptedStep::success(None));
        run_step(step, cancellation).await
    }
}

async fn run_step<T>(
    step: ScriptedStep<T>,
    cancellation: CancellationToken,
) -> Result<T, ClassifiedError> {
    let wait = async {
        if !step.delay.is_zero() {
            tokio::time::sleep(step.delay).await;
        }
        if let Some(gate) = &step.gate {
            gate.wait().await;
        }
    };

    match step.cancellation {
        CancellationBehavior::Cooperative => {
            tokio::select! {
                () = wait => step.result,
                () = cancellation.cancelled() => {
                    Err(ClassifiedError::new(ErrorKind::ProviderUnavailable))
                }
            }
        }
        CancellationBehavior::Ignore => {
            wait.await;
            step.result
        }
    }
}
