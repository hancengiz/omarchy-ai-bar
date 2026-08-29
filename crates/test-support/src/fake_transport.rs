//! Trait-neutral queued transport fake with deterministic request capture.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;

use tokio::sync::Mutex;

/// Failure returned by [`FakeTransport::send`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeTransportError<Failure> {
    /// A failure deliberately supplied by the script.
    Scripted(Failure),
    /// No scripted response remained for the captured request.
    Exhausted,
}

impl<Failure> Display for FakeTransportError<Failure>
where
    Failure: Display,
{
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scripted(failure) => write!(formatter, "scripted transport failure: {failure}"),
            Self::Exhausted => formatter.write_str("fake transport script is exhausted"),
        }
    }
}

impl<Failure> Error for FakeTransportError<Failure> where Failure: Error + 'static {}

impl<Failure> FakeTransportError<Failure> {
    /// Returns the scripted failure, or `None` for script exhaustion.
    #[must_use]
    pub fn into_scripted(self) -> Option<Failure> {
        match self {
            Self::Scripted(failure) => Some(failure),
            Self::Exhausted => None,
        }
    }
}

/// A clonable scripted endpoint independent of any production transport trait.
///
/// Clones share both the FIFO response script and captured-request history.
/// Every call records its request before consuming one result. The Tokio mutex
/// gives concurrent tests a single explicit ordering without blocking an
/// executor thread.
pub struct FakeTransport<Request, Response, Failure> {
    state: Arc<Mutex<State<Request, Response, Failure>>>,
}

impl<Request, Response, Failure> Clone for FakeTransport<Request, Response, Failure> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<Request, Response, Failure> Debug for FakeTransport<Request, Response, Failure> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeTransport")
            .field("state", &"<shared scripted state>")
            .finish()
    }
}

impl<Request, Response, Failure> Default for FakeTransport<Request, Response, Failure> {
    fn default() -> Self {
        Self::new([])
    }
}

impl<Request, Response, Failure> FakeTransport<Request, Response, Failure> {
    /// Creates a fake whose FIFO script is shared by every clone.
    pub fn new(script: impl IntoIterator<Item = Result<Response, Failure>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                script: script.into_iter().collect(),
                requests: Vec::new(),
            })),
        }
    }

    /// Captures `request` and consumes the next scripted result.
    ///
    /// # Errors
    ///
    /// Returns [`FakeTransportError::Scripted`] for an explicit scripted
    /// failure or [`FakeTransportError::Exhausted`] when the queue is empty.
    pub async fn send(&self, request: Request) -> Result<Response, FakeTransportError<Failure>> {
        let mut state = self.state.lock().await;
        state.requests.push(request);
        state
            .script
            .pop_front()
            .ok_or(FakeTransportError::Exhausted)?
            .map_err(FakeTransportError::Scripted)
    }

    /// Adds one result to the back of the shared FIFO script.
    pub async fn push(&self, result: Result<Response, Failure>) {
        self.state.lock().await.script.push_back(result);
    }

    /// Number of responses not yet consumed.
    pub async fn remaining(&self) -> usize {
        self.state.lock().await.script.len()
    }

    /// Returns a snapshot of captured requests in call order.
    pub async fn requests(&self) -> Vec<Request>
    where
        Request: Clone,
    {
        self.state.lock().await.requests.clone()
    }

    /// Removes and returns every captured request in call order.
    pub async fn take_requests(&self) -> Vec<Request> {
        std::mem::take(&mut self.state.lock().await.requests)
    }
}

struct State<Request, Response, Failure> {
    script: VecDeque<Result<Response, Failure>>,
    requests: Vec<Request>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clones_share_fifo_results_and_request_capture() {
        let transport = FakeTransport::new([Ok::<_, &'static str>(10), Err("offline"), Ok(30)]);
        let clone = transport.clone();

        assert_eq!(transport.send("first").await, Ok(10));
        assert_eq!(
            clone.send("second").await,
            Err(FakeTransportError::Scripted("offline"))
        );
        assert_eq!(transport.send("third").await, Ok(30));
        assert_eq!(
            clone.send("exhausted").await,
            Err(FakeTransportError::Exhausted)
        );
        assert_eq!(
            transport.requests().await,
            vec!["first", "second", "third", "exhausted"]
        );
        assert_eq!(transport.remaining().await, 0);
    }

    #[tokio::test]
    async fn scripts_and_capture_can_be_extended_and_drained() {
        let transport = FakeTransport::<u8, u8, &'static str>::default();
        transport.push(Ok(7)).await;
        assert_eq!(transport.send(1).await, Ok(7));
        assert_eq!(transport.take_requests().await, vec![1]);
        assert!(transport.requests().await.is_empty());
    }
}
