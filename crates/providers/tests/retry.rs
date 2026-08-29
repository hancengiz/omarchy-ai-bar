use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::retry::{RetryClock, RetryPolicy};
use oab_providers::transport::{HttpRequest, HttpTransport, TransportConfig, TransportError};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct RecordingClock {
    now: SystemTime,
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl RecordingClock {
    fn new() -> Self {
        Self {
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
            sleeps: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().expect("sleep record lock").clone()
    }
}

impl RetryClock for RecordingClock {
    fn wall_now(&self) -> SystemTime {
        self.now
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.sleeps
            .lock()
            .expect("sleep record lock")
            .push(duration);
        Box::pin(std::future::ready(()))
    }
}

fn policy(server: &FakeHttpServer) -> EndpointPolicy {
    EndpointPolicy::new([(server.origin().as_str(), EndpointClass::LoopbackDevelopment)])
        .expect("fake-server policy")
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        1024,
        0,
        RetryPolicy::one(Duration::from_secs(2), Duration::from_secs(30)),
    )
    .expect("retry config")
}

#[test]
fn retry_configuration_rejects_unordered_or_excessive_delays() {
    for retry in [
        RetryPolicy::one(Duration::from_secs(2), Duration::from_secs(1)),
        RetryPolicy::one(Duration::from_secs(1), Duration::from_secs(3_601)),
    ] {
        assert!(matches!(
            TransportConfig::new(
                Duration::from_millis(250),
                Duration::from_millis(250),
                1024,
                0,
                retry,
            ),
            Err(TransportError::InvalidConfiguration)
        ));
    }
}

#[tokio::test]
async fn retry_after_is_honored_once_under_a_fake_clock() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(200, b"ok".to_vec()),
    ])
    .await;
    let clock = RecordingClock::new();
    let transport = HttpTransport::with_clock(policy(&server), config(), clock.clone())
        .expect("HTTP transport");

    let response = transport
        .send(
            &HttpRequest::get(server.url("/retry")),
            &CancellationToken::new(),
        )
        .await
        .expect("one retry succeeds");
    assert_eq!(response.body(), b"ok");
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(7)]);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn retry_after_http_date_uses_the_injected_wall_clock() {
    let clock = RecordingClock::new();
    let retry_at = clock.now + Duration::from_secs(9);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new())
            .header("Retry-After", httpdate::fmt_http_date(retry_at)),
        FakeHttpResponse::new(200, b"ok".to_vec()),
    ])
    .await;
    let transport = HttpTransport::with_clock(policy(&server), config(), clock.clone())
        .expect("HTTP transport");

    let response = transport
        .send(
            &HttpRequest::get(server.url("/date-retry")),
            &CancellationToken::new(),
        )
        .await
        .expect("HTTP-date retry succeeds");
    assert_eq!(response.body(), b"ok");
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(9)]);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn retry_budget_never_attempts_a_third_request() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::new(200, b"must-not-run".to_vec()),
    ])
    .await;
    let clock = RecordingClock::new();
    let transport = HttpTransport::with_clock(policy(&server), config(), clock.clone())
        .expect("HTTP transport");

    assert!(matches!(
        transport
            .send(
                &HttpRequest::get(server.url("/retry")),
                &CancellationToken::new()
            )
            .await,
        Err(TransportError::ProviderUnavailable { status: 503, .. })
    ));
    assert_eq!(server.requests().len(), 2);
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(2)]);
}
