use std::time::Duration;

use oab_domain::ErrorKind;
use oab_providers::context::{FetchOutcome, preserve_last_good};
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{
    Authentication, HttpRequest, HttpTransport, TransportConfig, TransportError,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        64 * 1024,
        3,
        RetryPolicy::none(),
    )
    .expect("transport config")
}

fn policy(server: &FakeHttpServer) -> EndpointPolicy {
    EndpointPolicy::new([(server.origin().as_str(), EndpointClass::LoopbackDevelopment)])
        .expect("fake-server policy")
}

#[tokio::test]
async fn typed_auth_is_attached_after_validation_and_cookies_are_isolated() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, b"first".to_vec())
            .header("Set-Cookie", "session=server-secret; Path=/"),
        FakeHttpResponse::new(200, b"second".to_vec()),
    ])
    .await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");

    let authenticated = HttpRequest::get(server.url("/first"))
        .authentication(Authentication::bearer("fixture-bearer-token").expect("bearer"));
    transport
        .send(&authenticated, &CancellationToken::new())
        .await
        .expect("authenticated request");
    transport
        .send(
            &HttpRequest::get(server.url("/second")),
            &CancellationToken::new(),
        )
        .await
        .expect("isolated request");

    let requests = server.requests();
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer fixture-bearer-token")
    );
    assert_eq!(requests[1].header("authorization"), None);
    assert_eq!(requests[1].header("cookie"), None);
}

#[tokio::test]
async fn unapproved_redirect_is_rejected_before_auth_reaches_the_target() {
    let target = FakeHttpServer::start([FakeHttpResponse::new(200, b"target".to_vec())]).await;
    let redirect =
        FakeHttpServer::start([FakeHttpResponse::new(302, Vec::new())
            .header("Location", target.url("/stolen").as_str())])
        .await;
    let transport = HttpTransport::new(policy(&redirect), config()).expect("HTTP transport");
    let request = HttpRequest::get(redirect.url("/redirect"))
        .authentication(Authentication::bearer("fixture-redirect-token").expect("bearer"));

    assert!(matches!(
        transport.send(&request, &CancellationToken::new()).await,
        Err(TransportError::Endpoint(_))
    ));
    assert!(target.requests().is_empty());
}

#[tokio::test]
async fn approved_redirects_are_followed_only_within_the_configured_bound() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/second"),
        FakeHttpResponse::new(302, Vec::new()).header("Location", "/third"),
    ])
    .await;
    let redirect_config = TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        1024,
        1,
        RetryPolicy::none(),
    )
    .expect("redirect config");
    let transport = HttpTransport::new(policy(&server), redirect_config).expect("HTTP transport");

    assert!(matches!(
        transport
            .send(
                &HttpRequest::get(server.url("/first")),
                &CancellationToken::new()
            )
            .await,
        Err(TransportError::TooManyRedirects)
    ));
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn response_cap_deadline_and_cancellation_are_enforced() {
    let oversized = FakeHttpServer::start([FakeHttpResponse::new(200, vec![b'x'; 1024])]).await;
    let tiny_config = TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        32,
        0,
        RetryPolicy::none(),
    )
    .expect("tiny config");
    let transport = HttpTransport::new(policy(&oversized), tiny_config).expect("HTTP transport");
    assert!(matches!(
        transport
            .send(
                &HttpRequest::get(oversized.url("/large")),
                &CancellationToken::new()
            )
            .await,
        Err(TransportError::ResponseTooLarge)
    ));

    let stalled = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let timeout_config = TransportConfig::new(
        Duration::from_millis(100),
        Duration::from_millis(20),
        1024,
        0,
        RetryPolicy::none(),
    )
    .expect("timeout config");
    let transport = HttpTransport::new(policy(&stalled), timeout_config).expect("HTTP transport");
    assert!(matches!(
        transport
            .send(
                &HttpRequest::get(stalled.url("/stall")),
                &CancellationToken::new()
            )
            .await,
        Err(TransportError::Timeout)
    ));

    let cancelled_server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let transport =
        HttpTransport::new(policy(&cancelled_server), config()).expect("HTTP transport");
    let cancellation = CancellationToken::new();
    let request = HttpRequest::get(cancelled_server.url("/cancel"));
    let send = transport.send(&request, &cancellation);
    tokio::pin!(send);
    tokio::select! {
        result = &mut send => panic!("stalled request completed before cancellation: {result:?}"),
        result = tokio::time::timeout(
            Duration::from_millis(100),
            cancelled_server.wait_for_request_count(1),
        ) => result.expect("stalled request reached the fixture server"),
    }
    cancellation.cancel();
    assert!(matches!(send.await, Err(TransportError::Cancelled)));
}

#[tokio::test]
async fn status_truncation_and_malformed_json_map_to_stable_errors() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(401, Vec::new()),
        FakeHttpResponse::new(403, Vec::new()),
        FakeHttpResponse::new(408, Vec::new()),
        FakeHttpResponse::new(429, Vec::new()).header("Retry-After", "7"),
        FakeHttpResponse::new(503, Vec::new()),
        FakeHttpResponse::truncated(200, 100, b"short".to_vec()),
        FakeHttpResponse::new(200, b"{not-json".to_vec()),
    ])
    .await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");

    for expected in [
        ErrorKind::AuthenticationExpired,
        ErrorKind::PermissionDenied,
        ErrorKind::Network,
        ErrorKind::RateLimited,
        ErrorKind::ProviderUnavailable,
        ErrorKind::Parse,
    ] {
        let error = transport
            .send(
                &HttpRequest::get(server.url("/status")),
                &CancellationToken::new(),
            )
            .await
            .expect_err("scripted transport failure");
        assert_eq!(error.classified().kind(), expected);
    }

    let response = transport
        .send(
            &HttpRequest::get(server.url("/malformed")),
            &CancellationToken::new(),
        )
        .await
        .expect("malformed JSON transport succeeds");
    let last_good = serde_json::json!({"cached": true});
    let outcome = preserve_last_good(
        Some(last_good.clone()),
        response.json::<serde_json::Value>(),
    );
    assert_eq!(
        outcome,
        FetchOutcome::Retained {
            last_good,
            error: oab_domain::ClassifiedError::new(ErrorKind::Parse),
        }
    );
}
