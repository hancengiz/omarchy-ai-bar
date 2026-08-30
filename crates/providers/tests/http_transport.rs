use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::time::SystemTime;

use oab_domain::ErrorKind;
use oab_providers::cloud_signing::AwsCredentials;
use oab_providers::context::{FetchOutcome, preserve_last_good};
use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::retry::{RetryClock, RetryPolicy};
use oab_providers::transport::{
    Authentication, HttpRequest, HttpTransport, RequestAccept, RequestContentType, TransportConfig,
    TransportError,
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

#[derive(Clone)]
struct CountingClock {
    timestamp_samples: Arc<AtomicUsize>,
}

impl RetryClock for CountingClock {
    fn wall_now(&self) -> SystemTime {
        self.timestamp_samples.fetch_add(1, Ordering::SeqCst);
        SystemTime::UNIX_EPOCH + Duration::from_mins(24_015_636)
    }

    fn sleep(&self, _duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

#[tokio::test]
async fn typed_media_controls_emit_only_the_exact_supported_values() {
    let server =
        FakeHttpServer::start((0..8).map(|_| FakeHttpResponse::new(200, Vec::new()))).await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");
    let requests = [
        HttpRequest::get(server.url("/any")).accept(RequestAccept::Any),
        HttpRequest::get(server.url("/html")).accept(RequestAccept::Html),
        HttpRequest::get(server.url("/json-text-any")).accept(RequestAccept::JsonTextAny),
        HttpRequest::post(server.url("/json"), b"json".to_vec())
            .expect("JSON body")
            .accept(RequestAccept::Json)
            .content_type(RequestContentType::Json),
        HttpRequest::post(server.url("/form"), b"form".to_vec())
            .expect("form body")
            .content_type(RequestContentType::FormUrlEncoded),
        HttpRequest::post(server.url("/form-utf8"), b"form".to_vec())
            .expect("UTF-8 form body")
            .content_type(RequestContentType::FormUrlEncodedUtf8),
        HttpRequest::post(server.url("/aws-10"), b"aws".to_vec())
            .expect("AWS body")
            .content_type(RequestContentType::AwsJson10),
        HttpRequest::post(server.url("/aws-11"), b"aws".to_vec())
            .expect("AWS body")
            .content_type(RequestContentType::AwsJson11),
    ];

    for request in &requests {
        transport
            .send(request, &CancellationToken::new())
            .await
            .expect("typed request succeeds");
    }

    let captured = server.requests();
    assert_eq!(captured[0].header("accept"), Some("*/*"));
    assert_eq!(
        captured[1].header("accept"),
        Some("text/html,application/xhtml+xml")
    );
    assert_eq!(captured[1].header("content-type"), None);
    assert_eq!(
        captured[2].header("accept"),
        Some("application/json, text/plain, */*")
    );
    assert_eq!(captured[2].header("content-type"), None);
    assert_eq!(captured[3].header("accept"), Some("application/json"));
    assert_eq!(captured[3].header("content-type"), Some("application/json"));
    assert_eq!(
        captured[4].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        captured[5].header("content-type"),
        Some("application/x-www-form-urlencoded; charset=utf-8")
    );
    assert_eq!(
        captured[6].header("content-type"),
        Some("application/x-amz-json-1.0")
    );
    assert_eq!(
        captured[7].header("content-type"),
        Some("application/x-amz-json-1.1")
    );
}

#[tokio::test]
async fn explicitly_accepted_error_statuses_return_bounded_bodies() {
    let statuses = [400_u16, 401, 403, 404, 429];
    let server = FakeHttpServer::start(
        statuses
            .iter()
            .map(|status| FakeHttpResponse::new(*status, format!("body-{status}").into_bytes())),
    )
    .await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");

    for status in statuses {
        let request = HttpRequest::get(server.url("/accepted"))
            .accepted_statuses(&statuses)
            .expect("bounded accepted statuses");
        let response = transport
            .send(&request, &CancellationToken::new())
            .await
            .expect("explicitly accepted status returns a response");
        assert_eq!(response.status(), status);
        assert_eq!(response.body(), format!("body-{status}").as_bytes());
    }
}

#[tokio::test]
async fn explicitly_accepted_error_bodies_still_obey_the_response_cap() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(400, vec![b'x'; 33])]).await;
    let tiny_config = TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        32,
        0,
        RetryPolicy::none(),
    )
    .expect("tiny config");
    let transport = HttpTransport::new(policy(&server), tiny_config).expect("HTTP transport");
    let request = HttpRequest::get(server.url("/accepted-large"))
        .accepted_statuses(&[400])
        .expect("accepted status");

    assert!(matches!(
        transport.send(&request, &CancellationToken::new()).await,
        Err(TransportError::ResponseTooLarge)
    ));
}

#[tokio::test]
async fn error_statuses_still_use_default_stable_errors() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(400, b"hidden-400".to_vec()),
        FakeHttpResponse::new(401, b"hidden-401".to_vec()),
        FakeHttpResponse::new(403, b"hidden-403".to_vec()),
        FakeHttpResponse::new(404, b"hidden-404".to_vec()),
        FakeHttpResponse::new(429, b"hidden-429".to_vec()),
    ])
    .await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");

    for expected in [
        TransportError::Api { status: 400 },
        TransportError::AuthenticationExpired,
        TransportError::PermissionDenied,
        TransportError::Api { status: 404 },
        TransportError::RateLimited { retry_after: None },
    ] {
        let error = transport
            .send(
                &HttpRequest::get(server.url("/default-error")),
                &CancellationToken::new(),
            )
            .await
            .expect_err("default error status is rejected");
        assert_eq!(error.http_status(), expected.http_status());
        assert_eq!(error.classified().kind(), expected.classified().kind());
    }
}

#[tokio::test]
async fn response_headers_are_bounded_filtered_and_case_insensitive() {
    const HEADER_CANARY: &str = "fixture-response-header-secret";
    const BODY_CANARY: &str = "fixture-response-body-secret";
    let oversized = "x".repeat(8 * 1024 + 1);
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, BODY_CANARY.as_bytes().to_vec())
            .header("X-Visible", HEADER_CANARY)
            .header("X-Other", "other-value")
            .header("X-Hidden", "hidden-value"),
        FakeHttpResponse::new(200, Vec::new()).header("X-Large", oversized.clone()),
        FakeHttpResponse::new(200, Vec::new()).header("X-Large", oversized),
    ])
    .await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");
    let request = HttpRequest::get(server.url("/filtered"))
        .response_headers(&["x-visible", "X-OTHER"])
        .expect("response header allowlist");
    let response = transport
        .send(&request, &CancellationToken::new())
        .await
        .expect("selected response headers");

    assert_eq!(response.header("X-VISIBLE"), Some(HEADER_CANARY));
    assert_eq!(response.header("x-other"), Some("other-value"));
    assert_eq!(response.header("x-hidden"), None);
    assert_eq!(response.header("not a header"), None);
    let debug = format!("{response:?}");
    assert!(!debug.contains(HEADER_CANARY));
    assert!(!debug.contains(BODY_CANARY));

    let selected_large = HttpRequest::get(server.url("/large-selected"))
        .response_headers(&["x-large"])
        .expect("large header selection");
    assert!(matches!(
        transport
            .send(&selected_large, &CancellationToken::new())
            .await,
        Err(TransportError::ResponseTooLarge)
    ));

    transport
        .send(
            &HttpRequest::get(server.url("/large-unselected")),
            &CancellationToken::new(),
        )
        .await
        .expect("unselected response header is not retained");
}

#[test]
fn request_control_sets_are_validated_and_debug_is_redacted() {
    let url =
        url::Url::parse("https://example.com/path-canary?query=query-canary").expect("fixture URL");

    assert!(matches!(
        HttpRequest::get(url.clone()).accepted_statuses(&[200]),
        Err(TransportError::InvalidConfiguration)
    ));
    assert!(matches!(
        HttpRequest::get(url.clone()).accepted_statuses(&[400, 400]),
        Err(TransportError::InvalidConfiguration)
    ));
    assert!(matches!(
        HttpRequest::get(url.clone()).accepted_statuses(&(400_u16..=416).collect::<Vec<_>>()),
        Err(TransportError::InvalidConfiguration)
    ));

    let names = (0..33)
        .map(|index| format!("x-{index}"))
        .collect::<Vec<_>>();
    let names = names.iter().map(String::as_str).collect::<Vec<_>>();
    assert!(matches!(
        HttpRequest::get(url.clone()).response_headers(&names),
        Err(TransportError::InvalidConfiguration)
    ));
    for names in [
        &["x-repeat", "X-Repeat"][..],
        &["not a header"][..],
        &["set-cookie"][..],
    ] {
        assert!(matches!(
            HttpRequest::get(url.clone()).response_headers(names),
            Err(TransportError::InvalidConfiguration)
        ));
    }

    for reserved in ["Accept", "Content-Type", "Authorization", "Cookie", "Host"] {
        assert!(matches!(
            HttpRequest::get(url.clone()).public_header(reserved, "public-canary"),
            Err(TransportError::InvalidConfiguration)
        ));
        assert!(matches!(
            HttpRequest::get(url.clone()).sensitive_header(reserved, "sensitive-canary"),
            Err(TransportError::InvalidConfiguration)
        ));
    }

    assert!(matches!(
        HttpRequest::get(url.clone())
            .public_header("x-repeat", "one")
            .expect("first header")
            .sensitive_header("X-Repeat", "two"),
        Err(TransportError::InvalidConfiguration)
    ));
    assert!(matches!(
        HttpRequest::get(url.clone())
            .sensitive_header("x-repeat", "one")
            .expect("first header")
            .public_header("X-Repeat", "two"),
        Err(TransportError::InvalidConfiguration)
    ));

    let request = HttpRequest::post(url, b"body-canary".to_vec())
        .expect("bounded body")
        .authentication(Authentication::bearer("auth-canary").expect("bearer"))
        .public_header("x-provider", "header-canary")
        .expect("public header")
        .sensitive_header("x-client-context", "sensitive-header-canary")
        .expect("sensitive metadata header")
        .accepted_statuses(&[400, 429])
        .expect("accepted statuses")
        .response_headers(&["x-result"])
        .expect("response headers");
    let debug = format!("{request:?}");
    for canary in [
        "path-canary",
        "query-canary",
        "body-canary",
        "auth-canary",
        "header-canary",
        "sensitive-header-canary",
        "x-result",
    ] {
        assert!(!debug.contains(canary), "debug leaked {canary}: {debug}");
    }
}

#[tokio::test]
async fn sensitive_metadata_is_validation_bound_redacted_and_request_isolated() {
    let server = FakeHttpServer::start([
        FakeHttpResponse::new(200, Vec::new()),
        FakeHttpResponse::new(200, Vec::new()),
    ])
    .await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");
    let request = HttpRequest::get(server.url("/captured"))
        .sensitive_header("x-client-context", "fixture-context-secret")
        .expect("sensitive metadata");
    assert!(!format!("{request:?}").contains("fixture-context-secret"));

    transport
        .send(&request, &CancellationToken::new())
        .await
        .expect("captured metadata request");
    transport
        .send(
            &HttpRequest::get(server.url("/plain")),
            &CancellationToken::new(),
        )
        .await
        .expect("plain request");

    let requests = server.requests();
    assert_eq!(
        requests[0].header("x-client-context"),
        Some("fixture-context-secret")
    );
    assert_eq!(requests[1].header("x-client-context"), None);
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
async fn unapproved_cloud_request_is_rejected_before_signing() {
    let endpoints =
        EndpointPolicy::new([("https://approved.example.com", EndpointClass::PublicHttps)])
            .expect("public endpoint policy");
    let transport = HttpTransport::new(endpoints, config()).expect("HTTP transport");
    let credentials = AwsCredentials::new("fixture-access", "fixture-secret", None::<String>)
        .expect("AWS credentials");
    let authentication = Authentication::aws_sig_v4(credentials, "us-east-1", "bedrock")
        .expect("AWS authentication");
    let request = HttpRequest::get(
        url::Url::parse("https://unapproved.example.net/models").expect("fixture URL"),
    )
    .authentication(authentication);

    assert!(matches!(
        transport.send(&request, &CancellationToken::new()).await,
        Err(TransportError::Endpoint(_))
    ));
}

#[tokio::test]
async fn validated_loopback_seam_sends_the_exact_signed_request() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, b"ok".to_vec())]).await;
    let transport = HttpTransport::new(policy(&server), config()).expect("HTTP transport");
    let credentials = AwsCredentials::new(
        "fixture-loopback-access",
        "fixture-loopback-secret",
        Some("fixture-loopback-session"),
    )
    .expect("AWS credentials");
    let request = HttpRequest::post(server.url("/signed?model=claude"), b"exact-body".to_vec())
        .expect("signed request")
        .accept(RequestAccept::Json)
        .content_type(RequestContentType::AwsJson11)
        .public_header("x-amz-target", "Bedrock.List")
        .expect("target header")
        .authentication(
            Authentication::aws_sig_v4(credentials, "us-east-1", "bedrock")
                .expect("AWS authentication"),
        );

    let response = transport
        .send(&request, &CancellationToken::new())
        .await
        .expect("validated loopback signing seam");
    assert_eq!(response.body(), b"ok");

    let captured = server.requests();
    assert_eq!(captured[0].target(), "/signed?model=claude");
    assert_eq!(captured[0].body(), b"exact-body");
    assert_eq!(captured[0].header("accept"), Some("application/json"));
    assert_eq!(
        captured[0].header("content-type"),
        Some("application/x-amz-json-1.1")
    );
    assert_eq!(captured[0].header("x-amz-target"), Some("Bedrock.List"));
    assert_eq!(
        captured[0].header("x-amz-security-token"),
        Some("fixture-loopback-session")
    );
    assert!(
        captured[0]
            .header("authorization")
            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
    );
}

#[tokio::test]
async fn cloud_auth_is_resigned_for_each_retry_attempt() {
    let plaintext_server = FakeHttpServer::start([FakeHttpResponse::stall()]).await;
    let mut signed_url = plaintext_server.url("/signed");
    signed_url
        .set_scheme("https")
        .expect("HTTP URL accepts HTTPS scheme");
    let approved_origin = format!(
        "https://{}:{}",
        signed_url.host_str().expect("fixture host"),
        signed_url.port().expect("fixture port")
    );
    let endpoints =
        EndpointPolicy::new([(approved_origin.as_str(), EndpointClass::LoopbackDevelopment)])
            .expect("HTTPS loopback endpoint policy");
    let retrying_config = TransportConfig::new(
        Duration::from_millis(100),
        Duration::from_millis(20),
        1024,
        0,
        RetryPolicy::one(Duration::ZERO, Duration::ZERO),
    )
    .expect("retrying config");
    let timestamp_samples = Arc::new(AtomicUsize::new(0));
    let clock = CountingClock {
        timestamp_samples: Arc::clone(&timestamp_samples),
    };
    let transport =
        HttpTransport::with_clock(endpoints, retrying_config, clock).expect("HTTP transport");
    let credentials = AwsCredentials::new("fixture-access", "fixture-secret", None::<String>)
        .expect("AWS credentials");
    let request = HttpRequest::get(signed_url).authentication(
        Authentication::aws_sig_v4(credentials, "us-east-1", "bedrock")
            .expect("AWS authentication"),
    );

    assert!(
        transport
            .send(&request, &CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(timestamp_samples.load(Ordering::SeqCst), 2);
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
