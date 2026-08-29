use oab_providers::endpoint::{EndpointClass, EndpointPolicy};
use oab_providers::redaction::RedactedProviderText;
use std::time::Duration;

use oab_providers::retry::RetryPolicy;
use oab_providers::transport::{
    Authentication, HttpRequest, HttpTransport, TransportConfig, TransportError,
};
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;
use url::Url;

const KEY: &str = "fixture-api-key-canary";
const COOKIE: &str = "fixture-cookie-canary";
const TOKEN: &str = "fixture-token-canary";
const BODY: &str = "fixture-response-body-canary";

#[test]
fn request_auth_and_error_debug_views_exclude_secret_canaries() {
    let request = HttpRequest::get(
        Url::parse("https://api.example.com/usage?note=fixture-token-canary").expect("URL"),
    )
    .authentication(Authentication::bearer(TOKEN).expect("bearer"));
    let cookie = Authentication::cookie(COOKIE).expect("cookie");
    let key = Authentication::api_key("x-api-key", KEY).expect("API key");

    let debug = format!("{request:?} {cookie:?} {key:?}");
    for canary in [KEY, COOKIE, TOKEN, BODY] {
        assert!(!debug.contains(canary));
    }

    let error = TransportError::MalformedResponse;
    let debug = format!("{error:?}");
    assert!(!debug.contains(BODY));
}

#[test]
fn api_key_auth_rejects_routing_and_hop_by_hop_headers() {
    for name in [
        "authorization",
        "cookie",
        "host",
        "proxy-authorization",
        "connection",
        "transfer-encoding",
    ] {
        assert!(matches!(
            Authentication::api_key(name, KEY),
            Err(TransportError::InvalidConfiguration)
        ));
    }
}

#[test]
fn arbitrary_provider_text_is_replaced_at_the_diagnostic_boundary() {
    let raw =
        format!(r#"{{"api_key":"{KEY}","cookie":"{COOKIE}","token":"{TOKEN}","body":"{BODY}"}}"#);
    let redacted = RedactedProviderText::from_untrusted(&raw);
    let debug = format!("{redacted:?}");
    let display = redacted.to_string();
    for canary in [KEY, COOKIE, TOKEN, BODY] {
        assert!(!debug.contains(canary));
        assert!(!display.contains(canary));
    }
}

#[test]
fn validated_endpoint_diagnostics_drop_paths_and_queries() {
    let policy = EndpointPolicy::new([("https://api.example.com", EndpointClass::PublicHttps)])
        .expect("policy");
    let endpoint = policy
        .validate(
            &Url::parse("https://api.example.com/private/path?token=not-a-secret-field")
                .expect("URL"),
        )
        .expect_err("sensitive query key must be rejected");
    assert!(!format!("{endpoint:?}").contains("not-a-secret-field"));
}

#[tokio::test]
async fn response_diagnostics_exclude_provider_body_canaries() {
    let server =
        FakeHttpServer::start([FakeHttpResponse::new(200, BODY.as_bytes().to_vec())]).await;
    let policy =
        EndpointPolicy::new([(server.origin().as_str(), EndpointClass::LoopbackDevelopment)])
            .expect("fixture policy");
    let config = TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        1024,
        0,
        RetryPolicy::none(),
    )
    .expect("fixture config");
    let transport = HttpTransport::new(policy, config).expect("HTTP transport");
    let response = transport
        .send(
            &HttpRequest::get(server.url("/body-canary")),
            &CancellationToken::new(),
        )
        .await
        .expect("fixture response");

    assert!(!format!("{response:?}").contains(BODY));
}
