use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId};
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::ElevenLabs,
        ProviderInstanceId::new("elevenlabs-primary").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn config() -> TransportConfig {
    TransportConfig::new(
        Duration::from_millis(250),
        Duration::from_millis(250),
        1024,
        0,
        RetryPolicy::none(),
    )
    .expect("fixture transport config")
}

#[test]
fn api_key_resolution_is_ordered_trimmed_unquoted_and_redacted() {
    let environment = BTreeMap::from([
        ("PRIMARY".to_owned(), "   ".to_owned()),
        (
            "SECONDARY".to_owned(),
            "  'fixture-key-canary'  ".to_owned(),
        ),
        ("TERTIARY".to_owned(), "not-selected".to_owned()),
    ]);
    let credential = ApiKeyCredential::resolve(&environment, &["PRIMARY", "SECONDARY", "TERTIARY"])
        .expect("resolved credential");
    assert!(!format!("{credential:?}").contains("fixture-key-canary"));

    let missing = ApiKeyCredential::resolve(&BTreeMap::new(), &["PRIMARY"])
        .expect_err("missing key must fail");
    assert_eq!(missing.kind(), ErrorKind::MissingCredential);
}

#[tokio::test]
async fn fixed_client_keeps_scope_source_and_authentication_isolated() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, b"ok".to_vec())]).await;
    let client = FixedApiClient::new(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        "x-api-key",
        ApiKeyCredential::new("fixture-key-canary").expect("credential"),
        config(),
    )
    .expect("fixed API client");
    let cancellation = CancellationToken::new();
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ApiKey,
        cancellation.clone(),
    );
    let response = client
        .get(&context, client.url("usage").expect("usage URL"))
        .await
        .expect("account-scoped request");
    assert_eq!(response.body(), b"ok");
    assert_eq!(
        server.requests()[0].header("x-api-key"),
        Some("fixture-key-canary")
    );

    for rejected in [
        ProviderContext::new(
            scope("account-b"),
            ProviderSource::ApiKey,
            cancellation.clone(),
        ),
        ProviderContext::new(
            scope("account-a"),
            ProviderSource::Cli,
            cancellation.clone(),
        ),
    ] {
        let error = client
            .get(&rejected, client.url("usage").expect("usage URL"))
            .await
            .expect_err("mismatched context must fail");
        assert_eq!(error.kind(), ErrorKind::Api);
    }
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn bearer_client_uses_the_same_validation_and_scope_boundary() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, Vec::new())]).await;
    let client = FixedApiClient::new_bearer(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fixture-bearer-canary").expect("credential"),
        config(),
    )
    .expect("bearer client");
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    );
    client
        .get(&context, client.url("usage").expect("usage URL"))
        .await
        .expect("bearer request");
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Bearer fixture-bearer-canary")
    );
}

#[tokio::test]
async fn json_post_sets_media_type_and_preserves_bounded_body() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, Vec::new())]).await;
    let client = FixedApiClient::new(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        "api-key",
        ApiKeyCredential::new("fixture-key-canary").expect("credential"),
        config(),
    )
    .expect("fixed API client");
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    );
    client
        .post_json(
            &context,
            client.url("validate").expect("validation URL"),
            br#"{"probe":"ping"}"#.to_vec(),
        )
        .await
        .expect("JSON POST");
    let request = &server.requests()[0];
    assert_eq!(request.method(), "POST");
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.body(), br#"{"probe":"ping"}"#);
}

#[test]
fn fixed_paths_cannot_replace_the_approved_origin_or_inject_queries() {
    let client = FixedApiClient::new(
        scope("account-a"),
        url::Url::parse("https://api.example.com/v1/").expect("base URL"),
        EndpointClass::PublicHttps,
        "x-api-key",
        ApiKeyCredential::new("fixture-key").expect("credential"),
        config(),
    )
    .expect("fixed API client");

    for rejected in [
        "/replace-origin-path",
        "../escape",
        "https://attacker.example/steal",
        "\\\\attacker.example/steal",
        "usage?api_key=secret",
    ] {
        assert!(client.url(rejected).is_err(), "accepted {rejected}");
    }
}
