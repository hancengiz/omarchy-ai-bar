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
async fn client_can_bind_one_descriptor_supported_non_key_source() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, b"ok".to_vec())]).await;
    let client = FixedApiClient::new(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        "x-api-key",
        ApiKeyCredential::new("fixture-key-canary").expect("credential"),
        config(),
    )
    .expect("fixed API client")
    .with_source(ProviderSource::ConfigurableEndpoint)
    .expect("ElevenLabs supports endpoint overrides");
    let configured = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ConfigurableEndpoint,
        CancellationToken::new(),
    );
    assert_eq!(
        client
            .get(&configured, client.url("usage").expect("usage URL"))
            .await
            .expect("configured source")
            .body(),
        b"ok"
    );

    let api_key = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    );
    assert_eq!(
        client
            .get(&api_key, client.url("usage").expect("usage URL"))
            .await
            .expect_err("source binding remains exact")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(server.requests().len(), 1);

    let unsupported = FixedApiClient::new(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        "x-api-key",
        ApiKeyCredential::new("fixture-key-canary").expect("credential"),
        config(),
    )
    .expect("fixed API client")
    .with_source(ProviderSource::Cli)
    .expect_err("ElevenLabs has no CLI source");
    assert_eq!(unsupported.kind(), ErrorKind::Api);
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
async fn vendor_authorization_scheme_is_validated_and_redacted() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, Vec::new())]).await;
    let client = FixedApiClient::new_authorization_scheme(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        "Token",
        ApiKeyCredential::new("fixture-token-canary").expect("credential"),
        config(),
    )
    .expect("scheme client");
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    );
    client
        .get_json(&context, client.url("projects").expect("projects URL"))
        .await
        .expect("scheme request");
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Token fixture-token-canary")
    );
    assert!(!format!("{client:?}").contains("fixture-token-canary"));

    let error = FixedApiClient::new_authorization_scheme(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        "Token Injected",
        ApiKeyCredential::new("fixture").expect("credential"),
        config(),
    )
    .expect_err("invalid scheme");
    assert_eq!(error.kind(), ErrorKind::Api);
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

#[tokio::test]
async fn json_post_supports_bounded_public_client_metadata_headers() {
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, Vec::new())]).await;
    let client = FixedApiClient::new_bearer(
        scope("account-a"),
        server.url("/v1/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fixture-bearer-canary").expect("credential"),
        config(),
    )
    .expect("fixed API client");
    let context = ProviderContext::new(
        scope("account-a"),
        ProviderSource::ApiKey,
        CancellationToken::new(),
    );
    client
        .post_json_with_public_headers(
            &context,
            client.url("query").expect("query URL"),
            br#"{"query":"probe"}"#.to_vec(),
            &[("user-agent", "Provider/1.0"), ("x-client-id", "desktop")],
        )
        .await
        .expect("metadata JSON POST");
    let request = &server.requests()[0];
    assert_eq!(request.header("user-agent"), Some("Provider/1.0"));
    assert_eq!(request.header("x-client-id"), Some("desktop"));
    assert_eq!(
        request.header("authorization"),
        Some("Bearer fixture-bearer-canary")
    );

    let error = client
        .post_json_with_public_headers(
            &context,
            client.url("query").expect("query URL"),
            Vec::new(),
            &[("authorization", "not-allowed")],
        )
        .await
        .expect_err("reserved metadata header");
    assert_eq!(error.kind(), ErrorKind::Api);
    assert_eq!(server.requests().len(), 1);
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
