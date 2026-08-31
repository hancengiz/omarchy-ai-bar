use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ProviderId, ProviderInstanceId, RateWindow, Timestamp, UsagePercent,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::opencodego::OpenCodeGoProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::OpenCodeGo,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn credential_is_resolved_without_debug_disclosure() {
    let environment = BTreeMap::from([(
        "OPENCODE_API_KEY".to_owned(),
        "go_fixture_secret".to_owned(),
    )]);
    let credential = OpenCodeGoProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains("go_fixture_secret"));
}

#[tokio::test]
async fn public_usage_windows_preserve_percent_units_and_resets() {
    let body = br#"{"usage":{"rolling":{"percent":12,"resetsAt":"2026-09-01T02:00:00.000Z"},"weekly":{"percent":8,"resetsAt":"2026-09-07T00:00:00.000Z"},"monthly":{"percent":35,"resetInSec":3600}}}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let client = FixedApiClient::new_bearer(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("go_fixture_secret").expect("key"),
        TransportConfig::new(
            Duration::from_millis(250),
            Duration::from_millis(250),
            1024 * 1024,
            0,
            RetryPolicy::none(),
        )
        .expect("config"),
    )
    .expect("client");
    let provider = OpenCodeGoProvider::from_client(client).expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::ApiKey, CancellationToken::new());
    let fetched_at = Timestamp::from_unix_timestamp(1_788_217_200).expect("time");
    let sample = provider
        .fetch_at(&context, fetched_at)
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::OpenCodeGo);
    assert_eq!(
        sample
            .primary()
            .and_then(RateWindow::used_percent)
            .map(UsagePercent::get),
        Some(12.0)
    );
    assert_eq!(
        sample
            .secondary()
            .and_then(RateWindow::used_percent)
            .map(UsagePercent::get),
        Some(8.0)
    );
    assert_eq!(
        sample
            .tertiary()
            .and_then(RateWindow::used_percent)
            .map(UsagePercent::get),
        Some(35.0)
    );
    assert_eq!(server.requests()[0].target(), "/zen/go/v1/usage");
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Bearer go_fixture_secret")
    );
}
