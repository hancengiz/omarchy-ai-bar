use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, ErrorKind, ExactDecimal, ProviderId, ProviderInstanceId, Timestamp,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::deepseek::DeepSeekProvider;
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::DeepSeek,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn credential_is_required_and_redacted() {
    let environment = BTreeMap::from([(
        "DEEPSEEK_API_KEY".to_owned(),
        "fixture-deepseek-key".to_owned(),
    )]);
    let credential = DeepSeekProvider::resolve_credential(&environment).expect("credential");
    assert!(!format!("{credential:?}").contains("fixture-deepseek-key"));
    assert_eq!(
        DeepSeekProvider::resolve_credential(&BTreeMap::new())
            .expect_err("missing key")
            .kind(),
        ErrorKind::MissingCredential
    );
}

#[tokio::test]
async fn balance_is_normalized_without_inventing_a_quota() {
    let body = br#"{"is_available":true,"balance_infos":[{"currency":"CNY","total_balance":"42.50","granted_balance":"2.50","topped_up_balance":"40.00"}]}"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let client = FixedApiClient::new_bearer(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        ApiKeyCredential::new("fixture-deepseek-key").expect("key"),
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
    let provider = DeepSeekProvider::from_client(client).expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::ApiKey, CancellationToken::new());
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::from_unix_timestamp(1_800_000_000).expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::DeepSeek);
    assert_eq!(
        sample.balance().expect("balance").amount(),
        ExactDecimal::parse("42.50").expect("decimal")
    );
    assert_eq!(server.requests()[0].target(), "/user/balance");
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Bearer fixture-deepseek-key")
    );
}
