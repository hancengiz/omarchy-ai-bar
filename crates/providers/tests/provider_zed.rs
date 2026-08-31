use std::collections::BTreeMap;
use std::time::Duration;

use oab_domain::{
    AccountKey, AccountScope, BoundedText, ProviderId, ProviderInstanceId, RateWindow, Timestamp,
    UsagePercent,
};
use oab_providers::context::ProviderContext;
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::fixed_api::{ApiKeyCredential, FixedApiClient};
use oab_providers::providers::zed::{ZedProvider, ZedSettings};
use oab_providers::retry::RetryPolicy;
use oab_providers::transport::TransportConfig;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Zed,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn settings_require_both_credentials_and_redact_debug() {
    let values = BTreeMap::from([
        ("ZED_USER_ID".to_owned(), "4242".to_owned()),
        (
            "ZED_ACCESS_TOKEN".to_owned(),
            "fixture-zed-token".to_owned(),
        ),
    ]);
    let settings = ZedSettings::resolve(&values).expect("settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains("4242"));
    assert!(!debug.contains("fixture-zed-token"));
}

#[tokio::test]
async fn limited_predictions_and_billing_cycle_are_normalized() {
    let body = br#"{
      "user":{"id":4242,"github_login":"octocat","name":"The Octocat"},
      "plan":{
        "plan_v3":"zed_free",
        "subscription_period":{"started_at":"2026-08-01T00:00:00.000Z","ended_at":"2026-09-01T00:00:00.000Z"},
        "usage":{"edit_predictions":{"used":10,"limit":{"limited":20}}},
        "has_overdue_invoices":true
      }
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let client = FixedApiClient::new_authorization_scheme(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "4242",
        ApiKeyCredential::new("fixture-zed-token").expect("token"),
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
    let provider = ZedProvider::from_client(client).expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::ApiKey, CancellationToken::new());
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::parse("2026-08-16T12:00:00Z").expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(
        sample
            .primary()
            .and_then(RateWindow::used_percent)
            .map(UsagePercent::get),
        Some(50.0)
    );
    assert_eq!(
        sample
            .primary()
            .and_then(|window| window.reset_description())
            .map(BoundedText::as_str),
        Some("10 / 20 predictions")
    );
    assert_eq!(sample.extra_windows().len(), 1);
    assert_eq!(server.requests()[0].target(), "/client/users/me");
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("4242 fixture-zed-token")
    );
}

#[tokio::test]
async fn unlimited_limit_is_preserved_without_inventing_a_quota() {
    let body = br#"{
      "user":{"id":1,"github_login":"user","name":null},
      "plan":{"plan_v3":"zed_pro","subscription_period":null,"usage":{"edit_predictions":{"used":0,"limit":"unlimited"}},"has_overdue_invoices":false}
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let client = FixedApiClient::new_authorization_scheme(
        scope(),
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
        "1",
        ApiKeyCredential::new("token").expect("token"),
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
    let provider = ZedProvider::from_client(client).expect("provider");
    let context = ProviderContext::new(scope(), ProviderSource::ApiKey, CancellationToken::new());
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::parse("2026-08-16T12:00:00Z").expect("time"),
        )
        .await
        .expect("sample");
    assert_eq!(
        sample
            .primary()
            .and_then(|window| window.reset_description())
            .map(BoundedText::as_str),
        Some("Unlimited")
    );
}
