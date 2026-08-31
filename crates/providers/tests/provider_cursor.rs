use oab_domain::{
    AccountKey, AccountScope, ProviderId, ProviderInstanceId, RateWindow, Timestamp, UsagePercent,
};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::endpoint::EndpointClass;
use oab_providers::providers::cursor::CursorProvider;
use oab_test_support::http::{FakeHttpResponse, FakeHttpServer};
use tokio_util::sync::CancellationToken;

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Cursor,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[tokio::test]
async fn usage_summary_preserves_cursor_percentage_units() {
    let body = br#"{
      "billingCycleEnd":"2026-09-15T00:00:00Z",
      "membershipType":"pro",
      "individualUsage":{"plan":{"used":500,"limit":2000,"autoPercentUsed":0.36,"apiPercentUsed":75,"totalPercentUsed":25}},
      "teamUsage":null
    }"#;
    let server = FakeHttpServer::start([FakeHttpResponse::new(200, body.to_vec())]).await;
    let provider = CursorProvider::from_manual_capture_at(
        scope(),
        "Cookie: WorkosCursorSessionToken=fixture-session",
        server.url("/"),
        EndpointClass::LoopbackDevelopment,
    )
    .expect("provider");
    let context = ProviderContext::new(
        scope(),
        ProviderSource::ManualCookie,
        CancellationToken::new(),
    );
    let sample = provider
        .fetch_at(
            &context,
            Timestamp::parse("2026-08-31T00:00:00Z").expect("time"),
        )
        .await
        .expect("sample");

    assert_eq!(provider.descriptor().id, ProviderId::Cursor);
    assert_eq!(percent(sample.primary()), Some(25.0));
    assert_eq!(percent(sample.secondary()), Some(0.36));
    assert_eq!(percent(sample.tertiary()), Some(75.0));
    assert_eq!(server.requests()[0].target(), "/api/usage-summary");
    assert_eq!(
        server.requests()[0].header("cookie"),
        Some("WorkosCursorSessionToken=fixture-session")
    );
}

fn percent(window: Option<&RateWindow>) -> Option<f64> {
    window
        .and_then(RateWindow::used_percent)
        .map(UsagePercent::get)
}
