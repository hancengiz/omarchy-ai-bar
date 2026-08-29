use std::sync::{Mutex, PoisonError};

use oab_domain::PrivacyPolicy;
use oab_runtime::notifications::{
    FreedesktopNotificationSink, MAX_NOTIFICATION_BODY_BYTES, MAX_NOTIFICATION_SUMMARY_BYTES,
    NotificationEvent, NotificationFuture, NotificationIdentity, NotificationPayload,
    NotificationService, NotificationSink, NotificationSinkError,
};

#[derive(Debug, Default)]
struct FakeNotificationSink {
    delivered: Mutex<Vec<NotificationPayload>>,
}

impl FakeNotificationSink {
    fn take(&self) -> Vec<NotificationPayload> {
        std::mem::take(
            &mut *self
                .delivered
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }
}

impl NotificationSink for FakeNotificationSink {
    fn send(
        &self,
        payload: NotificationPayload,
    ) -> NotificationFuture<'_, Result<(), NotificationSinkError>> {
        Box::pin(async move {
            self.delivered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(payload);
            Ok(())
        })
    }
}

async fn assert_notification_sink_contract(sink: FakeNotificationSink) {
    let service = NotificationService::new(sink, PrivacyPolicy::HidePersonalInfo);
    service
        .notify(NotificationEvent::UpdateAvailable)
        .await
        .expect("deliver update notification");
    let delivered = service.sink().take();
    assert_eq!(delivered.len(), 1);
    assert!(!delivered[0].summary().is_empty());
    assert!(!delivered[0].body().is_empty());
    assert!(delivered[0].summary().len() <= MAX_NOTIFICATION_SUMMARY_BYTES);
    assert!(delivered[0].body().len() <= MAX_NOTIFICATION_BODY_BYTES);
    assert_eq!(delivered[0].icon(), "omarchy-ai-bar");
}

#[tokio::test]
async fn fake_implementation_passes_common_contract() {
    assert_notification_sink_contract(FakeNotificationSink::default()).await;
}

#[tokio::test]
async fn hidden_policy_removes_account_canaries_before_sink_boundary() {
    let identity =
        NotificationIdentity::new("provider-canary", "account-canary").expect("identity");
    let service = NotificationService::new(
        FakeNotificationSink::default(),
        PrivacyPolicy::HidePersonalInfo,
    );
    service
        .notify(NotificationEvent::RefreshFailed(identity))
        .await
        .expect("notify");
    let delivered = service.sink().take();
    let rendered = format!(
        "{} {} {:?}",
        delivered[0].summary(),
        delivered[0].body(),
        delivered[0]
    );
    assert!(!rendered.contains("provider-canary"));
    assert!(!rendered.contains("account-canary"));
}

#[tokio::test]
async fn personal_context_is_included_only_under_explicit_show_policy() {
    let identity = NotificationIdentity::new("Codex", "work@example.test").expect("identity");
    let service = NotificationService::new(
        FakeNotificationSink::default(),
        PrivacyPolicy::ShowPersonalInfo,
    );
    service
        .notify(NotificationEvent::usage_threshold(80, identity).expect("event"))
        .await
        .expect("notify");
    let delivered = service.sink().take();
    assert!(delivered[0].body().contains("Codex"));
    assert!(delivered[0].body().contains("work@example.test"));
}

#[test]
fn identity_and_event_debug_are_personal_info_safe() {
    let identity =
        NotificationIdentity::new("provider-canary", "account-canary").expect("identity");
    let output = format!(
        "{identity:?} {:?}",
        NotificationEvent::RefreshFailed(identity.clone())
    );
    assert!(!output.contains("provider-canary"));
    assert!(!output.contains("account-canary"));
}

#[tokio::test]
#[ignore = "requires a live freedesktop notification service and shows a desktop notification"]
async fn live_freedesktop_adapter_delivers() {
    NotificationService::new(FreedesktopNotificationSink, PrivacyPolicy::HidePersonalInfo)
        .notify(NotificationEvent::UpdateAvailable)
        .await
        .expect("live notification delivery");
}
