//! `StatusNotifierItem` fallback for sessions without a compatible QML frontend.

use std::sync::mpsc::SyncSender;

use ksni::menu::StandardItem;
use ksni::{MenuItem, Status, ToolTip, TrayMethods as _};
use thiserror::Error;

use crate::frontend_presence::SniStatus;
use crate::protocol::{NavigationDestination, RuntimeAction};

const TRAY_ID: &str = "omarchy-ai-bar";
const TRAY_TITLE: &str = "Omarchy AI Bar";

/// Error returned when a tray update races with service shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the Omarchy AI Bar tray service is closed")]
pub struct TrayClosed;

/// Async control handle for the fallback `StatusNotifierItem`.
pub struct TrayController {
    handle: ksni::Handle<OmarchyAiTray>,
}

impl TrayController {
    /// Starts the tray service and registers it when an SNI watcher is available.
    ///
    /// A temporarily missing watcher is treated as an offline desktop service;
    /// ksni will register this item when the watcher returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the session bus cannot be reached or initial SNI
    /// registration fails for a reason other than a missing watcher.
    pub async fn spawn(
        status: SniStatus,
        actions: SyncSender<RuntimeAction>,
    ) -> Result<Self, ksni::Error> {
        let tray = OmarchyAiTray { status, actions };
        let handle = tray.assume_sni_available(true).spawn().await?;
        Ok(Self { handle })
    }

    /// Changes whether the fallback should be visible to the tray host.
    ///
    /// # Errors
    ///
    /// Returns [`TrayClosed`] if shutdown won the race with this update.
    pub async fn set_status(&self, status: SniStatus) -> Result<(), TrayClosed> {
        self.handle
            .update(move |tray| tray.status = status)
            .await
            .ok_or(TrayClosed)
    }

    /// Returns whether the underlying tray service has stopped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Unregisters the SNI object and waits for its D-Bus service to stop.
    pub async fn shutdown(self) {
        self.handle.shutdown().await;
    }
}

struct OmarchyAiTray {
    status: SniStatus,
    actions: SyncSender<RuntimeAction>,
}

impl OmarchyAiTray {
    fn enqueue(&self, action: RuntimeAction) {
        // Tray callbacks run on the D-Bus service task. Saturation and consumer
        // shutdown must therefore be harmless and non-blocking.
        let _ = self.actions.try_send(action);
    }
}

impl ksni::Tray for OmarchyAiTray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        TRAY_ID.into()
    }

    fn title(&self) -> String {
        TRAY_TITLE.into()
    }

    fn status(&self) -> Status {
        match self.status {
            SniStatus::Active => Status::Active,
            SniStatus::Passive => Status::Passive,
        }
    }

    fn icon_name(&self) -> String {
        TRAY_ID.into()
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: TRAY_ID.into(),
            title: TRAY_TITLE.into(),
            description: "AI usage and account status".into(),
            ..ToolTip::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Refresh".into(),
                activate: Box::new(|tray: &mut Self| {
                    tray.enqueue(RuntimeAction::RefreshAll {});
                }),
                ..StandardItem::default()
            }
            .into(),
            StandardItem {
                label: "Settings...".into(),
                activate: Box::new(|tray: &mut Self| {
                    tray.enqueue(RuntimeAction::Navigate {
                        destination: NavigationDestination::General,
                    });
                }),
                ..StandardItem::default()
            }
            .into(),
            StandardItem {
                label: "About Omarchy AI Bar".into(),
                activate: Box::new(|tray: &mut Self| {
                    tray.enqueue(RuntimeAction::Navigate {
                        destination: NavigationDestination::About,
                    });
                }),
                ..StandardItem::default()
            }
            .into(),
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|tray: &mut Self| {
                    tray.enqueue(RuntimeAction::Quit {});
                }),
                ..StandardItem::default()
            }
            .into(),
        ]
    }
}
