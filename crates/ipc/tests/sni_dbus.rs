use std::collections::HashMap;
use std::error::Error;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt as _;
use oab_ipc::frontend_presence::SniStatus;
use oab_ipc::protocol::{NavigationDestination, RuntimeAction};
use oab_ipc::tray::TrayController;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

const WATCHER_NAME: &str = "org.kde.StatusNotifierWatcher";
const WATCHER_PATH: &str = "/StatusNotifierWatcher";
const WATCHER_INTERFACE: &str = "org.kde.StatusNotifierWatcher";
const SNI_PATH: &str = "/StatusNotifierItem";
const SNI_INTERFACE: &str = "org.kde.StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const MENU_INTERFACE: &str = "com.canonical.dbusmenu";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const SIGNAL_TIMEOUT: Duration = Duration::from_secs(2);

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Default)]
struct WatcherState {
    registered_items: Vec<String>,
    registered_hosts: Vec<String>,
    host_registered: bool,
    protocol_version: i32,
}

struct FakeWatcher {
    state: Arc<Mutex<WatcherState>>,
}

#[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
impl FakeWatcher {
    fn register_status_notifier_item(&self, service: &str) {
        self.state
            .lock()
            .expect("fake watcher state should not be poisoned")
            .registered_items
            .push(service.into());
    }

    fn register_status_notifier_host(&self, service: &str) {
        self.state
            .lock()
            .expect("fake watcher state should not be poisoned")
            .registered_hosts
            .push(service.into());
    }

    #[zbus(property)]
    fn registered_status_notifier_items(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("fake watcher state should not be poisoned")
            .registered_items
            .clone()
    }

    #[zbus(property)]
    fn is_status_notifier_host_registered(&self) -> bool {
        self.state
            .lock()
            .expect("fake watcher state should not be poisoned")
            .host_registered
    }

    #[zbus(property)]
    fn protocol_version(&self) -> i32 {
        self.state
            .lock()
            .expect("fake watcher state should not be poisoned")
            .protocol_version
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fallback_registers_updates_and_dispatches_typed_actions() {
    let result = tokio::time::timeout(TEST_TIMEOUT, exercise_sni()).await;
    result
        .expect("real session-D-Bus SNI exercise should finish before its deadline")
        .expect("real session-D-Bus SNI exercise should succeed");
}

async fn exercise_sni() -> TestResult {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        eprintln!("skipping SNI exercise: no session D-Bus address is available");
        return Ok(());
    }
    if watcher_name_is_owned().await? {
        eprintln!(
            "skipping isolated fake-watcher exercise: this session already owns {WATCHER_NAME}"
        );
        return Ok(());
    }

    let watcher_state = Arc::new(Mutex::new(WatcherState {
        host_registered: true,
        ..WatcherState::default()
    }));
    let watcher = zbus::connection::Builder::session()?
        .method_timeout(SIGNAL_TIMEOUT)
        .name(WATCHER_NAME)?
        .serve_at(
            WATCHER_PATH,
            FakeWatcher {
                state: watcher_state.clone(),
            },
        )?
        .build()
        .await?;

    let (actions_tx, actions_rx) = mpsc::sync_channel(4);
    let controller = TrayController::spawn(SniStatus::Passive, actions_tx).await?;
    let registered = watcher_state
        .lock()
        .expect("fake watcher state should not be poisoned")
        .registered_items
        .clone();
    assert_eq!(registered.len(), 1);
    let service_name = registered
        .into_iter()
        .next()
        .expect("one registered item was just asserted");
    assert!(service_name.starts_with("org.kde.StatusNotifierItem-"));

    let client = zbus::connection::Builder::session()?
        .method_timeout(SIGNAL_TIMEOUT)
        .build()
        .await?;
    assert_watcher_registration(&client, &service_name).await?;
    let sni = zbus::Proxy::new(&client, service_name.as_str(), SNI_PATH, SNI_INTERFACE).await?;
    assert_item_identity(&sni).await?;
    assert_status_transition(&controller, &sni, &client, &service_name, &actions_rx).await?;
    assert_menu_actions(&client, &service_name, &actions_rx).await?;

    controller.shutdown().await;
    assert_name_released(&client, &service_name).await?;
    watcher.close().await?;
    Ok(())
}

async fn assert_watcher_registration(client: &zbus::Connection, service: &str) -> TestResult {
    let watcher = zbus::Proxy::new(client, WATCHER_NAME, WATCHER_PATH, WATCHER_INTERFACE).await?;
    let registered: Vec<String> = watcher
        .get_property("RegisteredStatusNotifierItems")
        .await?;
    assert_eq!(registered, vec![service.to_string()]);
    assert!(
        watcher
            .get_property::<bool>("IsStatusNotifierHostRegistered")
            .await?
    );
    assert_eq!(watcher.get_property::<i32>("ProtocolVersion").await?, 0);
    Ok(())
}

async fn assert_item_identity(sni: &zbus::Proxy<'_>) -> TestResult {
    assert_eq!(sni.get_property::<String>("Id").await?, "omarchy-ai-bar");
    assert_eq!(sni.get_property::<String>("Title").await?, "Omarchy AI Bar");
    assert_eq!(
        sni.get_property::<String>("IconName").await?,
        "omarchy-ai-bar"
    );
    assert_eq!(sni.get_property::<String>("Status").await?, "Passive");
    assert!(sni.get_property::<bool>("ItemIsMenu").await?);
    assert_eq!(
        sni.get_property::<OwnedObjectPath>("Menu").await?,
        OwnedObjectPath::try_from(MENU_PATH)?
    );
    assert!(sni.introspect().await?.contains(SNI_INTERFACE));
    Ok(())
}

async fn assert_status_transition(
    controller: &TrayController,
    sni: &zbus::Proxy<'_>,
    client: &zbus::Connection,
    service: &str,
    actions: &mpsc::Receiver<RuntimeAction>,
) -> TestResult {
    let mut signals = sni.receive_signal("NewStatus").await?;
    controller.set_status(SniStatus::Active).await?;
    let signal = tokio::time::timeout(SIGNAL_TIMEOUT, signals.next())
        .await?
        .ok_or_else(|| std::io::Error::other("NewStatus signal stream ended"))?;
    let (status,): (String,) = signal.body().deserialize()?;
    assert_eq!(status, "Active");

    // A new proxy forces a fresh property Get instead of consulting the
    // original proxy's lazy property cache.
    let fresh_sni = zbus::Proxy::new(client, service, SNI_PATH, SNI_INTERFACE).await?;
    assert_eq!(fresh_sni.get_property::<String>("Status").await?, "Active");
    assert_eq!(actions.try_recv(), Err(TryRecvError::Empty));

    let activate_error = sni
        .call::<_, _, ()>("Activate", &(0_i32, 0_i32))
        .await
        .expect_err("menu-only SNI activation should ask the host to display its menu");
    assert!(activate_error.to_string().contains("ItemIsMenu"));
    assert_eq!(actions.try_recv(), Err(TryRecvError::Empty));
    Ok(())
}

async fn assert_menu_actions(
    client: &zbus::Connection,
    service: &str,
    actions: &mpsc::Receiver<RuntimeAction>,
) -> TestResult {
    let menu = zbus::Proxy::new(client, service, MENU_PATH, MENU_INTERFACE).await?;
    let items: Vec<(i32, HashMap<String, OwnedValue>)> = menu
        .call(
            "GetGroupProperties",
            &(Vec::<i32>::new(), vec!["label".to_string()]),
        )
        .await?;
    let labels = items
        .iter()
        .filter_map(|(_, properties)| menu_label(properties))
        .collect::<Vec<_>>();
    assert_eq!(
        labels,
        ["Refresh", "Settings...", "About Omarchy AI Bar", "Quit"]
    );

    for (label, expected) in [
        ("Refresh", RuntimeAction::RefreshAll {}),
        (
            "Settings...",
            RuntimeAction::Navigate {
                destination: NavigationDestination::General,
            },
        ),
        (
            "About Omarchy AI Bar",
            RuntimeAction::Navigate {
                destination: NavigationDestination::About,
            },
        ),
        ("Quit", RuntimeAction::Quit {}),
    ] {
        let item_id = menu_item_id(&items, label)
            .unwrap_or_else(|| panic!("{label} menu item should be exported"));
        let _: () = menu
            .call(
                "Event",
                &(
                    item_id,
                    "clicked".to_string(),
                    OwnedValue::from(0_u8),
                    0_u32,
                ),
            )
            .await?;
        assert_eq!(actions.try_recv()?, expected);
        assert_eq!(actions.try_recv(), Err(TryRecvError::Empty));
    }

    let refresh_id = menu_item_id(&items, "Refresh").expect("Refresh was asserted above");
    for _ in 0..5 {
        let _: () = menu
            .call(
                "Event",
                &(
                    refresh_id,
                    "clicked".to_string(),
                    OwnedValue::from(0_u8),
                    0_u32,
                ),
            )
            .await?;
    }
    for _ in 0..4 {
        assert_eq!(actions.try_recv()?, RuntimeAction::RefreshAll {});
    }
    assert_eq!(actions.try_recv(), Err(TryRecvError::Empty));
    Ok(())
}

async fn assert_name_released(client: &zbus::Connection, service: &str) -> TestResult {
    let dbus = zbus::Proxy::new(
        client,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let name_has_owner: bool = dbus.call("NameHasOwner", &(service,)).await?;
    assert!(!name_has_owner);
    Ok(())
}

fn menu_label(properties: &HashMap<String, OwnedValue>) -> Option<String> {
    properties
        .get("label")
        .and_then(|value| String::try_from(value.clone()).ok())
}

fn menu_item_id(items: &[(i32, HashMap<String, OwnedValue>)], label: &str) -> Option<i32> {
    items
        .iter()
        .find(|(_, properties)| menu_label(properties).as_deref() == Some(label))
        .map(|(id, _)| *id)
}

async fn watcher_name_is_owned() -> zbus::Result<bool> {
    let connection = zbus::connection::Builder::session()?
        .method_timeout(SIGNAL_TIMEOUT)
        .build()
        .await?;
    let dbus = zbus::Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    dbus.call("NameHasOwner", &(WATCHER_NAME,)).await
}
