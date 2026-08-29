use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use oab_cli::commands::bridge::{
    BridgeError, BridgeManager, BridgeStatus, OmarchyPluginCommands, PLUGIN_ID,
};
use oab_ipc::protocol::{
    AcceptedClientFrame, BridgeVersion, CapabilitySet, ClientHello, ClientMessage,
    FrontendSessionId, MIN_SUPPORTED_PROTOCOL_MAJOR, ProtocolVersion, ServerHandshakeContext,
};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Default)]
struct RecordingCommands {
    calls: Arc<Mutex<Vec<String>>>,
}

impl RecordingCommands {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("command record lock").clone()
    }

    fn push(&self, call: impl Into<String>) {
        self.calls
            .lock()
            .expect("command record lock")
            .push(call.into());
    }
}

impl OmarchyPluginCommands for RecordingCommands {
    fn validate(&self, plugin_dir: &Path) -> Result<(), BridgeError> {
        assert!(plugin_dir.exists(), "validation must see a staged tree");
        assert!(
            plugin_dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".local.omarchy-ai-bar.stage.")),
            "validation must run against staging, not the final path"
        );
        if self.calls.lock().expect("command record lock").is_empty() {
            assert!(
                !plugin_dir
                    .parent()
                    .expect("staging parent")
                    .join(PLUGIN_ID)
                    .exists(),
                "final plugin path must not exist during install validation"
            );
        }
        self.push(format!("validate:{}", plugin_dir.display()));
        Ok(())
    }

    fn rescan(&self) -> Result<(), BridgeError> {
        self.push("rescan");
        Ok(())
    }

    fn enable(&self, plugin_id: &str) -> Result<(), BridgeError> {
        self.push(format!("enable:{plugin_id}"));
        Ok(())
    }

    fn disable(&self, plugin_id: &str) -> Result<(), BridgeError> {
        self.push(format!("disable:{plugin_id}"));
        Ok(())
    }
}

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    config_home: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-bridge-{}-{label}-{sequence}",
            std::process::id()
        ));
        let source = root.join("package/usr/share/omarchy-ai-bar/omarchy-plugin");
        let config_home = root.join("home/.config");
        fs::create_dir_all(&source).expect("create packaged plugin source");
        write_plugin(&source, "0.1.0", "first payload");
        Self {
            root,
            source,
            config_home,
        }
    }

    fn manager(&self, commands: RecordingCommands) -> BridgeManager<RecordingCommands> {
        BridgeManager::new(&self.source, &self.config_home, commands)
    }

    fn destination(&self) -> PathBuf {
        self.config_home.join("omarchy/plugins").join(PLUGIN_ID)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove bridge fixture");
        }
    }
}

fn write_plugin(root: &Path, version: &str, panel: &str) {
    fs::write(
        root.join("manifest.json"),
        format!(
            r#"{{
  "schemaVersion": 1,
  "id": "{PLUGIN_ID}",
  "name": "Omarchy AI Bar",
  "version": "{version}",
  "kinds": ["bar-widget"],
  "entryPoints": {{"barWidget": "BarWidget.qml"}},
  "barWidget": {{"defaultSection": "right"}}
}}"#
        ),
    )
    .expect("write manifest");
    fs::write(root.join("BarWidget.qml"), panel).expect("write QML payload");
}

#[test]
fn install_validates_staging_before_atomic_movement_and_enables() {
    let fixture = Fixture::new("install");
    let commands = RecordingCommands::default();
    let manager = fixture.manager(commands.clone());

    manager.install().expect("install bridge");

    let destination = fixture.destination();
    assert!(destination.join("manifest.json").is_file());
    assert!(destination.join(".omarchy-ai-bar-managed.json").is_file());
    let calls = commands.calls();
    assert!(calls[0].starts_with("validate:"));
    assert_eq!(&calls[1..], &["rescan", &format!("enable:{PLUGIN_ID}")]);
    assert!(matches!(
        manager.status().expect("bridge status"),
        BridgeStatus::Installed {
            update_available: Some(false),
            ..
        }
    ));
}

#[test]
fn update_preserves_omarchy_state_and_refuses_modified_tree() {
    let fixture = Fixture::new("update");
    let commands = RecordingCommands::default();
    let manager = fixture.manager(commands);
    manager.install().expect("install bridge");

    let shell_state = fixture.config_home.join("omarchy/shell.json");
    let shell_contents = format!(
        r#"{{"plugins":[{{"id":"{PLUGIN_ID}","section":"left","index":2,"settings":{{"compact":true}}}}]}}"#
    );
    fs::write(&shell_state, &shell_contents).expect("write Omarchy state");
    write_plugin(&fixture.source, "0.2.0", "second payload");
    assert!(matches!(
        manager.status().expect("status before update"),
        BridgeStatus::Installed {
            update_available: Some(true),
            ..
        }
    ));

    manager.update().expect("update managed bridge");
    assert_eq!(
        fs::read_to_string(&shell_state).expect("read preserved Omarchy state"),
        shell_contents
    );
    assert_eq!(
        fs::read_to_string(fixture.destination().join("BarWidget.qml"))
            .expect("read updated payload"),
        "second payload"
    );

    fs::write(
        fixture.destination().join("BarWidget.qml"),
        "local modification",
    )
    .expect("modify managed payload");
    assert!(matches!(manager.update(), Err(BridgeError::ModifiedTree)));
    assert_eq!(
        fs::read_to_string(fixture.destination().join("BarWidget.qml"))
            .expect("read refused local edit"),
        "local modification"
    );
}

#[test]
fn uninstall_disables_and_removes_only_verified_application_files() {
    let fixture = Fixture::new("uninstall");
    let commands = RecordingCommands::default();
    let manager = fixture.manager(commands.clone());
    manager.install().expect("install bridge");

    let sibling = fixture
        .config_home
        .join("omarchy/plugins/example.other-plugin");
    fs::create_dir_all(&sibling).expect("create unrelated plugin");
    fs::write(sibling.join("keep"), "mine").expect("write unrelated plugin");
    let shell_state = fixture.config_home.join("omarchy/shell.json");
    fs::write(&shell_state, "user placement").expect("write Omarchy state");

    manager.uninstall().expect("uninstall bridge");

    assert!(!fixture.destination().exists());
    assert_eq!(
        fs::read_to_string(sibling.join("keep")).expect("read unrelated plugin"),
        "mine"
    );
    assert_eq!(
        fs::read_to_string(shell_state).expect("read untouched Omarchy state"),
        "user placement"
    );
    let calls = commands.calls();
    let tail = &calls[calls.len() - 2..];
    assert_eq!(tail, &[format!("disable:{PLUGIN_ID}"), "rescan".into()]);
}

#[test]
fn symlink_in_package_payload_is_rejected_before_install() {
    let fixture = Fixture::new("symlink");
    symlink("/etc/passwd", fixture.source.join("escape"))
        .expect("create malicious package symlink");
    let manager = fixture.manager(RecordingCommands::default());

    assert!(matches!(manager.install(), Err(BridgeError::UnsafePayload)));
    assert!(!fixture.destination().exists());
}

#[test]
fn update_accepts_one_previous_bridge_protocol_major() {
    let fixture = Fixture::new("previous-major");
    let manager = fixture.manager(RecordingCommands::default());
    manager.install().expect("install current bridge");

    let marker_path = fixture.destination().join(".omarchy-ai-bar-managed.json");
    let mut marker: serde_json::Value =
        serde_json::from_slice(&fs::read(&marker_path).expect("read marker"))
            .expect("parse marker");
    marker["protocol_major"] = 0.into();
    fs::write(
        &marker_path,
        serde_json::to_vec_pretty(&marker).expect("serialize previous marker"),
    )
    .expect("write previous marker");

    write_plugin(&fixture.source, "0.2.0", "compatible update");
    manager.update().expect("update previous-major bridge");
}

#[test]
fn backend_negotiates_the_previous_wire_major_during_rolling_updates() {
    let context = ServerHandshakeContext::new(CapabilitySet::default())
        .expect("create backend handshake context");
    let client = ClientMessage::hello(ClientHello::new(
        ProtocolVersion::new(MIN_SUPPORTED_PROTOCOL_MAJOR, 0),
        BridgeVersion::new(0, 9, 0),
        FrontendSessionId::parse("0123456789abcdef0123456789abcdef")
            .expect("parse frontend session id"),
        CapabilitySet::default(),
    ));

    let AcceptedClientFrame::Hello(server) = context
        .connection()
        .accept(&client)
        .expect("negotiate previous bridge protocol major")
    else {
        panic!("expected server hello");
    };
    assert_eq!(server.protocol().major(), MIN_SUPPORTED_PROTOCOL_MAJOR);
}
