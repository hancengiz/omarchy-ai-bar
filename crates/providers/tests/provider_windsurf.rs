use oab_domain::{
    AccountKey, AccountScope, ProviderId, ProviderInstanceId, RateWindow, Timestamp, UsagePercent,
};
use oab_providers::providers::windsurf::{WindsurfProvider, WindsurfSettings};
use rusqlite::{Connection, params};

fn scope() -> AccountScope {
    AccountScope::new(
        ProviderId::Windsurf,
        ProviderInstanceId::new("default").expect("instance"),
        AccountKey::new("fixture").expect("account"),
    )
}

#[test]
fn linux_state_database_is_read_from_a_private_snapshot() {
    let directory = tempfile::tempdir().expect("directory");
    let database = directory.path().join("state.vscdb");
    let connection = Connection::open(&database).expect("database");
    connection
        .execute(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
            [],
        )
        .expect("schema");
    let payload = br#"{
      "planName":"Pro Ultimate",
      "endTimestamp":1788220800000,
      "quotaUsage":{"dailyRemainingPercent":75,"weeklyRemainingPercent":40,"dailyResetAtUnix":1788220800,"weeklyResetAtUnix":1788825600}
    }"#;
    connection
        .execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            params!["windsurf.settings.cachedPlanInfo", payload],
        )
        .expect("insert");
    drop(connection);

    let settings =
        WindsurfSettings::for_profile_root(directory.path().to_path_buf()).expect("settings");
    assert!(!format!("{settings:?}").contains(directory.path().to_string_lossy().as_ref()));
    let provider = WindsurfProvider::new(scope(), settings);
    let sample = provider
        .read_at(Timestamp::parse("2026-08-31T00:00:00Z").expect("time"))
        .expect("sample");

    assert_eq!(percent(sample.primary()), Some(25.0));
    assert_eq!(percent(sample.secondary()), Some(60.0));
    assert_eq!(
        sample.subscription_expires_at(),
        Some(Timestamp::from_unix_timestamp(1_788_220_800).expect("expiry"))
    );
}

#[test]
fn legacy_message_and_flow_counts_remain_supported() {
    let directory = tempfile::tempdir().expect("directory");
    let connection = Connection::open(directory.path().join("state.vscdb")).expect("database");
    connection
        .execute(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )
        .expect("schema");
    let payload = r#"{"planName":"Legacy","usage":{"messages":100,"usedMessages":25,"remainingMessages":75,"flowActions":20,"usedFlowActions":10,"remainingFlowActions":10}}"#;
    connection
        .execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            params!["windsurf.settings.cachedPlanInfo", payload],
        )
        .expect("insert");
    drop(connection);

    let provider = WindsurfProvider::new(
        scope(),
        WindsurfSettings::for_profile_root(directory.path().to_path_buf()).expect("settings"),
    );
    let sample = provider
        .read_at(Timestamp::parse("2026-08-31T00:00:00Z").expect("time"))
        .expect("sample");
    assert_eq!(percent(sample.primary()), Some(25.0));
    assert_eq!(percent(sample.secondary()), Some(50.0));
}

fn percent(window: Option<&RateWindow>) -> Option<f64> {
    window
        .and_then(RateWindow::used_percent)
        .map(UsagePercent::get)
}
