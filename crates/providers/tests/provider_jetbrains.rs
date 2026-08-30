use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId, Timestamp};
use oab_providers::context::{ProviderAdapter, ProviderContext};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::jetbrains::{JetBrainsProvider, JetBrainsSettings};
use tokio_util::sync::CancellationToken;

const QUOTA: &[u8] = include_bytes!("../../../fixtures/providers/jetbrains/quota.xml");

fn scope(account: &str) -> AccountScope {
    AccountScope::new(
        ProviderId::JetBrains,
        ProviderInstanceId::new("jetbrains-local").expect("provider instance"),
        AccountKey::new(account).expect("account key"),
    )
}

fn context(account: &str, source: ProviderSource) -> ProviderContext {
    ProviderContext::new(scope(account), source, CancellationToken::new())
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::parse(value).expect("fixture timestamp")
}

fn write_quota(base: &Path, body: &[u8]) {
    let options = base.join("options");
    fs::create_dir_all(&options).expect("create IDE options");
    fs::write(options.join("AIAssistantQuotaManager2.xml"), body).expect("write quota fixture");
}

fn detail<'a>(sample: &'a oab_domain::UsageSample, label: &str) -> &'a str {
    sample
        .detail_sections()
        .iter()
        .flat_map(oab_domain::DetailSection::rows)
        .find(|row| row.label() == label)
        .map(oab_domain::DetailRow::value)
        .expect("detail row")
}

#[test]
fn xdg_discovery_projects_exact_quota_refill_and_identity() {
    let directory = TestDirectory::new("jetbrains-xdg");
    let config_home = directory.path().join("config");
    let ide = config_home.join("JetBrains/IntelliJIdea2026.2");
    write_quota(&ide, QUOTA);
    let environment = BTreeMap::from([
        (
            "HOME".to_owned(),
            directory.path().join("home").to_string_lossy().into_owned(),
        ),
        (
            "XDG_CONFIG_HOME".to_owned(),
            config_home.to_string_lossy().into_owned(),
        ),
        (
            "XDG_DATA_HOME".to_owned(),
            directory.path().join("data").to_string_lossy().into_owned(),
        ),
    ]);
    let settings = JetBrainsSettings::resolve(&environment).expect("Linux settings");
    let provider = JetBrainsProvider::new(scope("account-a"), settings).expect("provider");
    let sample = provider
        .fetch_at(
            &context("account-a", ProviderSource::LocalData),
            timestamp("2026-08-30T10:00:00Z"),
        )
        .expect("local quota");

    assert_eq!(provider.descriptor().id, ProviderId::JetBrains);
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get),
        Some(25.0)
    );
    assert_eq!(
        sample.primary().and_then(oab_domain::RateWindow::resets_at),
        Some(timestamp("2026-09-01T12:30:00Z"))
    );
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::reset_description)
            .map(oab_domain::BoundedText::as_str),
        Some("Resets in 2d 2h")
    );
    assert_eq!(
        sample
            .identity()
            .organization()
            .map(oab_domain::BoundedText::as_str),
        Some("IntelliJ IDEA 2026.2")
    );
    assert_eq!(
        sample
            .identity()
            .login_method()
            .map(oab_domain::BoundedText::as_str),
        Some("PRO")
    );
    assert_eq!(detail(&sample, "Credits used"), "25");
    assert_eq!(detail(&sample, "Credits maximum"), "100");
    assert_eq!(detail(&sample, "Credits available"), "75");
    assert_eq!(detail(&sample, "Refill type"), "MONTHLY");
    assert_eq!(detail(&sample, "Refill amount"), "100");
    assert_eq!(detail(&sample, "Refill duration"), "P1M");
    assert_eq!(detail(&sample, "IDE"), "IntelliJ IDEA 2026.2");
    assert_eq!(sample.provenance()[0].source(), "jetbrains");
}

#[test]
fn google_android_studio_root_is_linux_native_and_custom_path_stays_unlabeled() {
    let directory = TestDirectory::new("jetbrains-google");
    let google = directory.path().join("Google");
    let studio = google.join("AndroidStudio2026.1");
    write_quota(&studio, QUOTA);
    let settings = JetBrainsSettings::from_discovery_roots([google]).expect("root settings");
    let sample = JetBrainsProvider::new(scope("studio"), settings)
        .expect("provider")
        .fetch_at(
            &context("studio", ProviderSource::LocalData),
            timestamp("2026-08-30T10:00:00Z"),
        )
        .expect("Android Studio quota");
    assert_eq!(
        sample
            .identity()
            .organization()
            .map(oab_domain::BoundedText::as_str),
        Some("Android Studio 2026.1")
    );

    let custom = directory.path().join("custom-ide");
    write_quota(&custom, QUOTA);
    let settings = JetBrainsSettings::from_ide_path(&custom).expect("custom settings");
    let debug = format!("{settings:?}");
    assert!(!debug.contains(custom.to_string_lossy().as_ref()));
    let sample = JetBrainsProvider::new(scope("custom"), settings)
        .expect("provider")
        .fetch_at(
            &context("custom", ProviderSource::LocalData),
            timestamp("2026-08-30T10:00:00Z"),
        )
        .expect("custom quota");
    assert!(sample.identity().organization().is_none());
}

#[test]
fn first_quota_option_wins_and_refill_parse_failure_is_best_effort() {
    let directory = TestDirectory::new("jetbrains-first");
    let ide = directory.path().join("RustRover2026.3");
    let xml = br"<application><component name='AIAssistantQuotaManager2'>
      <option name='quotaInfo' value='{&quot;type&quot;:&quot;TRIAL&quot;,&quot;current&quot;:&quot;30&quot;,&quot;maximum&quot;:&quot;20&quot;}'/>
      <option name='quotaInfo' value='{&quot;current&quot;:&quot;1&quot;,&quot;maximum&quot;:&quot;100&quot;}'/>
      <option name='nextRefill' value='not-json'/>
    </component></application>";
    write_quota(&ide, xml);
    let settings = JetBrainsSettings::from_discovery_roots([directory.path().to_owned()])
        .expect("root settings");
    let sample = JetBrainsProvider::new(scope("first"), settings)
        .expect("provider")
        .fetch_at(
            &context("first", ProviderSource::LocalData),
            timestamp("2026-08-30T10:00:00Z"),
        )
        .expect("first option");
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get),
        Some(100.0)
    );
    assert!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::resets_at)
            .is_none()
    );
}

#[test]
fn missing_malformed_dtd_and_oversized_documents_fail_closed_without_paths() {
    let directory = TestDirectory::new("jetbrains-errors");
    let missing = directory.path().join("missing");
    let provider = JetBrainsProvider::new(
        scope("missing"),
        JetBrainsSettings::from_ide_path(&missing).expect("settings"),
    )
    .expect("provider");
    let error = provider
        .fetch_at(
            &context("missing", ProviderSource::LocalData),
            timestamp("2026-08-30T10:00:00Z"),
        )
        .expect_err("missing quota");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);
    assert!(!format!("{error:?}").contains(missing.to_string_lossy().as_ref()));

    let symlink_target = directory.path().join("symlink-target");
    write_quota(&symlink_target, QUOTA);
    let symlink_ide = directory.path().join("symlink-ide");
    fs::create_dir_all(symlink_ide.join("options")).expect("create symlink options");
    symlink(
        symlink_target.join("options/AIAssistantQuotaManager2.xml"),
        symlink_ide.join("options/AIAssistantQuotaManager2.xml"),
    )
    .expect("create quota symlink");
    let provider = JetBrainsProvider::new(
        scope("symlink"),
        JetBrainsSettings::from_ide_path(&symlink_ide).expect("settings"),
    )
    .expect("provider");
    assert_eq!(
        provider
            .fetch_at(
                &context("symlink", ProviderSource::LocalData),
                timestamp("2026-08-30T10:00:00Z"),
            )
            .expect_err("quota symlink")
            .kind(),
        ErrorKind::MissingCredential
    );

    for (label, body, expected) in [
        (
            "malformed",
            b"<component name='AIAssistantQuotaManager2'><option name='quotaInfo' value='not-json'/></component>".as_slice(),
            ErrorKind::Parse,
        ),
        (
            "dtd",
            b"<!DOCTYPE x [<!ENTITY leak SYSTEM 'file:///etc/passwd'>]><component name='AIAssistantQuotaManager2'><option name='quotaInfo' value='{}'/></component>".as_slice(),
            ErrorKind::Parse,
        ),
        (
            "no-quota",
            b"<component name='AIAssistantQuotaManager2'></component>".as_slice(),
            ErrorKind::MissingCredential,
        ),
    ] {
        let ide = directory.path().join(label);
        write_quota(&ide, body);
        let provider = JetBrainsProvider::new(
            scope(label),
            JetBrainsSettings::from_ide_path(&ide).expect("settings"),
        )
        .expect("provider");
        assert_eq!(
            provider
                .fetch_at(
                    &context(label, ProviderSource::LocalData),
                    timestamp("2026-08-30T10:00:00Z"),
                )
                .expect_err("invalid document")
                .kind(),
            expected
        );
    }

    let oversized = directory.path().join("oversized");
    write_quota(&oversized, &vec![b'x'; 1024 * 1024 + 1]);
    let provider = JetBrainsProvider::new(
        scope("oversized"),
        JetBrainsSettings::from_ide_path(&oversized).expect("settings"),
    )
    .expect("provider");
    assert_eq!(
        provider
            .fetch_at(
                &context("oversized", ProviderSource::LocalData),
                timestamp("2026-08-30T10:00:00Z"),
            )
            .expect_err("oversized document")
            .kind(),
        ErrorKind::Parse
    );
}

#[test]
fn quota_fifo_is_rejected_without_blocking() {
    let directory = TestDirectory::new("jetbrains-fifo");
    let fifo_ide = directory.path().join("fifo-ide");
    let fifo_options = fifo_ide.join("options");
    fs::create_dir_all(&fifo_options).expect("create FIFO options");
    let fifo_path = fifo_options.join("AIAssistantQuotaManager2.xml");
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("create quota FIFO");
    let provider = JetBrainsProvider::new(
        scope("fifo"),
        JetBrainsSettings::from_ide_path(&fifo_ide).expect("FIFO settings"),
    )
    .expect("FIFO provider");
    let (sender, result_channel) = mpsc::channel();
    let reader = thread::spawn(move || {
        let kind = provider
            .fetch_at(
                &context("fifo", ProviderSource::LocalData),
                timestamp("2026-08-30T10:00:00Z"),
            )
            .expect_err("quota FIFO")
            .kind();
        sender.send(kind).expect("send FIFO result");
    });
    let fifo_result = result_channel.recv_timeout(Duration::from_millis(500));
    if fifo_result.is_err() {
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unblock a regressed FIFO reader");
        drop(writer);
    }
    reader.join().expect("FIFO reader thread");
    assert_eq!(
        fifo_result.expect("quota FIFO must be rejected without blocking"),
        ErrorKind::Parse
    );
}

#[test]
fn settings_and_context_boundaries_fail_before_local_io() {
    let relative = BTreeMap::from([
        ("HOME".to_owned(), "/tmp/jetbrains-home".to_owned()),
        ("XDG_CONFIG_HOME".to_owned(), "relative".to_owned()),
    ]);
    assert_eq!(
        JetBrainsSettings::resolve(&relative)
            .expect_err("relative XDG root")
            .kind(),
        ErrorKind::Api
    );
    assert_eq!(
        JetBrainsSettings::from_ide_path("relative")
            .expect_err("relative IDE root")
            .kind(),
        ErrorKind::Api
    );

    let settings = JetBrainsSettings::from_ide_path("/definitely/not/read").expect("settings");
    let provider = JetBrainsProvider::new(scope("account-a"), settings).expect("provider");
    for bad_context in [
        context("account-b", ProviderSource::LocalData),
        context("account-a", ProviderSource::Cli),
    ] {
        assert_eq!(
            provider
                .fetch_at(&bad_context, timestamp("2026-08-30T10:00:00Z"))
                .expect_err("context mismatch")
                .kind(),
            ErrorKind::Api
        );
    }
}

#[tokio::test]
async fn adapter_fetch_is_lazy_and_returns_promptly_on_cancellation() {
    let directory = TestDirectory::new("jetbrains-cancel");
    let ide = directory.path().join("IntelliJIdea2026.2");
    write_quota(&ide, QUOTA);
    let provider = JetBrainsProvider::new(
        scope("cancelled"),
        JetBrainsSettings::from_ide_path(&ide).expect("settings"),
    )
    .expect("provider");
    let cancellation = CancellationToken::new();
    let fetch_context = ProviderContext::new(
        scope("cancelled"),
        ProviderSource::LocalData,
        cancellation.clone(),
    );

    let fetch = provider.fetch(&fetch_context);
    cancellation.cancel();
    let error = tokio::time::timeout(Duration::from_millis(500), fetch)
        .await
        .expect("cancelled local fetch deadline")
        .expect_err("cancelled local fetch");
    assert_eq!(error.kind(), ErrorKind::Network);

    let sample = tokio::time::timeout(
        Duration::from_secs(1),
        provider.fetch(&context("cancelled", ProviderSource::LocalData)),
    )
    .await
    .expect("offloaded local fetch deadline")
    .expect("offloaded local fetch");
    assert_eq!(
        sample
            .primary()
            .and_then(oab_domain::RateWindow::used_percent)
            .map(oab_domain::UsagePercent::get),
        Some(25.0)
    );
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-{label}-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
