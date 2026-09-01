use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId};
use oab_providers::browser_cookie::DisabledChromiumCookieDecryptor;
use oab_providers::browser_profile::{BrowserProfileDiscovery, BrowserProfileRoots};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::mistral::MistralProvider;
use oab_providers::providers::opencode::OpenCodeProvider;
use oab_providers::providers::perplexity::PerplexityProvider;
use oab_providers::providers::qwencloud::QwenCloudProvider;
use rusqlite::{Connection, params};
use time::OffsetDateTime;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const NOW_SECONDS: i64 = 1_800_000_000;
const FUTURE_SECONDS: i64 = 1_900_000_000;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omarchy-ai-bar-browser-provider-batch-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn scope(provider: ProviderId) -> AccountScope {
    AccountScope::new(
        provider,
        ProviderInstanceId::new("default").expect("provider instance"),
        AccountKey::new("ambient").expect("account"),
    )
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS).expect("fixture time")
}

fn browser_fixture(expiry: i64) -> (TestDirectory, BrowserProfileDiscovery) {
    let fixture = TestDirectory::new();
    let home = fixture.path().join("home");
    let config = fixture.path().join("config");
    let profile = home.join(".mozilla/firefox/Profiles/default");
    fs::create_dir_all(&profile).expect("Firefox profile");
    fs::create_dir_all(&config).expect("config root");
    fs::write(
        home.join(".mozilla/firefox/profiles.ini"),
        b"[Profile0]\nPath=Profiles/default\nIsRelative=1\nDefault=1\n",
    )
    .expect("Firefox profiles.ini");
    let connection = Connection::open(profile.join("cookies.sqlite")).expect("cookie database");
    connection
        .execute_batch(
            "CREATE TABLE moz_cookies(
                host TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                expiry INTEGER NOT NULL,
                isSecure INTEGER NOT NULL,
                value TEXT NOT NULL
             );",
        )
        .expect("Firefox cookie schema");
    for (host, name, value) in [
        (".opencode.ai", "auth", "opencode-session"),
        (
            ".perplexity.ai",
            "__Secure-authjs.session-token",
            "perplexity-session",
        ),
        (".qwencloud.com", "login_qwencloud_ticket", "qwen-session"),
        (".mistral.ai", "ory_session_fixture", "mistral-session"),
        (".mistral.ai", "csrftoken", "mistral-csrf"),
        (
            ".opencode.ai.evil.invalid",
            "auth",
            "must-not-cross-provider-boundary",
        ),
    ] {
        connection
            .execute(
                "INSERT INTO moz_cookies(host, name, path, expiry, isSecure, value)
                 VALUES (?1, ?2, '/', ?3, 1, ?4)",
                params![host, name, expiry, value],
            )
            .expect("fixture cookie");
    }
    drop(connection);
    let roots = BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("browser roots");
    (fixture, BrowserProfileDiscovery::with_roots(roots))
}

#[test]
fn provider_owned_browser_discovery_builds_all_four_adapters() {
    let (_fixture, discovery) = browser_fixture(FUTURE_SECONDS);
    let decryptor = DisabledChromiumCookieDecryptor;

    let opencode = OpenCodeProvider::new_browser_from_discovery(
        scope(ProviderId::OpenCode),
        &discovery,
        &decryptor,
        now(),
        None,
    )
    .expect("OpenCode browser adapter");
    assert_eq!(opencode.source(), ProviderSource::BrowserSession);

    let perplexity = PerplexityProvider::new_browser_from_discovery(
        scope(ProviderId::Perplexity),
        &discovery,
        &decryptor,
        now(),
    )
    .expect("Perplexity browser adapter");
    assert_eq!(perplexity.source(), ProviderSource::BrowserSession);

    let qwen = QwenCloudProvider::new_browser_from_discovery(
        scope(ProviderId::QwenCloud),
        &discovery,
        &decryptor,
        now(),
    )
    .expect("Qwen Cloud browser adapter");
    assert_eq!(qwen.source(), ProviderSource::BrowserSession);

    let mistral = MistralProvider::new_browser_from_discovery(
        scope(ProviderId::Mistral),
        &discovery,
        &decryptor,
        now(),
    )
    .expect("Mistral browser adapter");
    assert_eq!(mistral.source(), ProviderSource::BrowserSession);

    for debug in [
        format!("{opencode:?}"),
        format!("{perplexity:?}"),
        format!("{qwen:?}"),
        format!("{mistral:?}"),
    ] {
        for canary in [
            "opencode-session",
            "perplexity-session",
            "qwen-session",
            "mistral-session",
            "mistral-csrf",
            "must-not-cross-provider-boundary",
        ] {
            assert!(!debug.contains(canary));
        }
    }
}

#[test]
fn disabled_discovery_is_missing_and_expired_sessions_are_not_accepted() {
    let decryptor = DisabledChromiumCookieDecryptor;
    let disabled = BrowserProfileDiscovery::disabled();
    let error = OpenCodeProvider::new_browser_from_discovery(
        scope(ProviderId::OpenCode),
        &disabled,
        &decryptor,
        now(),
        None,
    )
    .expect_err("disabled discovery");
    assert_eq!(error.kind(), ErrorKind::MissingCredential);

    let (_fixture, expired) = browser_fixture(NOW_SECONDS - 1);
    for error in [
        OpenCodeProvider::new_browser_from_discovery(
            scope(ProviderId::OpenCode),
            &expired,
            &decryptor,
            now(),
            None,
        )
        .expect_err("expired OpenCode session"),
        PerplexityProvider::new_browser_from_discovery(
            scope(ProviderId::Perplexity),
            &expired,
            &decryptor,
            now(),
        )
        .expect_err("expired Perplexity session"),
        QwenCloudProvider::new_browser_from_discovery(
            scope(ProviderId::QwenCloud),
            &expired,
            &decryptor,
            now(),
        )
        .expect_err("expired Qwen Cloud session"),
        MistralProvider::new_browser_from_discovery(
            scope(ProviderId::Mistral),
            &expired,
            &decryptor,
            now(),
        )
        .expect_err("expired Mistral session"),
    ] {
        assert_eq!(error.kind(), ErrorKind::AuthenticationExpired);
    }
}
