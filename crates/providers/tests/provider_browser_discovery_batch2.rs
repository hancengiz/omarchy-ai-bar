use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oab_domain::{AccountKey, AccountScope, ErrorKind, ProviderId, ProviderInstanceId};
use oab_providers::browser_cookie::DisabledChromiumCookieDecryptor;
use oab_providers::browser_profile::{BrowserProfileDiscovery, BrowserProfileRoots};
use oab_providers::descriptor::ProviderSource;
use oab_providers::providers::abacus::AbacusProvider;
use oab_providers::providers::commandcode::CommandCodeProvider;
use oab_providers::providers::notion::NotionProvider;
use oab_providers::providers::t3chat::T3ChatProvider;
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
            "omarchy-ai-bar-browser-provider-batch2-{}-{sequence}",
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

fn browser_fixture(
    expiry: i64,
    first_profile: &[(&str, &str, &str)],
    second_profile: &[(&str, &str, &str)],
) -> (TestDirectory, BrowserProfileDiscovery) {
    let fixture = TestDirectory::new();
    let home = fixture.path().join("home");
    let config = fixture.path().join("config");
    let firefox = home.join(".mozilla/firefox");
    fs::create_dir_all(&firefox).expect("Firefox root");
    fs::create_dir_all(&config).expect("config root");
    fs::write(
        firefox.join("profiles.ini"),
        b"[Profile0]\nPath=Profiles/first\nIsRelative=1\nDefault=1\n\
[Profile1]\nPath=Profiles/second\nIsRelative=1\n",
    )
    .expect("Firefox profiles.ini");
    write_firefox_profile(&firefox.join("Profiles/first"), expiry, first_profile);
    write_firefox_profile(&firefox.join("Profiles/second"), expiry, second_profile);
    let roots = BrowserProfileRoots::new(&home, &config, None::<&Path>).expect("browser roots");
    (fixture, BrowserProfileDiscovery::with_roots(roots))
}

fn write_firefox_profile(path: &Path, expiry: i64, rows: &[(&str, &str, &str)]) {
    fs::create_dir_all(path).expect("Firefox profile");
    let connection = Connection::open(path.join("cookies.sqlite")).expect("cookie database");
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
    for (host, name, value) in rows {
        connection
            .execute(
                "INSERT INTO moz_cookies(host, name, path, expiry, isSecure, value)
                 VALUES (?1, ?2, '/', ?3, 1, ?4)",
                params![host, name, expiry, value],
            )
            .expect("fixture cookie");
    }
}

const VALID_ROWS: [(&str, &str, &str); 5] = [
    (".abacus.ai", "sessionid", "abacus-session-canary"),
    (
        ".commandcode.ai",
        "__Secure-better-auth.session_token",
        "command-session-canary",
    ),
    (".notion.com", "token_v2", "notion-session-canary"),
    (".t3.chat", "session", "t3-session-canary"),
    (".t3.chat.evil.invalid", "session", "cross-domain-canary"),
];

#[test]
fn provider_owned_discovery_builds_all_four_browser_adapters() {
    let (_fixture, discovery) = browser_fixture(FUTURE_SECONDS, &[], &VALID_ROWS);
    let decryptor = DisabledChromiumCookieDecryptor;

    let abacus = AbacusProvider::new_browser_from_discovery(
        scope(ProviderId::Abacus),
        &discovery,
        &decryptor,
        now(),
    )
    .expect("Abacus browser adapter");
    let command = CommandCodeProvider::new_browser_from_discovery(
        scope(ProviderId::CommandCode),
        &discovery,
        &decryptor,
        now(),
    )
    .expect("Command Code browser adapter");
    let notion = NotionProvider::new_browser_from_discovery(
        scope(ProviderId::Notion),
        &discovery,
        &decryptor,
        now(),
        None,
    )
    .expect("Notion browser adapter");
    let t3 = T3ChatProvider::new_browser_from_discovery(
        scope(ProviderId::T3Chat),
        &discovery,
        &decryptor,
        now(),
    )
    .expect("T3 Chat browser adapter");

    assert_eq!(abacus.source(), ProviderSource::BrowserSession);
    assert_eq!(command.source(), ProviderSource::BrowserSession);
    assert_eq!(notion.source(), ProviderSource::BrowserSession);
    assert_eq!(t3.source(), ProviderSource::BrowserSession);

    for debug in [
        format!("{abacus:?}"),
        format!("{command:?}"),
        format!("{notion:?}"),
        format!("{t3:?}"),
    ] {
        for canary in [
            "abacus-session-canary",
            "command-session-canary",
            "notion-session-canary",
            "t3-session-canary",
            "cross-domain-canary",
        ] {
            assert!(!debug.contains(canary));
        }
    }
}

#[test]
fn disabled_discovery_is_missing_and_expired_sessions_are_rejected() {
    let decryptor = DisabledChromiumCookieDecryptor;
    let disabled = BrowserProfileDiscovery::disabled();
    let (_fixture, expired) = browser_fixture(NOW_SECONDS - 1, &VALID_ROWS, &[]);

    for (discovery, expected) in [
        (&disabled, ErrorKind::MissingCredential),
        (&expired, ErrorKind::AuthenticationExpired),
    ] {
        let errors = [
            AbacusProvider::new_browser_from_discovery(
                scope(ProviderId::Abacus),
                discovery,
                &decryptor,
                now(),
            )
            .expect_err("Abacus unavailable session"),
            CommandCodeProvider::new_browser_from_discovery(
                scope(ProviderId::CommandCode),
                discovery,
                &decryptor,
                now(),
            )
            .expect_err("Command Code unavailable session"),
            NotionProvider::new_browser_from_discovery(
                scope(ProviderId::Notion),
                discovery,
                &decryptor,
                now(),
                None,
            )
            .expect_err("Notion unavailable session"),
            T3ChatProvider::new_browser_from_discovery(
                scope(ProviderId::T3Chat),
                discovery,
                &decryptor,
                now(),
            )
            .expect_err("T3 Chat unavailable session"),
        ];
        for error in errors {
            assert_eq!(error.kind(), expected);
        }
    }
}

#[test]
fn provider_specific_session_requirements_match_codexbar() {
    let rows = [
        (".abacus.ai", "csrftoken", "anonymous-abacus"),
        (".commandcode.ai", "analytics", "command-cookie"),
        (".notion.com", "notion_user_id", "anonymous-notion"),
        (".t3.chat", "analytics", "t3-cookie"),
    ];
    let (_fixture, discovery) = browser_fixture(FUTURE_SECONDS, &rows, &[]);
    let decryptor = DisabledChromiumCookieDecryptor;

    let abacus = AbacusProvider::new_browser_from_discovery(
        scope(ProviderId::Abacus),
        &discovery,
        &decryptor,
        now(),
    )
    .expect_err("Abacus requires a session-shaped cookie");
    assert_eq!(abacus.kind(), ErrorKind::AuthenticationExpired);

    let notion = NotionProvider::new_browser_from_discovery(
        scope(ProviderId::Notion),
        &discovery,
        &decryptor,
        now(),
        None,
    )
    .expect_err("Notion requires token_v2");
    assert_eq!(notion.kind(), ErrorKind::AuthenticationExpired);

    assert_eq!(
        CommandCodeProvider::new_browser_from_discovery(
            scope(ProviderId::CommandCode),
            &discovery,
            &decryptor,
            now(),
        )
        .expect("Command Code sends all domain cookies for API validation")
        .source(),
        ProviderSource::BrowserSession
    );
    assert_eq!(
        T3ChatProvider::new_browser_from_discovery(
            scope(ProviderId::T3Chat),
            &discovery,
            &decryptor,
            now(),
        )
        .expect("T3 Chat has no stable session-cookie name")
        .source(),
        ProviderSource::BrowserSession
    );
}
